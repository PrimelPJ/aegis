package store

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/PrimelPJ/aegis/internal/audit"
)

// Segment is a single append-only file holding a contiguous run of
// events. The log is split into segments so that old data can be
// archived, replicated or retention-expired without rewriting the
// whole history, and so a single file never grows unbounded.
//
// On-disk record layout (repeated):
//
//	┌────────────┬───────────────────────────┐
//	│ uint32 len │ len bytes of JSON(Event)   │
//	└────────────┴───────────────────────────┘
//
// JSON is used for storage readability; the tamper-evident hash is
// computed from a separate canonical binary encoding (see audit pkg),
// so storage format choices cannot weaken the integrity guarantee.
type Segment struct {
	baseSeq uint64
	path    string
	file    *os.File
	size    int64
}

const recordHeaderLen = 4

func segmentName(baseSeq uint64) string {
	return fmt.Sprintf("segment-%020d.log", baseSeq)
}

func createSegment(dir string, baseSeq uint64) (*Segment, error) {
	path := filepath.Join(dir, segmentName(baseSeq))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	return &Segment{baseSeq: baseSeq, path: path, file: f, size: info.Size()}, nil
}

// append writes one length-prefixed record and fsyncs it. An audit log
// must be durable before the writer is told the event was accepted, so
// a crash cannot lose an event that a caller believes is recorded.
func (s *Segment) append(e *audit.Event) (offset int64, err error) {
	payload, err := json.Marshal(e)
	if err != nil {
		return 0, err
	}
	var hdr [recordHeaderLen]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))

	offset = s.size
	if _, err = s.file.Write(hdr[:]); err != nil {
		return 0, err
	}
	if _, err = s.file.Write(payload); err != nil {
		return 0, err
	}
	if err = s.file.Sync(); err != nil {
		return 0, err
	}
	s.size += int64(recordHeaderLen + len(payload))
	return offset, nil
}

// readAt reads the record stored at the given byte offset.
func (s *Segment) readAt(offset int64) (audit.Event, error) {
	var hdr [recordHeaderLen]byte
	if _, err := s.file.ReadAt(hdr[:], offset); err != nil {
		return audit.Event{}, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	buf := make([]byte, n)
	if _, err := s.file.ReadAt(buf, offset+recordHeaderLen); err != nil {
		return audit.Event{}, err
	}
	var e audit.Event
	if err := json.Unmarshal(buf, &e); err != nil {
		return audit.Event{}, err
	}
	return e, nil
}

// scan replays every record in the segment in order, invoking fn with
// the event and its byte offset. A truncated trailing record (from a
// crash mid-write) stops the scan cleanly rather than corrupting state.
func (s *Segment) scan(fn func(e audit.Event, offset int64) error) error {
	if _, err := s.file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	r := bufio.NewReader(s.file)
	var offset int64
	for {
		var hdr [recordHeaderLen]byte
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			if err == io.EOF {
				return nil
			}
			if err == io.ErrUnexpectedEOF {
				return nil // torn header from crash; ignore tail
			}
			return err
		}
		n := binary.BigEndian.Uint32(hdr[:])
		buf := make([]byte, n)
		if _, err := io.ReadFull(r, buf); err != nil {
			if err == io.ErrUnexpectedEOF || err == io.EOF {
				return nil // torn body from crash; ignore tail
			}
			return err
		}
		var e audit.Event
		if err := json.Unmarshal(buf, &e); err != nil {
			return fmt.Errorf("segment %s: corrupt record at %d: %w", s.path, offset, err)
		}
		if err := fn(e, offset); err != nil {
			return err
		}
		offset += int64(recordHeaderLen + n)
	}
}

func (s *Segment) close() error {
	if s.file == nil {
		return nil
	}
	return s.file.Close()
}
