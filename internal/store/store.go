package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/PrimelPJ/aegis/internal/audit"
	"github.com/PrimelPJ/aegis/internal/keys"
	"github.com/PrimelPJ/aegis/internal/merkle"
)

// recordLoc points at a record's physical location.
type recordLoc struct {
	segIdx int
	offset int64
}

// Checkpoint is a signed commitment to the state of the log up to and
// including event Through. The Merkle root commits to every event; the
// HeadHash commits to the chain tip; the signature binds both to the
// server's signing identity. Auditors only need to trust the public
// key, not the storage.
type Checkpoint struct {
	ID         int    `json:"id"`
	Through    uint64 `json:"through_seq"`
	EventCount uint64 `json:"event_count"`
	MerkleRoot []byte `json:"merkle_root"`
	HeadHash   []byte `json:"head_hash"`
	IssuedUnix int64  `json:"issued_unix_nano"`
	PublicKey  []byte `json:"public_key"`
	Signature  []byte `json:"signature"`
}

// signedBytes is the exact message covered by the signature.
func (c *Checkpoint) signedBytes() []byte {
	b, _ := json.Marshal(struct {
		Through    uint64 `json:"through_seq"`
		EventCount uint64 `json:"event_count"`
		MerkleRoot []byte `json:"merkle_root"`
		HeadHash   []byte `json:"head_hash"`
		IssuedUnix int64  `json:"issued_unix_nano"`
	}{c.Through, c.EventCount, c.MerkleRoot, c.HeadHash, c.IssuedUnix})
	return b
}

// VerifySignature confirms the checkpoint was signed by the holder of
// the embedded public key.
func (c *Checkpoint) VerifySignature() bool {
	return keys.Verify(c.PublicKey, c.signedBytes(), c.Signature)
}

// Store is the durable, tamper-evident event log. It is safe for
// concurrent use.
type Store struct {
	mu         sync.RWMutex
	dir        string
	maxSegSize int64
	segments   []*Segment
	index      []recordLoc // index[seq] -> location
	leafHashes [][]byte    // merkle leaves, leafHashes[seq] = Hash
	headHash   []byte
	nextSeq    uint64
	id         *keys.Identity
	cpPath     string
	checkpts   []Checkpoint
}

// DefaultMaxSegmentSize rolls a new segment every 8 MiB.
const DefaultMaxSegmentSize = 8 << 20

// Open initialises (or recovers) a store rooted at dir. Recovery
// replays every segment, rebuilds the index and Merkle leaves, and
// re-derives the chain head. It does not silently repair corruption;
// use Verify to audit integrity.
func Open(dir string, maxSegSize int64) (*Store, error) {
	if maxSegSize <= 0 {
		maxSegSize = DefaultMaxSegmentSize
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	id, err := keys.LoadOrCreate(filepath.Join(dir, "keys"))
	if err != nil {
		return nil, err
	}
	s := &Store{
		dir:        dir,
		maxSegSize: maxSegSize,
		headHash:   audit.GenesisPrevHash,
		id:         id,
		cpPath:     filepath.Join(dir, "checkpoints.json"),
	}
	if err := s.recover(); err != nil {
		return nil, err
	}
	if err := s.loadCheckpoints(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) recover() error {
	matches, err := filepath.Glob(filepath.Join(s.dir, "segment-*.log"))
	if err != nil {
		return err
	}
	sort.Strings(matches)

	for _, path := range matches {
		var base uint64
		if _, err := fmt.Sscanf(filepath.Base(path), "segment-%020d.log", &base); err != nil {
			continue
		}
		seg, err := createSegment(s.dir, base)
		if err != nil {
			return err
		}
		segIdx := len(s.segments)
		s.segments = append(s.segments, seg)
		err = seg.scan(func(e audit.Event, offset int64) error {
			if e.Seq != s.nextSeq {
				return fmt.Errorf("recover: sequence gap, expected %d got %d",
					s.nextSeq, e.Seq)
			}
			s.index = append(s.index, recordLoc{segIdx: segIdx, offset: offset})
			s.leafHashes = append(s.leafHashes, append([]byte(nil), e.Hash...))
			s.headHash = e.Hash
			s.nextSeq++
			return nil
		})
		if err != nil {
			return err
		}
	}
	if len(s.segments) == 0 {
		seg, err := createSegment(s.dir, 0)
		if err != nil {
			return err
		}
		s.segments = append(s.segments, seg)
	}
	return nil
}

// activeSegment returns the segment new events are appended to,
// rolling to a fresh one if the current segment is full.
func (s *Store) activeSegment() (*Segment, int, error) {
	last := s.segments[len(s.segments)-1]
	if last.size < s.maxSegSize {
		return last, len(s.segments) - 1, nil
	}
	seg, err := createSegment(s.dir, s.nextSeq)
	if err != nil {
		return nil, 0, err
	}
	s.segments = append(s.segments, seg)
	return seg, len(s.segments) - 1, nil
}

// Append seals an event onto the chain and durably persists it. The
// returned Event carries the assigned sequence number and hashes.
func (s *Store) Append(e audit.Event) (audit.Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if e.TimeUnixN == 0 {
		e.TimeUnixN = time.Now().UnixNano()
	}
	e.Seal(s.nextSeq, s.headHash)

	seg, segIdx, err := s.activeSegment()
	if err != nil {
		return audit.Event{}, err
	}
	offset, err := seg.append(&e)
	if err != nil {
		return audit.Event{}, err
	}
	s.index = append(s.index, recordLoc{segIdx: segIdx, offset: offset})
	s.leafHashes = append(s.leafHashes, append([]byte(nil), e.Hash...))
	s.headHash = e.Hash
	s.nextSeq++
	return e, nil
}

var errNotFound = errors.New("store: event not found")

// Get returns the event at seq.
func (s *Store) Get(seq uint64) (audit.Event, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if seq >= s.nextSeq {
		return audit.Event{}, errNotFound
	}
	loc := s.index[seq]
	return s.segments[loc.segIdx].readAt(loc.offset)
}

// Range returns events in [from, to). to == 0 means "to the end".
func (s *Store) Range(from, to uint64) ([]audit.Event, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if to == 0 || to > s.nextSeq {
		to = s.nextSeq
	}
	if from > to {
		return nil, nil
	}
	out := make([]audit.Event, 0, to-from)
	for seq := from; seq < to; seq++ {
		loc := s.index[seq]
		e, err := s.segments[loc.segIdx].readAt(loc.offset)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

// Len returns the number of events in the log.
func (s *Store) Len() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.nextSeq
}

// Head returns the current chain tip hash.
func (s *Store) Head() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]byte(nil), s.headHash...)
}

// Checkpoint builds a Merkle tree over every event, signs the root and
// chain head, persists the checkpoint and returns it.
func (s *Store) Checkpoint() (Checkpoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.nextSeq == 0 {
		return Checkpoint{}, errors.New("store: nothing to checkpoint")
	}
	tree := merkle.New(s.leafHashes)
	cp := Checkpoint{
		ID:         len(s.checkpts) + 1,
		Through:    s.nextSeq - 1,
		EventCount: s.nextSeq,
		MerkleRoot: tree.Root(),
		HeadHash:   append([]byte(nil), s.headHash...),
		IssuedUnix: time.Now().UnixNano(),
		PublicKey:  append([]byte(nil), s.id.Pub...),
	}
	cp.Signature = s.id.Sign(cp.signedBytes())
	s.checkpts = append(s.checkpts, cp)
	if err := s.persistCheckpoints(); err != nil {
		return Checkpoint{}, err
	}
	return cp, nil
}

// LatestCheckpoint returns the most recent signed checkpoint.
func (s *Store) LatestCheckpoint() (Checkpoint, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.checkpts) == 0 {
		return Checkpoint{}, false
	}
	return s.checkpts[len(s.checkpts)-1], true
}

// ProveInclusion returns a Merkle inclusion proof for seq evaluated
// against the latest checkpoint, so a client can verify membership
// offline using only the signed root.
func (s *Store) ProveInclusion(seq uint64) (*merkle.Proof, Checkpoint, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.checkpts) == 0 {
		return nil, Checkpoint{}, errors.New("store: no checkpoint issued yet")
	}
	cp := s.checkpts[len(s.checkpts)-1]
	if seq > cp.Through {
		return nil, Checkpoint{}, fmt.Errorf("store: seq %d not covered by checkpoint %d", seq, cp.ID)
	}
	tree := merkle.New(s.leafHashes[:cp.EventCount])
	p, err := tree.Prove(int(seq))
	if err != nil {
		return nil, Checkpoint{}, err
	}
	return p, cp, nil
}

// VerifyResult is the outcome of a full self-audit.
type VerifyResult struct {
	OK            bool   `json:"ok"`
	EventsChecked uint64 `json:"events_checked"`
	BadSeq        uint64 `json:"bad_seq,omitempty"`
	Detail        string `json:"detail"`
}

// Verify replays the entire log from disk and re-runs chain
// verification, proving that nothing persisted has been altered.
func (s *Store) Verify() VerifyResult {
	all, err := s.Range(0, 0)
	if err != nil {
		return VerifyResult{Detail: "read error: " + err.Error()}
	}
	res := audit.VerifyChain(all)
	if !res.OK {
		return VerifyResult{EventsChecked: uint64(res.Verified),
			BadSeq: res.BadSeq, Detail: res.Err.Error()}
	}
	return VerifyResult{OK: true, EventsChecked: uint64(res.Verified),
		Detail: "all events chained and intact"}
}

func (s *Store) loadCheckpoints() error {
	b, err := os.ReadFile(s.cpPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return json.Unmarshal(b, &s.checkpts)
}

func (s *Store) persistCheckpoints() error {
	b, err := json.MarshalIndent(s.checkpts, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.cpPath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, s.cpPath) // atomic replace
}

// Close releases all open segment files.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var firstErr error
	for _, seg := range s.segments {
		if err := seg.close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
