// Package audit defines the canonical audit event model and the
// cryptographic hash-chain that links events into a tamper-evident log.
//
// Every event commits to the hash of the event before it. Changing,
// reordering, or deleting any historical event breaks the chain at a
// deterministic, reportable position.
package audit

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sort"
)

// HashSize is the length in bytes of a SHA-256 digest.
const HashSize = sha256.Size

// GenesisPrevHash is the predecessor hash of the very first event. It is
// 32 zero bytes; any other value for sequence 0 indicates tampering.
var GenesisPrevHash = make([]byte, HashSize)

// Event is a single immutable audit record. The Seq, PrevHash and Hash
// fields are assigned by the log when the event is appended; callers
// supply only the semantic fields.
type Event struct {
	Seq       uint64            `json:"seq"`
	TimeUnixN int64             `json:"time_unix_nano"`
	Actor     string            `json:"actor"`
	Action    string            `json:"action"`
	Resource  string            `json:"resource"`
	Outcome   string            `json:"outcome"`
	Source    string            `json:"source"`
	Meta      map[string]string `json:"meta,omitempty"`
	PrevHash  []byte            `json:"prev_hash"`
	Hash      []byte            `json:"hash"`
}

var (
	// ErrChainBroken means a recomputed hash did not match the stored
	// hash, i.e. the record was modified after it was written.
	ErrChainBroken = errors.New("audit: hash chain broken (record tampered)")
	// ErrLinkBroken means an event does not point at its true
	// predecessor, i.e. a record was inserted, deleted or reordered.
	ErrLinkBroken = errors.New("audit: chain link broken (record inserted/removed/reordered)")
)

// canonicalPayload returns a deterministic byte encoding of the
// semantic fields of an event plus its predecessor hash. The encoding
// is length-prefixed so that no choice of field values can produce a
// collision by shifting bytes across field boundaries.
//
// Map keys are sorted so the encoding is independent of Go map
// iteration order. JSON is deliberately NOT used for hashing because
// its whitespace and key ordering are not canonical.
func (e *Event) canonicalPayload() []byte {
	buf := make([]byte, 0, 256)
	buf = appendU64(buf, e.Seq)
	buf = appendI64(buf, e.TimeUnixN)
	buf = appendStr(buf, e.Actor)
	buf = appendStr(buf, e.Action)
	buf = appendStr(buf, e.Resource)
	buf = appendStr(buf, e.Outcome)
	buf = appendStr(buf, e.Source)

	keys := make([]string, 0, len(e.Meta))
	for k := range e.Meta {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	buf = appendU64(buf, uint64(len(keys)))
	for _, k := range keys {
		buf = appendStr(buf, k)
		buf = appendStr(buf, e.Meta[k])
	}

	// Bind this event to its predecessor: this is the chain.
	buf = appendBytes(buf, e.PrevHash)
	return buf
}

// ComputeHash derives the event hash from its canonical payload. It is
// pure: the same event always yields the same digest.
func (e *Event) ComputeHash() []byte {
	sum := sha256.Sum256(e.canonicalPayload())
	return sum[:]
}

// Seal assigns the sequence number, links the event to prevHash and
// fixes its hash. It is called exactly once, by the log, at append time.
func (e *Event) Seal(seq uint64, prevHash []byte) {
	e.Seq = seq
	e.PrevHash = clone(prevHash)
	e.Hash = e.ComputeHash()
}

// VerifySelf recomputes the hash and confirms the record has not been
// altered since it was sealed.
func (e *Event) VerifySelf() error {
	if !equalHash(e.Hash, e.ComputeHash()) {
		return ErrChainBroken
	}
	return nil
}

func appendU64(b []byte, v uint64) []byte {
	var x [8]byte
	binary.BigEndian.PutUint64(x[:], v)
	return append(b, x[:]...)
}

func appendI64(b []byte, v int64) []byte { return appendU64(b, uint64(v)) }

func appendStr(b []byte, s string) []byte {
	b = appendU64(b, uint64(len(s)))
	return append(b, s...)
}

func appendBytes(b, p []byte) []byte {
	b = appendU64(b, uint64(len(p)))
	return append(b, p...)
}

func equalHash(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

func clone(b []byte) []byte {
	c := make([]byte, len(b))
	copy(c, b)
	return c
}
