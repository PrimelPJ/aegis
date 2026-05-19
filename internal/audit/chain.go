package audit

import "fmt"

// ChainResult reports the outcome of verifying a contiguous run of
// events. If OK is false, BadSeq is the sequence number of the first
// event that failed and Err explains how.
type ChainResult struct {
	OK       bool
	Verified int
	BadSeq   uint64
	Err      error
	HeadHash []byte
}

func (r ChainResult) String() string {
	if r.OK {
		return fmt.Sprintf("chain OK: %d events verified, head=%x", r.Verified, shortHash(r.HeadHash))
	}
	return fmt.Sprintf("chain FAILED at seq=%d after %d good events: %v",
		r.BadSeq, r.Verified, r.Err)
}

// VerifyChain walks events in order and proves three properties:
//
//  1. Integrity: each stored hash equals the recomputed hash, so no
//     field of any record was modified.
//  2. Linkage: each event's PrevHash equals the prior event's Hash and
//     sequence numbers are strictly +1, so nothing was inserted,
//     deleted or reordered.
//  3. Anchoring: event 0 links to GenesisPrevHash.
//
// The walk is O(n) and allocation-free per event beyond the hash.
func VerifyChain(events []Event) ChainResult {
	prevHash := GenesisPrevHash
	var prevSeq uint64
	for i := range events {
		e := &events[i]

		if i == 0 {
			if !equalHash(e.PrevHash, GenesisPrevHash) {
				return ChainResult{BadSeq: e.Seq, Verified: i,
					Err: fmt.Errorf("%w: genesis not anchored", ErrLinkBroken)}
			}
		} else {
			if e.Seq != prevSeq+1 {
				return ChainResult{BadSeq: e.Seq, Verified: i,
					Err: fmt.Errorf("%w: expected seq %d, got %d",
						ErrLinkBroken, prevSeq+1, e.Seq)}
			}
			if !equalHash(e.PrevHash, prevHash) {
				return ChainResult{BadSeq: e.Seq, Verified: i,
					Err: fmt.Errorf("%w: prev_hash does not match preceding event",
						ErrLinkBroken)}
			}
		}

		if err := e.VerifySelf(); err != nil {
			return ChainResult{BadSeq: e.Seq, Verified: i, Err: err}
		}

		prevHash = e.Hash
		prevSeq = e.Seq
	}
	return ChainResult{OK: true, Verified: len(events), HeadHash: prevHash}
}

func shortHash(h []byte) []byte {
	if len(h) > 6 {
		return h[:6]
	}
	return h
}
