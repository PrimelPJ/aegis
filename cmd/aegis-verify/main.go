// Command aegis-verify is an independent auditor. It opens the data
// directory read-only, replays every event, re-derives the hash chain
// and Merkle root entirely from scratch, and checks them against the
// signed checkpoint using only the public key.
//
// It shares no state with the server: if the server (or anyone with
// disk access) altered history, this tool reports the exact event
// where the tamper occurred.
//
//	aegis-verify -data ./data            # full audit
//	aegis-verify -data ./data -seq 7     # prove one event's inclusion
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/PrimelPJ/aegis/internal/audit"
	"github.com/PrimelPJ/aegis/internal/merkle"
	"github.com/PrimelPJ/aegis/internal/store"
)

func main() {
	dataDir := flag.String("data", "./data", "data directory to audit")
	seq := flag.Int64("seq", -1, "if set, verify the inclusion proof for this sequence")
	flag.Parse()

	st, err := store.Open(*dataDir, store.DefaultMaxSegmentSize)
	if err != nil {
		fail("cannot open data: %v", err)
	}
	defer st.Close()

	events, err := st.Range(0, 0)
	if err != nil {
		fail("cannot read events: %v", err)
	}
	fmt.Printf("auditing %d events from %s\n", len(events), *dataDir)

	// 1. Independent hash-chain verification.
	res := audit.VerifyChain(events)
	if !res.OK {
		fail("CHAIN INTEGRITY FAILURE: %s", res.String())
	}
	fmt.Printf("  [PASS] hash chain: %s\n", res.String())

	// 2. Independent Merkle root recomputation vs signed checkpoint.
	cp, ok := st.LatestCheckpoint()
	if !ok {
		fmt.Println("  [WARN] no signed checkpoint to compare against")
	} else {
		if !cp.VerifySignature() {
			fail("CHECKPOINT SIGNATURE INVALID for checkpoint %d", cp.ID)
		}
		fmt.Printf("  [PASS] checkpoint %d signature valid (Ed25519)\n", cp.ID)

		leaves := make([][]byte, 0, cp.EventCount)
		for i := uint64(0); i < cp.EventCount; i++ {
			leaves = append(leaves, events[i].Hash)
		}
		root := merkle.New(leaves).Root()
		if !equal(root, cp.MerkleRoot) {
			fail("MERKLE ROOT MISMATCH: recomputed %x, checkpoint %x", root, cp.MerkleRoot)
		}
		fmt.Printf("  [PASS] Merkle root matches checkpoint: %x\n", root)
	}

	// 3. Optional single-event inclusion proof.
	if *seq >= 0 {
		proof, pcp, err := st.ProveInclusion(uint64(*seq))
		if err != nil {
			fail("inclusion proof: %v", err)
		}
		if err := proof.Verify(); err != nil {
			fail("INCLUSION PROOF INVALID for seq %d: %v", *seq, err)
		}
		fmt.Printf("  [PASS] event %d proven included under checkpoint %d (root %x)\n",
			*seq, pcp.ID, proof.Root)
	}

	fmt.Println("\nRESULT: audit log is intact and verifiable.")
}

func equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "\nRESULT: FAILED\n  "+format+"\n", args...)
	os.Exit(1)
}
