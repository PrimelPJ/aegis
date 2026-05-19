package merkle

import (
	"bytes"
	"fmt"
	"testing"
)

func leaves(n int) [][]byte {
	out := make([][]byte, n)
	for i := 0; i < n; i++ {
		out[i] = HashLeaf([]byte(fmt.Sprintf("event-%d", i)))
	}
	return out
}

func TestEmptyTreeRoot(t *testing.T) {
	if len(New(nil).Root()) != 32 {
		t.Fatal("empty tree must still produce a 32-byte root")
	}
}

func TestProofRoundTripAllSizes(t *testing.T) {
	for _, n := range []int{1, 2, 3, 4, 5, 8, 9, 17, 64, 100} {
		tr := New(leaves(n))
		for i := 0; i < n; i++ {
			p, err := tr.Prove(i)
			if err != nil {
				t.Fatalf("n=%d prove(%d): %v", n, i, err)
			}
			if err := p.Verify(); err != nil {
				t.Fatalf("n=%d proof for %d failed to verify: %v", n, i, err)
			}
			if !bytes.Equal(p.Root, tr.Root()) {
				t.Fatalf("n=%d proof root mismatch", n)
			}
		}
	}
}

func TestForgedLeafRejected(t *testing.T) {
	tr := New(leaves(16))
	p, _ := tr.Prove(7)
	p.Leaf = HashLeaf([]byte("forged"))
	if err := p.Verify(); err == nil {
		t.Fatal("a forged leaf must not verify against the real root")
	}
}

func TestTamperedRootRejected(t *testing.T) {
	tr := New(leaves(16))
	p, _ := tr.Prove(3)
	p.Root[0] ^= 0xFF
	if err := p.Verify(); err == nil {
		t.Fatal("a proof against a tampered root must fail")
	}
}

func TestRootChangesWhenLeafChanges(t *testing.T) {
	a := New(leaves(10)).Root()
	mod := leaves(10)
	mod[5] = HashLeaf([]byte("changed"))
	if bytes.Equal(a, New(mod).Root()) {
		t.Fatal("root must change when any leaf changes")
	}
}

func TestSecondPreimageSeparation(t *testing.T) {
	// A leaf and an interior node over the same bytes must differ,
	// thanks to domain-separation prefixes.
	l := HashLeaf([]byte("x"))
	i := hashInterior([]byte("x"), []byte("y"))
	if bytes.Equal(l, i) {
		t.Fatal("leaf and interior hashing must be domain-separated")
	}
}
