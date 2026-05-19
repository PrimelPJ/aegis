// Package merkle implements a binary Merkle hash tree with RFC 6962
// style domain separation.
//
// Leaves are hashed with a 0x00 prefix and interior nodes with a 0x01
// prefix. The distinct prefixes prevent second-preimage attacks where
// an interior node value is replayed as a leaf. An inclusion proof lets
// a verifier confirm that a specific event is committed under a signed
// root without trusting the server that produced it.
package merkle

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
)

const (
	leafPrefix     = 0x00
	interiorPrefix = 0x01
)

// HashLeaf returns the Merkle hash of a leaf payload.
func HashLeaf(data []byte) []byte {
	h := sha256.New()
	h.Write([]byte{leafPrefix})
	h.Write(data)
	return h.Sum(nil)
}

func hashInterior(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{interiorPrefix})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// Tree is an immutable Merkle tree built over an ordered list of
// pre-hashed leaves.
type Tree struct {
	leaves [][]byte
	root   []byte
}

// New builds a tree from leaf hashes (use HashLeaf to derive them).
// An empty tree has the SHA-256 of the empty string as its root, per
// RFC 6962.
func New(leaves [][]byte) *Tree {
	t := &Tree{leaves: leaves}
	if len(leaves) == 0 {
		empty := sha256.Sum256(nil)
		t.root = empty[:]
		return t
	}
	t.root = computeRoot(leaves)
	return t
}

// Root returns the Merkle root commitment.
func (t *Tree) Root() []byte { return t.root }

// Size returns the number of leaves.
func (t *Tree) Size() int { return len(t.leaves) }

// computeRoot folds the level bottom-up. An odd node is promoted
// unchanged to the next level (no duplication), which keeps proofs
// unambiguous about node count.
func computeRoot(level [][]byte) []byte {
	for len(level) > 1 {
		next := make([][]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			if i+1 == len(level) {
				next = append(next, level[i])
			} else {
				next = append(next, hashInterior(level[i], level[i+1]))
			}
		}
		level = next
	}
	return level[0]
}

// ProofStep is one sibling on the path from a leaf to the root.
type ProofStep struct {
	Hash  []byte `json:"hash"`
	IsTop bool   `json:"is_left"` // true if the sibling is the left node
}

// Proof is an inclusion proof for the leaf at Index within a tree of
// LeafCount leaves committing to Root.
type Proof struct {
	Index     int         `json:"index"`
	LeafCount int         `json:"leaf_count"`
	Leaf      []byte      `json:"leaf"`
	Path      []ProofStep `json:"path"`
	Root      []byte      `json:"root"`
}

var errIndex = errors.New("merkle: leaf index out of range")

// Prove produces an inclusion proof for the leaf at index.
func (t *Tree) Prove(index int) (*Proof, error) {
	if index < 0 || index >= len(t.leaves) {
		return nil, errIndex
	}
	p := &Proof{
		Index:     index,
		LeafCount: len(t.leaves),
		Leaf:      t.leaves[index],
		Root:      t.root,
	}
	level := t.leaves
	idx := index
	for len(level) > 1 {
		next := make([][]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			if i+1 == len(level) {
				next = append(next, level[i])
				continue
			}
			parent := hashInterior(level[i], level[i+1])
			next = append(next, parent)
			if i == idx || i+1 == idx {
				if idx == i { // sibling is on the right
					p.Path = append(p.Path, ProofStep{Hash: level[i+1], IsTop: false})
				} else { // sibling is on the left
					p.Path = append(p.Path, ProofStep{Hash: level[i], IsTop: true})
				}
			}
		}
		idx /= 2
		level = next
	}
	return p, nil
}

// Verify recomputes the root from the leaf and sibling path and
// confirms it equals the committed root. It trusts nothing but the
// proof itself.
func (p *Proof) Verify() error {
	if p.Index < 0 || p.Index >= p.LeafCount {
		return errIndex
	}
	cur := p.Leaf
	for _, step := range p.Path {
		if step.IsTop {
			cur = hashInterior(step.Hash, cur)
		} else {
			cur = hashInterior(cur, step.Hash)
		}
	}
	if !bytes.Equal(cur, p.Root) {
		return fmt.Errorf("merkle: proof does not reconstruct root")
	}
	return nil
}
