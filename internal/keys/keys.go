// Package keys handles the Ed25519 signing identity used to sign
// checkpoints. A checkpoint signature lets an auditor confirm that a
// Merkle root was vouched for by the holder of the private key, so a
// compromised storage layer alone cannot forge a valid history.
package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
)

// Identity is a loaded signing keypair.
type Identity struct {
	Priv ed25519.PrivateKey
	Pub  ed25519.PublicKey
}

const (
	privPEMType = "AEGIS ED25519 PRIVATE KEY"
	pubPEMType  = "AEGIS ED25519 PUBLIC KEY"
	privPerm    = 0o600
	pubPerm     = 0o644
)

// LoadOrCreate loads the keypair from dir, generating and persisting a
// fresh one on first run. The private key file is written 0600.
func LoadOrCreate(dir string) (*Identity, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	privPath := filepath.Join(dir, "signing.key")
	pubPath := filepath.Join(dir, "signing.pub")

	if b, err := os.ReadFile(privPath); err == nil {
		block, _ := pem.Decode(b)
		if block == nil || len(block.Bytes) != ed25519.PrivateKeySize {
			return nil, errors.New("keys: malformed private key file")
		}
		priv := ed25519.PrivateKey(block.Bytes)
		return &Identity{Priv: priv, Pub: priv.Public().(ed25519.PublicKey)}, nil
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := writePEM(privPath, privPEMType, priv, privPerm); err != nil {
		return nil, err
	}
	if err := writePEM(pubPath, pubPEMType, pub, pubPerm); err != nil {
		return nil, err
	}
	return &Identity{Priv: priv, Pub: pub}, nil
}

// LoadPublic reads only the public key, for an independent verifier
// that must never touch private material.
func LoadPublic(dir string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(filepath.Join(dir, "signing.pub"))
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil || len(block.Bytes) != ed25519.PublicKeySize {
		return nil, errors.New("keys: malformed public key file")
	}
	return ed25519.PublicKey(block.Bytes), nil
}

// Sign signs a message with the loaded private key.
func (id *Identity) Sign(msg []byte) []byte {
	return ed25519.Sign(id.Priv, msg)
}

// Verify checks a signature against a public key.
func Verify(pub ed25519.PublicKey, msg, sig []byte) bool {
	return ed25519.Verify(pub, msg, sig)
}

func writePEM(path, typ string, der []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, perm)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: typ, Bytes: der})
}
