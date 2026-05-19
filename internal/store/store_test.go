package store

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/PrimelPJ/aegis/internal/audit"
)

func newStore(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	st, err := Open(dir, 1024) // tiny segments to exercise rollover
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st, dir
}

func seed(t *testing.T, st *Store, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		_, err := st.Append(audit.Event{
			Actor: "svc", Action: "object.read", Resource: "doc", Outcome: "success",
		})
		if err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
}

func TestAppendAndGet(t *testing.T) {
	st, _ := newStore(t)
	seed(t, st, 200) // forces multiple segments at 1 KiB

	if st.Len() != 200 {
		t.Fatalf("expected 200 events, got %d", st.Len())
	}
	e, err := st.Get(150)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if e.Seq != 150 {
		t.Fatalf("expected seq 150, got %d", e.Seq)
	}
	if st.Verify().OK != true {
		t.Fatal("freshly written log must verify")
	}
}

func TestRecoveryRebuildsState(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir, 512)
	if err != nil {
		t.Fatal(err)
	}
	seed(t, st, 120)
	headBefore := st.Head()
	st.Close()

	// Reopen: state must be fully reconstructed from disk.
	st2, err := Open(dir, 512)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer st2.Close()
	if st2.Len() != 120 {
		t.Fatalf("recovery lost events: %d", st2.Len())
	}
	if string(st2.Head()) != string(headBefore) {
		t.Fatal("recovered head hash differs")
	}
	// New appends must continue the original chain.
	if _, err := st2.Append(audit.Event{Actor: "a", Action: "b"}); err != nil {
		t.Fatal(err)
	}
	if !st2.Verify().OK {
		t.Fatal("chain broken after recovery + append")
	}
}

func TestCheckpointSignedAndProvable(t *testing.T) {
	st, _ := newStore(t)
	seed(t, st, 40)

	cp, err := st.Checkpoint()
	if err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	if !cp.VerifySignature() {
		t.Fatal("checkpoint signature must verify")
	}
	proof, _, err := st.ProveInclusion(17)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}
	if err := proof.Verify(); err != nil {
		t.Fatalf("inclusion proof failed: %v", err)
	}
}

// TestOnDiskTamperDetected is the headline adversarial test: an
// attacker with filesystem access edits a persisted segment. The store
// must detect it on the next verification.
func TestOnDiskTamperDetected(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	seed(t, st, 30)
	st.Close()

	seg := filepath.Join(dir, "segment-"+pad(0)+".log")
	raw, err := os.ReadFile(seg)
	if err != nil {
		t.Fatal(err)
	}
	// Flip the outcome of an event directly in the file.
	tampered := replaceFirst(raw, []byte(`"outcome":"success"`), []byte(`"outcome":"FAILUR3"`))
	if string(tampered) == string(raw) {
		t.Fatal("test setup: nothing was tampered")
	}
	if err := os.WriteFile(seg, tampered, 0o644); err != nil {
		t.Fatal(err)
	}

	st2, err := Open(dir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	res := st2.Verify()
	if res.OK {
		t.Fatal("on-disk tampering went undetected")
	}
	t.Logf("tamper correctly detected: %s", res.Detail)
}

func pad(n int) string {
	s := []byte("00000000000000000000")
	d := []byte{}
	for n > 0 {
		d = append([]byte{byte('0' + n%10)}, d...)
		n /= 10
	}
	if len(d) == 0 {
		d = []byte("0")
	}
	copy(s[len(s)-len(d):], d)
	return string(s)
}

func replaceFirst(hay, old, new []byte) []byte {
	idx := indexOf(hay, old)
	if idx < 0 {
		return hay
	}
	out := make([]byte, 0, len(hay)-len(old)+len(new))
	out = append(out, hay[:idx]...)
	out = append(out, new...)
	out = append(out, hay[idx+len(old):]...)
	return out
}

func indexOf(hay, needle []byte) int {
outer:
	for i := 0; i+len(needle) <= len(hay); i++ {
		for j := range needle {
			if hay[i+j] != needle[j] {
				continue outer
			}
		}
		return i
	}
	return -1
}
