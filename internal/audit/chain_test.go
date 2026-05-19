package audit

import "testing"

func chainOf(n int) []Event {
	events := make([]Event, 0, n)
	prev := GenesisPrevHash
	for i := 0; i < n; i++ {
		e := Event{
			TimeUnixN: int64(1000 + i),
			Actor:     "user@example.com",
			Action:    "object.read",
			Resource:  "doc/42",
			Outcome:   "success",
			Source:    "test",
		}
		e.Seal(uint64(i), prev)
		prev = e.Hash
		events = append(events, e)
	}
	return events
}

func TestCleanChainVerifies(t *testing.T) {
	res := VerifyChain(chainOf(100))
	if !res.OK {
		t.Fatalf("expected clean chain to verify, got %v", res)
	}
	if res.Verified != 100 {
		t.Fatalf("expected 100 verified, got %d", res.Verified)
	}
}

func TestDeterministicHash(t *testing.T) {
	e := Event{Actor: "a", Action: "b", Meta: map[string]string{"z": "1", "a": "2"}}
	e.Seal(0, GenesisPrevHash)
	h1 := e.ComputeHash()
	// Rebuild an identical event; map order must not matter.
	e2 := Event{Actor: "a", Action: "b", Meta: map[string]string{"a": "2", "z": "1"}}
	e2.Seal(0, GenesisPrevHash)
	if string(h1) != string(e2.ComputeHash()) {
		t.Fatal("hash is not deterministic across map ordering")
	}
}

func TestTamperedFieldDetected(t *testing.T) {
	events := chainOf(50)
	events[20].Outcome = "failure" // mutate a field after sealing
	res := VerifyChain(events)
	if res.OK {
		t.Fatal("tampered record should not verify")
	}
	if res.BadSeq != 20 {
		t.Fatalf("expected failure at seq 20, got %d", res.BadSeq)
	}
}

func TestDeletedRecordDetected(t *testing.T) {
	events := chainOf(30)
	events = append(events[:10], events[11:]...) // drop event 10
	res := VerifyChain(events)
	if res.OK {
		t.Fatal("deletion should break the chain link")
	}
	if res.BadSeq != 11 {
		t.Fatalf("expected link break at seq 11, got %d", res.BadSeq)
	}
}

func TestReorderedRecordsDetected(t *testing.T) {
	events := chainOf(10)
	events[4], events[5] = events[5], events[4]
	if VerifyChain(events).OK {
		t.Fatal("reordering should break verification")
	}
}

func TestGenesisAnchoring(t *testing.T) {
	events := chainOf(5)
	events[0].PrevHash = make([]byte, HashSize)
	events[0].PrevHash[0] = 0xFF // not genesis
	events[0].Hash = events[0].ComputeHash()
	if VerifyChain(events).OK {
		t.Fatal("non-genesis anchor must be rejected")
	}
}
