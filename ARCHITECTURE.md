# Architecture and Threat Model

## 1. Data model

An event is the unit of the log:

```
Event {
  Seq        uint64            assigned by the log, strictly +1
  TimeUnixN  int64             ingestion timestamp (ns)
  Actor      string            who
  Action     string            what
  Resource   string            on what
  Outcome    string            success | failure | ...
  Source     string            origin system
  Meta       map[string]string arbitrary key/value
  PrevHash   [32]byte          hash of the preceding event
  Hash       [32]byte          SHA-256 of this event's canonical payload
}
```

### Canonical encoding

The hashed payload is a length-prefixed binary encoding, not JSON. Each
field is written as an 8-byte big-endian length followed by its bytes;
map keys are sorted. This matters: JSON whitespace and key ordering are
not canonical, so two semantically identical events could hash
differently, or two different events could be made to collide by
shifting bytes across field boundaries. Length prefixing closes both
gaps. JSON is used only for on-disk storage and the wire API, never for
hashing.

## 2. The hash chain

```
hash_0 = SHA256( canonical(event_0, prev = 0x00*32) )
hash_n = SHA256( canonical(event_n, prev = hash_{n-1}) )
```

Event 0 is anchored to 32 zero bytes (the genesis predecessor).
Verification walks the log and checks three independent properties:

1. **Integrity**: recomputed hash equals stored hash. Defeats field edits.
2. **Linkage**: `event.PrevHash == previous.Hash` and `Seq == prevSeq+1`. Defeats insertion, deletion, and reordering.
3. **Anchoring**: event 0 points at genesis. Defeats truncation of the prefix.

Any single break is reported with the exact failing sequence number.

## 3. Merkle commitments and checkpoints

Periodically the log builds a Merkle tree over every event hash
(`leaf = SHA256(0x00 || event_hash)`, `interior = SHA256(0x01 || L || R)`,
RFC 6962 domain separation against second-preimage attacks). The root,
the chain head, the event count, and a timestamp are signed with
Ed25519. That signed tuple is a **checkpoint**.

A checkpoint compresses trust: an auditor with only the public key can
confirm that the entire history up to that point is exactly what the
signer vouched for. An **inclusion proof** is the sibling path from one
leaf to the root (O(log n) hashes); it lets a third party confirm a
specific event is committed without downloading the whole log.

## 4. On-disk format

```
data/
  segment-00000000000000000000.log   append-only, length-prefixed records
  segment-00000000000000010234.log   rolls over at -segment-size bytes
  keys/signing.key                   Ed25519 private key, mode 0600
  keys/signing.pub                   Ed25519 public key
  checkpoints.json                   signed checkpoints, atomically replaced
```

Each record on disk: `uint32 length || JSON(event)`. Recovery replays
every segment in order, rebuilds the sequence index and Merkle leaves,
and re-derives the chain head. A record torn by a crash mid-write is
detected and the clean prefix is kept; it does not corrupt state.

## 5. Threat model

| Adversary capability | Result |
| --- | --- |
| Read the log | No confidentiality is claimed; this is an integrity system. Encrypt at rest separately if needed. |
| Edit a record in place (DB or file) | Hash mismatch. Verifier fails at that sequence. |
| Delete or reorder records | Broken `prev_hash` linkage. Verifier fails at the gap. |
| Insert a forged record into history | The following event's `prev_hash` no longer matches. Detected. |
| Replace the entire store and re-sign | Requires the Ed25519 private key. Out of scope if the key is in a KMS/HSM. |
| Steal the signing key | Can forge a self-consistent history from the point of compromise. Mitigations: KMS/HSM custody, key rotation recorded in-band, and external witnessing (publishing checkpoint roots to an append-only third party, as Certificate Transparency does). |
| Tamper between ingestion and sealing | The record is sealed synchronously inside `Append` under a lock before the writer is acknowledged. The exposure window is the in-process call, not storage. |

### Explicit non-goals

- Not a confidentiality system. No encryption of event contents.
- Not Byzantine fault tolerant. Single-writer; a replicated quorum is future work.
- Not a certified cryptographic implementation. Standard primitives, documented construction, no formal proofs.

## 6. Concurrency

`Append` holds a write lock for the seal-and-persist critical section,
guaranteeing a total order and a gap-free chain under concurrent
writers. Reads take a read lock and never block each other. The
detection engine is independently locked and evaluated synchronously so
a finding cannot be ordered before the event that caused it.

## 7. Where this maps to compliance

- **NIST SP 800-92** (log management): integrity and tamper detection.
- **ISO 27001 A.12.4**, **SOC 2 CC7.2/CC7.3**: protected, reviewable audit trails with evidence of non-alteration.
- **PCI DSS 10.5**: securing audit trails so they cannot be altered.

The signed checkpoint plus inclusion proof is exactly the artifact an
external auditor wants: portable, offline-verifiable evidence that the
trail was not edited.
