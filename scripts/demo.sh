#!/usr/bin/env bash
# End-to-end demonstration:
#   1. start the server
#   2. ingest normal events
#   3. trip the brute-force detection rule
#   4. issue a signed checkpoint and prove an event's inclusion
#   5. independently verify the log
#   6. simulate an attacker editing a persisted segment on disk
#   7. show the verifier catching it at the exact sequence
set -euo pipefail

ADDR="localhost:8088"
DATA="$(mktemp -d)"
BIN="${BIN:-bin}"

cleanup() { kill "${SRV_PID:-}" 2>/dev/null || true; rm -rf "$DATA"; }
trap cleanup EXIT

echo "==> starting aegisd (data=$DATA)"
"./$BIN/aegisd" -addr :8088 -data "$DATA" >/tmp/aegis-demo.log 2>&1 &
SRV_PID=$!
sleep 1.5

echo "==> ingesting 3 normal events"
for i in 1 2 3; do
  curl -s -X POST "$ADDR/v1/events" \
    -d "{\"actor\":\"alice\",\"action\":\"object.read\",\"resource\":\"doc/$i\",\"outcome\":\"success\",\"source\":\"app\"}" >/dev/null
done

echo "==> tripping brute-force rule (6 failed logins for 'mallory')"
for _ in $(seq 1 6); do
  curl -s -X POST "$ADDR/v1/events" \
    -d '{"actor":"mallory","action":"auth.login","outcome":"failure","source":"sshd"}' >/dev/null
done
echo "    alerts:"
curl -s "$ADDR/v1/alerts"; echo

echo "==> issuing signed checkpoint"
curl -s -X POST "$ADDR/v1/checkpoint" >/dev/null
echo "==> inclusion proof for event 1"
curl -s "$ADDR/v1/proof/1" | head -c 200; echo " ..."

echo "==> stopping server, running INDEPENDENT verifier"
kill "$SRV_PID"; wait "$SRV_PID" 2>/dev/null || true; SRV_PID=""
"./$BIN/aegis-verify" -data "$DATA" -seq 1

echo
echo "==> ATTACKER edits a persisted event directly on disk"
SEG="$(ls "$DATA"/segment-*.log | head -1)"
python3 - "$SEG" <<'PY'
import sys
p = sys.argv[1]
b = open(p, "rb").read()
# Equal-length edit: the record still parses, so the cryptographic
# hash chain (not just a length check) is what catches the change.
open(p, "wb").write(b.replace(b'"outcome":"success"', b'"outcome":"FAILED!"', 1))
print("    flipped outcome success -> FAILED! in", p.split("/")[-1])
PY

echo "==> re-running verifier (must fail at the tampered sequence)"
if "./$BIN/aegis-verify" -data "$DATA"; then
  echo "UNEXPECTED: verifier passed on tampered data"; exit 1
else
  echo
  echo "SUCCESS: tampering was detected and pinpointed."
fi
