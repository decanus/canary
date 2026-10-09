# CLAUDE.md

This repo builds **Canary**, a Go blockchain node whose proof of work is solving an elliptic-curve
discrete log on a fresh toy curve each block. Read `SPEC.md` fully before writing code; it is the
source of truth.

## Rules
- Work milestone by milestone (SPEC.md §15). Do not start a milestone until the previous one's
  acceptance criteria pass. Commit at the end of each milestone.
- `reference/` is read-only. `reference/canary.py` is the consensus oracle and
  `reference/test_vectors.json` is canonical. Never edit them to make tests pass.
  (The vectors were regenerated once on 2026-10-10 for the ECPoW → Canary rename of the `tag()`
  prefix; that file is now canonical.)
- Consensus code (`internal/consensus`) uses only the Go standard library, integer math, and no
  randomness. Never use `big.Int.ProbablyPrime` there (SPEC.md §3.3).
- If SPEC.md is ambiguous, match the Python reference and leave a `// SPEC:` comment explaining it.

## Commands
- `go test ./...` and `go vet ./...` must be green before each commit.
- `go run ./cmd/canary vectors reference/test_vectors.json`: conformance run.
- Cross-check with the reference: `python3 reference/canary.py verify <chain.json>` (Python 3.8+, no deps).
