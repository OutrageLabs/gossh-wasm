# Fuzzing Results (2026-02-18)

## Target Surfaces

Parser-heavy forwarding helpers:
- Binary frame parsing (`parseBinaryFrame`)
- CRLF guard (`containsCRLF`)
- Header boundary parser (`findHeaderEnd`)

## Build/Execution Constraints

- Native Go fuzzing (`-fuzz`) is not supported on `js/wasm` targets.
- Implemented host-only mirror fuzz harness in `parser_fuzz_host_test.go` (`//go:build !js`) to execute coverage-guided fuzzing over parser logic equivalent to wasm code paths.
- Kept wasm-target deterministic adversarial tests in `security_runtime_test.go` for runtime parity checks.

## Commands Executed

- `go test -run=^$ -fuzz=FuzzParseBinaryFrame -fuzztime=5s .`
- `go test -run=^$ -fuzz=FuzzContainsCRLF -fuzztime=5s .`
- `go test -run=^$ -fuzz=FuzzFindHeaderEnd -fuzztime=5s .`

## Outcomes

- All fuzz runs completed successfully (no crashes/panics).
- `FuzzParseBinaryFrame` reached ~7.4M execs in 5s and discovered additional interesting corpus inputs.
- `FuzzContainsCRLF` and `FuzzFindHeaderEnd` each reached ~3.8M execs in 5s with expanded interesting corpus.

## Follow-up Recommendations

1. Keep fuzz targets in CI on non-wasm runner as regression guard for parser logic.
2. If parser logic is refactored, keep host mirror functions synchronized or extract shared parser helpers into common file(s) to avoid drift.
3. Extend fuzz targets to JSON control message parsing and HTTP response parsing helpers when refactoring allows clean isolation.

