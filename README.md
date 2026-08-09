# pqc-audit

**Post-Quantum Cryptography readiness audit for Solidity smart contracts.**

`pqc-audit` scans `.sol` files for quantum-vulnerable cryptographic primitives
(ECDSA, secp256k1, BLS, etc.) and known NIST PQC implementation vulnerabilities
(Dilithium t₀ recovery, KyberSlash, Falcon single-trace attacks). It also runs
a gas-optimization pass and a security vulnerability scan.

## What it checks

### Phase 1 — Structure
Parses the Solidity pragma version, counts contracts, functions, and events.

### Phase 2 — Gas Optimization
Scans for 10 gas-optimization patterns (uint256 vs smaller types, calldata vs
memory, immutable constants, cache array length, prefix increment, custom
errors, variable packing, etc.) with estimated gas savings.

### Phase 3 — Security
Scans for 12 vulnerability patterns (reentrancy, unchecked external calls,
tx.origin, timestamp dependence, integer overflow, missing zero-address check,
unprotected selfdestruct, DoS via unbounded loops, etc.) plus context-aware
checks (state change after external call, missing events, improper access
control). Produces a severity breakdown and security score.

### Phase 4 — PQC Readiness
Inventories cryptographic primitives and assesses quantum risk:

| Primitive | Risk | Reason |
|-----------|------|--------|
| `ecrecover` / `ecdsa` / `secp256k1` | CRITICAL | Shor's algorithm breaks ECDSA in polynomial time |
| `bn128` / `bls12_381` | CRITICAL | Pairing curves broken by Shor's algorithm |
| `ripemd160` | HIGH | Short output, more vulnerable to Grover's |
| `keccak256` / `sha256` | MEDIUM | Grover's quadratic speedup (256-bit → 128-bit effective) |

It also scans for NIST PQC **implementation** vulnerabilities from 2024–2026
research:

| Vulnerability | Risk | Source |
|---------------|------|--------|
| Dilithium t₀ recovery | HIGH | Azevedo-Oliveira et al., CRYPTO 2025 — 200K–500K signatures enable key recovery |
| KyberSlash | CRITICAL | CVE-2024-37880 — division by q=3329 not constant-time |
| Falcon SHIFT SNARE | CRITICAL | ePrint 2025/146 — 99.99% key recovery from one power trace |
| Falcon One Fell Swoop | HIGH | ePrint 2025/2159 — 100% key recovery at -O0 |
| XMSS/LMS state reuse | CRITICAL | Reusing WOTS+ leaf = total security collapse |

### Phase 5 — Evidence Attestation
Records SHA-256 of the source file and the report for tamper-evidence.

## Installation

```bash
pip install pqc-audit
```

With optional PQC crypto backends for the evidence verification gate:

```bash
pip install pqc-audit[pqc]
```

## Usage

### CLI

```bash
# Audit a contract (outputs Markdown by default)
pqc-audit audit contract.sol

# JSON output
pqc-audit audit contract.sol --format json --output report.json

# Run mechanical PQC verification (requires [pqc] extras)
pqc-audit evidence --scheme SLH-DSA-128
```

### Python API

```python
from pqc_audit import analyze, to_markdown

report = analyze("contract.sol")
print(report["verdict"]["overall"])  # "PASS", "PASS_WITH_WARNINGS", or "FAIL"
print(report["phases"]["pqc_readiness"]["risk_level"])  # "LOW" .. "CRITICAL"

# Render as Markdown
md = to_markdown(report)
```

### Evidence contract (mechanical PQC verification)

```python
from pqc_audit import run_evidence_contract, available_schemes

print(available_schemes())
# {'ML-DSA-44': True, 'ML-DSA-65': True, 'ML-DSA-87': True, 'SLH-DSA-128': True}

result = run_evidence_contract("SLH-DSA-128")
print(result["verdict"])  # "PASS" or "PASS_WITH_WARNINGS"
print(result["summary"])  # "7/7 checks passed"
```

## What this tool CAN do

- Detect quantum-vulnerable cryptographic primitives in Solidity source text
- Flag known NIST PQC implementation vulnerabilities from published research
- Run gas-optimization and security pattern scans
- Mechanically verify PQC signature schemes (keygen → sign → verify → tamper)
- Produce a tamper-evident report with SHA-256 attestation

## What this tool CANNOT do

- **This is a readiness check, not a full security audit.** It uses regex-based
  pattern matching, not formal verification or symbolic execution.
- It does **not** prove a contract is secure. Absence of findings does not mean
  absence of vulnerabilities.
- It does **not** compile or execute Solidity. It is a static text scan.
- PQC implementation vulnerability detection is **heuristic** — it flags usage
  of known-vulnerable scheme names, it does not analyze the actual binary.
- The SLH-DSA-128 evidence contract falls back to a **pure-Python demo** if
  `pyspx` is not installed. This demo is NOT a real SPHINCS+ implementation.
  Production use requires `pip install pyspx`.
- Gas and security savings estimates are **rough approximations**, not measured.

## Dependencies

- **Core**: Python 3.10+ standard library only (no required dependencies)
- **Optional** (`pip install pqc-audit[pqc]`):
  - `dilithium_py` — ML-DSA (Dilithium) backend for evidence verification
  - `pyspx` — SLH-DSA (SPHINCS+) native backend for evidence verification
- **Dev** (`pip install pqc-audit[dev]`):
  - `pytest>=7.0`

## CI

GitHub Actions runs `pytest` on every push and pull request. See
`.github/workflows/ci.yml`.

## License

MIT

## Sources

- NIST FIPS 204 (ML-DSA / Dilithium) — finalized 2024
- NIST FIPS 205 (SLH-DSA / SPHINCS+) — finalized 2024
- NIST FIPS 206 (FN-DSA / Falcon) — selected, pending finalization
- Azevedo-Oliveira et al., "Dilithium Single-Trace Attack," CRYPTO 2025
- Bernstein et al., "KyberSlash," CVE-2024-37880
- ePrint 2025/146 — "SHIFT SNARE: Single-trace attack on Falcon"
- ePrint 2025/2159 — "One Fell Swoop: Single-trace attack on Falcon"
- CNSA 2.0 — NSA Commercial National Security Algorithm Suite
