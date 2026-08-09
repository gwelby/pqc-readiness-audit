"""pqc_audit — Post-Quantum Cryptography readiness audit for Solidity smart contracts.

This package provides:
  - ``analyze``: Run a full PQC-readiness audit (structure, gas, security, PQC) on a .sol file.
  - ``to_markdown``: Render an audit report as Markdown.
  - ``run_evidence_contract``: Mechanically verify a PQC signature scheme (keygen/sign/verify/tamper).

The audit is a *readiness check*, not a full security audit. It flags known
quantum-vulnerable cryptographic primitives (ECDSA, secp256k1, BLS, etc.) and
known NIST PQC implementation vulnerabilities (Dilithium t0 recovery, KyberSlash,
Falcon single-trace attacks). It does NOT prove a contract is secure.
"""
from __future__ import annotations

from .analyzer import analyze, to_markdown, scan_pqc_primitives, scan_pqc_impl_risks
from .evidence import run_evidence_contract, available_schemes

__version__ = "0.1.0"
__all__ = [
    "analyze",
    "to_markdown",
    "scan_pqc_primitives",
    "scan_pqc_impl_risks",
    "run_evidence_contract",
    "available_schemes",
    "__version__",
]
