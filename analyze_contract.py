#!/usr/bin/env python3
"""analyze_contract.py — PQC-Readiness Audit CLI

Usage:
    python3 scripts/analyze_contract.py <contract.sol> [--format json|md|pdf]

Phases:
  1. Structural parse — pragma, imports, functions, events
  2. Gas optimization — 22 patterns, quantified savings
  3. Security analysis — 10 vulnerability patterns, scored
  4. PQC readiness — cryptographic primitive inventory, quantum risk
  5. Evidence attestation — SHA-256 of source + report

Exit codes:
    0 — Clean audit (no critical issues)
    1 — Critical security findings or PQC-vulnerable primitives
    2 — CLI / file error
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# ── Paths ─────────────────────────────────────────────────────────────────────
WORKSPACE = Path(__file__).parent.parent
sys.path.insert(0, str(WORKSPACE / "smart_contract_testing" / "utils"))

import gas_optimizer
import security_analyzer

REPORTS_DIR = WORKSPACE / "REPORTS"

# ── PQC Primitive Risk Map ────────────────────────────────────────────────────
PQC_RISK_MAP = {
    "ecrecover":        {"risk": "CRITICAL", "reason": "ECDSA signature recovery — Shor's algorithm breaks this in polynomial time", "migration": "Replace with Dilithium-3 via experiments/demos/pqc_alternatives.py"},
    "keccak256":        {"risk": "MEDIUM",   "reason": "Hash function — Grover's algorithm gives quadratic speedup (256-bit → 128-bit effective)", "migration": "Double hash output length or use SHA-3-512"},
    "sha256":           {"risk": "MEDIUM",   "reason": "Same as keccak256 — Grover's quadratic speedup", "migration": "Use SHA-3-512 for new designs"},
    "ripemd160":        {"risk": "HIGH",     "reason": "Deprecated, shorter output, more vulnerable to Grover's", "migration": "Replace with SHA-3-256 or better"},
    "ecdsa":            {"risk": "CRITICAL", "reason": "Elliptic curve signatures — Shor's algorithm", "migration": "ML-DSA-65 (FIPS 204) via dilithium package"},
    "secp256k1":        {"risk": "CRITICAL", "reason": "Bitcoin/ Ethereum curve — Shor's algorithm", "migration": "ML-DSA-65 or SLH-DSA-128 (hash-based hedge)"},
    "bn128":            {"risk": "CRITICAL", "reason": "Pairing-friendly curve for zkSNARKs — Shor's algorithm", "migration": "Lattice-based SNARKs (research stage)"},
    "bls12_381":        {"risk": "CRITICAL", "reason": "BLS signatures — Shor's algorithm", "migration": "Hash-based BLS alternatives (research stage)"},
}

# ── NIST PQC Implementation Vulnerability Map (2024-2025) ─────────────────────
# Sources: publish/SECURITY_ADVISORY_NIST_PQC_2024.md, CVE-2024-37880, eprint 2024/1373
PQC_IMPL_RISK_MAP = {
    "dilithium_unpatched": {
        "risk": "HIGH",
        "reason": "Dilithium public key compression (t₀ omission): 200K-500K signatures enable t₀ recovery, then single-trace power analysis recovers full secret key with 9% probability (Azevedo-Oliveira et al., CRYPTO 2025)",
        "mitigation": "Use t₀-hardened implementations; rotate keys before 200K signatures; use SLH-DSA for high-volume signing",
    },
    "kyber_unpatched": {
        "risk": "CRITICAL",
        "reason": "KyberSlash timing attack: division by q=3329 is not constant-time on all platforms. Secret key recovery in minutes (Bernstein et al., CVE-2024-37880)",
        "mitigation": "Use patched Kyber reference (post-2024-06-03); verify constant-time division; use pqclean/liboqs latest",
    },
    "kyber_clang": {
        "risk": "HIGH",
        "reason": "Compiler-introduced timing leaks: LLVM Clang -O2/-O3 introduces secret-dependent branches in 'constant-time' C code (Antoon Purnal et al., 2024)",
        "mitigation": "Compile with -fno-if-conversion; verify assembly-level constant-time; use verified constant-time implementations",
    },
    "slh_dsa_rng_keygen": {
        "risk": "MEDIUM",
        "reason": "SLH-DSA is stateless by design. The real risk is RNG/keygen misuse producing weak or predictable secret keys",
        "mitigation": "Use a CSPRNG with enough entropy; verify keygen environment and entropy source; never reuse seed material",
    },
    "xmss_lms_state_reuse": {
        "risk": "CRITICAL",
        "reason": "Stateful hash-based signatures (XMSS, LMS) require strict one-time state. Reusing a WOTS+ leaf or state snapshot = total security collapse",
        "mitigation": "Never snapshot/restore signing state; use RFC 8391 / SP 800-208 state management; prefer SLH-DSA for stateless environments",
    },
    # ── Falcon / FN-DSA (FIPS 206) — 2025-2026 single-trace vulnerabilities ──
    "falcon_shift_snare": {
        "risk": "CRITICAL",
        "reason": "SHIFT SNARE (ePrint 2025/146): Single-trace power analysis on discrete Gaussian sampling. 99.99% full-key recovery from one power trace. Use audited or reference implementations — do not implement Falcon yourself.",
        "mitigation": "Use audited or reference implementations such as liboqs or reference Falcon; never implement Falcon yourself; comprehensive masking including floating-point addition; track power traces",
    },
    "falcon_one_fell_swoop": {
        "risk": "HIGH",
        "reason": "One Fell Swoop (ePrint 2025/2159): Single-trace attack on Falcon signing. 100% key recovery at -O0, 80% at -O3 with 5 traces. Affects sign_dyn design used in common libraries.",
        "mitigation": "Avoid sign_dyn design; use verified constant-time signing; compile with care; monitor for single-trace attack feasibility",
    },
    "falcon_fp_leakage": {
        "risk": "HIGH",
        "reason": "Floating-Point Leakage (TCHES 2026): Correlation power analysis on pre-image computation. ~1,000 traces for full key recovery in 30 minutes. Multiplication masking alone is insufficient.",
        "mitigation": "Implement comprehensive masking including floating-point addition; multiplication masking alone is insufficient; use hardware with DPA countermeasures",
    },
    "falcon_ntt_peel": {
        "risk": "HIGH",
        "reason": "NTT-PEEL (TCHES 2026): Bit-shift side-channel in NTT modular reduction. Affects both keygen and signing.",
        "mitigation": "Verify constant-time NTT modular reduction; use hardened NTT implementations; audit both keygen and signing paths",
    },
    "falcon_general": {
        "risk": "MEDIUM",
        "reason": "Falcon requires floating-point FFT and discrete Gaussian sampling — extraordinarily difficult to implement in constant time. Treat custom implementations as high risk.",
        "mitigation": "Use audited or reference implementations; do not implement Falcon yourself; assume single-trace power analysis is feasible on embedded hardware",
    },
}

# ── Falcon / FN-DSA (FIPS 206) Detection Patterns ─────────────────────────────
FALCON_PATTERNS = ("falcon", "fn-dsa", "fn_dsa", "fips206", "fips-206")

# ── Falcon Size Comparison (FIPS 206 vs FIPS 204) ─────────────────────────────
FALCON_SIZE_COMPARISON = {
    "falcon_512": {"pk": 897, "sig": 666, "total": 1563},
    "ml_dsa_44": {"pk": 1312, "sig": 2420, "total": 3732},
    "note": "Falcon-512 is 2.4x smaller than ML-DSA-44, but has 99.99% single-trace key recovery vulnerability per cited literature",
}

# ── Federal / NSS context keywords for CNSA 2.0 regulatory advisory ───────────
NSS_CONTEXT_PATTERNS = (
    "federal", "national security", "nss", "cnsa", "government",
    "defense", "defence", "dod", "nsa", "military", "classified",
)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def scan_pqc_primitives(source: str) -> list[dict]:
    """Find cryptographic primitives and assess quantum risk."""
    findings = []
    for name, info in PQC_RISK_MAP.items():
        if name.lower() in source.lower():
            findings.append({
                "primitive": name,
                "risk": info["risk"],
                "reason": info["reason"],
                "migration": info["migration"],
            })
    return findings


def scan_pqc_impl_risks(source: str, contract_path: Path) -> list[dict]:
    """Find NIST PQC implementation vulnerabilities (2024-2025 research)."""
    findings = []
    source_lower = source.lower()

    # Check for Dilithium usage without signature volume awareness
    if "dilithium" in source_lower or "ml-dsa" in source_lower:
        # High-volume contracts are at risk for t₀ recovery
        findings.append({
            "vulnerability": "dilithium_t0_recovery",
            "risk": PQC_IMPL_RISK_MAP["dilithium_unpatched"]["risk"],
            "reason": PQC_IMPL_RISK_MAP["dilithium_unpatched"]["reason"],
            "mitigation": PQC_IMPL_RISK_MAP["dilithium_unpatched"]["mitigation"],
        })

    # Check for Kyber usage
    if "kyber" in source_lower or "ml-kem" in source_lower:
        findings.append({
            "vulnerability": "kyberslash_timing",
            "risk": PQC_IMPL_RISK_MAP["kyber_unpatched"]["risk"],
            "reason": PQC_IMPL_RISK_MAP["kyber_unpatched"]["reason"],
            "mitigation": PQC_IMPL_RISK_MAP["kyber_unpatched"]["mitigation"],
        })

    # Check for compiler optimization flags that may introduce timing leaks
    if "-o2" in source_lower or "-o3" in source_lower or "optimize" in source_lower:
        if "kyber" in source_lower or "ml-kem" in source_lower:
            findings.append({
                "vulnerability": "compiler_timing_leak",
                "risk": PQC_IMPL_RISK_MAP["kyber_clang"]["risk"],
                "reason": PQC_IMPL_RISK_MAP["kyber_clang"]["reason"],
                "mitigation": PQC_IMPL_RISK_MAP["kyber_clang"]["mitigation"],
            })

    # Check for SLH-DSA RNG/keygen misuse
    if "sphincs" in source_lower or "slh-dsa" in source_lower:
        findings.append({
            "vulnerability": "slh_dsa_rng_keygen_misuse",
            "risk": PQC_IMPL_RISK_MAP["slh_dsa_rng_keygen"]["risk"],
            "reason": PQC_IMPL_RISK_MAP["slh_dsa_rng_keygen"]["reason"],
            "mitigation": PQC_IMPL_RISK_MAP["slh_dsa_rng_keygen"]["mitigation"],
        })

    # Check for XMSS/LMS state-reuse (stateful hash-based signatures)
    if "xmss" in source_lower or "lms" in source_lower:
        findings.append({
            "vulnerability": "xmss_lms_state_reuse",
            "risk": PQC_IMPL_RISK_MAP["xmss_lms_state_reuse"]["risk"],
            "reason": PQC_IMPL_RISK_MAP["xmss_lms_state_reuse"]["reason"],
            "mitigation": PQC_IMPL_RISK_MAP["xmss_lms_state_reuse"]["mitigation"],
        })

    # Check for Falcon / FN-DSA (FIPS 206) usage — most severe single-trace
    # vulnerabilities of any NIST PQC scheme (SHIFT SNARE: 99.99% key recovery
    # from one trace). See publish/BLOG_POST_NIST_PQC_AUDIT_FINAL.md Finding 4.
    if any(pat in source_lower for pat in FALCON_PATTERNS):
        # All five Falcon advisories fire on any Falcon/FN-DSA detection —
        # the scheme is extraordinarily fragile and every documented
        # vulnerability applies to any Falcon deployment.
        for key in ("falcon_shift_snare", "falcon_one_fell_swoop",
                    "falcon_fp_leakage", "falcon_ntt_peel", "falcon_general"):
            findings.append({
                "vulnerability": key,
                "risk": PQC_IMPL_RISK_MAP[key]["risk"],
                "reason": PQC_IMPL_RISK_MAP[key]["reason"],
                "mitigation": PQC_IMPL_RISK_MAP[key]["mitigation"],
            })

    return findings


def detect_falcon(source: str) -> bool:
    """Return True if Falcon / FN-DSA (FIPS 206) usage is detected."""
    source_lower = source.lower()
    return any(pat in source_lower for pat in FALCON_PATTERNS)


def detect_nss_context(source: str) -> bool:
    """Return True if the contract/source references a federal/NSS context."""
    source_lower = source.lower()
    return any(pat in source_lower for pat in NSS_CONTEXT_PATTERNS)


def analyze(contract_path: Path) -> dict:
    source = contract_path.read_text(encoding="utf-8")

    report = {
        "tool": "analyze_contract.py",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "contract": {
            "path": str(contract_path),
            "sha256": sha256_file(contract_path),
            "lines": len(source.splitlines()),
            "bytes": len(source.encode("utf-8")),
        },
        "phases": {},
        "verdict": {},
    }

    # ── Phase 1: Structural ─────────────────────────────────────────────────
    pragma_match = __import__("re").search(r'pragma solidity\s+([^;]+);', source)
    report["phases"]["structure"] = {
        "pragma": pragma_match.group(1).strip() if pragma_match else "unknown",
        "contract_count": len(__import__("re").findall(r'\bcontract\s+\w+', source)),
        "function_count": len(__import__("re").findall(r'\bfunction\s+\w+', source)),
        "event_count": len(__import__("re").findall(r'\bevent\s+\w+', source)),
    }

    # ── Phase 2: Gas Optimization ──────────────────────────────────────────
    gas_result = gas_optimizer.analyze_contract(contract_path)
    gas_findings = gas_result.get("recommendations", [])
    report["phases"]["gas_optimization"] = {
        "opportunities_found": len(gas_findings),
        "estimated_savings_percent": round(sum(f.get("estimated_gas_savings", 0) for f in gas_findings), 1),
        "findings": gas_findings[:10],  # cap output
    }

    # ── Phase 3: Security ────────────────────────────────────────────────────
    sec_result = security_analyzer.analyze_contract_security(contract_path)
    sec_findings = sec_result.get("vulnerabilities", [])
    critical = sum(1 for f in sec_findings if f.get("severity") == "critical")
    high = sum(1 for f in sec_findings if f.get("severity") == "high")
    medium = sum(1 for f in sec_findings if f.get("severity") == "medium")
    low = sum(1 for f in sec_findings if f.get("severity") == "low")
    report["phases"]["security"] = {
        "total_vulnerabilities": len(sec_findings),
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "score": max(0.0, 1.0 - (critical * 0.25 + high * 0.10 + medium * 0.05 + low * 0.01)),
        "findings": sec_findings[:15],
    }

    # ── Phase 4: PQC Readiness ────────────────────────────────────────────
    pqc_findings = scan_pqc_primitives(source)
    pqc_impl_findings = scan_pqc_impl_risks(source, contract_path)
    quantum_vulnerable = sum(1 for f in pqc_findings if f["risk"] == "CRITICAL")
    impl_critical = sum(1 for f in pqc_impl_findings if f["risk"] == "CRITICAL")
    impl_high = sum(1 for f in pqc_impl_findings if f["risk"] == "HIGH")

    # Falcon / FN-DSA (FIPS 206) specific advisory data
    falcon_detected = detect_falcon(source)
    nss_context = detect_nss_context(source)
    falcon_advisory = None
    if falcon_detected:
        falcon_advisory = {
            "detected": True,
            "size_comparison": FALCON_SIZE_COMPARISON,
            "regulatory": {
                "cnsa_2_0_excludes_fn_dsa": True,
                "nss_context_detected": nss_context,
                "advisory": ("CNSA 2.0 explicitly excludes FN-DSA (Falcon) from "
                             "NSS-approved algorithms. ML-KEM-1024 and ML-DSA-87 "
                             "are the only NSS-approved PQC parameter sets. "
                             + ("This contract references a federal/NSS context — "
                                "Falcon is NOT approved for National Security Systems."
                                if nss_context
                                else "If this contract is for a federal/NSS context, "
                                     "Falcon is NOT approved — use ML-DSA-87 instead.")),
            },
        }

    # Combined risk assessment
    if quantum_vulnerable > 0:
        overall_pqc_risk = "CRITICAL"
    elif impl_critical > 0:
        overall_pqc_risk = "CRITICAL"
    elif impl_high > 0 or len(pqc_findings) > 0:
        overall_pqc_risk = "HIGH"
    elif len(pqc_impl_findings) > 0:
        overall_pqc_risk = "MEDIUM"
    else:
        overall_pqc_risk = "LOW"

    report["phases"]["pqc_readiness"] = {
        "primitives_found": len(pqc_findings),
        "quantum_vulnerable": quantum_vulnerable,
        "implementation_vulnerabilities": len(pqc_impl_findings),
        "impl_critical": impl_critical,
        "impl_high": impl_high,
        "risk_level": overall_pqc_risk,
        "findings": pqc_findings,
        "implementation_findings": pqc_impl_findings,
        "falcon_advisory": falcon_advisory,
        "evidence": {
            "shor_breaks_ecdsa": True,
            "grover_affects_hashes": True,
            "nist_fips_204_available": True,  # Dilithium finalized
            "nist_fips_205_available": True,  # SLH-DSA finalized
            "nist_fips_206_available": False,  # FN-DSA (Falcon) selected, FIPS pending
            "nist_fips_206_status": "selected_pending_finalization",
            "security_advisory": "See /mnt/d/Crypto/publish/SECURITY_ADVISORY_NIST_PQC_2024.md for full hostile audit",
            "migration_example": "See /mnt/d/Crypto/experiments/demos/pqc_alternatives.py for working ML-DSA-65 and SLH-DSA-128 demos",
        },
    }

    # ── Phase 5: Evidence Attestation ───────────────────────────────────────
    report_json = json.dumps(report, sort_keys=True)
    security_clean = critical == 0 and high == 0
    pqc_ready = quantum_vulnerable == 0 and impl_critical == 0
    has_advisory_findings = (
        high > 0 or medium > 0 or low > 0
        or impl_high > 0 or len(pqc_findings) > 0 or len(pqc_impl_findings) > 0
    )
    if critical > 0 or not pqc_ready:
        overall = "FAIL"
    elif has_advisory_findings:
        overall = "PASS_WITH_WARNINGS"
    else:
        overall = "PASS"

    report["verdict"] = {
        "security_clean": security_clean,
        "pqc_ready": pqc_ready,
        "overall": overall,
        "report_sha256": hashlib.sha256(report_json.encode()).hexdigest(),
    }

    return report


def to_markdown(report: dict) -> str:
    p = report["phases"]
    v = report["verdict"]

    security_result = "✅ PASS" if v["security_clean"] else ("❌ FAIL" if p["security"]["critical"] else "⚠️ WARN")
    pqc_result = "✅ PASS" if v["pqc_ready"] and p["pqc_readiness"]["risk_level"] == "LOW" else ("❌ FAIL" if not v["pqc_ready"] else "⚠️ WARN")
    overall_result = {
        "PASS": "✅ PASS",
        "PASS_WITH_WARNINGS": "⚠️ PASS WITH WARNINGS",
        "FAIL": "❌ FAIL",
    }.get(v["overall"], v["overall"])

    md = f"""# PQC-Readiness Audit Report

**Contract:** `{report["contract"]["path"]}`  
**SHA-256:** `{report["contract"]["sha256"][:32]}...`  
**Lines:** {report["contract"]["lines"]}  
**Date:** {report["timestamp"][:10]}  
**Tool:** {report["tool"]} v{report["version"]}

---

## Executive Summary

| Check | Result | Detail |
|-------|--------|--------|
| Security Scan | {security_result} | {p["security"]["critical"]} critical, {p["security"]["high"]} high |
| PQC Readiness | {pqc_result} | {p["pqc_readiness"]["quantum_vulnerable"]} quantum-vulnerable primitives, {p["pqc_readiness"]["impl_critical"]} critical implementation advisories |
| Gas Optimization | {p["gas_optimization"]["opportunities_found"]} opportunities | ~{p["gas_optimization"]["estimated_savings_percent"]}% estimated savings |
| **OVERALL** | **{overall_result}** | |

---

## Phase 1: Structure

- **Solidity Version:** {p["structure"]["pragma"]}
- **Contracts:** {p["structure"]["contract_count"]}
- **Functions:** {p["structure"]["function_count"]}
- **Events:** {p["structure"]["event_count"]}

---

## Phase 2: Gas Optimization ({p["gas_optimization"]["opportunities_found"]} found)

| # | Pattern | Severity | Fixable |
|---|---------|----------|---------|
"""
    for i, f in enumerate(p["gas_optimization"]["findings"][:5], 1):
        fix = "Yes" if f.get("can_auto_fix") else "Manual"
        name = f.get('name') or f.get('pattern_name') or f.get('type') or 'Unnamed'
        sev = f.get('severity') or f.get('impact') or '?'
        md += f"| {i} | {name} | {sev} | {fix} |\n"

    md += f"""
---

## Phase 3: Security Analysis ({p["security"]["total_vulnerabilities"]} findings)

| Severity | Count |
|----------|-------|
| 🔴 Critical | {p["security"]["critical"]} |
| 🟠 High | {p["security"]["high"]} |
| 🟡 Medium | {p["security"]["medium"]} |
| 🟢 Low | {p["security"]["low"]} |

**Security Score:** {round(p["security"]["score"] * 100, 1)}/100

"""
    if p["security"]["findings"]:
        md += "### Top Findings\n\n"
        for f in p["security"]["findings"][:5]:
            sev = f.get("severity", "?").upper()
            md += f"- **[{sev}]** {f.get('name', 'Unknown')}: {f.get('description', '')[:100]}...\n"

    md += f"""
---

## Phase 4: Post-Quantum Cryptography Readiness

| Primitive | Risk | Migration Path |
|-----------|------|----------------|
"""
    if p["pqc_readiness"]["findings"]:
        for f in p["pqc_readiness"]["findings"]:
            md += f"| `{f['primitive']}` | {f['risk']} | {f['migration'][:70]}... |\n"
    else:
        md += "| *None found* | LOW | No action needed |\n"

    md += f"""
**Quantum Risk Level:** {p["pqc_readiness"]["risk_level"]}

> **NIST Status:** FIPS 204 (ML-DSA) and FIPS 205 (SLH-DSA) finalized. FIPS 206 (FN-DSA/Falcon) selected for standardization; publication pending.  
> **Crypto Lab Evidence:** Working demos at `/mnt/d/Crypto/experiments/demos/pqc_alternatives.py`. SLH-DSA-128 verified: 6/6 checks pass (keygen, sign, verify, tamper detection, SHA-256 integrity).

### Implementation Vulnerability Scan (2024-2026 Research)

| Vulnerability | Risk | Source |
|---------------|------|--------|
"""
    if p["pqc_readiness"]["implementation_findings"]:
        for f in p["pqc_readiness"]["implementation_findings"]:
            md += f"| {f['vulnerability']} | {f['risk']} | {f['reason'][:80]}... |\n"
        md += "\n**Mitigation:**\n"
        for f in p["pqc_readiness"]["implementation_findings"]:
            md += f"- {f['vulnerability']}: {f['mitigation'][:100]}...\n"
    else:
        md += "| *None detected* | LOW | No known implementation vulnerabilities match this contract |\n"

    # ── Falcon / FN-DSA (FIPS 206) advisory block ───────────────────────────
    falcon_adv = p["pqc_readiness"].get("falcon_advisory")
    if falcon_adv:
        md += """
### Falcon / FN-DSA (FIPS 206 selected) Advisory

> ⚠️ **Falcon detected.** Falcon has the most severe single-trace vulnerabilities of any NIST PQC selection. The cited SHIFT SNARE attack recovers the full secret key from a **single power trace** with 99.99% reported success — Falcon's cited attack almost never fails, while Dilithium's cited 9% single-trace attack fails 91% of the time.

**Size Comparison (Falcon-512 vs ML-DSA-44):**

| Scheme | Public Key | Signature | Total |
|--------|-----------|-----------|-------|
"""
        sc = falcon_adv["size_comparison"]
        md += f"| Falcon-512 | {sc['falcon_512']['pk']} bytes | {sc['falcon_512']['sig']} bytes | {sc['falcon_512']['total']} bytes |\n"
        md += f"| ML-DSA-44 | {sc['ml_dsa_44']['pk']} bytes | {sc['ml_dsa_44']['sig']} bytes | {sc['ml_dsa_44']['total']} bytes |\n"
        md += f"\n*{sc['note']}.*\n"

        reg = falcon_adv["regulatory"]
        nss_flag = "🚨 **NSS CONTEXT DETECTED** — " if reg["nss_context_detected"] else ""
        md += f"""
**Regulatory Advisory (CNSA 2.0):**

> {nss_flag}{reg['advisory']}

**Recommendation:** Do not implement Falcon yourself. Use audited or reference implementations such as liboqs or reference Falcon. For federal/NSS use, replace Falcon with ML-DSA-87 (CNSA 2.0 approved). For bandwidth-constrained non-NSS use, accept the single-trace risk and implement comprehensive side-channel countermeasures.
"""

    md += f"""
> **Security Advisory:** Full hostile audit at `/mnt/d/Crypto/publish/SECURITY_ADVISORY_NIST_PQC_2024.md`

---

## Evidence Attestation

- **Source SHA-256:** `{report["contract"]["sha256"]}`
- **Report SHA-256:** `{report["verdict"]["report_sha256"][:32]}...`
- **Formal Context:** Selected Fundamentals Lean files provide mathematical context, but this smart-contract audit does not certify physics claims or promote evidence tiers. See `/mnt/d/Fundamentals/CLAIMS.md` for current claim status.

---

*This report was generated mechanically. No LLM inference was used in the security or PQC assessments.*
*PQC-Readiness Audit — Crypto Workspace / CASCADE Ecosystem*
"""
    return md


def main() -> int:
    parser = argparse.ArgumentParser(description="PQC-Readiness Audit")
    parser.add_argument("contract", help="Path to .sol contract file")
    parser.add_argument("--format", choices=["json", "md", "pdf"], default="md",
                        help="Output format (pdf requires UniversalPublisher pipeline)")
    parser.add_argument("--output", help="Output file path (default: auto-named)")
    args = parser.parse_args()

    contract_path = Path(args.contract)
    if not contract_path.exists():
        print(f"[ERROR] Contract not found: {contract_path}", file=sys.stderr)
        return 2

    report = analyze(contract_path)

    # Determine output path
    if args.output:
        out_path = Path(args.output)
    else:
        REPORTS_DIR.mkdir(exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        stem = contract_path.stem
        ext = {"json": ".json", "md": ".md", "pdf": ".pdf"}[args.format]
        out_path = REPORTS_DIR / f"audit_{stem}_{ts}{ext}"

    if args.format == "json":
        out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    elif args.format == "md":
        out_path.write_text(to_markdown(report), encoding="utf-8")
    elif args.format == "pdf":
        # Write markdown first, then call UniversalPublisher LaTeX pipeline
        md_path = out_path.with_suffix(".md")
        md_path.write_text(to_markdown(report), encoding="utf-8")
        print(f"[INFO] Markdown written to {md_path}")
        print(f"[INFO] PDF generation: python3 /mnt/d/Projects/UniversalPublisher/src/latex_pdf_builder.py {md_path}")
        # Defer to UniversalPublisher — print instructions
        out_path = md_path  # Return the MD path for now

    print(f"\n{'=' * 60}")
    print(f"  PQC-Readiness Audit Complete")
    print(f"  Overall: {report['verdict']['overall']}")
    print(f"  Security: {report['phases']['security']['critical']} critical, {report['phases']['security']['high']} high")
    print(f"  PQC Risk: {report['phases']['pqc_readiness']['risk_level']}")
    print(f"  Output: {out_path}")
    print(f"{'=' * 60}")

    return 0 if report["verdict"]["overall"] in ("PASS", "PASS_WITH_WARNINGS") else 1


if __name__ == "__main__":
    sys.exit(main())
