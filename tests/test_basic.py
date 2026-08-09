"""tests/test_basic.py — Tests for the pqc-audit package.

Covers:
  1. Safe contract (no PQC issues) -> should pass / low risk
  2. ECDSA contract (ecrecover) -> should flag CRITICAL PQC risk
  3. Vulnerable contract (multiple issues) -> should flag security + PQC
  4. Evidence contract (SLH-DSA-128 always available) -> should pass
  5. Package API smoke tests
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from pqc_audit import (
    analyze,
    to_markdown,
    scan_pqc_primitives,
    scan_pqc_impl_risks,
    run_evidence_contract,
    available_schemes,
    __version__,
)

CONTRACTS_DIR = Path(__file__).parent / "test_contracts"


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def safe_contract() -> Path:
    return CONTRACTS_DIR / "SafeToken.sol"


@pytest.fixture
def ecdsa_contract() -> Path:
    return CONTRACTS_DIR / "ECDSAVerifier.sol"


@pytest.fixture
def vulnerable_contract() -> Path:
    return CONTRACTS_DIR / "VulnerableContract.sol"


# ── 1. Safe contract ──────────────────────────────────────────────────────────

class TestSafeContract:
    """A contract with no quantum-vulnerable primitives should pass PQC readiness."""

    def test_no_pqc_primitives_found(self, safe_contract: Path):
        report = analyze(safe_contract)
        pqc = report["phases"]["pqc_readiness"]
        assert pqc["primitives_found"] == 0, "Safe contract should have 0 PQC primitives"
        assert pqc["quantum_vulnerable"] == 0

    def test_low_pqc_risk(self, safe_contract: Path):
        report = analyze(safe_contract)
        assert report["phases"]["pqc_readiness"]["risk_level"] == "LOW"

    def test_pqc_ready(self, safe_contract: Path):
        report = analyze(safe_contract)
        assert report["verdict"]["pqc_ready"] is True

    def test_overall_pass_or_warning(self, safe_contract: Path):
        report = analyze(safe_contract)
        # SafeToken may have gas/security warnings but no critical PQC issues
        assert report["verdict"]["overall"] in ("PASS", "PASS_WITH_WARNINGS")

    def test_no_critical_security(self, safe_contract: Path):
        report = analyze(safe_contract)
        assert report["phases"]["security"]["critical"] == 0


# ── 2. ECDSA contract ─────────────────────────────────────────────────────────

class TestECDSAContract:
    """A contract using ecrecover should be flagged as CRITICAL PQC risk."""

    def test_ecrecover_detected(self, ecdsa_contract: Path):
        report = analyze(ecdsa_contract)
        pqc = report["phases"]["pqc_readiness"]
        primitives = [f["primitive"] for f in pqc["findings"]]
        assert "ecrecover" in primitives, "ecrecover should be detected"

    def test_critical_pqc_risk(self, ecdsa_contract: Path):
        report = analyze(ecdsa_contract)
        assert report["phases"]["pqc_readiness"]["risk_level"] == "CRITICAL"

    def test_quantum_vulnerable_count(self, ecdsa_contract: Path):
        report = analyze(ecdsa_contract)
        pqc = report["phases"]["pqc_readiness"]
        assert pqc["quantum_vulnerable"] >= 1

    def test_not_pqc_ready(self, ecdsa_contract: Path):
        report = analyze(ecdsa_contract)
        assert report["verdict"]["pqc_ready"] is False

    def test_overall_fail(self, ecdsa_contract: Path):
        report = analyze(ecdsa_contract)
        assert report["verdict"]["overall"] == "FAIL"

    def test_ecrecover_finding_has_migration(self, ecdsa_contract: Path):
        report = analyze(ecdsa_contract)
        pqc = report["phases"]["pqc_readiness"]
        ecrecover_finding = next(f for f in pqc["findings"] if f["primitive"] == "ecrecover")
        assert ecrecover_finding["risk"] == "CRITICAL"
        assert "migration" in ecrecover_finding
        assert len(ecrecover_finding["migration"]) > 0


# ── 3. Vulnerable contract ────────────────────────────────────────────────────

class TestVulnerableContract:
    """A contract with multiple vulnerabilities should flag both security and PQC."""

    def test_ecrecover_detected(self, vulnerable_contract: Path):
        report = analyze(vulnerable_contract)
        primitives = [f["primitive"] for f in report["phases"]["pqc_readiness"]["findings"]]
        assert "ecrecover" in primitives

    def test_sha256_detected(self, vulnerable_contract: Path):
        report = analyze(vulnerable_contract)
        primitives = [f["primitive"] for f in report["phases"]["pqc_readiness"]["findings"]]
        assert "sha256" in primitives

    def test_critical_pqc_risk(self, vulnerable_contract: Path):
        report = analyze(vulnerable_contract)
        assert report["phases"]["pqc_readiness"]["risk_level"] == "CRITICAL"

    def test_has_security_findings(self, vulnerable_contract: Path):
        report = analyze(vulnerable_contract)
        assert report["phases"]["security"]["total_vulnerabilities"] > 0

    def test_overall_fail(self, vulnerable_contract: Path):
        report = analyze(vulnerable_contract)
        assert report["verdict"]["overall"] == "FAIL"

    def test_selfdestruct_flagged(self, vulnerable_contract: Path):
        report = analyze(vulnerable_contract)
        sec_findings = report["phases"]["security"]["findings"]
        types = [f.get("type", f.get("name", "")) for f in sec_findings]
        assert any("self" in t.lower() or "destruct" in t.lower() or "suicide" in t.lower() for t in types)


# ── 4. Report structure & markdown ────────────────────────────────────────────

class TestReportStructure:
    """Verify the report dict has all expected phases and fields."""

    def test_report_has_all_phases(self, safe_contract: Path):
        report = analyze(safe_contract)
        phases = report["phases"]
        assert "structure" in phases
        assert "gas_optimization" in phases
        assert "security" in phases
        assert "pqc_readiness" in phases

    def test_report_has_verdict(self, safe_contract: Path):
        report = analyze(safe_contract)
        v = report["verdict"]
        assert "security_clean" in v
        assert "pqc_ready" in v
        assert "overall" in v
        assert "report_sha256" in v

    def test_report_has_contract_metadata(self, safe_contract: Path):
        report = analyze(safe_contract)
        c = report["contract"]
        assert "path" in c
        assert "sha256" in c
        assert "lines" in c
        assert c["lines"] > 0

    def test_markdown_output(self, safe_contract: Path):
        report = analyze(safe_contract)
        md = to_markdown(report)
        assert isinstance(md, str)
        assert "PQC-Readiness Audit Report" in md
        assert "Executive Summary" in md
        assert "Phase 1: Structure" in md
        assert "Phase 4" in md

    def test_report_json_serializable(self, safe_contract: Path):
        report = analyze(safe_contract)
        # Should not raise
        text = json.dumps(report, indent=2)
        assert len(text) > 0


# ── 5. Scan functions ─────────────────────────────────────────────────────────

class TestScanFunctions:
    """Test the standalone scan functions."""

    def test_scan_pqc_primitives_finds_ecrecover(self):
        source = "address signer = ecrecover(hash, v, r, s);"
        findings = scan_pqc_primitives(source)
        primitives = [f["primitive"] for f in findings]
        assert "ecrecover" in primitives

    def test_scan_pqc_primitives_clean(self):
        source = "uint256 balance = 100;"
        findings = scan_pqc_primitives(source)
        assert len(findings) == 0

    def test_scan_pqc_impl_risks_dilithium(self):
        source = "using Dilithium for signatures;"
        findings = scan_pqc_impl_risks(source)
        vulns = [f["vulnerability"] for f in findings]
        assert "dilithium_t0_recovery" in vulns

    def test_scan_pqc_impl_risks_kyber(self):
        source = "Kyber key exchange module"
        findings = scan_pqc_impl_risks(source)
        vulns = [f["vulnerability"] for f in findings]
        assert "kyberslash_timing" in vulns

    def test_scan_pqc_impl_risks_falcon(self):
        source = "Falcon signature scheme"
        findings = scan_pqc_impl_risks(source)
        vulns = [f["vulnerability"] for f in findings]
        assert "falcon_shift_snare" in vulns
        assert len(findings) == 5  # All 5 Falcon advisories

    def test_scan_pqc_impl_risks_clean(self):
        source = "uint256 balance = 100;"
        findings = scan_pqc_impl_risks(source)
        assert len(findings) == 0


# ── 6. Evidence contract ──────────────────────────────────────────────────────

class TestEvidenceContract:
    """Test the mechanical PQC verification gate."""

    def test_slh_dsa_always_available(self):
        schemes = available_schemes()
        assert "SLH-DSA-128" in schemes
        assert schemes["SLH-DSA-128"] is True

    def test_slh_dsa_passes(self):
        result = run_evidence_contract("SLH-DSA-128")
        assert result["verdict"] in ("PASS", "PASS_WITH_WARNINGS")
        assert result["verdict"] != "FAIL"

    def test_slh_dsa_all_checks_pass(self):
        result = run_evidence_contract("SLH-DSA-128")
        failed = [c for c in result["checks"] if not c["passed"]]
        assert len(failed) == 0, f"Failed checks: {failed}"

    def test_slh_dsa_has_6_checks(self):
        result = run_evidence_contract("SLH-DSA-128")
        # scheme_available, keygen, sign, verify_correct, tamper_detection, sig_integrity, impl_vulnerability_scan
        assert len(result["checks"]) >= 6

    def test_unknown_scheme_raises(self):
        result = run_evidence_contract("NOSUCH-SCHEME")
        assert result["verdict"] == "SKIP"


# ── 7. Package API ────────────────────────────────────────────────────────────

class TestPackageAPI:
    """Smoke tests for the package's public API."""

    def test_version_string(self):
        assert isinstance(__version__, str)
        assert __version__ == "0.1.0"

    def test_analyze_accepts_string_path(self, safe_contract: Path):
        report = analyze(str(safe_contract))
        assert "verdict" in report

    def test_available_schemes_returns_dict(self):
        schemes = available_schemes()
        assert isinstance(schemes, dict)
        assert len(schemes) > 0
