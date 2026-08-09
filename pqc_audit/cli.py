"""pqc_audit.cli — Command-line entry point for the PQC-Readiness Audit tool.

Usage:
    pqc-audit <contract.sol> [--format json|md] [--output PATH]
    pqc-audit --evidence [--scheme SCHEME]
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from .analyzer import analyze, to_markdown
from .evidence import run_evidence_contract, available_schemes


def _cmd_audit(args: argparse.Namespace) -> int:
    contract_path = Path(args.contract)
    if not contract_path.exists():
        print(f"[ERROR] Contract not found: {contract_path}", file=sys.stderr)
        return 2

    report = analyze(contract_path)

    if args.output:
        out_path = Path(args.output)
    else:
        out_dir = Path("REPORTS")
        out_dir.mkdir(exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        stem = contract_path.stem
        ext = ".json" if args.format == "json" else ".md"
        out_path = out_dir / f"audit_{stem}_{ts}{ext}"

    if args.format == "json":
        out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    else:
        out_path.write_text(to_markdown(report), encoding="utf-8")

    print(f"\n{'=' * 60}")
    print(f"  PQC-Readiness Audit Complete")
    print(f"  Overall: {report['verdict']['overall']}")
    print(f"  Security: {report['phases']['security']['critical']} critical, {report['phases']['security']['high']} high")
    print(f"  PQC Risk: {report['phases']['pqc_readiness']['risk_level']}")
    print(f"  Output: {out_path}")
    print(f"{'=' * 60}")

    return 0 if report["verdict"]["overall"] in ("PASS", "PASS_WITH_WARNINGS") else 1


def _cmd_evidence(args: argparse.Namespace) -> int:
    avail = available_schemes()
    if args.scheme == "all":
        schemes = [s for s, ok in avail.items() if ok]
    else:
        schemes = [args.scheme]

    if not schemes:
        print("[WARN] No available schemes found. Install PQC backends: pip install pqc-audit[pqc]", file=sys.stderr)
        return 1

    print("=" * 60)
    print("  PQC EVIDENCE CONTRACT GATE")
    print(f"  Schemes: {', '.join(schemes)}")
    print("=" * 60)

    total_pass = 0
    total_fail = 0
    total_skip = 0
    results = []

    for scheme in schemes:
        result = run_evidence_contract(scheme)
        results.append(result)
        v = result["verdict"]
        symbol = {"PASS": "[OK]", "PASS_WITH_WARNINGS": "[OK*]", "FAIL": "[FAIL]", "SKIP": "[SKIP]"}.get(v, "?")
        print(f"\n  {symbol} {scheme} — {v}")
        for c in result["checks"]:
            p = "+" if c["passed"] else "-"
            print(f"      [{p}] {c['check']}: {c['detail']}")
        if result.get("error"):
            print(f"      ERROR: {result['error']}")

        if v in ("PASS", "PASS_WITH_WARNINGS"):
            total_pass += 1
        elif v == "FAIL":
            total_fail += 1
        else:
            total_skip += 1

    total_impl_warnings = sum(len(r.get("implementation_warnings", [])) for r in results)
    print("\n" + "=" * 60)
    print(f"  SUMMARY: {total_pass} PASS  {total_fail} FAIL  {total_skip} SKIP")
    if total_impl_warnings:
        print(f"  IMPLEMENTATION WARNINGS: {total_impl_warnings}")
    verdict = "PASS_WITH_WARNINGS" if total_impl_warnings and total_fail == 0 and total_pass > 0 else ("PASS" if total_fail == 0 and total_pass > 0 else "FAIL")
    print(f"  VERDICT: {verdict}")
    print("=" * 60)

    return 0 if verdict in ("PASS", "PASS_WITH_WARNINGS") else 1


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Returns an exit code."""
    parser = argparse.ArgumentParser(
        prog="pqc-audit",
        description="PQC-Readiness Audit for Solidity smart contracts",
    )
    sub = parser.add_subparsers(dest="command")

    # audit subcommand (default)
    p_audit = sub.add_parser("audit", help="Audit a .sol contract file")
    p_audit.add_argument("contract", help="Path to .sol contract file")
    p_audit.add_argument("--format", choices=["json", "md"], default="md", help="Output format")
    p_audit.add_argument("--output", help="Output file path (default: auto-named in REPORTS/)")

    # evidence subcommand
    p_ev = sub.add_parser("evidence", help="Run mechanical PQC verification gate")
    p_ev.add_argument("--scheme", default="all", help="Scheme name or 'all'")

    args = parser.parse_args(argv)

    if args.command == "evidence":
        return _cmd_evidence(args)
    elif args.command == "audit":
        return _cmd_audit(args)
    else:
        # If no subcommand but a positional arg is given, treat as audit
        if argv and not argv[0].startswith("-"):
            args = p_audit.parse_args(argv)
            return _cmd_audit(args)
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())
