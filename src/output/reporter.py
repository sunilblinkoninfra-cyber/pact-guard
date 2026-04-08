"""
Output Reporter
Formats analysis results into multiple output formats:
- JSON (default, structured)
- Markdown (human-readable report)
- SARIF (GitHub Code Scanning / CI integration)
- Plain text (CLI display)
"""
import json
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from ..rules.rule_engine import Finding, Severity
from .risk_score import RiskScore


SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🟢",
}

SEVERITY_ANSI = {
    "critical": "\033[1;31m",  # bold red
    "high": "\033[0;31m",      # red
    "medium": "\033[0;33m",    # yellow
    "low": "\033[0;32m",       # green
    "reset": "\033[0m",
}


def build_json_report(
    findings: List[Finding],
    risk_score: RiskScore,
    summary: str,
    ai_enrichment: Dict[str, Any],
    filename: str,
    elapsed: float,
) -> Dict[str, Any]:
    """Build the canonical JSON output."""
    numbered_findings = []
    enriched_list = ai_enrichment.get("enriched_findings", [])

    for i, f in enumerate(findings, start=1):
        fd = f.to_dict(i)
        enrich = enriched_list[i-1] if i-1 < len(enriched_list) else {}
        if enrich:
            if enrich.get("ai_explanation"):
                fd["ai_explanation"] = enrich["ai_explanation"]
            if enrich.get("attack_scenario"):
                fd["attack_scenario"] = enrich["attack_scenario"]
            if enrich.get("fixed_code"):
                fd["fixed_code_example"] = enrich["fixed_code"]
        numbered_findings.append(fd)

    report = {
        "schema_version": "1.0",
        "tool": "pact-guard",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "analyzed_file": filename,
        "elapsed_seconds": round(elapsed, 3),
        "summary": summary,
        "risk_score": risk_score.to_dict(),
        "findings": numbered_findings,
    }

    if ai_enrichment.get("risk_narrative"):
        report["ai_risk_narrative"] = ai_enrichment["risk_narrative"]
    if ai_enrichment.get("compound_risks"):
        report["compound_risks"] = ai_enrichment["compound_risks"]

    return report


def render_cli(report: Dict[str, Any], color: bool = True) -> str:
    """Render a colorized CLI summary of the report."""
    lines = []
    A = SEVERITY_ANSI
    reset = A["reset"] if color else ""

    def c(sev: str, text: str) -> str:
        if not color:
            return text
        return f"{A.get(sev, '')}{text}{reset}"

    lines.append("")
    lines.append("╔══════════════════════════════════════════════════════════════╗")
    lines.append("║          PACT GUARD — Security Analysis Report            ║")
    lines.append("╚══════════════════════════════════════════════════════════════╝")
    lines.append(f"  File:    {report.get('analyzed_file', 'unknown')}")
    lines.append(f"  Time:    {report.get('generated_at', '')}")
    lines.append(f"  Elapsed: {report.get('elapsed_seconds', 0)}s")
    lines.append("")

    rs = report.get("risk_score", {})
    grade = rs.get("letter_grade", "?")
    label = rs.get("label", "")
    score = rs.get("security_score", 0)
    grade_color = "critical" if score < 55 else ("high" if score < 70 else
                  ("medium" if score < 85 else "low"))
    lines.append(f"  Security Score: {c(grade_color, f'{score:.1f}/100')}  "
                 f"Grade: {c(grade_color, grade)}  ({label})")
    bd = rs.get("breakdown", {})
    lines.append(
        f"  Findings: "
        f"{c('critical', str(bd.get('critical', 0)) + ' critical')}  "
        f"{c('high', str(bd.get('high', 0)) + ' high')}  "
        f"{c('medium', str(bd.get('medium', 0)) + ' medium')}  "
        f"{c('low', str(bd.get('low', 0)) + ' low')}"
    )
    lines.append("")
    lines.append("  Summary:")
    lines.append(f"  {report.get('summary', '')}")
    lines.append("")

    findings = report.get("findings", [])
    if not findings:
        lines.append("  ✅  No findings detected.")
    else:
        lines.append(f"  ─── Findings ({len(findings)}) ─────────────────────────────────")
        for f in findings:
            sev = f["severity"]
            emoji = SEVERITY_EMOJI.get(sev, "⚪")
            lines.append("")
            lines.append(
                f"  {emoji}  [{c(sev, f['id'])}] {c(sev, f['title'])} "
                f"({c(sev, sev.upper())})"
            )
            loc = f.get("location", {})
            lines.append(
                f"     Location: {loc.get('module', '?')} > "
                f"{loc.get('function', '?')} (line {loc.get('line', '?')})"
            )
            lines.append(f"     Issue: {f['issue'][:120]}{'...' if len(f['issue']) > 120 else ''}")
            lines.append(f"     Risk:  {f['risk'][:120]}{'...' if len(f['risk']) > 120 else ''}")
            if f.get("ai_explanation"):
                lines.append(f"     AI:    {f['ai_explanation'][:150]}...")
            lines.append(f"     Fix:   {f['recommendation'][:120]}{'...' if len(f['recommendation']) > 120 else ''}")

    lines.append("")
    lines.append("══════════════════════════════════════════════════════════════")
    lines.append("")
    return "\n".join(lines)


def render_markdown(report: Dict[str, Any]) -> str:
    """Render a Markdown report suitable for GitHub PR comments."""
    rs = report.get("risk_score", {})
    bd = rs.get("breakdown", {})
    lines = []

    lines.append("# 🛡️ PactGuard — Security Analysis Report")
    lines.append(f"")
    lines.append(f"**File:** `{report.get('analyzed_file', 'unknown')}`  ")
    lines.append(f"**Generated:** {report.get('generated_at', '')}  ")
    lines.append(f"**Security Score:** `{rs.get('security_score', 0):.1f}/100` — "
                 f"Grade **{rs.get('letter_grade', '?')}** ({rs.get('label', '')})")
    lines.append("")
    lines.append("## Summary")
    lines.append(f"> {report.get('summary', '')}")
    lines.append("")

    if report.get("ai_risk_narrative"):
        lines.append("## AI Risk Narrative")
        lines.append(f"> {report['ai_risk_narrative']}")
        lines.append("")

    # Stats table
    lines.append("## Finding Statistics")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    lines.append(f"| 🔴 Critical | {bd.get('critical', 0)} |")
    lines.append(f"| 🟠 High | {bd.get('high', 0)} |")
    lines.append(f"| 🟡 Medium | {bd.get('medium', 0)} |")
    lines.append(f"| 🟢 Low | {bd.get('low', 0)} |")
    lines.append(f"| **Total** | **{bd.get('total', 0)}** |")
    lines.append("")

    findings = report.get("findings", [])
    if findings:
        lines.append("## Findings")
        lines.append("")
        for f in findings:
            sev = f["severity"]
            emoji = SEVERITY_EMOJI.get(sev, "⚪")
            loc = f.get("location", {})
            lines.append(f"### {emoji} [{f['id']}] {f['title']}")
            lines.append(f"**Severity:** `{sev.upper()}` | "
                         f"**Location:** `{loc.get('module', '?')}::{loc.get('function', '?')}` "
                         f"(line {loc.get('line', '?')}) | "
                         f"**Rule:** `{f.get('rule_id', '?')}`")
            lines.append("")
            lines.append(f"**Issue:** {f['issue']}")
            lines.append("")
            lines.append(f"**Risk:** {f['risk']}")
            lines.append("")
            if f.get("ai_explanation"):
                lines.append(f"**AI Analysis:** {f['ai_explanation']}")
                lines.append("")
            if f.get("attack_scenario"):
                lines.append(f"**Attack Scenario:** {f['attack_scenario']}")
                lines.append("")
            lines.append(f"**Recommendation:** {f['recommendation']}")
            lines.append("")
            if f.get("fixed_code_example"):
                lines.append("**Fixed Code:**")
                lines.append("```pact")
                lines.append(f.get("fixed_code_example", ""))
                lines.append("```")
                lines.append("")
            lines.append("---")
            lines.append("")
    else:
        lines.append("## ✅ No Findings")
        lines.append("No security issues were detected by static analysis.")

    lines.append("")
    lines.append("*Generated by [pact-guard](https://github.com/your-org/pact-guard)*")
    return "\n".join(lines)


def render_sarif(report: Dict[str, Any]) -> Dict[str, Any]:
    """
    Output SARIF 2.1 format for GitHub Advanced Security / CI integration.
    See: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
    """
    SARIF_LEVEL = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
    }

    rules = []
    rule_ids = set()
    results = []

    for f in report.get("findings", []):
        rid = f.get("rule_id", f.get("id", "R-000"))
        if rid not in rule_ids:
            rule_ids.add(rid)
            rules.append({
                "id": rid,
                "name": f["title"].replace(" ", ""),
                "shortDescription": {"text": f["title"]},
                "fullDescription": {"text": f["issue"]},
                "help": {"text": f["recommendation"]},
                "defaultConfiguration": {
                    "level": SARIF_LEVEL.get(f["severity"], "warning")
                },
                "properties": {
                    "tags": f.get("tags", []),
                    "severity": f["severity"],
                },
            })

        loc = f.get("location", {})
        results.append({
            "ruleId": rid,
            "level": SARIF_LEVEL.get(f["severity"], "warning"),
            "message": {"text": f"{f['issue']} — {f['recommendation']}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": report.get("analyzed_file", "unknown.pact")
                    },
                    "region": {"startLine": max(1, loc.get("line", 1))}
                },
                "logicalLocations": [{
                    "name": loc.get("function", ""),
                    "kind": "function",
                    "fullyQualifiedName": f"{loc.get('module', '')}::{loc.get('function', '')}",
                }],
            }],
        })

    return {
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.6.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "pact-guard",
                    "version": "1.0.0",
                    "informationUri": "https://github.com/your-org/pact-guard",
                    "rules": rules,
                }
            },
            "results": results,
            "invocations": [{
                "executionSuccessful": True,
                "toolExecutionNotifications": [],
            }],
        }],
    }
