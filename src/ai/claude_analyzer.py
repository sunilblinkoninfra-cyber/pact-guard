"""
AI Reasoning Layer — Claude API Integration
Uses Anthropic's Claude to provide deep security explanations,
context-aware risk assessment, and improved code fix suggestions.
"""
import json
import os
import re
from typing import List, Optional, Dict, Any
import urllib.request
import urllib.error

from ..rules.rule_engine import Finding, Severity


CLAUDE_API_URL = "https://api.anthropic.com/v1/messages"
DEFAULT_MODEL = "claude-sonnet-4-20250514"

SYSTEM_PROMPT = """You are a Kadena Pact smart contract security expert conducting a formal audit.
You have deep knowledge of:
- Pact's capability-based security model and how it differs from EVM-style smart contracts
- The @managed annotation for linear resource tracking (prevents double-spend)
- Guard types: keyset-ref-guard, create-user-guard, create-principal-guard, create-pact-guard
- Module governance patterns (defcap GOVERNANCE vs keyset string governance)
- Defpact multi-step transaction security and cross-chain considerations
- Kadena's coin contract as the reference implementation for fungible tokens
- The Checks-Effects-Interactions pattern in Pact context
- Real DeFi exploits and how they map to Pact-specific vulnerabilities

Your job: provide CONTEXT-SPECIFIC analysis for each finding. Do NOT give generic advice.
Reference the ACTUAL function name, table name, and code structure from the contract.
Name the specific attack vector (e.g., "front-running the init() call at block 0").
Provide a complete, syntactically correct Pact fix that matches the contract's existing style.

Rules:
- Every explanation must reference the specific function and line numbers provided
- Fixes must use Pact syntax only (no Solidity/EVM idioms)
- For DeFi contracts, mention the economic attack (token inflation, double-spend, etc.)
- Keep ai_explanation under 80 words but make every word count
- attack_scenario must be concrete: "Attacker calls X with Y to achieve Z"
- fixed_code must be complete and runnable, not a template

Respond ONLY with valid JSON matching the schema. No markdown, no preamble."""

ENRICHMENT_PROMPT_TEMPLATE = """You are auditing a Pact smart contract. 
Static analysis found the following security findings:

CONTRACT CODE:
```pact
{contract_code}
```

STATIC ANALYSIS FINDINGS:
{findings_json}

For each finding, provide CONTEXT-SPECIFIC analysis referencing the ACTUAL function names, 
table names, and line numbers from the contract. Return a JSON object with this exact structure:
{{
  "overall_risk_score": <0-100, lower=more dangerous>,
  "risk_narrative": "<2-3 sentences specific to THIS contract — mention the module name, key vulnerabilities, and economic impact>",
  "compound_risks": ["<specific compound risk 1, e.g., 'CEI violation in transfer() combined with unmanaged DEBIT capability enables atomic double-spend'>"],
  "enriched_findings": [
    {{
      "rule_id": "<must match input rule_id exactly>",
      "ai_explanation": "<60-80 words, context-specific: name the function, explain WHY it's vulnerable in THIS contract, not generic>",
      "attack_scenario": "<concrete 2-step attack: 'Attacker calls [FUNCTION] with [ARGS]. Because [MISSING CONTROL], this causes [EXPLOIT]'>",
      "fixed_code": "<complete syntactically-correct Pact code. Must match the contract's existing style and use ACTUAL table/function names>",
      "confidence_adjustment": <float between -0.15 and 0.15>
    }}
  ]
}}"""


class AIAnalyzer:
    """
    Enriches static analysis findings with Claude AI reasoning.
    Falls back gracefully if API key is unavailable.
    """

    def __init__(self, api_key: Optional[str] = None, model: str = DEFAULT_MODEL):
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self.model = model
        self.available = bool(self.api_key)

    def enrich_findings(
        self,
        contract_source: str,
        findings: List[Finding],
        timeout: int = 60,
    ) -> Dict[str, Any]:
        """
        Call Claude API to enrich findings with deep analysis.
        Returns enriched findings dict or empty dict on failure.
        """
        if not self.available or not findings:
            return {}

        # Truncate source to avoid hitting context limits
        source_snippet = contract_source[:4000] + (
            "\n... [truncated]" if len(contract_source) > 4000 else ""
        )

        findings_data = [
            {
                "rule_id": f.rule_id,
                "title": f.title,
                "severity": f.severity.value,
                "location": f.location.to_dict(),
                "issue": f.issue,
                "risk": f.risk,
                "recommendation": f.recommendation,
            }
            for f in findings
        ]

        prompt = ENRICHMENT_PROMPT_TEMPLATE.format(
            contract_code=source_snippet,
            findings_json=json.dumps(findings_data, indent=2),
        )

        try:
            result = self._call_api(prompt, timeout)
            return self._parse_enrichment(result)
        except Exception as e:
            return {"error": str(e), "enriched_findings": []}

    def generate_executive_summary(
        self, contract_source: str, findings: List[Finding]
    ) -> str:
        """Generate a concise executive summary of the contract's security posture."""
        if not self.available:
            return self._fallback_summary(findings)

        severity_counts = {}
        for f in findings:
            severity_counts[f.severity.value] = severity_counts.get(f.severity.value, 0) + 1

        prompt = f"""Analyze this Pact smart contract and provide a 3-paragraph executive security summary.
        
Contract (first 2000 chars):
```pact
{contract_source[:2000]}
```

Finding counts: {json.dumps(severity_counts)}
Finding titles: {json.dumps([f.title for f in findings[:10]])}

Write a concise executive summary covering:
1. Overall security posture (1-2 sentences)
2. Most critical risks (1-2 sentences)  
3. Priority recommendations (1-2 sentences)

Return ONLY the summary text, no JSON."""

        try:
            return self._call_api(prompt, timeout=30)
        except Exception:
            return self._fallback_summary(findings)

    def suggest_secure_pattern(self, pattern_name: str, context: str) -> str:
        """Ask Claude for the best Pact pattern for a specific security concern."""
        if not self.available:
            return ""

        prompt = f"""Provide the best Pact code pattern for: {pattern_name}
Context: {context}
Return only valid Pact code with inline comments. Keep it under 30 lines."""

        try:
            return self._call_api(prompt, timeout=20)
        except Exception:
            return ""

    def _call_api(self, user_message: str, timeout: int = 60) -> str:
        """Make a direct HTTP call to the Anthropic API."""
        payload = {
            "model": self.model,
            "max_tokens": 2048,
            "system": SYSTEM_PROMPT,
            "messages": [{"role": "user", "content": user_message}],
        }

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            CLAUDE_API_URL,
            data=data,
            headers={
                "Content-Type": "application/json",
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
            },
            method="POST",
        )

        with urllib.request.urlopen(req, timeout=timeout) as resp:
            response_data = json.loads(resp.read().decode("utf-8"))

        if "content" in response_data and response_data["content"]:
            return response_data["content"][0].get("text", "")
        return ""

    def _parse_enrichment(self, raw_text: str) -> Dict[str, Any]:
        """Extract JSON from Claude's response."""
        # Try to find JSON block
        json_match = re.search(r'\{[\s\S]*\}', raw_text)
        if not json_match:
            return {"enriched_findings": [], "error": "No JSON found in response"}
        try:
            return json.loads(json_match.group())
        except json.JSONDecodeError as e:
            return {"enriched_findings": [], "error": f"JSON parse error: {e}"}

    def _fallback_summary(self, findings: List[Finding]) -> str:
        """Generate a summary without AI when API is unavailable."""
        if not findings:
            return "No security issues detected. Manual review still recommended."

        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        high = [f for f in findings if f.severity == Severity.HIGH]
        medium = [f for f in findings if f.severity == Severity.MEDIUM]
        low = [f for f in findings if f.severity == Severity.LOW]

        lines = [
            f"Static analysis identified {len(findings)} finding(s): "
            f"{len(critical)} critical, {len(high)} high, {len(medium)} medium, {len(low)} low.",
        ]
        if critical:
            lines.append(
                f"Critical issues requiring immediate attention: "
                f"{', '.join(f.title for f in critical[:3])}."
            )
        if high:
            lines.append(
                f"High severity issues: {', '.join(f.title for f in high[:3])}."
            )
        lines.append(
            "Recommend manual review by a Pact security expert before mainnet deployment."
        )
        return " ".join(lines)
