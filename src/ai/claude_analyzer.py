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

SYSTEM_PROMPT = """You are a senior Kadena Pact smart contract security auditor and blockchain engineer.
You specialize in the Pact language, Kadena's capability-based security model, and DeFi security.

Your role is to:
1. Analyze static analysis findings from a Pact contract scanner
2. Provide deep technical explanations of WHY each finding is dangerous
3. Suggest the best possible fix using Pact idioms and patterns
4. Rate the overall contract risk posture
5. Identify any patterns or combinations of findings that compound risk

Always respond with valid JSON matching the schema provided.
Be specific, technical, and actionable. Reference Pact documentation concepts like:
- The capability system (defcap, with-capability, require-capability)
- @managed capabilities for linear resource tracking
- Guard types (keyset-ref-guard, create-user-guard, create-principal-guard)
- Module governance patterns
- Defpact step authentication

Never hallucinate Pact functions. Stick to the actual Pact language spec."""

ENRICHMENT_PROMPT_TEMPLATE = """You are auditing a Pact smart contract. 
Static analysis found the following security findings:

CONTRACT CODE:
```pact
{contract_code}
```

STATIC ANALYSIS FINDINGS:
{findings_json}

For each finding, provide enriched analysis. Return a JSON object with this structure:
{{
  "overall_risk_score": <number 0-100>,
  "risk_narrative": "<2-3 sentence overall assessment>",
  "compound_risks": ["<risk1>", "<risk2>"],
  "enriched_findings": [
    {{
      "rule_id": "<same as input>",
      "ai_explanation": "<deep technical explanation of why this specific code is vulnerable>",
      "attack_scenario": "<concrete step-by-step attack scenario>",
      "fixed_code": "<complete corrected Pact code snippet>",
      "confidence_adjustment": <-0.2 to 0.2 adjustment to static confidence>
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
