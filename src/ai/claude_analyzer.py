"""
AI Reasoning Layer — Multi-Provider Support
Supports OpenAI (GPT-4o, GPT-4-turbo) and Anthropic (Claude) APIs.
Auto-detects which key is available; can be forced via provider argument.

Priority: OPENAI_API_KEY → ANTHROPIC_API_KEY → fallback (no AI)
"""
import json, os, re
from typing import List, Optional, Dict, Any
import urllib.request, urllib.error
from ..rules.rule_engine import Finding, Severity

OPENAI_API_URL    = "https://api.openai.com/v1/chat/completions"
ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
OPENAI_DEFAULT    = "gpt-4o"
ANTHROPIC_DEFAULT = "claude-sonnet-4-20250514"

SYSTEM_PROMPT = """You are a Kadena Pact smart contract security expert conducting a formal audit.
You have deep knowledge of:
- Pact's capability-based security model and how it differs from EVM-style smart contracts
- The @managed annotation for linear resource tracking (prevents double-spend)
- Guard types: keyset-ref-guard, create-user-guard, create-principal-guard, create-pact-guard
- Module governance patterns (defcap GOVERNANCE vs keyset string governance)
- Defpact multi-step transaction security and cross-chain considerations
- Kadena's coin contract as the reference implementation for fungible tokens
- The Checks-Effects-Interactions pattern in Pact context

Your job: provide CONTEXT-SPECIFIC analysis for each finding. Do NOT give generic advice.
Reference the ACTUAL function name, table name, and code structure from the contract.
Name the specific attack vector. Provide complete, syntactically correct Pact fixes.
Respond ONLY with valid JSON. No markdown, no preamble."""

ENRICHMENT_PROMPT = """Analyze this Pact contract and its static analysis findings.

CONTRACT:
```pact
{contract_code}
```

FINDINGS:
{findings_json}

Return a JSON object:
{{
  "overall_risk_score": <0-100>,
  "risk_narrative": "<2-3 sentences specific to THIS contract>",
  "compound_risks": ["<compound risk referencing actual function names>"],
  "enriched_findings": [
    {{
      "rule_id": "<same as input>",
      "ai_explanation": "<60-80 words, context-specific, names the function and WHY it's vulnerable>",
      "attack_scenario": "<concrete: Attacker calls [FUNCTION] with [ARGS]. Because [MISSING CONTROL], this [EXPLOIT]>",
      "fixed_code": "<complete runnable Pact code using ACTUAL table/function names>",
      "confidence_adjustment": <-0.15 to 0.15>
    }}
  ]
}}"""


def detect_provider(api_key=None, openai_key=None, anthropic_key=None, force=None):
    """Returns (provider, key, model). Priority: openai → anthropic → none."""
    # Single key auto-detect
    if api_key:
        if api_key.startswith("sk-ant"):
            return ("anthropic", api_key, ANTHROPIC_DEFAULT)
        return ("openai", api_key, OPENAI_DEFAULT)

    okey = openai_key    or os.environ.get("OPENAI_API_KEY",    "")
    akey = anthropic_key or os.environ.get("ANTHROPIC_API_KEY", "")

    if force == "openai":
        return ("openai", okey, OPENAI_DEFAULT) if okey else ("none", "", "")
    if force == "anthropic":
        return ("anthropic", akey, ANTHROPIC_DEFAULT) if akey else ("none", "", "")

    if okey:  return ("openai",    okey, OPENAI_DEFAULT)
    if akey:  return ("anthropic", akey, ANTHROPIC_DEFAULT)
    return ("none", "", "")


class AIAnalyzer:
    """Multi-provider AI analyzer. Supports OpenAI and Anthropic."""

    def __init__(self, api_key=None, openai_key=None, anthropic_key=None,
                 provider=None, model=None):
        self.provider, self.api_key, detected_model = detect_provider(
            api_key=api_key, openai_key=openai_key, anthropic_key=anthropic_key, force=provider)
        self.model     = model or detected_model
        self.available = self.provider != "none" and bool(self.api_key)

    # ── Public API ────────────────────────────────────────────────

    def enrich_findings(self, contract_source: str, findings: List[Finding],
                        timeout: int = 60) -> Dict[str, Any]:
        if not self.available or not findings:
            return {}
        snippet = contract_source[:4000] + ("\n...[truncated]" if len(contract_source) > 4000 else "")
        prompt  = ENRICHMENT_PROMPT.format(
            contract_code=snippet,
            findings_json=json.dumps([
                {"rule_id": f.rule_id, "title": f.title, "severity": f.severity.value,
                 "location": f.location.to_dict(), "issue": f.issue, "risk": f.risk}
                for f in findings
            ], indent=2)
        )
        try:
            raw = self._call(prompt, timeout)
            return self._parse(raw)
        except Exception as e:
            return {"error": str(e), "enriched_findings": []}

    def generate_executive_summary(self, contract_source: str, findings: List[Finding]) -> str:
        if not self.available:
            return self._fallback_summary(findings)
        counts = {}
        for f in findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        prompt = (
            f"Analyze this Pact contract and write a 3-paragraph executive security summary.\n\n"
            f"Contract:\n```pact\n{contract_source[:2000]}\n```\n\n"
            f"Findings: {json.dumps(counts)}\n"
            f"Critical: {[f.title for f in findings if f.severity == Severity.CRITICAL][:5]}\n\n"
            "Paragraphs: 1) Overall posture + module name/purpose. "
            "2) Critical risks naming specific functions. "
            "3) Priority recommendations.\n"
            "Return ONLY the summary text, no JSON."
        )
        try:
            return self._call(prompt, timeout=30)
        except Exception:
            return self._fallback_summary(findings)

    def get_provider_info(self) -> Dict[str, str]:
        return {"provider": self.provider, "model": self.model,
                "available": str(self.available),
                "key_prefix": (self.api_key[:12] + "...") if self.api_key else ""}

    # ── Internal routing ──────────────────────────────────────────

    def _call(self, prompt: str, timeout: int) -> str:
        if self.provider == "openai":
            return self._call_openai(prompt, timeout)
        return self._call_anthropic(prompt, timeout)

    def _call_openai(self, prompt: str, timeout: int) -> str:
        payload = {
            "model": self.model,
            "max_tokens": 2048,
            "temperature": 0.2,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user",   "content": prompt},
            ],
        }
        req = urllib.request.Request(
            OPENAI_API_URL,
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {self.api_key}"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read())
        return data["choices"][0]["message"]["content"]

    def _call_anthropic(self, prompt: str, timeout: int) -> str:
        payload = {
            "model": self.model,
            "max_tokens": 2048,
            "system": SYSTEM_PROMPT,
            "messages": [{"role": "user", "content": prompt}],
        }
        req = urllib.request.Request(
            ANTHROPIC_API_URL,
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json",
                     "x-api-key": self.api_key,
                     "anthropic-version": "2023-06-01"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read())
        return data["content"][0]["text"]

    def _parse(self, raw: str) -> Dict[str, Any]:
        raw = re.sub(r"```json\s*", "", raw)
        raw = re.sub(r"```\s*", "", raw)
        m = re.search(r"\{[\s\S]*\}", raw)
        if not m:
            return {"enriched_findings": [], "error": "No JSON found"}
        try:
            return json.loads(m.group())
        except json.JSONDecodeError as e:
            return {"enriched_findings": [], "error": str(e)}

    def _fallback_summary(self, findings: List[Finding]) -> str:
        if not findings:
            return "No security issues detected. Manual review still recommended."
        crit = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high = sum(1 for f in findings if f.severity == Severity.HIGH)
        med  = sum(1 for f in findings if f.severity == Severity.MEDIUM)
        low  = sum(1 for f in findings if f.severity == Severity.LOW)
        lines = [f"Static analysis found {len(findings)} issue(s): {crit} critical, {high} high, {med} medium, {low} low."]
        crit_titles = [f.title for f in findings if f.severity == Severity.CRITICAL][:3]
        if crit_titles:
            lines.append(f"Critical: {', '.join(crit_titles)}.")
        lines.append("Manual Pact security review recommended before mainnet deployment.")
        return " ".join(lines)
