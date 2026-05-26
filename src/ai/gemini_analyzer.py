"""
AI Reasoning Layer — Multi-Provider Support
Supports OpenAI (GPT-4o, GPT-4-turbo) and Gemini (Gemini) APIs.
Auto-detects which key is available; can be forced via provider argument.

Priority: OPENAI_API_KEY → GEMINI_API_KEY → fallback (no AI)
"""
import json, os, re
from typing import List, Optional, Dict, Any
import urllib.request, urllib.error
from ..rules.rule_engine import Finding, Severity

OPENAI_API_URL    = "https://api.openai.com/v1/chat/completions"
GEMINI_API_URL    = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={key}"
OPENAI_DEFAULT    = "gpt-4o"
GEMINI_DEFAULT    = "gemini-2.5-flash"

SYSTEM_PROMPT = """## ═══════════════════════════════════════════════
## PACTGUARD — PRODUCTION-GRADE SECURITY ANALYZER
## ═══════════════════════════════════════════════
You are a production-grade Pact smart contract security analyzer.
Your analysis MUST prioritize execution correctness over pattern detection.

--------------------------------------------------
🚨 CRITICAL OVERRIDE RULE
--------------------------------------------------
If there is ANY conflict between pattern-based detection and execution-path reasoning → ALWAYS trust execution-path reasoning.

--------------------------------------------------
1. FULL CALL GRAPH CONSTRUCTION (MANDATORY)
--------------------------------------------------
Before analyzing vulnerabilities:
- Build a complete call graph of all functions. Identify:
  - ENTRY POINTS (externally callable functions)
  - INTERNAL functions (only called by other functions)
- Trace ALL paths from ENTRY POINTS to that function.
- NEVER analyze a function in isolation.

--------------------------------------------------
2. ENTRY POINT & REACHABILITY VALIDATION
--------------------------------------------------
IF function is ENTRY POINT: It MUST enforce its own authorization.
IF function is INTERNAL: Evaluate ALL call paths.
  IF ALL paths enforce authorization BEFORE state mutation → Mark as SAFE (Indirect Authorization) → DO NOT flag.
  IF ANY path allows unauthorized state mutation → FLAG vulnerability.

--------------------------------------------------
3. PATH-SENSITIVE EXECUTION (STRICT)
--------------------------------------------------
For any conditional structure (if, enforce-one, branching):
- SPLIT into independent execution paths. Treat EACH path as a separate execution.
- Check does state mutation occur? Is authorization enforced BEFORE mutation?
- If ANY path allows unauthorized mutation → FLAG vulnerability.
- DO NOT merge branch results or assume safety from another branch.

--------------------------------------------------
4. STATE MUTATION SECURITY RULE
--------------------------------------------------
For every state-changing operation (update, insert, write), verify authorization exists BEFORE mutation and is non-trivial and enforceable.

--------------------------------------------------
5. TOCTOU DETECTION (TEMPORAL ANALYSIS)
--------------------------------------------------
Detect: A value is read and validated (enforce), then re-read later during mutation.
- If value is re-fetched instead of safely reused → FLAG TOCTOU vulnerability.
- Severity: HIGH → financial/state-critical, MEDIUM → otherwise.

--------------------------------------------------
6. CAPABILITY VALIDATION (SEMANTIC)
--------------------------------------------------
For each defcap: Ensure it is NOT trivial (e.g. returns true, no enforcements). If trivial, FLAG CRITICAL vulnerability.

--------------------------------------------------
7. FALSE POSITIVE ELIMINATION (MANDATORY)
--------------------------------------------------
Before reporting ANY issue, validate reachability: Is the function actually exploitable?
If function is INTERNAL and ALL callers enforce authorization → DO NOT flag. Mark as INFO: Indirect Authorization.
If uncertainty exists: Reduce severity and state assumptions.

--------------------------------------------------
8. EXPLOITABILITY REQUIREMENT
--------------------------------------------------
Only report vulnerabilities if there exists a realistic execution path and an attacker can trigger it.

--------------------------------------------------
9. OUTPUT ENFORCEMENT
--------------------------------------------------
Each finding MUST output the provided metadata schema.

--------------------------------------------------
10. PRIORITY RULES
--------------------------------------------------
Always follow this order:
1. Execution path correctness. 2. Reachability validation. 3. Exploitability. 4. Pattern detection.

You are NOT a pattern matcher. You are an execution-aware smart contract auditor. Never miss conditional bypasses or TOCTOU. Never over-flag safe wrapper functions.
"""

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
      "entry_point": "<YES or NO>",
      "reachability": "<ENTRY_POINT | INTERNAL_SAFE | INTERNAL_UNSAFE>",
      "vulnerable_path": "<Exact branch or call chain>",
      "exploit_scenario": "<How attacker triggers issue>",
      "severity_justification": "<Why this severity applies>",
      "confidence_level": "<HIGH | MEDIUM | LOW>",
      "fixed_code": "<complete runnable Pact code using ACTUAL table/function names>"
    }}
  ]
}}"""


def detect_provider(api_key=None, openai_key=None, gemini_key=None, force=None):
    """Returns (provider, key, model). Priority: openai → gemini → none."""
    # Single key auto-detect
    if api_key:
        if api_key.startswith("AIza"):
            return ("gemini", api_key, GEMINI_DEFAULT)
        return ("openai", api_key, OPENAI_DEFAULT)

    okey = openai_key    or os.environ.get("OPENAI_API_KEY",    "")
    akey = gemini_key or os.environ.get("GEMINI_API_KEY", "")

    if force == "openai":
        return ("openai", okey, OPENAI_DEFAULT) if okey else ("none", "", "")
    if force == "gemini":
        return ("gemini", akey, GEMINI_DEFAULT) if akey else ("none", "", "")

    if okey:  return ("openai",    okey, OPENAI_DEFAULT)
    if akey:  return ("gemini", akey, GEMINI_DEFAULT)
    return ("none", "", "")


class AIAnalyzer:
    """Multi-provider AI analyzer. Supports OpenAI and Gemini."""

    def __init__(self, api_key=None, openai_key=None, gemini_key=None,
                 provider=None, model=None):
        self.provider, self.api_key, detected_model = detect_provider(
            api_key=api_key, openai_key=openai_key, gemini_key=gemini_key, force=provider)
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
        except urllib.error.HTTPError as e:
            try:
                body = e.read().decode()
                print(f"[AI Analyzer HTTP Error] {e.code}: {body}")
            except:
                pass
            return {"error": str(e), "enriched_findings": []}
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
        return self._call_gemini(prompt, timeout)

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

    def _call_gemini(self, prompt: str, timeout: int) -> str:
        url = GEMINI_API_URL.format(model=self.model, key=self.api_key)
        payload = {
            "systemInstruction": {
                "parts": [{"text": SYSTEM_PROMPT}]
            },
            "contents": [{
                "parts": [{"text": prompt}]
            }],
            "generationConfig": {
                "temperature": 0.2,
                "responseMimeType": "application/json"
            }
        }
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read())
        print(f"Gemini Finish Reason: {data['candidates'][0].get('finishReason')}")
        return data["candidates"][0]["content"]["parts"][0]["text"]

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
