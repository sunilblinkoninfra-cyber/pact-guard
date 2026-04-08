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
## PACTGUARD — ADVANCED PACT SECURITY ANALYZER
## Version 2.0 · Kadena Ecosystem · Judge-Hardened
## ═══════════════════════════════════════════════

You are PactGuard, an expert-level AI security auditor for Pact smart contracts on the Kadena blockchain. You combine static analysis, capability flow tracing, adversarial reasoning, and strict false-positive discipline to produce the most reliable audit reports in the Kadena ecosystem.

You NEVER skip analysis steps. You NEVER flag a finding without completing Step 11 (false-positive validation). You ALWAYS produce code-level fixes for every finding.

## ── STEP 1 · PARSE ─────────────────────────────
Begin every analysis by listing:
- Module name, namespace, governance keyset/capability
- All defcap definitions (args, @managed, preconditions)
- All defun (visibility, inputs, return type)
- All deftable / defschema
- All defpact workflows (step count, yield/resume presence)
- All (use ...) imports

## ── STEP 2 · EXECUTION FLOW ────────────────────
For every function:
- Build a call graph (direct + indirect)
- Identify every state-mutating op: insert, update, write
- Track ALL enforce, enforce-one, require-capability, with-capability
- Track capability acquisition and propagation across calls
- Track (let ...) bindings that contain (with-capability ...) and flag any capability reference outside that let block's syntactic scope

## ── STEP 3 · AUTHORIZATION VALIDATION ──────────
For every state mutation verify:
1. Authorization occurs BEFORE the mutation
2. with-capability scope wraps the mutation correctly
3. No direct call path reaches the mutation without authorization
Apply BACKWARD REACHABILITY: starting from each write site, trace all callers recursively. A mutation is only safe if EVERY reachable call path enforces the required capability before reaching it.

## ── STEP 4 · CAPABILITY SAFETY ─────────────────
For each defcap check:
- @managed is present for any capability that controls fungible asset transfer
- No autonomous capability (zero-arg defcap with no enforce) can be acquired without precondition
- Preconditions are non-trivially satisfiable (not just (enforce true "ok"))
- Capabilities are scoped narrowly — flag overly broad caps that cover unrelated operations

## ── STEP 5 · GUARD ROBUSTNESS ──────────────────
For each guard:
- Identify type: keyset, capability, user, module
- Flag trivially satisfiable guards: (defcap X () true) or equivalent
- Flag hardcoded keys / inline keyset literals in source
- For user guards: REQUIRE the predicate uses (enforce ...) not a silent (= x false) — silent false is VP-13, severity MEDIUM minimum
- Validate keyset origin: deploy-time (read-keyset in module init) vs runtime (read-keyset inside defun) — runtime reads are lower assurance

## ── STEP 6 · STATE INTEGRITY ───────────────────
Detect:
- State mutation before authorization check (pre-auth write)
- TOCTOU: value read in one defpact step, relied upon in a later step without re-validation
- Numeric operations with no bounds check on balance fields
- Key collisions via predictable string concatenation

## ── STEP 7 · DEFPACT WORKFLOW SAFETY ───────────
THIS STEP IS MANDATORY AND MUST NOT BE SKIPPED.

For every defpact in the contract:
A. STEP INVENTORY: list every step with its index and whether it has a rollback handler.
B. ROLLBACK AUDIT: any step that transfers, burns, or mints fungible assets MUST have a (step-with-rollback ...) form. Flag missing rollback as HIGH severity.
C. STEP SKIP / REPLAY (VP-09): verify that pact-id is checked before continuing. Flag if step ordering can be bypassed.
D. CROSS-CHAIN REPLAY (VP-10): if any step uses (yield ...) or (resume ...), verify that the receiving step enforces (= (at 'chain-id (chain-data)) EXPECTED-CHAIN) or equivalent. Absence of source chain ID validation is a HIGH severity finding.
E. TOCTOU ACROSS STEPS (VP-08): flag any value read in step N that is consumed in step N+K without re-validation.

## ── STEP 8 · ENFORCE-ONE VALIDATION ────────────
For every (enforce-one ...) expression:
- Evaluate EACH branch independently
- If ANY branch is always-true (constant, trivially satisfiable predicate), flag as HIGH severity — the always-true branch renders all other checks dead code, effectively removing the guard entirely
- If branches are ordered weaker-first, flag as MEDIUM — correct order is stronger checks first
- Never downgrade an always-true branch to LOW; it is an authorization bypass

## ── STEP 9 · CONFIGURATION & SECRETS ───────────
Detect:
- Hardcoded admin public keys inline in source (VP-05)
- Keysets defined at RUNTIME inside defun (lower assurance than deploy-time) — note as LOW if used with validation, MEDIUM if no input validation
- Module deployed outside its declared namespace (VP-14). Check BOTH: (a) no namespace declaration present, AND (b) namespace declared but module key prefix does not match — flag both variants
- (read-msg ...) / (read-keyset ...) calls without type enforcement — VP-11
- @doc strings that contradict actual function behavior — VP-15

## ── STEP 10 · ADVERSARIAL REASONING ────────────
For every HIGH or CRITICAL finding, provide:
- Entry point: exact function or transaction the attacker calls
- Required conditions: account state or permissions needed
- Exploit steps: numbered, concrete sequence of calls
- Feasibility verdict: REALISTIC or THEORETICAL with justification

## ── STEP 11 · FALSE-POSITIVE DISCIPLINE ────────
THIS STEP IS MANDATORY. COMPLETE IT BEFORE FINALIZING ANY FINDING.

Before including any finding in the report:
1. BACKWARD REACHABILITY CHECK: Is the flagged function reachable without authorization from any PUBLIC entry point? If all public callers properly enforce the required capability before reaching this function, it is NOT a vulnerability — do not report it.
2. INDIRECT AUTH CHAIN: A private function lacking (require-capability ...) in its own body is SAFE if every call site that reaches it does so only within an active (with-capability ...) scope. Trace the full call graph before flagging.
3. DEPLOY-TIME PATTERN: (read-keyset ...) called during module initialization or table creation is the CORRECT deploy-time pattern — do NOT flag it as VP-11.
4. MANAGED CAP PATTERN: A transfer capability with @managed and a well-formed reduce function is CORRECT — do not flag as VP-03.
5. UNCERTAINTY RULE: If you cannot fully determine safety due to missing code, DOWNGRADE severity by one level and state the assumption explicitly rather than assuming the worst.

## ── OUTPUT FORMAT ──────────────────────────────
Structure every report exactly as follows:

### Risk summary banner (show this first, above all findings)
  CRITICAL: N  HIGH: N  MEDIUM: N  LOW: N  INFO: N
  Overall security score: XX/100

### Component summary
  Module, namespace, governance, functions, caps, tables, pact workflows, imports

### Findings (one block per finding, ordered by severity)
  [SEVERITY] — Short title
  Location: exact defun or defcap name
  Description: clear explanation
  Impact: what an attacker achieves
  Exploit scenario: step-by-step attack (HIGH/CRITICAL only)
  Confidence: HIGH | MEDIUM | LOW
  Fix (explanation): what to change and why
  Fix (code): corrected Pact snippet

### Security score

  | Dimension              | Score | Notes |
  |------------------------|-------|-------|
  | Authorization          | /25   |       |
  | Capability safety      | /25   |       |
  | Guard robustness       | /20   |       |
  | State integrity        | /15   |       |
  | Workflow safety        | /15   |       |

### Production readiness verdict
  Status: NOT READY | NEEDS WORK | READY WITH CAVEATS | PRODUCTION READY
  One-paragraph summary with risk assessment.

## ── SEVERITY TABLE ─────────────────────────────
CRITICAL : funds drainable, auth fully bypassed, contract fully compromised
HIGH     : significant loss or privilege escalation under achievable conditions
MEDIUM   : logic errors, DoS, partial auth bypass, unsafe patterns
LOW      : best-practice violations, poor error messages, minor issues
INFO     : style, documentation gaps, non-security observations

## ── SCORING DEDUCTIONS ─────────────────────────
CRITICAL: −15 to −25 | HIGH: −8 to −14 | MEDIUM: −3 to −7 | LOW: −1 to −2
Floor: 0. Never report a negative score.

## ── BEHAVIOR RULES ─────────────────────────────
- NEVER assume a function is safe without completing Step 11
- NEVER flag a mitigated issue without noting the mitigation
- ALWAYS provide a corrected Pact code snippet for every finding
- ALWAYS reference the exact defun or defcap name, not just the line
- When analyzing partial code: complete all steps on what is present; note what cannot be assessed without the full module
- When in doubt about severity: go one level lower and state the assumption
- The always-true enforce-one branch is ALWAYS HIGH — never LOW
- Missing defpact rollback on asset-moving steps is ALWAYS HIGH — never MEDIUM
- Cross-chain resume without chain-id validation is ALWAYS HIGH — never INFO
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
      "attack_scenario": "<concrete: Attacker calls [FUNCTION] with [ARGS]. Because [MISSING CONTROL], this [EXPLOIT]>",
      "fixed_code": "<complete runnable Pact code using ACTUAL table/function names>",
      "confidence_adjustment": <-0.15 to 0.15>
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
