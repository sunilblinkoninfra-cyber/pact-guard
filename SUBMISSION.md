# 🛡️ PactGuard — Competition Submission

## Live Demo

**→ https://sunilblinkoninfra-cyber.github.io/pact-guard**

No signup. No server. Paste your Pact contract and get results in under 5ms.

---

## What It Does

PactGuard automatically analyzes Kadena Pact smart contracts for security vulnerabilities before deployment. It combines a **real recursive-descent parser** (not regex), **12 Pact-specific detection rules**, **Gemini AI explanations**, and a **risk scoring system** into one tool.

Paste a contract. Get findings with severity, location, risk explanation, and a corrected code snippet — in under a second.

---

## Quick Start (30 seconds)

```bash
git clone https://github.com/sunilblinkoninfra-cyber/pact-guard
cd pact-guard

# Instant analysis, no setup needed
python cli.py tests/contracts/vulnerable-defi.pact --no-ai

# One-liner for CI
python cli.py contract.pact --no-ai --summary
# → F- | 0/100 | crit=12 high=9 med=2 low=0 | contract.pact

# JSON output for tooling
python cli.py contract.pact --no-ai --format json | jq .risk_score

# Web UI
pip install flask && python web_app.py
```

---

## Detection Coverage

All 7 vulnerability categories from the problem statement:

| Category | Rules | Example detection |
|----------|-------|-------------------|
| Missing capability checks | R-001, R-005 | Empty `defcap` body; unguarded `update` |
| Weak guard logic | R-003, R-009 | `define-keyset 'admin "admin"` |
| State before auth | R-006 | `update` before `enforce` in same function |
| Unsafe enforcement | R-005, R-007 | `defcap` with no `enforce-guard` |
| Multi-step pact | R-008 | `defpact` with mutations and no capability guards |
| Public modifying state | R-004 | `transfer()` mutates `accounts` without `TRANSFER` cap |
| Hardcoded keys | R-003 | Module governed by bare `'admin` string |

**Bonus rules:**
- **R-012** — `TRANSFER` cap missing `@managed` (enables double-spend)
- **R-011** — Circular `compose-capability` chains
- **R-010** — Init race condition (front-running at deployment)

---

## Test Results

```
vulnerable-defi.pact  → Grade: F-  Score: 0.0/100   Findings: 23 (12 crit, 9 high, 2 med)
safe-token.pact       → Grade: A+  Score: 100.0/100  Findings: 0
Kadena coin contract  → Grade: A+  Score: 100.0/100  Findings: 0  (zero false positives)
```

---

## Architecture

```
Pact source → Tokenizer → Recursive Descent Parser → Typed AST
                                                          │
                                              12 Rule Classes (BaseRule)
                                                          │
                                         Risk Scorer (compound multipliers)
                                                          │
                                         Gemini API (context-specific AI)
                                                          │
                          CLI · Web UI · JSON · Markdown · SARIF 2.1
```

**Zero mandatory dependencies.** Pure Python 3.9+ stdlib for the core engine.

---

## All Evaluation Criteria

### Security Coverage (30%)
- 12 rules, all Pact-specific
- Detects every vulnerability category in the problem statement
- Zero false positives on Kadena's reference coin contract

### Technical Quality (25%)
- Real recursive-descent parser with typed AST (`ModuleNode`, `FunctionNode`)
- `BaseRule` interface — new rules in ~20 lines
- 39 unit tests, all passing
- SARIF 2.1 output for GitHub Code Scanning

### AI Integration Quality (20%)
- Gemini API with context-specific prompts that reference actual function/table names
- `ai_explanation`, `attack_scenario`, `fixed_code` per finding
- Graceful fallback when no API key

### Usability (15%)
- `python cli.py contract.pact` — works in 30 seconds, zero config
- Live GitHub Pages demo at the URL above
- `--summary` flag for shell scripting
- Drag-and-drop .pact files onto the web UI
- Multiple output formats: CLI, JSON, Markdown, SARIF

### Innovation (10%)
- **Compound risk multipliers** — 1.5× when CEI + reentrancy co-occur
- **Serverless analysis backend** — GitHub Actions API triggered from browser
- **6 CI co-worker agents** — regression, documentation, versioning, pre-release, security, nightly
- **VSCode extension scaffold** — inline squiggles and hover explanations
- **Automated fix suggestions** — syntactically-correct Pact patches per finding

---

## Bonus Features

- ✅ Capability guard misuse detection (R-002, R-009)
- ✅ Risk scoring system (A+ to F-, compound multipliers)
- ✅ Automated patch recommendations (`fixed_code_example` on every finding)
- ⚡ Formal verification hints in recommendations

---

## Repository

https://github.com/sunilblinkoninfra-cyber/pact-guard
