# 🛡️ PactGuard

<div align="center">

![Version](https://img.shields.io/badge/version-1.0.0-blue?style=flat-square)
[![Tests](https://img.shields.io/github/actions/workflow/status/sunilblinkoninfra-cyber/pact-guard/repo-setup.yml?branch=main&label=tests&style=flat-square)](https://github.com/sunilblinkoninfra-cyber/pact-guard/actions)
[![License](https://img.shields.io/github/license/sunilblinkoninfra-cyber/pact-guard?style=flat-square)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-yellow?style=flat-square)](https://python.org)
[![Zero Deps](https://img.shields.io/badge/dependencies-zero-brightgreen?style=flat-square)](pyproject.toml)
[![Rules](https://img.shields.io/badge/detection_rules-12-red?style=flat-square)](src/rules/rule_engine.py)

**AI-powered security analyzer for Kadena Pact smart contracts.**

Combines recursive descent static analysis with Gemini AI to detect vulnerabilities, explain risks, and suggest fixes.

[📖 Docs](https://sunilblinkoninfra-cyber.github.io/pact-guard) · [🚀 Releases](https://github.com/sunilblinkoninfra-cyber/pact-guard/releases) · [🐛 Issues](https://github.com/sunilblinkoninfra-cyber/pact-guard/issues)

</div>

---

## Overview

PactGuard builds a typed AST from your contract, tracks capability flows, identifies vulnerability patterns, then uses Gemini AI to explain exactly why something is dangerous and how to fix it — all in under a second.

```
$ python cli.py tests/contracts/vulnerable-defi.pact --no-ai

  Security Score: 0.0/100   Grade: F-   (Severely Vulnerable)
  Findings: 12 critical  8 high  2 medium  0 low

  🔴 [F-001] Capability Missing Authorization Enforcement         CRITICAL
     Location: vulnerable-defi-token::TRANSFER (line 25)
     Issue: Capability `TRANSFER` has an empty body — grants access to anyone.

  🟠 [F-006] State Change Before Authorization Check (CEI)        HIGH
     Location: vulnerable-defi-token::transfer (line 58)
     Issue: State mutation at line 58 occurs BEFORE enforce at line 61.

  🔴 [F-007] Unguarded Administrative Function                   CRITICAL
     Location: vulnerable-defi-token::init (line 42)
     Issue: `init` lacks any capability guard — callable by any account.
  ...
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        INPUT LAYER                              │
│       CLI · Web UI (Flask) · Python API · stdin/file/dir        │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                PACT PARSER  (src/parser/)                        │
│   Tokenizer → Recursive Descent Parser → Typed AST              │
│   Tracks: capabilities · guards · mutations · enforcements      │
└──────────────────────────────┬──────────────────────────────────┘
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│               RULE ENGINE  (src/rules/)  — 12 rules             │
│   R-001 CRITICAL  Mutation without capability guard             │
│   R-005 CRITICAL  Empty capability body                         │
│   R-006 HIGH      CEI violation (state before auth)             │
│   R-007 CRITICAL  Unguarded admin function                      │
│   R-012 HIGH      Transfer cap missing @managed   … +7 more    │
└──────────┬──────────────────────────────────┬───────────────────┘
           ▼                                  ▼
┌─────────────────────┐          ┌──────────────────────────┐
│   RISK SCORER       │          │   AI LAYER (Gemini API)  │
│   0–100 score       │          │   Deep explanations      │
│   A+ → F- grades    │          │   Attack scenarios       │
│   Compound risk     │          │   Auto-fix code snippets │
└──────────┬──────────┘          └────────────┬─────────────┘
           └───────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                 REPORTER  (src/output/)                          │
│         CLI (ANSI color) · JSON · Markdown · SARIF 2.1          │
└─────────────────────────────────────────────────────────────────┘
```

---

## Quick Start

Zero mandatory dependencies — pure Python 3.9+ stdlib.

```bash
git clone https://github.com/sunilblinkoninfra-cyber/pact-guard.git
cd pact-guard

# Analyze immediately (no setup needed)
python cli.py tests/contracts/vulnerable-defi.pact --no-ai

# With Gemini AI enrichment
export GEMINI_API_KEY=AIza...
python cli.py mytoken.pact

# Output formats
python cli.py mytoken.pact --format json -o report.json
python cli.py mytoken.pact --format sarif -o results.sarif
python cli.py mytoken.pact --format markdown

# Scan a directory
python cli.py --dir ./contracts --format json

# CI mode: fail on high+ findings
python cli.py contracts/ --exit-code --fail-on high

# Web UI
pip install flask && python web_app.py  # http://localhost:8080
```

---

## Detection Rules

| ID | Severity | Title | Tags |
|----|----------|-------|------|
| R-001 | 🔴 CRITICAL | State Mutation Without Capability Guard | access-control, state-mutation |
| R-002 | 🟡 MEDIUM | Overly Broad Capability Scope | capability, least-privilege |
| R-003 | 🟠 HIGH | Hardcoded Admin Keyset Reference | keyset, hardcoded, admin |
| R-004 | 🟠 HIGH | Public Function Modifies Sensitive State | access-control, DeFi |
| R-005 | 🔴 CRITICAL | Capability Missing Authorization Enforcement | capability, enforce |
| R-006 | 🟠 HIGH | State Change Before Authorization — CEI Violation | reentrancy, ordering |
| R-007 | 🔴 CRITICAL | Unguarded Administrative Function | admin, governance |
| R-008 | 🟠 HIGH | Unsafe Multi-Step Pact Logic | defpact, cross-chain |
| R-009 | 🟠 HIGH | Weak or Bypassable Guard Construction | guard, authentication |
| R-010 | 🟡 MEDIUM | Unprotected Table Initialization | deployment |
| R-011 | 🟡 MEDIUM | Capability Composition Re-entrancy | reentrancy, compose |
| R-012 | 🟠 HIGH | Transfer Capability Missing `@managed` | double-spend, DeFi |

```bash
python cli.py --list-rules   # full table with severity + tags
```

---

## Test Results

| Contract | Findings | Grade | Score |
|----------|----------|-------|-------|
| `tests/contracts/vulnerable-defi.pact` | **22** (12 crit, 8 high, 2 med) | **F-** | 0.0 / 100 |
| `tests/contracts/safe-token.pact` | **0** | **A+** | 100.0 / 100 |

```bash
python -m pytest tests/ -v   # 39 passed in 0.29s
```

---

## Risk Scoring System

| Grade | Score | Label |
|-------|-------|-------|
| **A+** | 97–100 | Excellent |
| **A**  | 90–96  | Very Good |
| **B**  | 80–89  | Good |
| **C**  | 70–79  | Moderate Risk |
| **D**  | 55–69  | High Risk |
| **F**  | 35–54  | Critical Risk |
| **F-** | 0–34   | Severely Vulnerable |

Co-occurring vulnerabilities apply compound multipliers (up to 1.5×) to the total risk score.

---

## AI Integration

Set `GEMINI_API_KEY` and each finding gains:

- **`ai_explanation`** — technical explanation specific to your code
- **`attack_scenario`** — concrete exploit walkthrough
- **`fixed_code`** — corrected Pact code snippet
- **`ai_risk_narrative`** — executive summary

Gracefully skipped when no key is present.

---

## CLI Reference

```
python cli.py [file] [options]

  file                  .pact file, or '-' for stdin
  --dir, -d PATH        Scan directory recursively
  --format FMT          cli | json | markdown | sarif
  --output, -o FILE     Write to file
  --severity LEVEL      Filter by severity (comma-separated)
  --no-ai               Skip AI enrichment
  --exit-code           Non-zero exit if findings found
  --fail-on LEVEL       Threshold: critical|high|medium|low
  --skip-rules RULES    E.g. R-003,R-009
  --confidence FLOAT    Min confidence 0.0–1.0
  --list-rules          Print all rules
  --no-color            Disable ANSI colors
```

---

## CI/CD

```yaml
# .github/workflows/security.yml
- name: PactGuard scan
  run: |
    python cli.py --dir contracts \
      --format sarif --output results.sarif \
      --exit-code --fail-on high

- name: Upload to GitHub Code Scanning
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

---

## Project Structure

```
pact-guard/
├── cli.py                      CLI entry point
├── web_app.py                  Flask web server
├── src/
│   ├── parser/                 Tokenizer + AST builder
│   ├── rules/                  12 detection rules
│   ├── ai/                     Gemini API integration
│   ├── output/                 Risk scorer + reporters
│   └── core/                   PactGuard orchestrator
├── web/index.html              Web UI
├── docs/                       GitHub Pages site
├── tests/
│   ├── test_sentinel.py        39 unit tests
│   └── contracts/              Test .pact files
├── vscode-extension/           VSCode plugin scaffold
└── .github/workflows/          CI/CD pipelines
```

---

## Evaluation Criteria

| Criterion | Weight | Coverage |
|-----------|--------|----------|
| Security Coverage | 30% | 12 rules · accurate detection · zero false positives on safe contract |
| Technical Quality | 25% | Typed AST · BaseRule interface · 39 tests · SARIF · zero deps |
| AI Integration | 20% | Gemini explanations · attack scenarios · auto-fix code |
| Usability | 15% | CLI + Web UI + Python API · 4 output formats · CI integration |
| Innovation | 10% | Compound risk multipliers · automated patches · VSCode extension |

**Bonus:** Capability guard misuse detection ✅ · Risk scoring ✅ · Automated patches ✅

---

## License

[MIT](LICENSE) © 2024 PactGuard Contributors

---

<div align="center">Built for the Kadena Pact security competition. Star ⭐ if this helps you write safer contracts.</div>
