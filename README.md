# 🛡️ Pact Sentinel

**AI-powered security analyzer for Kadena Pact smart contracts.**

Static analysis + AI reasoning + structured findings for production Pact contracts.

```
╔══════════════════════════════════════════════════════════════╗
║                     PACT SENTINEL v1.0                       ║
║          Smart Contract Security Analyzer — Kadena           ║
╚══════════════════════════════════════════════════════════════╝
```

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         INPUT LAYER                             │
│   CLI (cli.py)  ·  Web UI (web_app.py)  ·  Python API          │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                    PACT PARSER (src/parser/)                     │
│                                                                 │
│   Tokenizer  →  Recursive Descent Parser  →  AST               │
│                                                                 │
│   Nodes: ModuleNode · FunctionNode · ASTNode                    │
│   Tracks: capabilities · guards · mutations · enforcements      │
└──────────────────────────────┬──────────────────────────────────┘
                               │  ContractFile AST
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                   RULE ENGINE (src/rules/)                      │
│                                                                 │
│   R-001  State Mutation Without Capability Guard   [CRITICAL]   │
│   R-002  Overly Broad Capability Scope             [MEDIUM]     │
│   R-003  Hardcoded Admin Keyset                    [HIGH]       │
│   R-004  Public Function Mutates Sensitive State   [HIGH]       │
│   R-005  Capability Missing Authorization          [CRITICAL]   │
│   R-006  CEI Violation (state before auth)         [HIGH]       │
│   R-007  Unguarded Administrative Function         [CRITICAL]   │
│   R-008  Unsafe defpact Step Logic                 [HIGH]       │
│   R-009  Weak Guard Construction                   [HIGH]       │
│   R-010  Unprotected Table Initialization          [MEDIUM]     │
│   R-011  Capability Composition Re-entrancy        [MEDIUM]     │
│   R-012  Transfer Cap Missing @managed             [HIGH]       │
└──────────────────────────────┬──────────────────────────────────┘
                               │  List[Finding]
                               ▼
┌──────────────────────────────────────┐    ┌──────────────────────┐
│   RISK SCORER (src/output/)          │    │  AI LAYER (src/ai/)  │
│                                      │    │                      │
│   Severity weights + compound risk   │    │  Claude API          │
│   A+ → F- letter grade              │    │  - Deep explanation  │
│   0-100 security score               │    │  - Attack scenario   │
└──────────────────────┬───────────────┘    │  - Fixed code        │
                       │                    └──────────┬───────────┘
                       └──────────────┬────────────────┘
                                      ▼
┌─────────────────────────────────────────────────────────────────┐
│                      REPORTER (src/output/)                     │
│                                                                 │
│   JSON ·  CLI (ANSI color)  ·  Markdown  ·  SARIF 2.1          │
└─────────────────────────────────────────────────────────────────┘
                               │
                    ┌──────────┼──────────┐
                    ▼          ▼          ▼
               Terminal   PR Comment  GitHub
                          (Markdown)  Code Scan
                                      (SARIF)
```

---

## ⚡ Quick Start

### Prerequisites
- Python 3.9+
- No external dependencies for core analysis

### 1. Clone & run

```bash
git clone https://github.com/your-org/pact-sentinel
cd pact-sentinel

# No pip install needed for core! (stdlib only)
# Optional: pip install flask rich  (for web UI and enhanced output)

# Analyze a contract
python cli.py tests/vulnerable-defi.pact

# Output JSON
python cli.py tests/vulnerable-defi.pact --format json

# Web UI
python web_app.py
# → Open http://localhost:8080
```

### 2. With AI enrichment

```bash
export ANTHROPIC_API_KEY=sk-ant-api03-...
python cli.py mytoken.pact
```

### 3. Analyze a directory

```bash
python cli.py --dir ./contracts --format json -o report.json
```

---

## 🖥️ CLI Reference

```
usage: pact-sentinel [-h] [--dir DIRECTORY] [--format {cli,json,markdown,sarif}]
                     [--output FILE] [--severity LEVEL] [--tags TAGS]
                     [--skip-rules RULES] [--no-ai] [--api-key KEY]
                     [--exit-code] [--fail-on {critical,high,medium,low}]
                     [--confidence THRESHOLD] [--no-color] [--list-rules]
                     [file]

Options:
  file                  Path to .pact file or '-' for stdin
  --dir, -d             Analyze all .pact files in directory
  --format, -f          Output: cli | json | markdown | sarif
  --output, -o          Write output to file
  --severity, -s        Filter: critical,high,medium,low
  --no-ai               Skip AI enrichment (faster, no API key needed)
  --api-key             Anthropic API key (or ANTHROPIC_API_KEY env var)
  --exit-code           Non-zero exit if findings >= threshold (CI mode)
  --fail-on             Minimum severity to fail: critical|high|medium|low
  --confidence          Min confidence score 0.0-1.0 (default: 0.5)
  --skip-rules          Comma-separated rule IDs to skip
  --list-rules          Print all available rules and exit
```

---

## 📋 Detection Rules

| ID | Severity | Title | Tags |
|----|----------|-------|------|
| R-001 | 🔴 CRITICAL | State Mutation Without Capability Guard | access-control, capability |
| R-002 | 🟡 MEDIUM | Overly Broad Capability Scope | capability, least-privilege |
| R-003 | 🟠 HIGH | Hardcoded Admin Keyset | keyset, hardcoded |
| R-004 | 🟠 HIGH | Public Function Modifies Sensitive State | access-control, DeFi |
| R-005 | 🔴 CRITICAL | Capability Missing Authorization | capability, enforce |
| R-006 | 🟠 HIGH | CEI Violation (state before auth) | reentrancy, ordering |
| R-007 | 🔴 CRITICAL | Unguarded Administrative Function | admin, governance |
| R-008 | 🟠 HIGH | Unsafe defpact Step Logic | defpact, cross-chain |
| R-009 | 🟠 HIGH | Weak Guard Construction | guard, authentication |
| R-010 | 🟡 MEDIUM | Unprotected Table Initialization | deployment, race-condition |
| R-011 | 🟡 MEDIUM | Capability Composition Re-entrancy | reentrancy, compose |
| R-012 | 🟠 HIGH | Transfer Cap Missing @managed | double-spend, DeFi |

---

## 📤 Output Example

```json
{
  "schema_version": "1.0",
  "tool": "pact-sentinel",
  "risk_score": {
    "security_score": 0.0,
    "letter_grade": "F-",
    "label": "Severely Vulnerable",
    "breakdown": { "critical": 12, "high": 8, "medium": 2, "low": 0 }
  },
  "summary": "22 findings detected...",
  "findings": [
    {
      "id": "F-001",
      "rule_id": "R-005",
      "title": "Capability Missing Authorization Enforcement",
      "severity": "critical",
      "location": { "module": "my-token", "function": "TRANSFER", "line": 25 },
      "issue": "...",
      "risk": "...",
      "recommendation": "...",
      "fixed_code_example": "..."
    }
  ]
}
```

---

## 🔄 CI/CD Integration

### GitHub Actions

The included workflow (`.github/workflows/pact-sentinel.yml`):
- ✅ Runs on every PR touching `.pact` files
- ✅ Uploads SARIF to GitHub Code Scanning
- ✅ Posts findings as PR comments
- ✅ Fails build on high/critical findings
- ✅ AI enrichment on main branch merges

```yaml
# Minimal GitHub Actions setup
- name: Run Pact Sentinel
  run: |
    python cli.py --dir contracts \
      --format sarif --output results.sarif \
      --exit-code --fail-on high

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

### Pre-commit hook

```bash
# .git/hooks/pre-commit
#!/bin/bash
PACT_FILES=$(git diff --cached --name-only | grep '\.pact$')
if [ -n "$PACT_FILES" ]; then
    for file in $PACT_FILES; do
        python /path/to/cli.py "$file" --exit-code --fail-on critical --no-ai
        if [ $? -ne 0 ]; then
            echo "❌ Pact Sentinel: Critical vulnerabilities in $file"
            exit 1
        fi
    done
fi
```

---

## 🧩 Extending — Adding Custom Rules

```python
# src/rules/custom_rules.py
from src.rules.rule_engine import BaseRule, Finding, Severity, Location

class R013_MyCustomRule(BaseRule):
    rule_id = "R-013"
    title = "My Custom Check"
    severity = Severity.MEDIUM
    tags = ["custom", "my-project"]

    def analyze(self, contract):
        findings = []
        for mod in contract.modules:
            for fn_name, fn in mod.functions.items():
                # Your logic here
                if "dangerous-pattern" in fn.name:
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=self.severity,
                        location=self._loc(mod.name, fn),
                        issue=f"Found dangerous pattern in {fn_name}",
                        risk="...",
                        recommendation="...",
                    ))
        return findings

# Register it
from src.rules.rule_engine import ALL_RULES
ALL_RULES.append(R013_MyCustomRule())
```

---

## 🔌 VSCode Extension

```bash
cd vscode-extension
npm install
npm run compile
# Press F5 in VSCode to launch Extension Development Host
```

**Features:**
- Inline red squiggles on vulnerable lines
- Hover to see finding details
- Auto-analyze on save
- Status bar with security grade
- Report panel with all findings

---

## 📊 Risk Scoring

| Grade | Score | Label |
|-------|-------|-------|
| A+ | 97-100 | Excellent |
| A | 90-96 | Very Good |
| B | 80-89 | Good |
| C | 70-79 | Moderate Risk |
| D | 55-69 | High Risk |
| F | 35-54 | Critical Risk |
| F- | 0-34 | Severely Vulnerable |

Compound multipliers apply when related vulnerability patterns co-occur (e.g., CEI violations + reentrancy patterns = 1.5× multiplier).

---

## 🗂️ Project Structure

```
pact-sentinel/
├── cli.py                      # CLI entry point
├── web_app.py                  # Flask web server
├── requirements.txt
├── src/
│   ├── parser/
│   │   ├── ast_nodes.py        # AST node definitions
│   │   └── pact_parser.py      # Recursive descent parser
│   ├── rules/
│   │   └── rule_engine.py      # 12 detection rules
│   ├── ai/
│   │   └── claude_analyzer.py  # Claude API integration
│   ├── output/
│   │   ├── risk_score.py       # Scoring system
│   │   └── reporter.py         # JSON/MD/SARIF/CLI output
│   └── core/
│       └── analyzer.py         # Orchestrator
├── web/
│   └── index.html              # Web UI SPA
├── vscode-extension/           # VSCode plugin
│   ├── package.json
│   └── src/extension.ts
├── tests/
│   └── vulnerable-defi.pact    # Test contract (22 findings)
└── .github/
    └── workflows/
        └── pact-sentinel.yml   # CI/CD workflow
```

---

## 📜 License

MIT © 2024 Pact Sentinel

---

*Built with ❤️ for the Kadena ecosystem.*
