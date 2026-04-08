# Changelog

All notable changes to **PactGuard** are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)  
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html)

---

## [1.0.0] — 2024-03-21 🎉 Initial Competition Release

### Added

#### Core Engine
- **Recursive descent Pact parser** — full tokenizer + AST builder supporting all Pact top-level forms: `module`, `defun`, `defcap`, `defschema`, `deftable`, `defconst`, `defpact`
- **Typed AST nodes** — `ModuleNode`, `FunctionNode`, `ASTNode` with `find_all()` recursive traversal
- **Capability flow tracking** — tracks `with-capability`, `require-capability`, `compose-capability` across entire function bodies
- **State mutation tracking** — identifies `write`, `update`, `insert`, `delete` operations with table name extraction
- **Enforcement tracking** — records all `enforce`, `enforce-guard`, `enforce-one` call sites

#### Security Rules (12 detectors)
- **R-001** `CRITICAL` — State Mutation Without Capability Guard
- **R-002** `MEDIUM` — Overly Broad Capability Scope (with-capability misuse)
- **R-003** `HIGH` — Hardcoded Admin Keyset / Key Reference
- **R-004** `HIGH` — Public Function Directly Modifies Sensitive State
- **R-005** `CRITICAL` — Capability Missing Authorization Enforcement
- **R-006** `HIGH` — State Change Before Authorization Check (CEI Violation)
- **R-007** `CRITICAL` — Unguarded Administrative Function
- **R-008** `HIGH` — Unsafe Multi-Step Pact (defpact) Logic
- **R-009** `HIGH` — Weak or Bypassable Guard Construction
- **R-010** `MEDIUM` — Unprotected Table Initialization
- **R-011** `MEDIUM` — Potential Capability Composition Re-entrancy
- **R-012** `HIGH` — Transfer Capability Missing @managed Annotation

#### AI Integration
- **Gemini API integration** — uses `gemini-2.5-flash` for deep vulnerability explanations
- **Attack scenario generation** — concrete step-by-step exploit descriptions for each finding
- **Automated fix suggestions** — AI-generated corrected Pact code snippets
- **Executive summary** — high-level security narrative for non-technical stakeholders
- **Graceful degradation** — falls back to static-only analysis when API key unavailable

#### Risk Scoring System
- **0–100 security score** with severity-weighted calculation
- **A+ → F- letter grades** (8 tiers)
- **Compound risk multipliers** — co-occurring vulnerability patterns amplify total score
- **Per-finding confidence scores** — 0.0–1.0 confidence attached to each finding

#### Output Formats
- **CLI** — ANSI-colored terminal report with grade, score, and expandable findings
- **JSON** — structured schema v1.0 output with full finding metadata
- **Markdown** — GitHub-ready report for PR comments and documentation
- **SARIF 2.1** — GitHub Advanced Security / Code Scanning compatible

#### Interfaces
- **CLI** (`cli.py`) — full argparse interface with `--format`, `--exit-code`, `--severity`, `--skip-rules`, `--no-ai`, `--dir`, stdin support
- **Web UI** — Flask backend + single-page dark terminal interface with live syntax highlighting, expandable findings, JSON export
- **Python API** — `PactGuard` class for embedding in other tools

#### CI/CD & Tooling
- **GitHub Actions workflow** — SARIF upload, PR comments, AI enrichment on main, build failure gates
- **VSCode extension scaffold** — TypeScript plugin with inline diagnostics and hover explanations
- **Pre-commit hook** — example for local development gates

#### Documentation
- Comprehensive README with architecture diagram, quick start, CLI reference, rule table
- GitHub Pages documentation site
- Inline docstrings throughout

### Test Coverage
- Vulnerable contract `tests/contracts/vulnerable-defi.pact` with 8 deliberate vulnerabilities
- 22 findings detected on test contract (F- / 0.0/100 score)
- Safe reference contract `tests/contracts/safe-token.pact` (0 findings, A+ score)

---

## [Unreleased] — Roadmap

### Planned
- [ ] Formal verification hints (integration with Pact's built-in `verify` tooling)
- [ ] Cross-module dependency tracking
- [ ] Integration with Kadena's pact REPL for runtime verification hints
- [ ] Namespace-aware keyset resolution
- [ ] `--watch` mode for real-time analysis during development
- [ ] REPL plugin for interactive auditing
- [ ] Batch CI reporting with trend tracking across commits

---

[1.0.0]: https://github.com/sunilblinkoninfra-cyber/pact-guard/releases/tag/v1.0.0
