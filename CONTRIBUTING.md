# Contributing to PactGuard

Thank you for your interest in contributing! This document covers how to add rules, fix bugs, or improve the tool.

## Quick Start

```bash
git clone https://github.com/sunilblinkoninfra-cyber/pact-guard.git
cd pact-guard
python -m pytest tests/ -v
python cli.py tests/contracts/vulnerable-defi.pact --no-ai
```

No pip install needed — zero mandatory dependencies.

## Adding a New Detection Rule

Rules live in `src/rules/rule_engine.py`. Each rule is a Python class:

```python
class R013_YourNewRule(BaseRule):
    rule_id = "R-013"
    title = "Your Rule Title"
    severity = Severity.HIGH      # critical | high | medium | low
    tags = ["your-tag", "pact"]   # searchable tags

    def analyze(self, contract: ContractFile) -> List[Finding]:
        findings = []
        for mod in contract.modules:
            for fn_name, fn in mod.functions.items():
                # Your detection logic here
                if <vulnerable_condition>:
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=self.severity,
                        location=self._loc(mod.name, fn),
                        issue="What is wrong and where",
                        risk="Why this is dangerous",
                        recommendation="How to fix it",
                        fixed_code_example="(defun safe-version ...)",
                        tags=self.tags,
                    ))
        return findings

# Register at bottom of file:
ALL_RULES.append(R013_YourNewRule())
```

## AST Reference

Key node types available during analysis:

| Node | Description |
|------|-------------|
| `fn.state_mutations` | List of write/update/insert/delete nodes |
| `fn.capability_guards` | Capabilities acquired via `with-capability` |
| `fn.capabilities_required` | `require-capability` calls |
| `fn.enforcements` | `enforce` / `enforce-guard` calls |
| `fn.body` | Raw list of body AST nodes |
| `fn.visibility` | `Visibility.PUBLIC` or `Visibility.PRIVATE` |
| `mod.capabilities` | Dict of `defcap` nodes |
| `mod.tables` | Dict of `deftable` nodes |

## Pull Request Guidelines

1. One rule per PR
2. Include a test `.pact` file that triggers the rule
3. Add the rule to the table in `README.md`
4. Update `CHANGELOG.md` under `[Unreleased]`
5. Run `python -m pytest tests/` — all tests must pass

## Code Style

- Python 3.9+ compatible (no walrus operator, no 3.10+ match)
- Type hints on all public functions
- Docstrings on all classes
- No external dependencies in `src/` (stdlib only)

## Reporting Vulnerabilities in PactGuard Itself

Open a GitHub Issue with the `security` label. Do not disclose publicly before a fix is available.
