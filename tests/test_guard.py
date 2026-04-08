"""
PactGuard — Test Suite
Tests the parser, rule engine, and risk scorer.
Run: python -m pytest tests/ -v
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from src.parser.pact_parser import parse_contract
from src.parser.ast_nodes import NodeType
from src.rules.rule_engine import (
    ALL_RULES, RULES_BY_ID,
    R001_MissingCapabilityBeforeMutation,
    R005_MissingEnforceInCapability,
    R006_StateChangeBeforeAuth,
    R007_UnguardedAdminFunction,
    R012_MissingManagedCapability,
    Severity,
)
from src.output.risk_score import compute_risk_score
from src.core.analyzer import PactGuard


# ── Fixtures ─────────────────────────────────────────

VULNERABLE_CONTRACT = """
(module vuln-token 'admin
  (defschema account-schema balance:decimal guard:guard)
  (deftable accounts:{account-schema})

  (defcap TRANSFER (sender:string amount:decimal))

  (defun init ()
    (insert accounts "alice" {'balance: 100.0, 'guard: (read-keyset "ks")}))

  (defun transfer (sender:string receiver:string amount:decimal)
    (update accounts sender {'balance: 0.0})
    (enforce (> amount 0.0) "positive"))

  (defun admin-reset ()
    (update accounts "alice" {'balance: 0.0}))
)
"""

SAFE_CONTRACT = """
(module safe-token GOVERNANCE
  (defcap GOVERNANCE ()
    (enforce-guard (keyset-ref-guard 'ns.admin-ks)))

  (defcap TRANSFER (sender:string receiver:string amount:decimal)
    @managed amount TRANSFER-mgr
    (enforce-guard (at 'guard (read accounts sender)))
    (enforce (> amount 0.0) "positive"))

  (defun TRANSFER-mgr:decimal (m:decimal r:decimal)
    (enforce (>= m r) "exceeded") (- m r))

  (defschema account-schema balance:decimal guard:guard)
  (deftable accounts:{account-schema})

  (defun transfer (sender:string receiver:string amount:decimal)
    (enforce (!= sender receiver) "no self-transfer")
    (enforce (> amount 0.0) "positive")
    (with-capability (TRANSFER sender receiver amount)
      (with-read accounts sender {'balance := bal}
        (enforce (>= bal amount) "insufficient")
        (update accounts sender {'balance: (- bal amount)}))
      (with-read accounts receiver {'balance := recv-bal}
        (update accounts receiver {'balance: (+ recv-bal amount)}))))
)
"""

EMPTY_CAP_CONTRACT = """
(module empty-cap 'admin
  (deftable tokens:{object})
  (defcap MINT (account:string amount:decimal))
  (defcap BURN (account:string))
  (defun mint (account:string amount:decimal)
    (with-capability (MINT account amount)
      (insert tokens account {'amount: amount})))
)
"""

MANAGED_MISSING_CONTRACT = """
(module defi 'admin
  (deftable pool:{object})
  (defcap WITHDRAW (account:string amount:decimal)
    (enforce-guard (at 'guard (read pool account))))
  (defcap TRANSFER (from:string to:string amount:decimal)
    (enforce-guard (at 'guard (read pool from))))
  (defun withdraw (account:string amount:decimal)
    (with-capability (WITHDRAW account amount)
      (update pool account {'balance: 0.0})))
)
"""


# ── Parser tests ─────────────────────────────────────

class TestParser:
    def test_parses_module_name(self):
        c = parse_contract(VULNERABLE_CONTRACT)
        assert len(c.modules) == 1
        assert c.modules[0].name == "vuln-token"

    def test_parses_functions(self):
        c = parse_contract(VULNERABLE_CONTRACT)
        mod = c.modules[0]
        assert "transfer" in mod.functions
        assert "init" in mod.functions
        assert "admin-reset" in mod.functions

    def test_parses_capabilities(self):
        c = parse_contract(VULNERABLE_CONTRACT)
        mod = c.modules[0]
        assert "TRANSFER" in mod.capabilities

    def test_detects_state_mutations(self):
        c = parse_contract(VULNERABLE_CONTRACT)
        transfer_fn = c.modules[0].functions["transfer"]
        assert len(transfer_fn.state_mutations) > 0
        mutation_ops = [m.name for m in transfer_fn.state_mutations]
        assert "update" in mutation_ops

    def test_safe_contract_has_capability_guards(self):
        c = parse_contract(SAFE_CONTRACT)
        transfer_fn = c.modules[0].functions["transfer"]
        assert len(transfer_fn.capability_guards) > 0

    def test_safe_contract_has_managed_cap(self):
        c = parse_contract(SAFE_CONTRACT)
        transfer_cap = c.modules[0].capabilities.get("TRANSFER")
        assert transfer_cap is not None
        assert transfer_cap.managed is True

    def test_parses_enforce_calls(self):
        c = parse_contract(VULNERABLE_CONTRACT)
        transfer_fn = c.modules[0].functions["transfer"]
        assert len(transfer_fn.enforcements) > 0

    def test_empty_contract(self):
        c = parse_contract("")
        assert c.modules == []

    def test_multimodule(self):
        src = SAFE_CONTRACT + "\n" + VULNERABLE_CONTRACT
        c = parse_contract(src)
        assert len(c.modules) == 2


# ── Rule Engine tests ─────────────────────────────────

class TestR001MissingCapability:
    def setup_method(self):
        self.rule = R001_MissingCapabilityBeforeMutation()

    def test_detects_unguarded_mutation(self):
        contract = parse_contract(VULNERABLE_CONTRACT)
        findings = self.rule.analyze(contract)
        assert len(findings) > 0
        assert all(f.severity == Severity.CRITICAL for f in findings)

    def test_no_finding_on_safe_contract(self):
        contract = parse_contract(SAFE_CONTRACT)
        findings = self.rule.analyze(contract)
        assert len(findings) == 0

    def test_finding_contains_table_name(self):
        contract = parse_contract(VULNERABLE_CONTRACT)
        findings = self.rule.analyze(contract)
        # At least one finding should mention the table
        issues = " ".join(f.issue for f in findings)
        assert "accounts" in issues or "tokens" in issues or "table" in issues.lower()


class TestR005EmptyCapability:
    def setup_method(self):
        self.rule = R005_MissingEnforceInCapability()

    def test_detects_empty_cap(self):
        contract = parse_contract(EMPTY_CAP_CONTRACT)
        findings = self.rule.analyze(contract)
        cap_names = [f.location.function for f in findings]
        assert "MINT" in cap_names or "BURN" in cap_names

    def test_no_false_positive_on_safe(self):
        contract = parse_contract(SAFE_CONTRACT)
        findings = self.rule.analyze(contract)
        # GOVERNANCE and TRANSFER both have enforcements
        assert len(findings) == 0

    def test_empty_cap_severity_is_critical(self):
        contract = parse_contract(EMPTY_CAP_CONTRACT)
        findings = self.rule.analyze(contract)
        for f in findings:
            assert f.severity == Severity.CRITICAL


class TestR006CEIViolation:
    def setup_method(self):
        self.rule = R006_StateChangeBeforeAuth()

    def test_detects_mutation_before_enforce(self):
        contract = parse_contract(VULNERABLE_CONTRACT)
        findings = self.rule.analyze(contract)
        # transfer() updates before enforce
        fn_names = [f.location.function for f in findings]
        assert "transfer" in fn_names

    def test_no_violation_in_safe_contract(self):
        contract = parse_contract(SAFE_CONTRACT)
        findings = self.rule.analyze(contract)
        assert len(findings) == 0


class TestR007UnguardedAdmin:
    def setup_method(self):
        self.rule = R007_UnguardedAdminFunction()

    def test_detects_unguarded_init(self):
        contract = parse_contract(VULNERABLE_CONTRACT)
        findings = self.rule.analyze(contract)
        fn_names = [f.location.function for f in findings]
        assert "init" in fn_names or "admin-reset" in fn_names

    def test_all_critical(self):
        contract = parse_contract(VULNERABLE_CONTRACT)
        findings = self.rule.analyze(contract)
        for f in findings:
            assert f.severity == Severity.CRITICAL


class TestR012ManagedCapability:
    def setup_method(self):
        self.rule = R012_MissingManagedCapability()

    def test_detects_unmanaged_transfer(self):
        contract = parse_contract(MANAGED_MISSING_CONTRACT)
        findings = self.rule.analyze(contract)
        cap_names = [f.location.function for f in findings]
        assert "TRANSFER" in cap_names or "WITHDRAW" in cap_names

    def test_no_finding_when_managed(self):
        contract = parse_contract(SAFE_CONTRACT)
        findings = self.rule.analyze(contract)
        assert len(findings) == 0


# ── Risk Scorer tests ─────────────────────────────────

class TestRiskScorer:
    def test_no_findings_gives_perfect_score(self):
        score = compute_risk_score([])
        assert score.normalized == 100.0
        assert score.letter_grade == "A+"
        assert score.label == "Clean"

    def test_critical_findings_give_low_score(self):
        contract = parse_contract(VULNERABLE_CONTRACT)
        all_findings = []
        for rule in ALL_RULES:
            all_findings.extend(rule.analyze(contract))
        score = compute_risk_score(all_findings)
        assert score.normalized < 50.0

    def test_compound_multiplier_applied(self):
        """CEI + reentrancy tags together should increase multiplier."""
        contract = parse_contract(VULNERABLE_CONTRACT)
        all_findings = []
        for rule in ALL_RULES:
            all_findings.extend(rule.analyze(contract))
        score = compute_risk_score(all_findings)
        assert score.compound_multiplier >= 1.0

    def test_score_dict_has_required_keys(self):
        score = compute_risk_score([])
        d = score.to_dict()
        for key in ["security_score", "letter_grade", "label", "breakdown"]:
            assert key in d


# ── Full Analyzer tests ───────────────────────────────

class TestAnalyzer:
    def setup_method(self):
        self.sentinel = PactGuard(use_ai=False)

    def test_analyzes_vulnerable_contract(self):
        result = self.sentinel.analyze_source(VULNERABLE_CONTRACT)
        assert len(result.findings) > 0
        assert result.risk_score.normalized < 80.0

    def test_analyzes_safe_contract(self):
        result = self.sentinel.analyze_source(SAFE_CONTRACT)
        # Safe contract should have few or no findings
        critical = [f for f in result.findings if f.severity == Severity.CRITICAL]
        assert len(critical) == 0

    def test_json_output_valid_structure(self):
        import json
        result = self.sentinel.analyze_source(VULNERABLE_CONTRACT)
        report = json.loads(result.as_json())
        assert "findings" in report
        assert "risk_score" in report
        assert "summary" in report
        assert "schema_version" in report

    def test_each_finding_has_required_fields(self):
        result = self.sentinel.analyze_source(VULNERABLE_CONTRACT)
        for f in result.findings:
            assert f.rule_id
            assert f.title
            assert f.severity
            assert f.location.module
            assert f.issue
            assert f.risk
            assert f.recommendation

    def test_empty_source_returns_no_findings(self):
        result = self.sentinel.analyze_source("")
        assert result.findings == []

    def test_directory_analysis(self, tmp_path):
        (tmp_path / "test.pact").write_text(VULNERABLE_CONTRACT)
        (tmp_path / "safe.pact").write_text(SAFE_CONTRACT)
        results = self.sentinel.analyze_directory(tmp_path)
        assert len(results) == 2

    def test_markdown_output_contains_grade(self):
        result = self.sentinel.analyze_source(VULNERABLE_CONTRACT)
        md = result.as_markdown()
        assert "Security Score" in md
        assert "Grade" in md

    def test_sarif_output_valid(self):
        import json
        result = self.sentinel.analyze_source(VULNERABLE_CONTRACT)
        sarif = json.loads(result.as_sarif())
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) > 0


# ── Integration: vulnerable-defi.pact ────────────────

class TestVulnerableDefiContract:
    """Integration test against the real vulnerable contract fixture."""

    def setup_method(self):
        contract_path = os.path.join(
            os.path.dirname(__file__), "contracts", "vulnerable-defi.pact"
        )
        if not os.path.exists(contract_path):
            pytest.skip("vulnerable-defi.pact not found")
        self.sentinel = PactGuard(use_ai=False)
        self.result = self.sentinel.analyze_file(contract_path)

    def test_detects_multiple_findings(self):
        assert len(self.result.findings) >= 10

    def test_grade_is_f(self):
        assert self.result.risk_score.letter_grade in ("F", "F-")

    def test_finds_empty_capability(self):
        titles = [f.title for f in self.result.findings]
        assert any("Capability Missing" in t for t in titles)

    def test_finds_unguarded_admin(self):
        titles = [f.title for f in self.result.findings]
        assert any("Administrative" in t or "Admin" in t for t in titles)

    def test_finds_state_mutation(self):
        rules = [f.rule_id for f in self.result.findings]
        assert "R-001" in rules

    def test_finds_cei_violation(self):
        rules = [f.rule_id for f in self.result.findings]
        assert "R-006" in rules


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
