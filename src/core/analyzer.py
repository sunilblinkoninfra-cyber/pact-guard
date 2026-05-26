"""
Core Analyzer — PactGuard Orchestrator
Coordinates: Parser → Rule Engine → AI Enrichment → Risk Score → Reporter
"""
import time
import json
from pathlib import Path
from typing import List, Optional, Dict, Any, Union

from ..parser.pact_parser import parse_contract, parse_file
from ..parser.ast_nodes import ContractFile
from ..rules.rule_engine import Finding, get_rules, ALL_RULES
from ..ai.gemini_analyzer import AIAnalyzer
from ..output.risk_score import compute_risk_score, RiskScore
from .postprocess import apply_fp_reduction_layer
from ..output.reporter import build_json_report, render_cli, render_markdown, render_sarif


class AnalysisResult:
    def __init__(
        self,
        contract: ContractFile,
        findings: List[Finding],
        risk_score: RiskScore,
        summary: str,
        ai_enrichment: Dict[str, Any],
        report: Dict[str, Any],
        elapsed: float,
    ):
        self.contract = contract
        self.findings = findings
        self.risk_score = risk_score
        self.summary = summary
        self.ai_enrichment = ai_enrichment
        self.report = report
        self.elapsed = elapsed

    def as_json(self, indent: int = 2) -> str:
        return json.dumps(self.report, indent=indent)

    def as_cli(self, color: bool = True) -> str:
        return render_cli(self.report, color=color)

    def as_markdown(self) -> str:
        return render_markdown(self.report)

    def as_sarif(self) -> str:
        return json.dumps(render_sarif(self.report), indent=2)


class PactGuard:
    """
    Main entry point for the Pact security analyzer.

    Usage:
        # Auto-detect from env vars (OPENAI_API_KEY or GEMINI_API_KEY)
        sentinel = PactGuard()

        # Explicit OpenAI
        sentinel = PactGuard(openai_key="sk-...")

        # Explicit Gemini  
        sentinel = PactGuard(gemini_key="AIza...")

        # Force provider
        sentinel = PactGuard(ai_provider="openai")
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        openai_key: Optional[str] = None,
        gemini_key: Optional[str] = None,
        ai_provider: Optional[str] = None,
        use_ai: bool = True,
        severity_filter: Optional[str] = None,
        tag_filter: Optional[List[str]] = None,
        skip_rules: Optional[List[str]] = None,
        confidence_threshold: float = 0.5,
    ):
        if use_ai:
            self.ai = AIAnalyzer(
                api_key=api_key,
                openai_key=openai_key,
                gemini_key=gemini_key,
                provider=ai_provider,
            )
        else:
            self.ai = AIAnalyzer(api_key="")
        self.rules = get_rules(severity_filter=severity_filter, tag_filter=tag_filter)
        if skip_rules:
            self.rules = [r for r in self.rules if r.rule_id not in skip_rules]
        self.confidence_threshold = confidence_threshold


    def _build_analysis_context(self, contract: ContractFile) -> dict:
        call_graph = {}
        capability_flow = {}
        scope_tree = {} # Track let scopes

        for mod in contract.modules:
            all_fns = {**mod.functions, **mod.capabilities}
            for fn_name, fn in all_fns.items():
                if fn_name not in call_graph:
                    call_graph[fn_name] = {"calls": [], "called_by": [], "is_public": True}

                # Evaluate public
                if getattr(fn, "visibility", None):
                    is_pub = (fn.visibility.value != "private")
                    call_graph[fn_name]["is_public"] = is_pub
                elif fn_name.startswith("-") or fn_name.startswith("_"):
                    call_graph[fn_name]["is_public"] = False
                
                # Direct auth checks
                has_auth = bool(getattr(fn, "capability_guards", [])) or bool(getattr(fn, "capabilities_required", [])) or bool(getattr(fn, "enforcements", []))
                
                # Check for let blocks with with-capability to flag scope leaks
                scope_leak = False
                for node in fn.body:
                    if node.node_type and str(node.node_type).endswith("LET"):
                        # Basic heuristic: if let body has with-capability assigned, but used outside?
                        for child in node.children:
                            if child.name in ["with-capability", "require-capability"]:
                                has_auth = True
                                
                capability_flow[fn_name] = {"has_direct_auth": has_auth, "scope_leak": scope_leak}
                
                # Fill calls
                for node in fn.body:
                    # simplistic flatten
                    def _flat(n):
                        res = [n]
                        for c in n.children: res.extend(_flat(c))
                        return res
                    
                    for sub in _flat(node):
                        if str(sub.node_type).endswith("CALL") and sub.name:
                            call_graph[fn_name]["calls"].append(sub.name)
                            if sub.name not in call_graph:
                                call_graph[sub.name] = {"calls": [], "called_by": [], "is_public": True}
                            call_graph[sub.name]["called_by"].append(fn_name)

        return {
            "call_graph": call_graph,
            "capability_flow": capability_flow,
            "scope_tree": scope_tree
        }

    def analyze_source(self, source: str, filename: str = "<stdin>") -> AnalysisResult:
        """Analyze Pact source code string."""
        start = time.time()

        # 1. Parse
        try:
            contract = parse_contract(source, filename)
        except Exception as e:
            # Return a minimal error result
            contract = ContractFile(source=source, filename=filename)
            return self._make_error_result(str(e), filename, time.time() - start)

        # 2. Static Analysis
        raw_findings = []
        for rule in self.rules:
            try:
                rule.analyzer_context = self._build_analysis_context(contract)
                raw_findings.extend(rule.analyze(contract))
            except Exception:
                pass  # don't let one rule crash everything

                # Execute Core Tracking & Post-process
        context = self._build_analysis_context(contract)
        findings = apply_fp_reduction_layer(raw_findings, contract, context)

        # Filter by confidence threshold using safe value getter
        def _get_conf(val):
            return {"high": 1.0, "medium": 0.5, "low": 0.2}.get(val.value if hasattr(val, "value") else str(val).lower(), 1.0)
        findings = [f for f in findings if _get_conf(f.confidence) >= self.confidence_threshold]

        # Deduplicate (same rule + same location)
        findings = self._deduplicate(findings)

        # Sort by severity (with info)
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings.sort(key=lambda f: (sev_order.get(f.severity.value, 4), f.location.line))

        # 3. Risk Score
        risk_score = compute_risk_score(findings)

        # 4. AI Enrichment (async-optional; runs synchronously here)
        ai_enrichment: Dict[str, Any] = {}
        if self.ai.available and findings:
            ai_enrichment = self.ai.enrich_findings(source, findings[:8])  # limit to 8

        # 5. Summary
        summary = self.ai.generate_executive_summary(source, findings)

        # 6. Build report
        elapsed = time.time() - start
        report = build_json_report(
            findings=findings,
            risk_score=risk_score,
            summary=summary,
            ai_enrichment=ai_enrichment,
            filename=filename,
            elapsed=elapsed,
        )

        return AnalysisResult(
            contract=contract,
            findings=findings,
            risk_score=risk_score,
            summary=summary,
            ai_enrichment=ai_enrichment,
            report=report,
            elapsed=elapsed,
        )

    def analyze_file(self, path: Union[str, Path]) -> AnalysisResult:
        """Analyze a Pact file from disk."""
        path = Path(path)
        with open(path, "r", encoding="utf-8") as f:
            source = f.read()
        return self.analyze_source(source, filename=str(path))

    def analyze_directory(self, directory: Union[str, Path]) -> List[AnalysisResult]:
        """Analyze all .pact files in a directory recursively."""
        directory = Path(directory)
        results = []
        for pact_file in sorted(directory.rglob("*.pact")):
            results.append(self.analyze_file(pact_file))
        return results

    def _deduplicate(self, findings: List[Finding]) -> List[Finding]:
        seen = set()
        unique = []
        for f in findings:
            key = (f.rule_id, f.location.module, f.location.function, f.location.line)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    def _make_error_result(self, error: str, filename: str, elapsed: float) -> AnalysisResult:
        from ..output.risk_score import RiskScore
        rs = RiskScore(
            raw_score=0, normalized=0,
            letter_grade="?", label="Parse Error",
            breakdown={"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0},
            compound_multiplier=1.0,
        )
        report = {
            "schema_version": "1.0",
            "tool": "pact-guard",
            "analyzed_file": filename,
            "elapsed_seconds": round(elapsed, 3),
            "error": f"Parse error: {error}",
            "summary": f"Failed to parse contract: {error}",
            "risk_score": rs.to_dict(),
            "findings": [],
        }
        return AnalysisResult(
            contract=ContractFile(filename=filename),
            findings=[],
            risk_score=rs,
            summary=report["summary"],
            ai_enrichment={},
            report=report,
            elapsed=elapsed,
        )
