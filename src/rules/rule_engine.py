"""
Pact Security Rule Engine — v1.1.0
Fixed: deduplication by function, R-003 top-level keyset detection,
       context-aware recommendations, expanded R-012 managed detection.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Optional, Set, Tuple
from enum import Enum

from ..parser.ast_nodes import (
    ASTNode, FunctionNode, ModuleNode, ContractFile, NodeType, Visibility
)


class Severity(str, Enum):
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"

    @property
    def score(self) -> int:
        return {"low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]


@dataclass
class Location:
    module:   str = ""
    function: str = ""
    line:     int = 0
    col:      int = 0

    def to_dict(self):
        d = {"module": self.module, "function": self.function, "line": self.line}
        if self.col:
            d["col"] = self.col
        return d


@dataclass
class Finding:
    rule_id:           str
    title:             str
    severity:          Severity
    location:          Location
    issue:             str
    risk:              str
    recommendation:    str
    fixed_code_example:str = ""
    tags:              List[str] = field(default_factory=list)
    confidence:        float = 1.0

    def to_dict(self, idx: int) -> dict:
        return {
            "id":                 f"F-{idx:03d}",
            "rule_id":            self.rule_id,
            "title":              self.title,
            "severity":           self.severity.value,
            "confidence":         self.confidence,
            "location":           self.location.to_dict(),
            "issue":              self.issue,
            "risk":               self.risk,
            "recommendation":     self.recommendation,
            "fixed_code_example": self.fixed_code_example,
            "tags":               self.tags,
        }


class BaseRule(ABC):
    rule_id:  str       = "R-000"
    title:    str       = "Base Rule"
    severity: Severity  = Severity.LOW
    tags:     List[str] = []

    @abstractmethod
    def analyze(self, contract: ContractFile) -> List[Finding]: ...

    def _loc(self, mod_name: str,
             fn: Optional[FunctionNode] = None,
             node: Optional[ASTNode]   = None) -> Location:
        line    = 0
        fn_name = ""
        if fn:
            fn_name = fn.name
            line    = fn.location.line if fn.location else 0
        if node and node.location:
            line = node.location.line
        return Location(module=mod_name, function=fn_name, line=line)

    # ------------------------------------------------------------------
    # Helpers for context-aware fix text
    # ------------------------------------------------------------------
    def _infer_function_purpose(self, fn_name: str) -> str:
        """Return a human-readable purpose hint based on function name."""
        n = fn_name.lower()
        if any(x in n for x in ['transfer', 'send', 'pay']):
            return "token transfer"
        if any(x in n for x in ['mint', 'issue', 'create-token']):
            return "token minting"
        if any(x in n for x in ['burn', 'destroy']):
            return "token burning"
        if any(x in n for x in ['init', 'initialize', 'deploy']):
            return "contract initialization"
        if any(x in n for x in ['pause', 'freeze', 'halt']):
            return "emergency circuit-breaker"
        if any(x in n for x in ['unpause', 'resume', 'unfreeze']):
            return "contract resumption"
        if any(x in n for x in ['admin', 'owner', 'set-admin']):
            return "administrative control"
        if any(x in n for x in ['upgrade', 'migrate']):
            return "contract upgrade"
        if any(x in n for x in ['withdraw', 'debit']):
            return "balance debit"
        if any(x in n for x in ['deposit', 'credit', 'fund']):
            return "balance credit"
        if any(x in n for x in ['create', 'register']):
            return "account or resource creation"
        if any(x in n for x in ['update', 'set', 'change']):
            return "state update"
        return "state-modifying operation"

    def _cap_name_for(self, fn_name: str) -> str:
        """Suggest an appropriate capability name for a function."""
        n = fn_name.upper().replace('-', '_')
        for prefix in ['PRIVATE_', 'PRIVATE-']:
            if n.startswith(prefix):
                n = n[len(prefix):]
        return n + "_AUTH"

    def _flatten(self, node: ASTNode) -> List[Tuple[int, ASTNode]]:
        results = []
        if node.location:
            results.append((node.location.line, node))
        for child in node.children:
            results.extend(self._flatten(child))
        return results


# ══════════════════════════════════════════════════════════════════════
# R-001 — State Mutation Without Capability Guard
# ══════════════════════════════════════════════════════════════════════
class R001_MissingCapabilityBeforeMutation(BaseRule):
    rule_id  = "R-001"
    title    = "State Mutation Without Capability Guard"
    severity = Severity.CRITICAL
    tags     = ["access-control", "capability", "state-mutation"]

    def analyze(self, contract: ContractFile) -> List[Finding]:
        findings = []
        for mod in contract.modules:
            for fn_name, fn in mod.functions.items():
                if fn.visibility == Visibility.PRIVATE or fn_name.startswith('_') or 'internal' in fn_name.lower():
                    continue
                if not fn.state_mutations:
                    continue
                if fn.capability_guards or fn.capabilities_required or fn.enforcements:
                    continue
                
                # FP Calibration: Check if it delegates to private helpers or external enforces
                delegates = False
                for node in fn.body:
                    for _, n in self._flatten(node):
                        if n.name and ('enforce' in n.name or 'require' in n.name or n.name.startswith('_')):
                            delegates = True
                            break
                if delegates:
                    continue

                # ONE finding per function (pick worst mutation)
                mutation = fn.state_mutations[0]
                table    = mutation.attributes.get("table", "?")
                purpose  = self._infer_function_purpose(fn_name)
                cap_name = self._cap_name_for(fn_name)
                loc      = self._loc(mod.name, fn)
                if mutation.location:
                    loc.line = mutation.location.line
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=self.severity,
                    location=loc,
                    issue=(
                        f"`{fn_name}` performs `{mutation.name}` on table `{table}` "
                        f"with no capability guard or enforce check."
                    ),
                    risk=(
                        f"Any account can call `{fn_name}` and modify `{table}` without authorization. "
                        f"For a {purpose} function this enables direct exploitation — "
                        f"unauthorized state changes, fund theft, or contract takeover."
                    ),
                    recommendation=(
                        f"`{fn_name}` is a {purpose} function. "
                        f"Define a `{cap_name}` capability that enforces the caller's identity "
                        f"(via `enforce-guard`) and wrap the `{mutation.name}` call inside "
                        f"`(with-capability ({cap_name} ...))`."
                    ),
                    fixed_code_example=(
                        f"(defcap {cap_name} (account:string)\n"
                        f"  @doc \"Guard for {fn_name}\"\n"
                        f"  (enforce-guard (at 'guard (read {table} account))))\n\n"
                        f"(defun {fn_name} (...)\n"
                        f"  (with-capability ({cap_name} account)\n"
                        f"    ({mutation.name} {table} account {{...}})))"
                    ),
                    tags=self.tags,
                ))
        return findings


# ══════════════════════════════════════════════════════════════════════
# R-002 — Overly Broad Capability Scope
# ══════════════════════════════════════════════════════════════════════
class R002_ImproperWithCapabilityUsage(BaseRule):
    rule_id  = "R-002"
    title    = "Overly Broad Capability Scope (with-capability Misuse)"
    severity = Severity.MEDIUM
    tags     = ["capability", "scope", "least-privilege"]

    def analyze(self, contract: ContractFile) -> List[Finding]:
        findings = []
        for mod in contract.modules:
            for fn_name, fn in {**mod.functions, **mod.pacts}.items():
                for node in fn.find_all(NodeType.WITH_CAPABILITY):
                    body     = node.attributes.get("body", [])
                    cap_name = node.attributes.get("capability", "?")
                    if not body:
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            title=self.title,
                            severity=Severity.MEDIUM,
                            location=self._loc(mod.name, fn, node),
                            issue=(
                                f"`(with-capability ({cap_name} ...))` in `{fn_name}` "
                                f"has an empty body — the capability is granted but unused."
                            ),
                            risk=(
                                "Granting capabilities with no body creates dead access control — "
                                "it masks logic errors and makes auditing impossible."
                            ),
                            recommendation=(
                                f"Move all sensitive operations on `{fn_name}` into the "
                                f"`(with-capability ({cap_name} ...))` body, or remove the grant "
                                f"if it is not needed. If propagating to a callee, add "
                                f"`(require-capability ({cap_name} ...))` in the called function."
                            ),
                            fixed_code_example=(
                                f"(with-capability ({cap_name} account)\n"
                                f"  ;; All guarded operations go here\n"
                                f"  (update accounts account {{'balance: new-balance}}))"
                            ),
                            tags=self.tags,
                            confidence=0.8,
                        ))
        return findings


# ══════════════════════════════════════════════════════════════════════
# R-003 — Hardcoded Admin Keyset  (FIXED: now catches top-level defines)
# ══════════════════════════════════════════════════════════════════════
class R003_HardcodedAdminKeyset(BaseRule):
    rule_id  = "R-003"
    title    = "Hardcoded Admin Keyset / Key Reference"
    severity = Severity.HIGH
    tags     = ["keyset", "hardcoded", "admin", "decentralization"]

    SUSPICIOUS_NAMES = {
        '"admin"', '"operator"', '"root"', '"owner"', '"god"',
        '"superuser"', "'admin", "'operator", "'owner", "'root",
        "admin", "operator", "owner", "root",
    }

    def analyze(self, contract: ContractFile) -> List[Finding]:
        import re
        findings = []

        # ── Check top-level keyset definitions ─────────────────────
        for ks_node in contract.top_level_keysets:
            args = ks_node.attributes.get("args", [])
            for arg in args:
                raw = (arg.name or arg.raw or "").strip('"').strip("'")
                if raw.lower() in {s.strip('"\'') for s in self.SUSPICIOUS_NAMES}:
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=self.severity,
                        location=Location(module="<top-level>", function="define-keyset",
                                          line=ks_node.location.line if ks_node.location else 0),
                        issue=(
                            f"Top-level `(define-keyset '{raw} ...)` uses a generic admin name. "
                            f"This creates a well-known privileged keyset name attackers can target."
                        ),
                        risk=(
                            "Generic keyset names like 'admin' or 'operator' are frequently targeted "
                            "in deployment attacks. If the keyset is not rotated or is misconfigured, "
                            "any account can claim ownership."
                        ),
                        recommendation=(
                            f"Use a namespaced keyset: `(define-keyset 'your-project.admin-ks ...)`. "
                            f"Always read the keyset from transaction data: "
                            f"`(define-keyset 'project.admin (read-keyset \"admin\"))` "
                            f"and confirm via `(enforce-guard (keyset-ref-guard 'project.admin))`."
                        ),
                        fixed_code_example=(
                            "(namespace 'your-project)\n"
                            "(define-keyset 'your-project.admin-ks (read-keyset \"admin\"))\n\n"
                            "(defcap GOVERNANCE ()\n"
                            "  (enforce-guard (keyset-ref-guard 'your-project.admin-ks)))"
                        ),
                        tags=self.tags,
                    ))

        # ── Check inside module functions ──────────────────────────
        for mod in contract.modules:
            # Also check module governance field itself
            gov = mod.governance
            if gov and gov.strip('"\'').lower() in {s.strip('"\'') for s in self.SUSPICIOUS_NAMES}:
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=self.severity,
                    location=Location(module=mod.name, function="<module-governance>",
                                      line=mod.location.line if mod.location else 0),
                    issue=(
                        f"Module `{mod.name}` is governed by hardcoded keyset `{gov}`. "
                        f"Using a string literal as module governance is a security anti-pattern."
                    ),
                    risk=(
                        "A module governed by a bare string keyset (not a capability) cannot "
                        "enforce upgrade authorization at runtime. Any account holding that keyset "
                        "can upgrade the module without time-locks or multi-sig."
                    ),
                    recommendation=(
                        f"Replace `(module {mod.name} '{gov} ...)` with a GOVERNANCE capability: "
                        f"`(module {mod.name} GOVERNANCE ...)` and define "
                        f"`(defcap GOVERNANCE () (enforce-guard (keyset-ref-guard 'ns.admin-ks)))`."
                    ),
                    fixed_code_example=(
                        f"(module {mod.name} GOVERNANCE\n"
                        f"  (defcap GOVERNANCE ()\n"
                        f"    (enforce-guard (keyset-ref-guard 'ns.admin-ks)))\n"
                        f"  ...)"
                    ),
                    tags=self.tags,
                ))

            all_fns = list(mod.functions.values()) + list(mod.capabilities.values())
            for fn in all_fns:
                for node in fn.find_all(NodeType.KEYSET_REF_GUARD):
                    args = node.attributes.get("args", [])
                    for arg in args:
                        raw = (arg.name or arg.raw or "").strip()
                        if raw.strip('"\'').lower() in {s.strip('"\'') for s in self.SUSPICIOUS_NAMES}:
                            findings.append(Finding(
                                rule_id=self.rule_id,
                                title=self.title,
                                severity=self.severity,
                                location=self._loc(mod.name, fn, node),
                                issue=(
                                    f"Hardcoded keyset reference `{raw}` in `{fn.name}` "
                                    f"creates a privileged single point of control."
                                ),
                                risk=(
                                    "Generic admin keysets are prime attack targets. A compromised key "
                                    "or misconfigured keyset grants full contract control with no recovery path."
                                ),
                                recommendation=(
                                    "Use a namespaced keyset stored in a module constant. "
                                    "Prefer a GOVERNANCE capability pattern over raw keyset strings."
                                ),
                                fixed_code_example=(
                                    "(defcap GOVERNANCE ()\n"
                                    "  (enforce-guard (keyset-ref-guard 'project.admin-ks)))"
                                ),
                                tags=self.tags,
                            ))
        return findings


# ══════════════════════════════════════════════════════════════════════
# R-004 — Public Function Mutates Sensitive State (FIXED: 1 per function)
# ══════════════════════════════════════════════════════════════════════
class R004_PublicFunctionMutatingSensitiveState(BaseRule):
    rule_id  = "R-004"
    title    = "Public Function Directly Modifies Sensitive State"
    severity = Severity.HIGH
    tags     = ["access-control", "public-function", "sensitive-state"]

    SENSITIVE = ["account", "balance", "token", "ledger", "vault", "pool", "stake", "reserve", "fund"]

    def _is_sensitive(self, table: str) -> bool:
        return any(p in table.lower() for p in self.SENSITIVE)

    def analyze(self, contract: ContractFile) -> List[Finding]:
        findings = []
        for mod in contract.modules:
            for fn_name, fn in mod.functions.items():
                if fn.visibility == Visibility.PRIVATE or fn_name.startswith('_') or 'internal' in fn_name.lower():
                    continue
                if fn.capability_guards or fn.enforcements:
                    continue  # protected — skip

                # FP Calibration: Check if it delegates to private helpers or external enforces
                delegates = False
                for node in fn.body:
                    for _, n in self._flatten(node):
                        if n.name and ('enforce' in n.name or 'require' in n.name or n.name.startswith('_')):
                            delegates = True
                            break
                if delegates:
                    continue

                # Find FIRST sensitive mutation (deduplicate per function)
                sensitive_mutation = next(
                    (m for m in fn.state_mutations if self._is_sensitive(m.attributes.get("table", ""))),
                    None
                )
                if not sensitive_mutation:
                    continue
                table   = sensitive_mutation.attributes.get("table", "?")
                purpose = self._infer_function_purpose(fn_name)
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=self.severity,
                    location=self._loc(mod.name, fn, sensitive_mutation),
                    issue=(
                        f"Public `{fn_name}` directly mutates sensitive table `{table}` "
                        f"without any capability protection."
                    ),
                    risk=(
                        f"`{fn_name}` appears to be a {purpose} function. "
                        f"Direct unguarded access to `{table}` allows any caller to manipulate "
                        f"balances or ownership records — enabling token inflation, theft, or account takeover."
                    ),
                    recommendation=(
                        f"Wrap the `{table}` mutation inside a dedicated capability "
                        f"(e.g., `TRANSFER`, `DEBIT`, or `CREDIT` following the Kadena coin contract pattern). "
                        f"Use `@managed` on transfer capabilities to prevent double-spend."
                    ),
                    fixed_code_example=(
                        f"(defcap DEBIT (sender:string amount:decimal)\n"
                        f"  @managed amount DEBIT-mgr\n"
                        f"  (enforce-guard (at 'guard (read {table} sender))))\n\n"
                        f"(defun DEBIT-mgr:decimal (managed:decimal requested:decimal)\n"
                        f"  (enforce (>= managed requested) \"Exceeds authorized amount\")\n"
                        f"  (- managed requested))\n\n"
                        f"(defun {fn_name} (sender:string receiver:string amount:decimal)\n"
                        f"  (with-capability (DEBIT sender amount)\n"
                        f"    (update {table} sender {{'balance: (- old-bal amount)}}))"
                    ),
                    tags=self.tags,
                ))
        return findings


# ══════════════════════════════════════════════════════════════════════
# R-005 — Capability Missing Authorization Enforcement
# ══════════════════════════════════════════════════════════════════════
class R005_MissingEnforceInCapability(BaseRule):
    rule_id  = "R-005"
    title    = "Capability Missing Authorization Enforcement"
    severity = Severity.CRITICAL
    tags     = ["capability", "enforce", "authorization"]

    def analyze(self, contract: ContractFile) -> List[Finding]:
        findings = []
        for mod in contract.modules:
            for cap_name, cap in mod.capabilities.items():
                if cap.event:
                    continue  # @event caps are informational
                if cap.managed and not cap.enforcements and not cap.capabilities_required:
                    continue  # manager handles auth
                has_enforce = bool(cap.enforcements)
                has_require = bool(cap.capabilities_required)
                body_exists = len(cap.body) > 0

                if not body_exists:
                    purpose = self._infer_function_purpose(cap_name)
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=Severity.CRITICAL,
                        location=self._loc(mod.name, cap),
                        issue=(
                            f"Capability `{cap_name}` has an empty body — "
                            f"it grants permission to anyone unconditionally."
                        ),
                        risk=(
                            f"`{cap_name}` appears to be a {purpose} capability. "
                            f"Empty capabilities are equivalent to no access control — "
                            f"any transaction can acquire this capability for free, bypassing all security."
                        ),
                        recommendation=(
                            f"Add `enforce-guard` or `enforce` in `{cap_name}` to verify the caller. "
                            f"For account-based capabilities: `(enforce-guard (at 'guard (read table account)))`. "
                            f"For admin capabilities: `(enforce-guard (keyset-ref-guard 'ns.admin-ks))`."
                        ),
                        fixed_code_example=(
                            f"(defcap {cap_name} (account:string)\n"
                            f"  @doc \"Enforces account ownership\"\n"
                            f"  (enforce-guard (at 'guard (read accounts account))))"
                        ),
                        tags=self.tags,
                    ))
                elif body_exists and not has_enforce and not has_require:
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=Severity.CRITICAL,
                        location=self._loc(mod.name, cap),
                        issue=(
                            f"Capability `{cap_name}` has a body but contains no `enforce`, "
                            f"`enforce-guard`, or `require-capability` — grants access unconditionally."
                        ),
                        risk=(
                            "A capability body without enforcement is a no-op gate. "
                            "Any caller can acquire it, defeating Pact's capability security model entirely."
                        ),
                        recommendation=(
                            f"Add an `enforce-guard` or `enforce` check as the first expression "
                            f"in `{cap_name}`. The check must verify the caller has permission "
                            f"before the capability token is granted."
                        ),
                        fixed_code_example=(
                            f"(defcap {cap_name} (account:string)\n"
                            f"  (enforce-guard (at 'guard (read accounts account))))"
                        ),
                        tags=self.tags,
                    ))
        return findings


# ══════════════════════════════════════════════════════════════════════
# R-006 — CEI Violation
# ══════════════════════════════════════════════════════════════════════
class R006_StateChangeBeforeAuth(BaseRule):
    rule_id  = "R-006"
    title    = "State Change Before Authorization Check (CEI Violation)"
    severity = Severity.HIGH
    tags     = ["cei", "reentrancy", "ordering", "toctou"]

    def analyze(self, contract: ContractFile) -> List[Finding]:
        findings = []
        for mod in contract.modules:
            for fn_name, fn in {**mod.functions, **mod.pacts}.items():
                self._check_ordering(mod.name, fn, findings)
        return findings

    def _check_ordering(self, mod_name: str, fn: FunctionNode, findings: List[Finding]):
        first_mut_line  = None
        first_mut_node  = None
        for node in fn.body:
            for line, n in self._flatten(node):
                nt = n.node_type
                if nt in (NodeType.WRITE, NodeType.UPDATE, NodeType.INSERT, NodeType.DELETE):
                    if first_mut_line is None:
                        # FP Case 2: CEI violation is only high risk if modifying sensitive tables.
                        # Local counters/stats can be safely reordered.
                        table = n.attributes.get("table", "?")
                        if any(s in table.lower() for s in ["account", "balance", "token", "ledger", "vault", "pool"]):
                            first_mut_line = line
                            first_mut_node = n
                elif nt in (NodeType.ENFORCE, NodeType.ENFORCE_GUARD, NodeType.ENFORCE_ONE):
                    if first_mut_line is not None and line > first_mut_line:
                        table   = first_mut_node.attributes.get("table", "?") if first_mut_node else "?"
                        purpose = self._infer_function_purpose(fn.name)
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            title=self.title,
                            severity=self.severity,
                            location=Location(module=mod_name, function=fn.name, line=first_mut_line),
                            issue=(
                                f"`{fn.name}`: `{first_mut_node.name if first_mut_node else 'update'}` "
                                f"on `{table}` (line {first_mut_line}) occurs BEFORE "
                                f"`{n.name}` (line {line})."
                            ),
                            risk=(
                                f"`{fn.name}` is a {purpose} function. "
                                f"State committed before validation cannot be rolled back if the check fails. "
                                f"In cross-module calls this creates a classic read-modify-write reentrancy window."
                            ),
                            recommendation=(
                                f"Restructure `{fn.name}` to follow Checks-Effects-Interactions:\n"
                                f"  1. ALL `enforce`/`enforce-guard` checks first\n"
                                f"  2. State reads (`with-read`, `select`)\n"
                                f"  3. State writes (`update`, `insert`) last\n"
                                f"Never write to `{table}` before all authorization is confirmed."
                            ),
                            fixed_code_example=(
                                f"(defun {fn.name} (...)\n"
                                f"  ;; ── 1. CHECKS (all validation first) ──\n"
                                f"  (enforce (> amount 0.0) \"Amount must be positive\")\n"
                                f"  (enforce-guard (at 'guard (read accounts sender)))\n"
                                f"  ;; ── 2. READS ──\n"
                                f"  (with-read accounts sender {{'balance := bal}}\n"
                                f"    (enforce (>= bal amount) \"Insufficient balance\")\n"
                                f"    ;; ── 3. EFFECTS (writes last) ──\n"
                                f"    (update accounts sender {{'balance: (- bal amount)}})))"
                            ),
                            tags=self.tags,
                            confidence=0.85,
                        ))
                        return
        pass


# ══════════════════════════════════════════════════════════════════════
# R-007 — Unguarded Administrative Function
# ══════════════════════════════════════════════════════════════════════
class R007_UnguardedAdminFunction(BaseRule):
    rule_id  = "R-007"
    title    = "Unguarded Administrative Function"
    severity = Severity.CRITICAL
    tags     = ["admin", "access-control", "governance"]

    ADMIN_PATTERNS = [
        "init", "admin", "upgrade", "migrate", "pause", "unpause",
        "set-owner", "set-admin", "emergency", "destroy", "mint",
        "freeze", "unfreeze", "halt", "resume",
    ]

    def analyze(self, contract: ContractFile) -> List[Finding]:
        findings = []
        for mod in contract.modules:
            for fn_name, fn in mod.functions.items():
                if not any(pat in fn_name.lower() for pat in self.ADMIN_PATTERNS):
                    continue
                if fn.capability_guards or fn.capabilities_required or fn.enforcements:
                    continue
                purpose = self._infer_function_purpose(fn_name)
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=self.severity,
                    location=self._loc(mod.name, fn),
                    issue=(
                        f"Administrative function `{fn_name}` (a {purpose}) has no "
                        f"capability guard, enforce check, or require-capability."
                    ),
                    risk=(
                        f"`{fn_name}` is a {purpose} function callable by any account. "
                        f"An attacker monitoring the mempool can front-run deployment, "
                        f"seize governance, drain funds, or permanently disable the contract."
                    ),
                    recommendation=(
                        f"`{fn_name}` is a {purpose} and must be gated by the module's "
                        f"GOVERNANCE capability. This enforces the governing keyset and "
                        f"prevents unauthorized access at the transaction level."
                    ),
                    fixed_code_example=(
                        f"(defcap GOVERNANCE ()\n"
                        f"  @doc \"Module governance — requires admin keyset\"\n"
                        f"  (enforce-guard (keyset-ref-guard 'ns.admin-ks)))\n\n"
                        f"(defun {fn_name} (...)\n"
                        f"  (with-capability (GOVERNANCE)\n"
                        f"    ;; {purpose} logic here\n"
                        f"  ))"
                    ),
                    tags=self.tags,
                ))
        return findings


# ══════════════════════════════════════════════════════════════════════
# R-008 — Unsafe defpact Step Logic
# ══════════════════════════════════════════════════════════════════════
class R008_UnsafeDefpactFallback(BaseRule):
    rule_id  = "R-008"
    title    = "Unsafe Multi-Step Pact (defpact) Logic"
    severity = Severity.HIGH
    tags     = ["defpact", "multi-step", "rollback", "cross-chain"]

    def analyze(self, contract: ContractFile) -> List[Finding]:
        findings = []
        for mod in contract.modules:
            for pact_name, pact in mod.pacts.items():
                if pact.state_mutations and not pact.capability_guards:
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=self.severity,
                        location=self._loc(mod.name, pact),
                        issue=(
                            f"`defpact` `{pact_name}` mutates state in "
                            f"{len(pact.state_mutations)} step(s) without per-step capability guards."
                        ),
                        risk=(
                            f"Multi-step pacts without per-step auth allow adversaries to resume "
                            f"execution out of sequence with manipulated state. "
                            f"In cross-chain bridge scenarios this enables double-spend attacks."
                        ),
                        recommendation=(
                            f"Each step in `{pact_name}` that modifies state must call "
                            f"`(require-capability ...)` at the start, binding the authorized "
                            f"initiator across all steps of the pact execution."
                        ),
                        fixed_code_example=(
                            f"(defpact {pact_name} (sender:string receiver:string amount:decimal)\n"
                            f"  (step\n"
                            f"    (with-capability (TRANSFER sender receiver amount)\n"
                            f"      (debit sender amount)))\n"
                            f"  (step\n"
                            f"    (with-capability (TRANSFER sender receiver amount)\n"
                            f"      (credit receiver amount))))"
                        ),
                        tags=self.tags,
                    ))
        return findings


# ══════════════════════════════════════════════════════════════════════
# R-009 — Weak Guard Construction
# ══════════════════════════════════════════════════════════════════════
class R009_WeakGuardPattern(BaseRule):
    rule_id  = "R-009"
    title    = "Weak or Bypassable Guard Construction"
    severity = Severity.HIGH
    tags     = ["guard", "authentication", "user-controlled"]

    def analyze(self, contract: ContractFile) -> List[Finding]:
        findings = []
        for mod in contract.modules:
            all_fns = list(mod.functions.values()) + list(mod.capabilities.values())
            for fn in all_fns:
                for node in fn.find_all(NodeType.CREATE_USER_GUARD):
                    for arg in node.children:
                        if arg.node_type == NodeType.IDENTIFIER:
                            findings.append(Finding(
                                rule_id=self.rule_id,
                                title=self.title,
                                severity=self.severity,
                                location=self._loc(mod.name, fn, node),
                                issue=(
                                    f"`{fn.name}` calls `create-user-guard` with user-controlled "
                                    f"argument `{arg.name}` without validation."
                                ),
                                risk=(
                                    "A maliciously crafted guard function can always succeed, "
                                    "granting the attacker ownership of any account that stores it."
                                ),
                                recommendation=(
                                    "Validate guard inputs before `create-user-guard`. "
                                    "Prefer `keyset-ref-guard` with a known keyset, "
                                    "or `create-principal-guard` for single-key accounts."
                                ),
                                fixed_code_example=(
                                    "(enforce (!= account \"\") \"Account cannot be empty\")\n"
                                    "(enforce (= (typeof guard) \"guard\") \"Must be a guard\")\n"
                                    "(let ((g (create-user-guard (validate-account account))))\n"
                                    "  (insert accounts account {'guard: g}))"
                                ),
                                tags=self.tags,
                                confidence=0.75,
                            ))
        return findings


# ══════════════════════════════════════════════════════════════════════
# R-010 — Unprotected Table Initialization
# ══════════════════════════════════════════════════════════════════════
class R010_UnprotectedTableInit(BaseRule):
    rule_id  = "R-010"
    title    = "Unprotected Table Initialization"
    severity = Severity.MEDIUM
    tags     = ["table", "initialization", "deployment"]

    def analyze(self, contract: ContractFile) -> List[Finding]:
        findings = []
        for mod in contract.modules:
            init_fns = [
                fn for name, fn in mod.functions.items()
                if any(kw in name.lower() for kw in ["init", "create", "setup", "deploy"])
            ]
            for fn in init_fns:
                if fn.state_mutations and not fn.capability_guards and not fn.enforcements:
                    purpose = self._infer_function_purpose(fn.name)
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=self.severity,
                        location=self._loc(mod.name, fn),
                        issue=(
                            f"`{fn.name}` ({purpose}) inserts/writes to tables "
                            f"without governance protection."
                        ),
                        risk=(
                            "Mempool front-running attack: an attacker monitoring the deployment "
                            "transaction can call this function before the legitimate operator, "
                            "seeding tables with malicious initial state (e.g., attacker-owned admin accounts)."
                        ),
                        recommendation=(
                            f"Protect `{fn.name}` with the module's GOVERNANCE capability. "
                            f"For truly one-time initialization, also add a guard that fails "
                            f"if initialization has already occurred (read-with-default pattern)."
                        ),
                        fixed_code_example=(
                            f"(defun {fn.name} ()\n"
                            f"  (with-capability (GOVERNANCE)\n"
                            f"    ;; Guard against re-initialization\n"
                            f"    (with-default-read config-table 'initialized\n"
                            f"      {{'initialized: false}}\n"
                            f"      {{'initialized := already-init}}\n"
                            f"      (enforce (not already-init) \"Already initialized\")\n"
                            f"      (insert config-table 'initialized {{'initialized: true}}))))"
                        ),
                        tags=self.tags,
                    ))
        return findings


# ══════════════════════════════════════════════════════════════════════
# R-011 — Capability Composition Re-entrancy
# ══════════════════════════════════════════════════════════════════════
class R011_ReentrancyViaCompose(BaseRule):
    rule_id  = "R-011"
    title    = "Potential Capability Composition Re-entrancy"
    severity = Severity.MEDIUM
    tags     = ["reentrancy", "capability", "compose-capability"]

    def analyze(self, contract: ContractFile) -> List[Finding]:
        findings = []
        for mod in contract.modules:
            cap_graph: dict = {}
            for cap_name, cap in mod.capabilities.items():
                cap_graph[cap_name] = set(cap.capabilities_composed)
            for cap_name in cap_graph:
                cycle = self._find_cycle(cap_name, cap_graph, set(), [])
                if cycle:
                    cap = mod.capabilities.get(cap_name)
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=self.severity,
                        location=self._loc(mod.name, cap),
                        issue=(
                            f"Circular capability composition: "
                            f"{' -> '.join(cycle + [cycle[0]])}"
                        ),
                        risk=(
                            "Circular composition creates unexpected permission escalation paths. "
                            "Granting one capability may transitively grant unintended capabilities."
                        ),
                        recommendation=(
                            "Ensure capability composition graphs are acyclic. "
                            "Use explicit, one-directional delegation."
                        ),
                        fixed_code_example=(
                            ";; Break the cycle — CAP-A should not compose CAP-B\n"
                            ";; if CAP-B already composes CAP-A\n"
                            "(defcap CAP-A (account:string)\n"
                            "  (enforce-guard (at 'guard (read accounts account))))\n\n"
                            "(defcap CAP-B (account:string)\n"
                            "  (compose-capability (CAP-A account)))  ;; one direction only"
                        ),
                        tags=self.tags,
                    ))
        return findings

    def _find_cycle(self, node, graph, visited, path):
        if node in visited:
            return path[path.index(node):] if node in path else None
        visited.add(node)
        path.append(node)
        for n in graph.get(node, []):
            r = self._find_cycle(n, graph, visited, path)
            if r:
                return r
        path.pop()
        visited.discard(node)
        return None


# ══════════════════════════════════════════════════════════════════════
# R-012 — Transfer Cap Missing @managed (IMPROVED: more patterns)
# ══════════════════════════════════════════════════════════════════════
class R012_MissingManagedCapability(BaseRule):
    rule_id  = "R-012"
    title    = "Transfer Capability Missing @managed Annotation"
    severity = Severity.HIGH
    tags     = ["managed-capability", "double-spend", "transfer"]

    TRANSFER_PATTERNS = [
        "transfer", "debit", "withdraw", "send", "pay",
        "swap", "exchange", "bridge", "cross-chain",
    ]

    def analyze(self, contract: ContractFile) -> List[Finding]:
        findings = []
        for mod in contract.modules:
            for cap_name, cap in mod.capabilities.items():
                is_transfer = any(p in cap_name.lower() for p in self.TRANSFER_PATTERNS)
                if not is_transfer or cap.managed or cap.event:
                    continue
                # Check if it has a decimal param (likely an amount)
                has_amount_param = any(
                    'amount' in p.lower() or p.lower().endswith(':decimal')
                    for p in cap.params
                )
                if not has_amount_param:
                    continue
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=self.severity,
                    location=self._loc(mod.name, cap),
                    issue=(
                        f"Capability `{cap_name}` is a transfer/payment capability "
                        f"without `@managed`. The same grant can be used multiple times in one tx."
                    ),
                    risk=(
                        f"`{cap_name}` without `@managed` allows double-spend: "
                        f"a single authorization for N tokens can be consumed multiple times "
                        f"in nested calls within a single transaction, draining more than authorized."
                    ),
                    recommendation=(
                        f"Add `@managed amount {cap_name}-mgr` and implement a manager function "
                        f"that tracks consumed amount. Follow the Kadena coin contract pattern exactly."
                    ),
                    fixed_code_example=(
                        f"(defcap {cap_name} (sender:string receiver:string amount:decimal)\n"
                        f"  @managed amount {cap_name}-mgr\n"
                        f"  (enforce-guard (at 'guard (read accounts sender)))\n"
                        f"  (enforce (> amount 0.0) \"Positive non-zero amount\")\n"
                        f"  (enforce (!= sender receiver) \"Same-account restriction\"))\n\n"
                        f"(defun {cap_name}-mgr:decimal (managed:decimal requested:decimal)\n"
                        f"  (enforce (>= managed requested) \"{cap_name} limit exceeded\")\n"
                        f"  (- managed requested))"
                    ),
                    tags=self.tags,
                ))
        return findings


# ══════════════════════════════════════════════════════════════════════
# Rule Registry
# ══════════════════════════════════════════════════════════════════════
ALL_RULES: List[BaseRule] = [
    R001_MissingCapabilityBeforeMutation(),
    R002_ImproperWithCapabilityUsage(),
    R003_HardcodedAdminKeyset(),
    R004_PublicFunctionMutatingSensitiveState(),
    R005_MissingEnforceInCapability(),
    R006_StateChangeBeforeAuth(),
    R007_UnguardedAdminFunction(),
    R008_UnsafeDefpactFallback(),
    R009_WeakGuardPattern(),
    R010_UnprotectedTableInit(),
    R011_ReentrancyViaCompose(),
    R012_MissingManagedCapability(),
]
RULES_BY_ID: dict = {r.rule_id: r for r in ALL_RULES}

def get_rules(severity_filter=None, tag_filter=None):
    rules = list(ALL_RULES)
    if severity_filter:
        rules = [r for r in rules if r.severity.value == severity_filter]
    if tag_filter:
        rules = [r for r in rules if any(t in r.tags for t in tag_filter)]
    return rules
