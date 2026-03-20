"""
Pact Security Rule Engine
Implements static analysis rules to detect vulnerabilities in Pact contracts.
Each rule is a standalone class implementing the BaseRule interface.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Optional, Set, Tuple
from enum import Enum

from ..parser.ast_nodes import (
    ASTNode, FunctionNode, ModuleNode, ContractFile, NodeType, Visibility
)


# ─────────────────────────────────────────
# Data Models
# ─────────────────────────────────────────

class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def score(self) -> int:
        return {"low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]


@dataclass
class Location:
    module: str = ""
    function: str = ""
    line: int = 0
    col: int = 0

    def to_dict(self):
        d = {"module": self.module, "function": self.function, "line": self.line}
        if self.col:
            d["col"] = self.col
        return d


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    location: Location
    issue: str
    risk: str
    recommendation: str
    fixed_code_example: str = ""
    tags: List[str] = field(default_factory=list)
    confidence: float = 1.0  # 0.0 - 1.0

    def to_dict(self, idx: int) -> dict:
        return {
            "id": f"F-{idx:03d}",
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "location": self.location.to_dict(),
            "issue": self.issue,
            "risk": self.risk,
            "recommendation": self.recommendation,
            "fixed_code_example": self.fixed_code_example,
            "tags": self.tags,
        }


# ─────────────────────────────────────────
# Base Rule
# ─────────────────────────────────────────

class BaseRule(ABC):
    rule_id: str = "R-000"
    title: str = "Base Rule"
    severity: Severity = Severity.LOW
    tags: List[str] = []

    @abstractmethod
    def analyze(self, contract: ContractFile) -> List[Finding]:
        """Analyze a parsed contract and return findings."""
        ...

    def _loc(self, mod_name: str, fn: Optional[FunctionNode] = None,
             node: Optional[ASTNode] = None) -> Location:
        line = 0
        fn_name = ""
        if fn:
            fn_name = fn.name
            line = fn.location.line if fn.location else 0
        if node and node.location:
            line = node.location.line
        return Location(module=mod_name, function=fn_name, line=line)


# ─────────────────────────────────────────
# Rule Implementations
# ─────────────────────────────────────────

class R001_MissingCapabilityBeforeMutation(BaseRule):
    """
    RULE R-001: State mutation without capability guard.
    Detects public functions that write/update/insert/delete table rows
    without wrapping the mutation in a with-capability or having
    a require-capability guard.
    """
    rule_id = "R-001"
    title = "State Mutation Without Capability Guard"
    severity = Severity.CRITICAL
    tags = ["access-control", "capability", "state-mutation"]

    def analyze(self, contract: ContractFile) -> List[Finding]:
        findings = []
        for mod in contract.modules:
            for fn_name, fn in mod.functions.items():
                if fn.visibility == Visibility.PRIVATE:
                    continue
                if not fn.state_mutations:
                    continue
                has_cap_guard = bool(fn.capability_guards or fn.capabilities_required)
                has_enforce = bool(fn.enforcements)
                if not has_cap_guard and not has_enforce:
                    loc = self._loc(mod.name, fn)
                    for mutation in fn.state_mutations:
                        if mutation.location:
                            loc.line = mutation.location.line
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            title=self.title,
                            severity=self.severity,
                            location=loc,
                            issue=(
                                f"Function `{fn_name}` performs a `{mutation.name}` "
                                f"on table `{mutation.attributes.get('table', '?')}` "
                                f"without any capability guard or enforce check."
                            ),
                            risk=(
                                "Any caller can modify critical state without authorization. "
                                "This can lead to unauthorized fund transfers, data manipulation, "
                                "or complete contract takeover."
                            ),
                            recommendation=(
                                "Wrap all state mutations inside `(with-capability ...)` or "
                                "add `(require-capability ...)` at the top of the function. "
                                "Define a specific capability (e.g., TRANSFER, ADMIN) that must "
                                "be granted before the function executes."
                            ),
                            fixed_code_example=(
                                f"(defcap {fn_name.upper()}-AUTH (account:string)\n"
                                f"  (enforce-guard (at 'guard (read accounts account))))\n\n"
                                f"(defun {fn_name} (account:string amount:decimal)\n"
                                f"  (with-capability ({fn_name.upper()}-AUTH account)\n"
                                f"    ({mutation.name} {mutation.attributes.get('table', 'table')} account {{...}})))"
                            ),
                            tags=self.tags,
                        ))
        return findings


class R002_ImproperWithCapabilityUsage(BaseRule):
    """
    RULE R-002: Detects with-capability used without actual body containing
    sensitive operations — indicating dead/useless capability grants, or
    overly broad capability scoping.
    """
    rule_id = "R-002"
    title = "Overly Broad Capability Scope (with-capability Misuse)"
    severity = Severity.MEDIUM
    tags = ["capability", "scope", "least-privilege"]

    def analyze(self, contract: ContractFile) -> List[Finding]:
        findings = []
        for mod in contract.modules:
            for fn_name, fn in {**mod.functions, **mod.pacts}.items():
                for node in fn.find_all(NodeType.WITH_CAPABILITY):
                    body = node.attributes.get("body", [])
                    cap_name = node.attributes.get("capability", "?")
                    # Check: body is empty or contains only reads
                    if not body:
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            title=self.title,
                            severity=Severity.MEDIUM,
                            location=self._loc(mod.name, fn, node),
                            issue=(
                                f"`(with-capability ({cap_name} ...))` in `{fn_name}` "
                                f"has an empty body — the capability is granted but never consumed."
                            ),
                            risk=(
                                "Granting capabilities without using them can mask logic errors "
                                "and may indicate orphaned access control, making auditing harder."
                            ),
                            recommendation=(
                                "Ensure the protected operations are within the `with-capability` body. "
                                "If the grant is intentional (e.g., propagating to callees), use "
                                "`require-capability` in the called function to make the dependency explicit."
                            ),
                            fixed_code_example=(
                                f"(with-capability ({cap_name} account)\n"
                                f"  ;; All sensitive operations go here\n"
                                f"  (update accounts account {{'balance: new-balance}}))"
                            ),
                            tags=self.tags,
                            confidence=0.8,
                        ))
        return findings


class R003_HardcodedAdminKeyset(BaseRule):
    """
    RULE R-003: Hardcoded keyset names or admin keys as string literals.
    Detects string literals used directly in keyset definitions or enforce-guard
    that look like hardcoded admin accounts.
    """
    rule_id = "R-003"
    title = "Hardcoded Admin Keyset / Key Reference"
    severity = Severity.HIGH
    tags = ["keyset", "hardcoded", "admin", "decentralization"]

    # Patterns that suggest hardcoded admin
    SUSPICIOUS_PATTERNS = [
        r'"admin"',
        r'"operator"',
        r'"root"',
        r'"owner"',
        r'"god"',
        r'"superuser"',
        r'"[a-zA-Z0-9]{64}"',   # raw 64-char public key
    ]

    def analyze(self, contract: ContractFile) -> List[Finding]:
        import re
        findings = []
        for mod in contract.modules:
            all_fns = list(mod.functions.values()) + list(mod.capabilities.values())
            for fn in all_fns:
                for node in fn.find_all(NodeType.KEYSET_REF_GUARD):
                    args = node.attributes.get("args", [])
                    for arg in args:
                        raw = arg.name or arg.raw or ""
                        for pat in self.SUSPICIOUS_PATTERNS:
                            if re.search(pat, raw, re.IGNORECASE):
                                findings.append(Finding(
                                    rule_id=self.rule_id,
                                    title=self.title,
                                    severity=self.severity,
                                    location=self._loc(mod.name, fn, node),
                                    issue=(
                                        f"Hardcoded keyset reference `{raw}` detected in "
                                        f"`{fn.name}`. This creates a privileged single point of control."
                                    ),
                                    risk=(
                                        "If the private key is compromised or the keyset is immutable, "
                                        "there is no recovery path. Hardcoded admin keys violate the "
                                        "principle of decentralized governance."
                                    ),
                                    recommendation=(
                                        "Use a governance capability (e.g., `(defcap GOVERNANCE ())`), "
                                        "parameterize the keyset through the module governance field, "
                                        "or read the keyset from a table to allow rotation."
                                    ),
                                    fixed_code_example=(
                                        "(defcap GOVERNANCE ()\n"
                                        "  (enforce-guard (keyset-ref-guard 'project.admin-keyset)))\n\n"
                                        "(defun admin-action ()\n"
                                        "  (with-capability (GOVERNANCE)\n"
                                        "    ;; protected logic here\n"
                                        "  ))"
                                    ),
                                    tags=self.tags,
                                ))
        return findings


class R004_PublicFunctionMutatingSensitiveState(BaseRule):
    """
    RULE R-004: Public functions that directly modify balance/account tables
    without routing through a protected transfer capability.
    """
    rule_id = "R-004"
    title = "Public Function Directly Modifies Sensitive State"
    severity = Severity.HIGH
    tags = ["access-control", "public-function", "sensitive-state"]

    SENSITIVE_TABLE_PATTERNS = ["account", "balance", "token", "ledger", "vault", "pool", "stake"]

    def _is_sensitive_table(self, table_name: str) -> bool:
        t = table_name.lower()
        return any(p in t for p in self.SENSITIVE_TABLE_PATTERNS)

    def analyze(self, contract: ContractFile) -> List[Finding]:
        findings = []
        for mod in contract.modules:
            for fn_name, fn in mod.functions.items():
                if fn.visibility == Visibility.PRIVATE:
                    continue
                for mutation in fn.state_mutations:
                    table = mutation.attributes.get("table", "")
                    if not self._is_sensitive_table(table):
                        continue
                    # If no capability guard AND this is a write/update to sensitive table
                    if not fn.capability_guards:
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            title=self.title,
                            severity=self.severity,
                            location=self._loc(mod.name, fn, mutation),
                            issue=(
                                f"Public function `{fn_name}` mutates sensitive table "
                                f"`{table}` without capability protection."
                            ),
                            risk=(
                                "Direct public mutation of balance/account tables enables "
                                "unauthorized fund manipulation, double-spend attacks, and "
                                "balance inflation. Critical vulnerability in DeFi contracts."
                            ),
                            recommendation=(
                                "All balance/account mutations MUST be guarded by a dedicated "
                                "transfer capability like `TRANSFER` or `DEBIT`/`CREDIT`. "
                                "Follow the coin contract pattern."
                            ),
                            fixed_code_example=(
                                "(defcap DEBIT (sender:string amount:decimal)\n"
                                "  @managed amount DEBIT-mgr\n"
                                "  (enforce-guard (at 'guard (read coin-table sender))))\n\n"
                                "(defun transfer (sender:string receiver:string amount:decimal)\n"
                                "  (with-capability (DEBIT sender amount)\n"
                                "    (update coin-table sender { 'balance: (- old-bal amount) })))"
                            ),
                            tags=self.tags,
                        ))
        return findings


class R005_MissingEnforceInCapability(BaseRule):
    """
    RULE R-005: A defcap body contains no enforce/enforce-guard/require-capability call.
    An empty or unchecked capability grants permission without verifying anything.
    """
    rule_id = "R-005"
    title = "Capability Missing Authorization Enforcement"
    severity = Severity.CRITICAL
    tags = ["capability", "enforce", "authorization"]

    def analyze(self, contract: ContractFile) -> List[Finding]:
        findings = []
        for mod in contract.modules:
            for cap_name, cap in mod.capabilities.items():
                # @event caps are informational, skip
                if cap.event:
                    continue
                # @managed caps can have empty enforcement (manager handles it)
                if cap.managed and not cap.enforcements and not cap.capabilities_required:
                    continue
                has_enforce = bool(cap.enforcements)
                has_require = bool(cap.capabilities_required)
                body_non_trivial = len(cap.body) > 0

                if body_non_trivial and not has_enforce and not has_require:
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=self.severity,
                        location=self._loc(mod.name, cap),
                        issue=(
                            f"Capability `{cap_name}` has a body but contains no `enforce`, "
                            f"`enforce-guard`, or `require-capability` call. "
                            f"It grants access unconditionally."
                        ),
                        risk=(
                            "A capability that doesn't enforce any condition is essentially a "
                            "no-op access gate — any caller can acquire it, defeating the entire "
                            "capability-based security model."
                        ),
                        recommendation=(
                            "Add an appropriate `enforce-guard` or `enforce` check inside the "
                            "capability body to verify the caller's identity or authorization."
                        ),
                        fixed_code_example=(
                            f"(defcap {cap_name} (account:string)\n"
                            f"  (enforce-guard (at 'guard (read accounts account)))\n"
                            f"  ;; or for admin: (enforce-guard (keyset-ref-guard 'ns.admin)))"
                        ),
                        tags=self.tags,
                    ))
                elif not body_non_trivial:
                    # completely empty cap
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=Severity.CRITICAL,
                        location=self._loc(mod.name, cap),
                        issue=(
                            f"Capability `{cap_name}` has an empty body — "
                            f"it grants permission to anyone without any check."
                        ),
                        risk=(
                            "Empty capabilities are equivalent to no access control. "
                            "Any transaction can acquire this capability freely."
                        ),
                        recommendation=(
                            "Define enforcement logic in the capability body. "
                            "Never deploy a capability without authorization checks."
                        ),
                        fixed_code_example=(
                            f"(defcap {cap_name} (account:string)\n"
                            f"  (enforce-guard (at 'guard (read accounts account))))"
                        ),
                        tags=self.tags,
                    ))
        return findings


class R006_StateChangeBeforeAuth(BaseRule):
    """
    RULE R-006: Checks-Effects-Interactions violation — state mutation
    appears BEFORE enforce/guard checks in function body order.
    Classic reentrancy / TOCTOU pattern.
    """
    rule_id = "R-006"
    title = "State Change Before Authorization Check (CEI Violation)"
    severity = Severity.HIGH
    tags = ["cei", "reentrancy", "ordering", "toctou"]

    def analyze(self, contract: ContractFile) -> List[Finding]:
        findings = []
        for mod in contract.modules:
            for fn_name, fn in {**mod.functions, **mod.pacts}.items():
                self._check_ordering(mod.name, fn, findings)
        return findings

    def _check_ordering(self, mod_name: str, fn: FunctionNode, findings: List[Finding]):
        """Walk through body nodes linearly and flag mutation before enforce."""
        first_mutation_line = None
        first_mutation_node = None

        for node in fn.body:
            lines = self._collect_node_lines(node)
            for (line, n) in lines:
                nt = n.node_type
                if nt in (NodeType.WRITE, NodeType.UPDATE, NodeType.INSERT, NodeType.DELETE):
                    if first_mutation_line is None:
                        first_mutation_line = line
                        first_mutation_node = n
                elif nt in (NodeType.ENFORCE, NodeType.ENFORCE_GUARD, NodeType.ENFORCE_ONE):
                    if first_mutation_line is not None and line > first_mutation_line:
                        # enforce AFTER mutation — CEI violation
                        loc = Location(
                            module=mod_name, function=fn.name,
                            line=first_mutation_line
                        )
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            title=self.title,
                            severity=self.severity,
                            location=loc,
                            issue=(
                                f"In `{fn.name}`: state mutation at line {first_mutation_line} "
                                f"occurs BEFORE enforce check at line {line}. "
                                f"Table: `{first_mutation_node.attributes.get('table', '?')}`."
                            ),
                            risk=(
                                "Authorization checks after state changes mean a failed check "
                                "cannot undo already-committed mutations. In Pact, database writes "
                                "within a transaction are only rolled back on tx failure, but "
                                "intermediate state can be read by concurrent/nested calls."
                            ),
                            recommendation=(
                                "Follow Checks-Effects-Interactions: ALL enforce/guard checks "
                                "must appear BEFORE any state mutations. Restructure the function "
                                "to validate first, then mutate."
                            ),
                            fixed_code_example=(
                                f"(defun {fn.name} (...)\n"
                                f"  ;; 1. CHECKS first\n"
                                f"  (enforce (> amount 0.0) \"Amount must be positive\")\n"
                                f"  (enforce-guard (at 'guard (read accounts sender)))\n"
                                f"  ;; 2. EFFECTS after\n"
                                f"  (update accounts sender {{'balance: new-balance}}))"
                            ),
                            tags=self.tags,
                            confidence=0.85,
                        ))
                        return  # one finding per function

    def _collect_node_lines(self, node: ASTNode) -> List[Tuple[int, ASTNode]]:
        """Flatten a node tree into (line, node) pairs in order."""
        results = []
        if node.location:
            results.append((node.location.line, node))
        for child in node.children:
            results.extend(self._collect_node_lines(child))
        return results


class R007_UnguardedAdminFunction(BaseRule):
    """
    RULE R-007: Functions named with admin/init/upgrade/migrate patterns
    that lack module governance or capability guards.
    """
    rule_id = "R-007"
    title = "Unguarded Administrative Function"
    severity = Severity.CRITICAL
    tags = ["admin", "access-control", "governance"]

    ADMIN_PATTERNS = ["init", "admin", "upgrade", "migrate", "pause", "unpause",
                      "set-owner", "set-admin", "emergency", "destroy", "mint"]

    def analyze(self, contract: ContractFile) -> List[Finding]:
        findings = []
        for mod in contract.modules:
            for fn_name, fn in mod.functions.items():
                is_admin = any(pat in fn_name.lower() for pat in self.ADMIN_PATTERNS)
                if not is_admin:
                    continue
                has_guard = bool(fn.capability_guards or fn.capabilities_required or fn.enforcements)
                if not has_guard:
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=self.severity,
                        location=self._loc(mod.name, fn),
                        issue=(
                            f"Administrative function `{fn_name}` lacks any capability guard, "
                            f"enforce check, or require-capability. It is publicly callable "
                            f"without restriction."
                        ),
                        risk=(
                            "Unguarded admin/init functions are primary attack vectors. "
                            "Attackers can call them post-deployment to seize control, "
                            "drain funds, or disable the contract."
                        ),
                        recommendation=(
                            "Protect all administrative functions with a `GOVERNANCE` or "
                            "`ADMIN` capability that enforces the module's governing keyset. "
                            "Consider adding a deployment-time init guard."
                        ),
                        fixed_code_example=(
                            "(defcap GOVERNANCE ()\n"
                            "  (enforce-guard (keyset-ref-guard 'ns.admin-ks)))\n\n"
                            f"(defun {fn_name} (...)\n"
                            f"  (with-capability (GOVERNANCE)\n"
                            f"    ;; admin logic here\n"
                            f"  ))"
                        ),
                        tags=self.tags,
                    ))
        return findings


class R008_UnsafeDefpactFallback(BaseRule):
    """
    RULE R-008: Multi-step pacts (defpact) without proper rollback logic
    or cross-chain pact steps lacking authentication.
    """
    rule_id = "R-008"
    title = "Unsafe Multi-Step Pact (defpact) Logic"
    severity = Severity.HIGH
    tags = ["defpact", "multi-step", "rollback", "cross-chain"]

    def analyze(self, contract: ContractFile) -> List[Finding]:
        findings = []
        for mod in contract.modules:
            for pact_name, pact in mod.pacts.items():
                # Check: pact has mutations but no capability guard
                if pact.state_mutations and not pact.capability_guards:
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=self.severity,
                        location=self._loc(mod.name, pact),
                        issue=(
                            f"defpact `{pact_name}` contains state mutations but no "
                            f"capability guards. Pact steps can be resumed by any account."
                        ),
                        risk=(
                            "Multi-step pacts without per-step authentication allow adversaries "
                            "to resume pact execution out of sequence or with manipulated state, "
                            "enabling double-spend attacks in cross-chain bridge scenarios."
                        ),
                        recommendation=(
                            "Each pact step that mutates state should require an appropriate "
                            "capability. Use `(require-capability ...)` in each step to bind "
                            "the authorized initiator across all steps."
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


class R009_WeakGuardPattern(BaseRule):
    """
    RULE R-009: Detects guards constructed with user-supplied data directly,
    creating bypassable guards (e.g., create-user-guard with no validation).
    """
    rule_id = "R-009"
    title = "Weak or Bypassable Guard Construction"
    severity = Severity.HIGH
    tags = ["guard", "authentication", "user-controlled"]

    def analyze(self, contract: ContractFile) -> List[Finding]:
        findings = []
        for mod in contract.modules:
            all_fns = list(mod.functions.values()) + list(mod.capabilities.values())
            for fn in all_fns:
                for node in fn.find_all(NodeType.CREATE_USER_GUARD):
                    # create-user-guard taking a parameter directly without validation
                    args = node.children
                    # If the argument is a function call that takes user-controlled data
                    for arg in args:
                        if arg.node_type == NodeType.IDENTIFIER:
                            # Direct user-param reference — potentially unsafe
                            findings.append(Finding(
                                rule_id=self.rule_id,
                                title=self.title,
                                severity=self.severity,
                                location=self._loc(mod.name, fn, node),
                                issue=(
                                    f"In `{fn.name}`: `create-user-guard` is called with "
                                    f"potentially user-controlled argument `{arg.name}`. "
                                    f"Without validation, a malicious guard function can be injected."
                                ),
                                risk=(
                                    "User-supplied guard functions can be crafted to always succeed, "
                                    "bypass ownership checks, or execute malicious code when guard "
                                    "enforcement is invoked."
                                ),
                                recommendation=(
                                    "Validate guard construction inputs strictly. Prefer "
                                    "`keyset-ref-guard` with known keysets or pattern-match the "
                                    "guard against expected shapes before storing."
                                ),
                                fixed_code_example=(
                                    ";; Validate the account exists before creating a guard\n"
                                    "(enforce (!= account \"\") \"Account cannot be empty\")\n"
                                    "(enforce (= (typeof guard) \"guard\") \"Invalid guard type\")\n"
                                    "(let ((g (create-user-guard (validate-account account))))\n"
                                    "  (insert accounts account { 'guard: g }))"
                                ),
                                tags=self.tags,
                                confidence=0.75,
                            ))
        return findings


class R010_UnprotectedTableInit(BaseRule):
    """
    RULE R-010: Tables initialized/created in functions lacking governance
    protection, allowing race conditions at deployment.
    """
    rule_id = "R-010"
    title = "Unprotected Table Initialization"
    severity = Severity.MEDIUM
    tags = ["table", "initialization", "deployment"]

    def analyze(self, contract: ContractFile) -> List[Finding]:
        findings = []
        for mod in contract.modules:
            init_fns = [fn for name, fn in mod.functions.items()
                        if "init" in name.lower() or "create" in name.lower()]
            for fn in init_fns:
                if fn.state_mutations and not fn.capability_guards and not fn.enforcements:
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=self.severity,
                        location=self._loc(mod.name, fn),
                        issue=(
                            f"Initialization function `{fn.name}` inserts/writes to tables "
                            f"without governance protection."
                        ),
                        risk=(
                            "Race conditions at deployment: an attacker monitoring the mempool "
                            "can front-run the init call, seeding tables with malicious initial "
                            "state before the legitimate operator."
                        ),
                        recommendation=(
                            "Protect all init functions with a governance capability or "
                            "a one-time initialization guard that can only succeed once."
                        ),
                        fixed_code_example=(
                            "(defun init ()\n"
                            "  (with-capability (GOVERNANCE)\n"
                            "    (insert config-table 'init {\n"
                            "      'initialized: true,\n"
                            "      'admin: (read-msg 'admin)\n"
                            "    })))"
                        ),
                        tags=self.tags,
                    ))
        return findings


class R011_ReentrancyViaCompose(BaseRule):
    """
    RULE R-011: Detects patterns where compose-capability is used to
    acquire multiple capabilities in a way that could create circular
    authorization chains.
    """
    rule_id = "R-011"
    title = "Potential Capability Composition Re-entrancy"
    severity = Severity.MEDIUM
    tags = ["reentrancy", "capability", "compose-capability"]

    def analyze(self, contract: ContractFile) -> List[Finding]:
        findings = []
        for mod in contract.modules:
            # Build a capability composition graph
            cap_graph: dict = {}
            for cap_name, cap in mod.capabilities.items():
                composed = cap.capabilities_composed
                cap_graph[cap_name] = set(composed)

            # Detect cycles
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
                            f"Circular capability composition detected: "
                            f"{' -> '.join(cycle + [cycle[0]])}"
                        ),
                        risk=(
                            "Circular capability composition can create unexpected permission "
                            "escalation paths where granting one capability transitively grants "
                            "unintended capabilities."
                        ),
                        recommendation=(
                            "Ensure capability composition graphs are acyclic. "
                            "Use explicit, one-directional delegation. "
                            "Review each compose-capability to confirm the permission model."
                        ),
                        fixed_code_example=(
                            ";; Break the cycle: CAP-A should NOT compose CAP-B\n"
                            ";; if CAP-B already composes CAP-A\n"
                            "(defcap CAP-A (account:string)\n"
                            "  (enforce-guard (at 'guard (read accounts account))))\n\n"
                            "(defcap CAP-B (account:string)\n"
                            "  (compose-capability (CAP-A account)))  ;; one direction only"
                        ),
                        tags=self.tags,
                    ))
        return findings

    def _find_cycle(self, node: str, graph: dict, visited: Set[str],
                    path: List[str]) -> Optional[List[str]]:
        if node in visited:
            if node in path:
                return path[path.index(node):]
            return None
        visited.add(node)
        path.append(node)
        for neighbor in graph.get(node, []):
            result = self._find_cycle(neighbor, graph, visited, path)
            if result:
                return result
        path.pop()
        visited.discard(node)
        return None


class R012_MissingManagedCapability(BaseRule):
    """
    RULE R-012: Transfer-like functions using capabilities without @managed annotation.
    Managed capabilities prevent double-spending by tracking how much of a resource
    has been authorized.
    """
    rule_id = "R-012"
    title = "Transfer Capability Missing @managed Annotation"
    severity = Severity.HIGH
    tags = ["managed-capability", "double-spend", "transfer"]

    TRANSFER_PATTERNS = ["transfer", "debit", "withdraw", "send", "pay"]

    def analyze(self, contract: ContractFile) -> List[Finding]:
        findings = []
        for mod in contract.modules:
            for cap_name, cap in mod.capabilities.items():
                is_transfer = any(p in cap_name.lower() for p in self.TRANSFER_PATTERNS)
                if is_transfer and not cap.managed and not cap.event:
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=self.severity,
                        location=self._loc(mod.name, cap),
                        issue=(
                            f"Capability `{cap_name}` appears to be a transfer/payment "
                            f"capability but lacks `@managed` annotation. Without management, "
                            f"the same capability grant can be consumed multiple times."
                        ),
                        risk=(
                            "Unmanaged transfer capabilities allow the same authorization to be "
                            "used multiple times within a transaction, enabling double-spend attacks "
                            "and draining accounts beyond the authorized amount."
                        ),
                        recommendation=(
                            "Add `@managed amount TRANSFER-mgr` to the capability and implement "
                            "a manager function that enforces the amount constraint, "
                            "following the standard coin contract pattern."
                        ),
                        fixed_code_example=(
                            f"(defcap {cap_name} (sender:string receiver:string amount:decimal)\n"
                            f"  @managed amount {cap_name}-mgr\n"
                            f"  (enforce-guard (at 'guard (read accounts sender))))\n\n"
                            f"(defun {cap_name}-mgr:decimal (managed:decimal requested:decimal)\n"
                            f"  (enforce (>= managed requested) \"Insufficient authorization\")\n"
                            f"  (- managed requested))"
                        ),
                        tags=self.tags,
                    ))
        return findings


# ─────────────────────────────────────────
# Rule Registry
# ─────────────────────────────────────────

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


def get_rules(severity_filter: Optional[str] = None,
              tag_filter: Optional[List[str]] = None) -> List[BaseRule]:
    rules = list(ALL_RULES)
    if severity_filter:
        rules = [r for r in rules if r.severity.value == severity_filter]
    if tag_filter:
        rules = [r for r in rules if any(t in r.tags for t in tag_filter)]
    return rules
