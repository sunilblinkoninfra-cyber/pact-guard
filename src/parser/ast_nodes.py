"""
Pact AST Node Definitions
Structured representation of Pact smart contract elements
"""
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from enum import Enum


class NodeType(Enum):
    MODULE = "module"
    DEFUN = "defun"
    DEFCAP = "defcap"
    DEFSCHEMA = "defschema"
    DEFTABLE = "deftable"
    DEFCONST = "defconst"
    DEFPACT = "defpact"
    CALL = "call"
    WITH_CAPABILITY = "with-capability"
    REQUIRE_CAPABILITY = "require-capability"
    COMPOSE_CAPABILITY = "compose-capability"
    ENFORCE = "enforce"
    ENFORCE_ONE = "enforce-one"
    ENFORCE_GUARD = "enforce-guard"
    KEYSET_REF_GUARD = "keyset-ref-guard"
    CREATE_USER_GUARD = "create-user-guard"
    READ = "read"
    WRITE = "write"
    UPDATE = "update"
    INSERT = "insert"
    DELETE = "delete"
    LET = "let"
    BIND = "bind"
    IF = "if"
    LAMBDA = "lambda"
    LITERAL = "literal"
    IDENTIFIER = "identifier"
    KEYSET_DEFINE = "define-keyset"
    KEYSET_READ = "read-keyset"
    COIN_TRANSFER = "coin.transfer"
    UNKNOWN = "unknown"


class Visibility(Enum):
    PUBLIC = "public"
    PRIVATE = "private"  # starts with `private-` by convention


@dataclass
class SourceLocation:
    line: int
    col: int = 0
    end_line: int = 0

    def to_dict(self):
        return {"line": self.line, "col": self.col}


@dataclass
class ASTNode:
    node_type: NodeType
    name: str = ""
    location: Optional[SourceLocation] = None
    children: List["ASTNode"] = field(default_factory=list)
    attributes: Dict[str, Any] = field(default_factory=dict)
    raw: str = ""

    def find_all(self, node_type: NodeType) -> List["ASTNode"]:
        """Recursively find all nodes of a given type."""
        results = []
        if self.node_type == node_type:
            results.append(self)
        for child in self.children:
            results.extend(child.find_all(node_type))
        return results

    def find_first(self, node_type: NodeType) -> Optional["ASTNode"]:
        results = self.find_all(node_type)
        return results[0] if results else None

    def has_child_type(self, node_type: NodeType) -> bool:
        return any(c.node_type == node_type for c in self.children)


@dataclass
class FunctionNode(ASTNode):
    params: List[str] = field(default_factory=list)
    visibility: Visibility = Visibility.PUBLIC
    doc: str = ""
    body: List[ASTNode] = field(default_factory=list)
    managed: bool = False       # for defcap: @managed
    event: bool = False          # for defcap: @event
    capabilities_required: List[str] = field(default_factory=list)
    capabilities_composed: List[str] = field(default_factory=list)
    state_mutations: List[ASTNode] = field(default_factory=list)
    enforcements: List[ASTNode] = field(default_factory=list)
    capability_guards: List[str] = field(default_factory=list)


@dataclass
class ModuleNode(ASTNode):
    governance: str = ""          # keyset or capability governing module
    functions: Dict[str, FunctionNode] = field(default_factory=dict)
    capabilities: Dict[str, FunctionNode] = field(default_factory=dict)
    schemas: Dict[str, ASTNode] = field(default_factory=dict)
    tables: Dict[str, ASTNode] = field(default_factory=dict)
    constants: Dict[str, ASTNode] = field(default_factory=dict)
    pacts: Dict[str, FunctionNode] = field(default_factory=dict)
    imports: List[str] = field(default_factory=list)


@dataclass
class ContractFile:
    """Top-level representation of a parsed Pact file."""
    source: str = ""
    filename: str = ""
    modules: List[ModuleNode] = field(default_factory=list)
    top_level_keysets: List[ASTNode] = field(default_factory=list)
    raw_lines: List[str] = field(default_factory=list)

    def get_all_functions(self) -> List[FunctionNode]:
        fns = []
        for mod in self.modules:
            fns.extend(mod.functions.values())
        return fns

    def get_all_capabilities(self) -> List[FunctionNode]:
        caps = []
        for mod in self.modules:
            caps.extend(mod.capabilities.values())
        return caps
