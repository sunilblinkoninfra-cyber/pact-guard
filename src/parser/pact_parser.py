"""
Pact Smart Contract Parser
Builds a structured AST from Pact source code using recursive descent parsing.
Handles: modules, defun, defcap, defschema, deftable, defconst, defpact,
         with-capability, require-capability, enforce, enforce-guard,
         read/write/update/insert/delete, keyset operations.
"""
import re
from typing import List, Optional, Tuple, Dict, Any
from .ast_nodes import (
    ASTNode, FunctionNode, ModuleNode, ContractFile,
    NodeType, SourceLocation, Visibility
)


# ─────────────────────────────────────────
# Tokenizer
# ─────────────────────────────────────────

class Token:
    __slots__ = ("type", "value", "line", "col")

    def __init__(self, type_: str, value: str, line: int, col: int):
        self.type = type_
        self.value = value
        self.line = line
        self.col = col

    def __repr__(self):
        return f"Token({self.type}, {self.value!r}, L{self.line})"


TOKEN_PATTERNS = [
    ("COMMENT",    r';[^\n]*'),
    ("STRING",     r'"(?:[^"\\]|\\.)*"'),
    ("NUMBER",     r'-?\d+\.?\d*'),
    ("BOOL",       r'\b(?:true|false)\b'),
    ("LPAREN",     r'\('),
    ("RPAREN",     r'\)'),
    ("LBRACKET",   r'\['),
    ("RBRACKET",   r'\]'),
    ("LBRACE",     r'\{'),
    ("RBRACE",     r'\}'),
    ("AT",         r'@'),
    ("COLON",      r':'),
    ("DOT",        r'\.'),
    ("BACKTICK",   r'`'),
    ("SYMBOL",     r"'[a-zA-Z_\-][a-zA-Z0-9_\-/]*"),
    ("IDENT",      r'[a-zA-Z_\-][a-zA-Z0-9_\-\.\/\?\!]*'),
    ("WHITESPACE", r'[ \t\r\n]+'),
]

MASTER_PATTERN = re.compile(
    '|'.join(f'(?P<{name}>{pat})' for name, pat in TOKEN_PATTERNS)
)


def tokenize(source: str) -> List[Token]:
    tokens = []
    line = 1
    line_start = 0
    for m in MASTER_PATTERN.finditer(source):
        kind = m.lastgroup
        value = m.group()
        col = m.start() - line_start
        newlines = value.count('\n')
        if kind in ("WHITESPACE", "COMMENT"):
            if newlines:
                line += newlines
                line_start = m.end() - len(value.split('\n')[-1])
            continue
        tokens.append(Token(kind, value, line, col))
        if newlines:
            line += newlines
            line_start = m.end() - len(value.split('\n')[-1])
    return tokens


# ─────────────────────────────────────────
# Recursive Descent Parser
# ─────────────────────────────────────────

class PactParser:
    """
    Recursive descent parser for Pact smart contracts.
    Builds a ContractFile AST from tokenized source.
    """

    STATE_MUTATION_OPS = {"write", "update", "insert", "delete", "with-default-read"}
    READ_OPS = {"read", "select", "keys", "fold-db"}
    AUTH_OPS = {"enforce", "enforce-one", "enforce-guard", "require-capability"}
    CAPABILITY_OPS = {"with-capability", "require-capability", "compose-capability",
                      "install-capability", "emit-event"}
    KEYSET_OPS = {"define-keyset", "read-keyset", "keyset-ref-guard",
                  "create-user-guard", "create-keyset-guard"}

    def __init__(self, source: str, filename: str = "<string>"):
        self.source = source
        self.filename = filename
        self.tokens = tokenize(source)
        self.pos = 0
        self.raw_lines = source.splitlines()

    # ── Token helpers ──────────────────────────────

    def peek(self, offset: int = 0) -> Optional[Token]:
        idx = self.pos + offset
        return self.tokens[idx] if idx < len(self.tokens) else None

    def advance(self) -> Optional[Token]:
        tok = self.peek()
        self.pos += 1
        return tok

    def expect(self, type_: str, value: str = None) -> Token:
        tok = self.advance()
        if tok is None:
            raise SyntaxError(f"Expected {type_!r} but reached end of file")
        if tok.type != type_:
            raise SyntaxError(
                f"L{tok.line}: Expected token type {type_!r}, got {tok.type!r} ({tok.value!r})"
            )
        if value is not None and tok.value != value:
            raise SyntaxError(
                f"L{tok.line}: Expected {value!r}, got {tok.value!r}"
            )
        return tok

    def match(self, type_: str, value: str = None) -> bool:
        tok = self.peek()
        if tok is None:
            return False
        if tok.type != type_:
            return False
        if value is not None and tok.value != value:
            return False
        return True

    def match_ident(self, value: str) -> bool:
        return self.match("IDENT", value)

    def loc(self, tok: Token) -> SourceLocation:
        return SourceLocation(line=tok.line, col=tok.col)

    # ── S-expression parser ────────────────────────

    def parse_sexp(self) -> Optional[ASTNode]:
        """Parse any s-expression. Returns an ASTNode."""
        tok = self.peek()
        if tok is None:
            return None

        if tok.type == "LPAREN":
            return self.parse_list()
        elif tok.type == "LBRACKET":
            return self.parse_vector()
        elif tok.type == "LBRACE":
            return self.parse_object()
        elif tok.type in ("STRING", "NUMBER", "BOOL", "SYMBOL"):
            self.advance()
            return ASTNode(NodeType.LITERAL, name=tok.value,
                           location=self.loc(tok), raw=tok.value)
        elif tok.type == "IDENT":
            self.advance()
            return ASTNode(NodeType.IDENTIFIER, name=tok.value,
                           location=self.loc(tok), raw=tok.value)
        elif tok.type == "AT":
            return self.parse_decorator()
        elif tok.type == "RPAREN":
            return None  # caller handles closing paren
        else:
            self.advance()
            return ASTNode(NodeType.UNKNOWN, name=tok.value,
                           location=self.loc(tok), raw=tok.value)

    def parse_list(self) -> ASTNode:
        """Parse a parenthesized list, recognizing special forms."""
        lparen = self.expect("LPAREN")
        loc = self.loc(lparen)

        head = self.peek()
        if head is None or head.type == "RPAREN":
            self.advance()
            return ASTNode(NodeType.UNKNOWN, name="()", location=loc)

        # Dispatch on head keyword
        if head.type == "IDENT":
            v = head.value
            if v == "module":
                return self._parse_module(loc)
            elif v == "defun":
                return self._parse_defun(loc)
            elif v == "defcap":
                return self._parse_defcap(loc)
            elif v == "defschema":
                return self._parse_defschema(loc)
            elif v == "deftable":
                return self._parse_deftable(loc)
            elif v == "defconst":
                return self._parse_defconst(loc)
            elif v == "defpact":
                return self._parse_defpact(loc)
            elif v == "with-capability":
                return self._parse_with_capability(loc)
            elif v == "require-capability":
                return self._parse_require_capability(loc)
            elif v == "compose-capability":
                return self._parse_compose_capability(loc)
            elif v in ("enforce", "enforce-one", "enforce-guard"):
                return self._parse_enforce(loc, v)
            elif v in self.STATE_MUTATION_OPS:
                return self._parse_state_op(loc, v)
            elif v in self.READ_OPS:
                return self._parse_state_op(loc, v)
            elif v in self.KEYSET_OPS:
                return self._parse_keyset_op(loc, v)
            elif v in ("let", "let*"):
                return self._parse_let(loc)
            elif v == "bind":
                return self._parse_bind(loc)
            elif v == "if":
                return self._parse_if(loc)
            elif v == "define-keyset":
                return self._parse_keyset_op(loc, v)
            else:
                return self._parse_generic_call(loc)
        else:
            return self._parse_generic_call(loc)

    def _consume_until_rparen(self) -> List[ASTNode]:
        """Consume s-expressions until RPAREN."""
        children = []
        while self.peek() and not self.match("RPAREN"):
            node = self.parse_sexp()
            if node:
                children.append(node)
        if self.match("RPAREN"):
            self.advance()
        return children

    def _parse_generic_call(self, loc: SourceLocation) -> ASTNode:
        head = self.advance()  # function name
        children = []
        while self.peek() and not self.match("RPAREN"):
            node = self.parse_sexp()
            if node:
                children.append(node)
        if self.match("RPAREN"):
            self.advance()
        name = head.value if head else ""
        node_type = NodeType.CALL
        return ASTNode(node_type, name=name, location=loc, children=children)

    def parse_vector(self) -> ASTNode:
        self.expect("LBRACKET")
        children = []
        while self.peek() and not self.match("RBRACKET"):
            n = self.parse_sexp()
            if n:
                children.append(n)
        if self.match("RBRACKET"):
            self.advance()
        return ASTNode(NodeType.LITERAL, name="vector", children=children)

    def parse_object(self) -> ASTNode:
        self.expect("LBRACE")
        pairs = []
        while self.peek() and not self.match("RBRACE"):
            n = self.parse_sexp()
            if n:
                pairs.append(n)
        if self.match("RBRACE"):
            self.advance()
        return ASTNode(NodeType.LITERAL, name="object", children=pairs)

    def parse_decorator(self) -> ASTNode:
        at_tok = self.advance()  # @
        name_tok = self.advance()
        loc = self.loc(at_tok)
        return ASTNode(NodeType.UNKNOWN, name=f"@{name_tok.value if name_tok else ''}",
                       location=loc)

    def _parse_params(self) -> List[str]:
        """Parse a parameter list like (param1:type param2:type ...)"""
        params = []
        if not self.match("LPAREN"):
            return params
        self.advance()  # (
        while self.peek() and not self.match("RPAREN"):
            tok = self.advance()
            if tok and tok.type == "IDENT":
                name = tok.value
                # skip :type annotation
                if self.match("COLON"):
                    self.advance()
                    self._skip_type()
                params.append(name)
            elif tok and tok.type in ("LBRACE", "RBRACE"):
                pass  # skip object type syntax
        if self.match("RPAREN"):
            self.advance()
        return params

    def _skip_type(self):
        """Skip a type annotation (possibly complex like [object{schema}])"""
        tok = self.peek()
        if tok is None:
            return
        if tok.type == "LBRACKET":
            self.parse_vector()
        elif tok.type == "LBRACE":
            self.parse_object()
        elif tok.type == "IDENT":
            self.advance()
            # check for qualified name like module.type
            if self.match("IDENT") or self.match("DOT"):
                pass
        else:
            self.advance()

    def _parse_doc_string(self) -> str:
        if self.match("STRING"):
            tok = self.advance()
            return tok.value.strip('"')
        return ""

    # ── Top-level forms ─────────────────────────────

    def _parse_module(self, loc: SourceLocation) -> ModuleNode:
        self.advance()  # consume 'module'
        name_tok = self.advance()
        name = name_tok.value if name_tok else "unknown"
        # governance: keyset name or capability
        gov_tok = self.advance()
        governance = gov_tok.value if gov_tok else ""

        mod = ModuleNode(
            node_type=NodeType.MODULE,
            name=name,
            governance=governance,
            location=loc
        )

        # Optional doc string
        mod.attributes["doc"] = self._parse_doc_string()

        # Parse body
        while self.peek() and not self.match("RPAREN"):
            tok = self.peek()
            if tok and tok.type == "IDENT" and tok.value == "use":
                self.advance()  # use
                imp = self.advance()
                mod.imports.append(imp.value if imp else "")
                # skip version/hash
                while self.peek() and not self.match("RPAREN") and not self.match("LPAREN"):
                    self.advance()
                continue
            node = self.parse_sexp()
            if node is None:
                continue
            if isinstance(node, FunctionNode):
                if node.node_type == NodeType.DEFCAP:
                    mod.capabilities[node.name] = node
                elif node.node_type == NodeType.DEFPACT:
                    mod.pacts[node.name] = node
                else:
                    mod.functions[node.name] = node
            elif node.node_type == NodeType.DEFSCHEMA:
                mod.schemas[node.name] = node
            elif node.node_type == NodeType.DEFTABLE:
                mod.tables[node.name] = node
            elif node.node_type == NodeType.DEFCONST:
                mod.constants[node.name] = node

        if self.match("RPAREN"):
            self.advance()
        return mod

    def _parse_defun(self, loc: SourceLocation) -> FunctionNode:
        self.advance()  # consume 'defun'
        name_tok = self.advance()
        name = name_tok.value if name_tok else "unknown"
        params = self._parse_params()
        doc = self._parse_doc_string()

        fn = FunctionNode(
            node_type=NodeType.DEFUN,
            name=name,
            params=params,
            doc=doc,
            location=loc
        )
        fn.visibility = Visibility.PRIVATE if name.startswith("private-") or name.startswith("-") else Visibility.PUBLIC

        # Parse body
        while self.peek() and not self.match("RPAREN"):
            node = self.parse_sexp()
            if node:
                fn.body.append(node)
                fn.children.append(node)
                self._classify_body_node(fn, node)

        if self.match("RPAREN"):
            self.advance()
        return fn

    def _parse_defcap(self, loc: SourceLocation) -> FunctionNode:
        self.advance()  # consume 'defcap'
        name_tok = self.advance()
        name = name_tok.value if name_tok else "unknown"
        params = self._parse_params()
        doc = self._parse_doc_string()

        cap = FunctionNode(
            node_type=NodeType.DEFCAP,
            name=name,
            params=params,
            doc=doc,
            location=loc
        )

        # Parse body and decorators
        while self.peek() and not self.match("RPAREN"):
            tok = self.peek()
            if tok and tok.type == "AT":
                self.advance()  # @
                attr_tok = self.advance()
                attr = attr_tok.value if attr_tok else ""
                if attr == "managed":
                    cap.managed = True
                    # optional manager function
                    while self.peek() and not self.match("RPAREN") and not self.match("LPAREN") and not self.match("AT"):
                        self.advance()
                elif attr == "event":
                    cap.event = True
                continue
            node = self.parse_sexp()
            if node:
                cap.body.append(node)
                cap.children.append(node)
                self._classify_body_node(cap, node)

        if self.match("RPAREN"):
            self.advance()
        return cap

    def _parse_defschema(self, loc: SourceLocation) -> ASTNode:
        self.advance()  # defschema
        name_tok = self.advance()
        name = name_tok.value if name_tok else "unknown"
        doc = self._parse_doc_string()
        fields = {}
        while self.peek() and not self.match("RPAREN"):
            field_tok = self.advance()
            if field_tok and field_tok.type == "IDENT":
                fname = field_tok.value
                if self.match("COLON"):
                    self.advance()
                    self._skip_type()
                fields[fname] = None
            elif field_tok and field_tok.type == "STRING":
                pass  # doc string
        if self.match("RPAREN"):
            self.advance()
        node = ASTNode(NodeType.DEFSCHEMA, name=name, location=loc)
        node.attributes["fields"] = fields
        node.attributes["doc"] = doc
        return node

    def _parse_deftable(self, loc: SourceLocation) -> ASTNode:
        self.advance()  # deftable
        name_tok = self.advance()
        name = name_tok.value if name_tok else "unknown"
        # skip schema annotation :{module.schema}
        while self.peek() and not self.match("RPAREN"):
            self.advance()
        if self.match("RPAREN"):
            self.advance()
        node = ASTNode(NodeType.DEFTABLE, name=name, location=loc)
        return node

    def _parse_defconst(self, loc: SourceLocation) -> ASTNode:
        self.advance()  # defconst
        name_tok = self.advance()
        name = name_tok.value if name_tok else "unknown"
        val = self.parse_sexp()
        doc = self._parse_doc_string()
        while self.peek() and not self.match("RPAREN"):
            self.advance()
        if self.match("RPAREN"):
            self.advance()
        node = ASTNode(NodeType.DEFCONST, name=name, location=loc)
        node.attributes["value"] = val
        node.attributes["doc"] = doc
        return node

    def _parse_defpact(self, loc: SourceLocation) -> FunctionNode:
        self.advance()  # defpact
        name_tok = self.advance()
        name = name_tok.value if name_tok else "unknown"
        params = self._parse_params()
        doc = self._parse_doc_string()

        pact = FunctionNode(
            node_type=NodeType.DEFPACT,
            name=name,
            params=params,
            doc=doc,
            location=loc
        )

        while self.peek() and not self.match("RPAREN"):
            node = self.parse_sexp()
            if node:
                pact.body.append(node)
                pact.children.append(node)
                self._classify_body_node(pact, node)

        if self.match("RPAREN"):
            self.advance()
        return pact

    def _parse_with_capability(self, loc: SourceLocation) -> ASTNode:
        self.advance()  # with-capability
        cap_call = self.parse_sexp()  # (CAP-NAME args...)
        cap_name = cap_call.name if cap_call else "unknown"
        node = ASTNode(NodeType.WITH_CAPABILITY, name=cap_name, location=loc)
        node.attributes["capability"] = cap_name
        node.children.append(cap_call)
        # body
        body_nodes = []
        while self.peek() and not self.match("RPAREN"):
            n = self.parse_sexp()
            if n:
                body_nodes.append(n)
                node.children.append(n)
        if self.match("RPAREN"):
            self.advance()
        node.attributes["body"] = body_nodes
        return node

    def _parse_require_capability(self, loc: SourceLocation) -> ASTNode:
        self.advance()  # require-capability
        cap_call = self.parse_sexp()
        cap_name = cap_call.name if cap_call else "unknown"
        node = ASTNode(NodeType.REQUIRE_CAPABILITY, name=cap_name, location=loc)
        node.attributes["capability"] = cap_name
        if self.match("RPAREN"):
            self.advance()
        return node

    def _parse_compose_capability(self, loc: SourceLocation) -> ASTNode:
        self.advance()  # compose-capability
        cap_call = self.parse_sexp()
        cap_name = cap_call.name if cap_call else "unknown"
        node = ASTNode(NodeType.COMPOSE_CAPABILITY, name=cap_name, location=loc)
        node.attributes["capability"] = cap_name
        if self.match("RPAREN"):
            self.advance()
        return node

    def _parse_enforce(self, loc: SourceLocation, variant: str) -> ASTNode:
        self.advance()  # consume enforce/enforce-one/enforce-guard
        type_map = {
            "enforce": NodeType.ENFORCE,
            "enforce-one": NodeType.ENFORCE_ONE,
            "enforce-guard": NodeType.ENFORCE_GUARD,
        }
        node = ASTNode(type_map.get(variant, NodeType.ENFORCE), name=variant, location=loc)
        args = []
        while self.peek() and not self.match("RPAREN"):
            n = self.parse_sexp()
            if n:
                args.append(n)
                node.children.append(n)
        if self.match("RPAREN"):
            self.advance()
        node.attributes["args"] = args
        return node

    def _parse_state_op(self, loc: SourceLocation, op: str) -> ASTNode:
        self.advance()  # consume op name
        type_map = {
            "write": NodeType.WRITE,
            "update": NodeType.UPDATE,
            "insert": NodeType.INSERT,
            "delete": NodeType.DELETE,
            "read": NodeType.READ,
            "select": NodeType.READ,
            "keys": NodeType.READ,
            "fold-db": NodeType.READ,
            "with-default-read": NodeType.READ,
        }
        node = ASTNode(type_map.get(op, NodeType.UNKNOWN), name=op, location=loc)
        args = []
        while self.peek() and not self.match("RPAREN"):
            n = self.parse_sexp()
            if n:
                args.append(n)
                node.children.append(n)
        if self.match("RPAREN"):
            self.advance()
        # First arg is typically the table name
        if args:
            node.attributes["table"] = args[0].name if args[0] else ""
        return node

    def _parse_keyset_op(self, loc: SourceLocation, op: str) -> ASTNode:
        self.advance()  # consume op name
        type_map = {
            "define-keyset": NodeType.KEYSET_DEFINE,
            "read-keyset": NodeType.KEYSET_READ,
            "keyset-ref-guard": NodeType.KEYSET_REF_GUARD,
            "create-user-guard": NodeType.CREATE_USER_GUARD,
        }
        node = ASTNode(type_map.get(op, NodeType.UNKNOWN), name=op, location=loc)
        args = []
        while self.peek() and not self.match("RPAREN"):
            n = self.parse_sexp()
            if n:
                args.append(n)
                node.children.append(n)
        if self.match("RPAREN"):
            self.advance()
        node.attributes["args"] = args
        return node

    def _parse_let(self, loc: SourceLocation) -> ASTNode:
        self.advance()  # let / let*
        node = ASTNode(NodeType.LET, name="let", location=loc)
        # bindings
        if self.match("LPAREN"):
            self.advance()
            while self.peek() and not self.match("RPAREN"):
                n = self.parse_sexp()
                if n:
                    node.children.append(n)
            if self.match("RPAREN"):
                self.advance()
        # body
        while self.peek() and not self.match("RPAREN"):
            n = self.parse_sexp()
            if n:
                node.children.append(n)
        if self.match("RPAREN"):
            self.advance()
        return node

    def _parse_bind(self, loc: SourceLocation) -> ASTNode:
        self.advance()  # bind
        node = ASTNode(NodeType.BIND, name="bind", location=loc)
        children = self._consume_until_rparen()
        node.children = children
        return node

    def _parse_if(self, loc: SourceLocation) -> ASTNode:
        self.advance()  # if
        node = ASTNode(NodeType.IF, name="if", location=loc)
        children = self._consume_until_rparen()
        node.children = children
        return node

    # ── Body node classification ────────────────────

    def _classify_body_node(self, fn: FunctionNode, node: ASTNode):
        """Walk a body node and populate capability/mutation/enforcement lists on fn."""
        if node is None:
            return
        nt = node.node_type
        if nt == NodeType.WITH_CAPABILITY:
            cap = node.attributes.get("capability", node.name)
            fn.capability_guards.append(cap)
            # Recurse into body
            for body_node in node.attributes.get("body", []):
                self._classify_body_node(fn, body_node)
        elif nt == NodeType.REQUIRE_CAPABILITY:
            fn.capabilities_required.append(node.attributes.get("capability", node.name))
        elif nt == NodeType.COMPOSE_CAPABILITY:
            fn.capabilities_composed.append(node.attributes.get("capability", node.name))
        elif nt in (NodeType.WRITE, NodeType.UPDATE, NodeType.INSERT, NodeType.DELETE):
            fn.state_mutations.append(node)
        elif nt in (NodeType.ENFORCE, NodeType.ENFORCE_ONE, NodeType.ENFORCE_GUARD):
            fn.enforcements.append(node)
        # Recurse into children
        for child in node.children:
            self._classify_body_node(fn, child)

    # ── Entry point ─────────────────────────────────

    def parse(self) -> ContractFile:
        contract = ContractFile(
            source=self.source,
            filename=self.filename,
            raw_lines=self.raw_lines
        )

        while self.peek():
            tok = self.peek()
            if tok.type == "LPAREN":
                node = self.parse_sexp()
                if isinstance(node, ModuleNode):
                    contract.modules.append(node)
                elif node and node.node_type in (NodeType.KEYSET_DEFINE,):
                    contract.top_level_keysets.append(node)
                # top-level bare expressions (ignored)
            else:
                self.advance()  # skip stray tokens

        return contract


# ── Public API ───────────────────────────────────────

def parse_contract(source: str, filename: str = "<string>") -> ContractFile:
    """Parse Pact source and return a ContractFile AST."""
    parser = PactParser(source, filename)
    return parser.parse()


def parse_file(path: str) -> ContractFile:
    """Parse a Pact file from disk."""
    with open(path, "r", encoding="utf-8") as f:
        source = f.read()
    return parse_contract(source, filename=path)
