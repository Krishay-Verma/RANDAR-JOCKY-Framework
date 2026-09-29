"""
Parser for the JOCKY DSL.

Hand-written recursive-descent parser. Produces an Investigation IR
from a token list. Grammar validation and semantic validation
(collector/rule existence) remain separate stages.

Extended grammar:

  investigation := 'investigation' STRING '{' statement* '}'

  statement := collect_stmt
             | analyze_stmt
             | report_stmt
             | let_stmt
             | if_stmt

  collect_stmt := 'collect' IDENT ';'
  analyze_stmt := 'analyze' IDENT ';'
  report_stmt  := 'report'  STRING ';'
  let_stmt     := 'let' IDENT '=' expr ';'
  if_stmt      := 'if' condition '{' statement* '}'
                  ('else' '{' statement* '}')?

  condition := expr comparison_op expr
  comparison_op := '>' | '<' | '>=' | '<=' | '==' | '!='

  expr := INTEGER
        | STRING
        | 'true' | 'false'
        | IDENT                    (variable reference)
        | IDENT '.' IDENT          (evidence property access)
"""

from jocky.language.lexer import Token, TokenType
from jocky.language.ir import (
    Investigation,
    CollectCommand, AnalyzeCommand, ReportCommand,
    LetCommand, IfCommand, UserRuleCommand,
    LiteralExpr, VarExpr, PropertyExpr,
    Condition,
    Command, Expr,
)

# IDENT-based statement keywords (excludes 'let' and 'if' which are
# their own token types and are dispatched by type, not value).
_STATEMENT_KEYWORDS = {"collect", "analyze", "report"}

# Token types that are valid comparison operators.
_COMPARISON_TYPES = {
    TokenType.GT, TokenType.LT, TokenType.GTE,
    TokenType.LTE, TokenType.EQ, TokenType.NEQ,
}


class ParseError(Exception):
    """Raised when the token stream does not match the JOCKY grammar."""
    pass


_MAX_PARSE_DEPTH = 10


class Parser:
    def __init__(self, tokens: list[Token]) -> None:
        self._tokens = tokens
        self._pos = 0
        self._depth = 0

    def _current(self) -> Token:
        return self._tokens[self._pos]

    def _advance(self) -> Token:
        tok = self._tokens[self._pos]
        self._pos += 1
        return tok

    def _expect(self, type_: TokenType, what: str) -> Token:
        tok = self._current()
        if tok.type != type_:
            raise ParseError(
                f"Line {tok.line}: expected {what}, got {tok.value!r}"
            )
        return self._advance()

    def _expect_ident(self, value: str) -> Token:
        tok = self._current()
        if tok.type != TokenType.IDENT or tok.value != value:
            raise ParseError(
                f"Line {tok.line}: expected '{value}', got {tok.value!r}"
            )
        return self._advance()

    # ── Top-level ──────────────────────────────────────────────────────────────

    def parse(self) -> Investigation:
        self._expect_ident("investigation")
        name_tok = self._expect(TokenType.STRING, "investigation name (string)")
        self._expect(TokenType.LBRACE, "'{'")

        commands = self._parse_block_contents("investigation")

        self._expect(TokenType.RBRACE, "'}'")
        self._expect(TokenType.EOF, "end of script (unexpected extra content)")

        return Investigation(name=name_tok.value, commands=commands)

    # ── Block helpers ──────────────────────────────────────────────────────────

    def _parse_block_contents(self, context: str) -> list[Command]:
        """Parse statements until RBRACE or EOF."""
        commands: list[Command] = []
        while self._current().type not in (TokenType.RBRACE, TokenType.EOF):
            commands.append(self._parse_statement())
        return commands

    # ── Statement dispatch ─────────────────────────────────────────────────────

    def _parse_statement(self) -> Command:
        tok = self._current()

        # Keyword token types dispatched by type (not value).
        if tok.type == TokenType.LET:
            return self._parse_let()
        if tok.type == TokenType.IF:
            return self._parse_if()
        if tok.type == TokenType.RULE:
            return self._parse_rule()

        # IDENT-based keywords.
        if tok.type != TokenType.IDENT or tok.value not in _STATEMENT_KEYWORDS:
            raise ParseError(
                f"Line {tok.line}: expected statement keyword "
                f"('collect', 'analyze', 'report', 'let', 'if', 'rule'), "
                f"got {tok.value!r}"
            )

        keyword = self._advance().value

        if keyword == "collect":
            arg = self._expect(TokenType.IDENT, "collector name")
            self._expect(TokenType.SEMICOLON, "';'")
            return CollectCommand(target=arg.value, line=arg.line)

        if keyword == "analyze":
            arg = self._expect(TokenType.IDENT, "rule name")
            condition = None
            if self._current().type == TokenType.WHERE:
                self._advance()
                condition = self._parse_boolean_condition()
            self._expect(TokenType.SEMICOLON, "';'")
            return AnalyzeCommand(rule=arg.value, line=arg.line, where=condition)

        # keyword == "report"
        arg = self._expect(TokenType.STRING, "report name (string)")
        self._expect(TokenType.SEMICOLON, "';'")
        return ReportCommand(name=arg.value, line=arg.line)

    # ── let ────────────────────────────────────────────────────────────────────

    def _parse_let(self) -> LetCommand:
        line = self._current().line
        self._advance()  # consume LET
        name_tok = self._expect(TokenType.IDENT, "variable name")
        self._expect(TokenType.ASSIGN, "'='")
        value = self._parse_expr()
        self._expect(TokenType.SEMICOLON, "';'")
        return LetCommand(name=name_tok.value, value=value, line=line)

    # ── if / else ──────────────────────────────────────────────────────────────

    def _parse_if(self) -> IfCommand:
        line = self._current().line
        self._advance()  # consume IF
        self._depth += 1
        if self._depth > _MAX_PARSE_DEPTH:
            raise ParseError(
                f"Line {line}: 'if' blocks nested deeper than "
                f"{_MAX_PARSE_DEPTH} levels"
            )

        condition = self._parse_condition()

        self._expect(TokenType.LBRACE, "'{' after condition")
        then_commands = self._parse_block_contents("if")
        if self._current().type == TokenType.EOF:
            raise ParseError(
                f"Line {self._current().line}: unclosed 'if' block — missing '}}'"
            )
        self._expect(TokenType.RBRACE, "'}'")

        else_commands: list[Command] = []
        if self._current().type == TokenType.ELSE:
            self._advance()  # consume ELSE
            self._expect(TokenType.LBRACE, "'{' after 'else'")
            else_commands = self._parse_block_contents("else")
            if self._current().type == TokenType.EOF:
                raise ParseError(
                    f"Line {self._current().line}: unclosed 'else' block — missing '}}'"
                )
            self._expect(TokenType.RBRACE, "'}'")

        self._depth -= 1
        return IfCommand(
            condition=condition,
            then_commands=then_commands,
            else_commands=else_commands,
            line=line,
        )

    # ── Conditions / boolean logic ─────────────────────────────────────────────

    def _parse_condition(self) -> Condition:
        return self._parse_boolean_condition()

    def _parse_boolean_condition(self) -> Condition:
        return self._parse_or_condition()

    def _parse_or_condition(self) -> Condition:
        node = self._parse_and_condition()
        children = [node]
        while self._current().type == TokenType.OR:
            self._advance(); children.append(self._parse_and_condition())
        return children[0] if len(children) == 1 else Condition(kind="or", children=children)

    def _parse_and_condition(self) -> Condition:
        node = self._parse_not_condition()
        children = [node]
        while self._current().type == TokenType.AND:
            self._advance(); children.append(self._parse_not_condition())
        return children[0] if len(children) == 1 else Condition(kind="and", children=children)

    def _parse_not_condition(self) -> Condition:
        if self._current().type == TokenType.NOT:
            line = self._current().line; self._advance()
            return Condition(kind="not", children=[self._parse_not_condition()])
        left = self._parse_expr()
        op = self._current()
        if op.type not in _COMPARISON_TYPES:
            raise ParseError(f"Line {op.line}: expected comparison operator after expression, got {op.value!r}")
        self._advance()
        right = self._parse_expr()
        return Condition(left=left, operator=op.value, right=right)

    def _parse_rule(self) -> UserRuleCommand:
        line = self._current().line; self._advance()
        name = self._expect(TokenType.STRING, "rule name (string)")
        self._expect(TokenType.LBRACE, "'{' after rule name")
        self._expect(TokenType.WHEN, "'when'")
        condition = self._parse_boolean_condition()
        self._expect(TokenType.SEMICOLON, "';'")
        self._expect(TokenType.SEVERITY, "'severity'")
        sev = self._expect(TokenType.IDENT, "severity name")
        if sev.value not in {"informational", "review_recommended", "medium", "high", "critical"}:
            raise ParseError(f"Line {sev.line}: invalid severity {sev.value!r}")
        self._expect(TokenType.SEMICOLON, "';'")
        self._expect(TokenType.RBRACE, "'}'")
        return UserRuleCommand(name=name.value, condition=condition, severity=sev.value, line=line)

    # ── Expression ─────────────────────────────────────────────────────────────

    def _parse_expr(self) -> Expr:
        tok = self._current()

        if tok.type == TokenType.INTEGER:
            self._advance()
            return LiteralExpr(value=int(tok.value))

        if tok.type == TokenType.STRING:
            self._advance()
            return LiteralExpr(value=tok.value)

        if tok.type == TokenType.IDENT:
            name = tok.value
            self._advance()
            # Boolean literals handled as special identifiers.
            if name == "true":
                return LiteralExpr(value=True)
            if name == "false":
                return LiteralExpr(value=False)
            # Property access: collector.property
            if self._current().type == TokenType.DOT:
                self._advance()  # consume DOT
                prop_tok = self._expect(TokenType.IDENT, "property name after '.'")
                return PropertyExpr(collector=name, property=prop_tok.value)
            # Plain variable reference
            return VarExpr(name=name)

        raise ParseError(
            f"Line {tok.line}: expected expression (number, string, "
            f"variable, or collector.property), got {tok.value!r}"
        )


def parse(tokens: list[Token]) -> Investigation:
    """Convenience wrapper."""
    return Parser(tokens).parse()