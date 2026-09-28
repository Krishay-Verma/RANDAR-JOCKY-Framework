"""
Lexer for the JOCKY DSL.

Token additions over the original:
  - LET, IF, ELSE      keyword tokens (reserved words)
  - ASSIGN             =
  - EQ, NEQ            == !=
  - GT, LT, GTE, LTE  > < >= <=
  - DOT                .
  - INTEGER            whole-number literals

Security notes:
  - '!' alone (without '=') is a hard LexError — no silent misparse.
  - Number literals are integers only; no floats to avoid IEEE-754 edge
    cases in comparisons.
  - Keywords are identified at lex time so they cannot be used as
    collector or rule names even if the parser is extended.
"""

from dataclasses import dataclass
from enum import Enum, auto


class TokenType(Enum):
    # Original tokens
    IDENT     = auto()
    STRING    = auto()
    LBRACE    = auto()
    RBRACE    = auto()
    SEMICOLON = auto()
    EOF       = auto()

    # Keywords
    LET  = auto()
    IF   = auto()
    ELSE = auto()

    # Assignment and comparison operators
    ASSIGN = auto()   # =
    EQ     = auto()   # ==
    NEQ    = auto()   # !=
    GT     = auto()   # >
    LT     = auto()   # 
    GTE    = auto()   # >=
    LTE    = auto()   # <=

    # Property access
    DOT = auto()      # .

    # Literals
    INTEGER = auto()  # whole-number literal


@dataclass
class Token:
    type: TokenType
    value: str
    line: int


class LexError(Exception):
    """Raised when the lexer encounters an unrecognised character."""
    pass


# Reserved words — tokenised as their own type, never as IDENT.
_KEYWORDS: dict[str, TokenType] = {
    "let":  TokenType.LET,
    "if":   TokenType.IF,
    "else": TokenType.ELSE,
}

# ASCII digits only: str.isdigit() also accepts characters such as '\u00b2'
# which int() rejects, turning hostile input into an unhandled exception.
_DIGITS = frozenset("0123456789")
_MAX_INT_DIGITS = 15

_SINGLE_CHAR_TOKENS: dict[str, TokenType] = {
    "{": TokenType.LBRACE,
    "}": TokenType.RBRACE,
    ";": TokenType.SEMICOLON,
    ".": TokenType.DOT,
}


def tokenize(source: str) -> list[Token]:
    """
    Convert JOCKY source text into a flat token list.

    Raises LexError on any unrecognised character.
    """
    tokens: list[Token] = []
    line = 1
    i = 0
    n = len(source)

    while i < n:
        char = source[i]

        # Whitespace
        if char == "\n":
            line += 1
            i += 1
            continue
        if char.isspace():
            i += 1
            continue

        # Single-line comments
        if char == "/" and i + 1 < n and source[i + 1] == "/":
            while i < n and source[i] != "\n":
                i += 1
            continue

        # Single-character tokens (no lookahead needed)
        if char in _SINGLE_CHAR_TOKENS:
            tokens.append(Token(_SINGLE_CHAR_TOKENS[char], char, line))
            i += 1
            continue

        # Two-character operators with single-character fallback: = ==
        if char == "=":
            if i + 1 < n and source[i + 1] == "=":
                tokens.append(Token(TokenType.EQ, "==", line))
                i += 2
            else:
                tokens.append(Token(TokenType.ASSIGN, "=", line))
                i += 1
            continue

        # > >=
        if char == ">":
            if i + 1 < n and source[i + 1] == "=":
                tokens.append(Token(TokenType.GTE, ">=", line))
                i += 2
            else:
                tokens.append(Token(TokenType.GT, ">", line))
                i += 1
            continue

        # < <=
        if char == "<":
            if i + 1 < n and source[i + 1] == "=":
                tokens.append(Token(TokenType.LTE, "<=", line))
                i += 2
            else:
                tokens.append(Token(TokenType.LT, "<", line))
                i += 1
            continue

        # != (bare ! is always an error — there is no unary not in JOCKY)
        if char == "!":
            if i + 1 < n and source[i + 1] == "=":
                tokens.append(Token(TokenType.NEQ, "!=", line))
                i += 2
                continue
            raise LexError(
                f"Unexpected character '!' at line {line}. "
                "Did you mean '!='?"
            )

        # String literals
        if char == '"':
            start_line = line
            i += 1
            start = i
            while i < n and source[i] != '"':
                if source[i] == "\n":
                    line += 1
                i += 1
            if i >= n:
                raise LexError(
                    f"Unterminated string starting at line {start_line}"
                )
            value = source[start:i]
            i += 1
            tokens.append(Token(TokenType.STRING, value, start_line))
            continue

        # Integer literals
        if char in _DIGITS:
            start = i
            while i < n and source[i] in _DIGITS:
                i += 1
            if i - start > _MAX_INT_DIGITS:
                raise LexError(
                    f"Integer literal too long at line {line} "
                    f"(max {_MAX_INT_DIGITS} digits)"
                )
            tokens.append(Token(TokenType.INTEGER, source[start:i], line))
            continue

        # Identifiers and keywords
        if char.isalpha() or char == "_":
            start = i
            while i < n and (source[i].isalnum() or source[i] == "_"):
                i += 1
            value = source[start:i]
            token_type = _KEYWORDS.get(value, TokenType.IDENT)
            tokens.append(Token(token_type, value, line))
            continue

        raise LexError(f"Unrecognised character {char!r} at line {line}")

    tokens.append(Token(TokenType.EOF, "", line))
    return tokens