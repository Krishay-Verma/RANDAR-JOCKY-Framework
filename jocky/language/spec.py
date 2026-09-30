"""Machine-readable V2.0 JOCKY language/toolchain specification."""

from __future__ import annotations

LANGUAGE_VERSION = "2.0"
GRAMMAR_VERSION = "2.0"

RESERVED_WORDS = frozenset({
    "let", "if", "else", "where", "and", "or", "not",
    "rule", "when", "severity",
})

STATEMENTS = frozenset({"collect", "analyze", "report", "let", "if", "rule"})
COMPARISON_OPERATORS = frozenset({">", "<", ">=", "<=", "==", "!="})
SEVERITIES = frozenset({"informational", "review_recommended", "medium", "high", "critical"})
TARGETS = frozenset({"portable", "windows", "ubuntu"})

MAX_SOURCE_BYTES = 20_000
MAX_PARSE_DEPTH = 10
MAX_BYTECODE_OPCODES = 2_000

EBNF = r'''\
investigation := "investigation" STRING "{" statement* "}" ;
statement := collect_stmt | analyze_stmt | report_stmt | let_stmt | if_stmt | rule_stmt ;
collect_stmt := "collect" IDENT ";" ;
analyze_stmt := "analyze" IDENT ("where" condition)? ";" ;
report_stmt := "report" STRING ";" ;
let_stmt := "let" IDENT "=" expr ";" ;
if_stmt := "if" condition "{" statement* "}" ("else" "{" statement* "}")? ;
rule_stmt := "rule" STRING "{" "when" condition ";" "severity" IDENT ";" "}" ;
condition := or_condition ;
or_condition := and_condition ("or" and_condition)* ;
and_condition := not_condition ("and" not_condition)* ;
not_condition := "not" not_condition | expr comparison_op expr ;
comparison_op := ">" | "<" | ">=" | "<=" | "==" | "!=" ;
expr := INTEGER | STRING | "true" | "false" | IDENT | IDENT "." IDENT ;
'''


def as_dict() -> dict:
    return {
        "language_version": LANGUAGE_VERSION,
        "grammar_version": GRAMMAR_VERSION,
        "reserved_words": sorted(RESERVED_WORDS),
        "statements": sorted(STATEMENTS),
        "comparison_operators": sorted(COMPARISON_OPERATORS),
        "severities": sorted(SEVERITIES),
        "targets": sorted(TARGETS),
        "limits": {
            "max_source_bytes": MAX_SOURCE_BYTES,
            "max_parse_depth": MAX_PARSE_DEPTH,
            "max_bytecode_opcodes": MAX_BYTECODE_OPCODES,
        },
        "ebnf": EBNF,
    }
