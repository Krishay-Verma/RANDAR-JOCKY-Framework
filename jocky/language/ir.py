"""
Intermediate representation for JOCKY investigations.

The IR is a tree of pure dataclasses — no execution behaviour,
no side effects. The interpreter is the only place that acts on it.

New nodes over the original:
  - LiteralExpr   a constant value (int, str, bool)
  - VarExpr       a reference to a let-bound variable
  - PropertyExpr  collector.property evidence access
  - Condition     left op right comparison
  - LetCommand    variable binding
  - IfCommand     conditional branch (with optional else)
"""

from __future__ import annotations  # enables forward reference in IfCommand

from dataclasses import dataclass, field


# ── Expression nodes ───────────────────────────────────────────────────────────

@dataclass
class LiteralExpr:
    """A constant value: integer, string, or boolean."""
    value: int | str | bool


@dataclass
class VarExpr:
    """A reference to a variable declared with 'let'."""
    name: str


@dataclass
class PropertyExpr:
    """
    An evidence property access: <collector>.<property>.

    Example: processes.count, system_info.hostname
    The interpreter resolves these through a strict allowlist.
    """
    collector: str
    property: str


# Union type for all expression kinds.
Expr = LiteralExpr | VarExpr | PropertyExpr


# ── Condition node ─────────────────────────────────────────────────────────────

@dataclass
class Condition:
    """Boolean condition tree. Leaf nodes contain a comparison."""
    left: Expr | None = None
    operator: str = "=="
    right: Expr | None = None
    kind: str = "comparison"
    children: list["Condition"] = field(default_factory=list)


@dataclass
class UserRuleCommand:
    """Bounded analyst-authored rule over finding evidence."""
    name: str
    condition: Condition
    severity: str
    line: int


# ── Command nodes ──────────────────────────────────────────────────────────────

@dataclass
class CollectCommand:
    target: str
    line: int


@dataclass
class AnalyzeCommand:
    rule: str
    line: int
    where: Condition | None = None


@dataclass
class ReportCommand:
    name: str
    line: int


@dataclass
class LetCommand:
    """Bind a variable name to the result of an expression."""
    name: str
    value: Expr
    line: int


@dataclass
class IfCommand:
    """
    Conditional execution.

    then_commands runs when condition is true.
    else_commands runs when condition is false (may be empty).
    Both lists may contain any Command type, including nested IfCommands.
    """
    condition: Condition
    then_commands: list[Command]
    else_commands: list[Command]
    line: int


# Union type for all command kinds (referenced by IfCommand above).
Command = CollectCommand | AnalyzeCommand | ReportCommand | LetCommand | IfCommand | UserRuleCommand


# ── Root node ──────────────────────────────────────────────────────────────────

@dataclass
class Investigation:
    name: str
    commands: list[Command] = field(default_factory=list)