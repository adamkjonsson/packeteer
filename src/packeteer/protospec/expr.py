"""The expression language a spec uses for sizes, counts and switch selectors.

Expressions appear wherever a spec needs a value it cannot know in advance::

    size:   {expr: "header.length * 4"}
    repeat: {count: "qdcount"}
    switch: {on: "length >> 6"}

They are written as strings and parsed here into a typed tree, so that the
checker can scope and type every one of them **before any data exists** — which
is what lets a spec be validated rather than merely tried.

**The parser is Python's.**  :func:`ast.parse` in expression mode does the
tokenising and precedence, and this module walks the result against a
whitelist.  That is why "no calls, no loops, no indexing" holds by
construction rather than by vigilance: a construct is refused because it is
absent from the whitelist, and refused **by name** — *a function call is not
allowed in an expression* — rather than by leaking an AST class name at a spec
author.

Four types, and no coercion: ``int``, ``str``, ``bytes``, ``bool``.  Arithmetic
and ordering are integer-only, equality needs both sides to be the same type,
and ``and`` / ``or`` / ``not`` need booleans — ``qdcount and ...`` is an error
rather than a test for non-zero.  ``/`` floors, because there is no
floating-point type, and a float literal is refused rather than truncated.

This is kober's language, less its closed table of three functions.  A call is
therefore reported as *not supported yet* rather than as a syntax error, since
a spec written for kober may well contain one.
"""
from __future__ import annotations

import ast
from collections.abc import Iterator
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Union

from packeteer.protospec.errors import SpecError
from packeteer.protospec.spec import Location

__all__ = [
    "BinOp",
    "BoolLiteral",
    "BoolOp",
    "BytesLiteral",
    "Compare",
    "Expr",
    "ExprType",
    "IntLiteral",
    "Ref",
    "StrLiteral",
    "UnaryOp",
    "parse",
    "references",
    "type_of",
    "unparse",
]

#: Scope words a reference may start with.  A bare name means ``this``.
SCOPE_WORDS: frozenset[str] = frozenset({"this", "parent", "root"})

#: How this language spells booleans — YAML's way, not Python's.
_BOOL_WORDS: dict[str, bool] = {"true": True, "false": False}

#: Largest shift a spec may ask for.  A shift is the one arithmetic operator
#: that turns a small expression into an arbitrarily large integer, so a
#: crafted spec could otherwise exhaust memory before anything checks it.
MAX_SHIFT: int = 1024


class ExprType(Enum):
    """The type of an expression's value.  There are four, and no coercion."""

    INT = "int"
    STR = "str"
    BYTES = "bytes"
    BOOL = "bool"


# ── the tree ──────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class IntLiteral:
    """An integer literal, in any base Python accepts.

    Attributes:
        value: The value.

    """

    value: int


@dataclass(frozen=True)
class StrLiteral:
    """A text literal.

    Attributes:
        value: The value.

    """

    value: str


@dataclass(frozen=True)
class BytesLiteral:
    """A bytes literal.

    Attributes:
        value: The value.

    """

    value: bytes


@dataclass(frozen=True)
class BoolLiteral:
    """``true`` or ``false``.

    Attributes:
        value: The value.

    """

    value: bool


@dataclass(frozen=True)
class Ref:
    """A reference to a field, possibly in an enclosing or nested unit.

    Attributes:
        scope: ``"this"``, ``"parent"`` or ``"root"``.  A bare name is
            ``"this"``.
        path: Field names, outermost first — ``("header", "length")`` for
            ``header.length``.

    """

    scope: str
    path: tuple[str, ...]


@dataclass(frozen=True)
class UnaryOp:
    """``-x``, ``~x`` or ``not x``.

    Attributes:
        op: The operator, as written.
        operand: What it applies to.

    """

    op: str
    operand: Expr


@dataclass(frozen=True)
class BinOp:
    """An arithmetic or bitwise operation.

    Attributes:
        op: The operator, as written.
        left: Left operand.
        right: Right operand.

    """

    op: str
    left: Expr
    right: Expr


@dataclass(frozen=True)
class BoolOp:
    """``and`` or ``or``, which short-circuit.

    Short-circuiting matters more here than it usually would: the language has
    no conditional expression, so it is the only way to guard a division —
    ``n != 0 and total / n > 5``.

    Attributes:
        op: ``"and"`` or ``"or"``.
        operands: Two or more operands.

    """

    op: str
    operands: tuple[Expr, ...]


@dataclass(frozen=True)
class Compare:
    """A comparison.

    Attributes:
        op: The operator, as written.
        left: Left operand.
        right: Right operand.

    """

    op: str
    left: Expr
    right: Expr


Expr = Union[
    IntLiteral, StrLiteral, BytesLiteral, BoolLiteral,
    Ref, UnaryOp, BinOp, BoolOp, Compare,
]


# ── parsing ───────────────────────────────────────────────────────────────────

_BIN_OPS: dict[type[ast.operator], str] = {
    ast.Add: "+", ast.Sub: "-", ast.Mult: "*", ast.Mod: "%",
    ast.FloorDiv: "/", ast.Div: "/",
    ast.BitAnd: "&", ast.BitOr: "|", ast.BitXor: "^",
    ast.LShift: "<<", ast.RShift: ">>",
}
_CMP_OPS: dict[type[ast.cmpop], str] = {
    ast.Eq: "==", ast.NotEq: "!=",
    ast.Lt: "<", ast.LtE: "<=", ast.Gt: ">", ast.GtE: ">=",
}
_UNARY_OPS: dict[type[ast.unaryop], str] = {
    ast.USub: "-", ast.Invert: "~", ast.Not: "not",
}

# Every construct Python's grammar has that this language does not, named the
# way a spec author would say it rather than the way ast spells it.
_REFUSED: dict[type[ast.AST], str] = {
    ast.Lambda: "a lambda",
    ast.IfExp: "a conditional expression",
    ast.ListComp: "a comprehension",
    ast.SetComp: "a comprehension",
    ast.DictComp: "a comprehension",
    ast.GeneratorExp: "a comprehension",
    ast.Await: "await",
    ast.Yield: "yield",
    ast.Subscript: "indexing",
    ast.Starred: "unpacking",
    ast.List: "a list",
    ast.Tuple: "a tuple",
    ast.Dict: "a dict",
    ast.Set: "a set",
    ast.Slice: "a slice",
    ast.JoinedStr: "an f-string",
    ast.NamedExpr: "an assignment expression",
}


def parse(source: str, loc: Location) -> Expr:
    """Parse an expression into a typed tree.

    Args:
        source: The expression, as written in the spec.
        loc: Where in the spec it is, for error messages.

    Returns:
        The parsed expression.

    Raises:
        SpecError: If *source* is not a valid expression, or uses a construct
            this language does not have.

    """
    if not source.strip():
        raise SpecError("an expression cannot be empty", loc)
    try:
        tree = ast.parse(source, mode="eval")
    except SyntaxError as exc:
        raise SpecError(f"cannot parse expression {source!r}: {exc.msg}", loc) from exc
    return _convert(tree.body, loc)


def _convert(node: ast.expr, loc: Location) -> Expr:
    """Convert one whitelisted AST node, refusing everything else by name."""
    for refused, name in _REFUSED.items():
        if isinstance(node, refused):
            raise SpecError(f"{name} is not allowed in an expression", loc)

    if isinstance(node, ast.Constant):
        return _constant(node, loc)
    if isinstance(node, ast.Name) and node.id in _BOOL_WORDS:
        # This language spells booleans the way YAML does.  Python's parser
        # sees bare names, so they are caught before a name becomes a Ref —
        # which means a field cannot be called `true` or `false`.
        return BoolLiteral(value=_BOOL_WORDS[node.id])
    if isinstance(node, (ast.Name, ast.Attribute)):
        return _reference(node, loc)
    if isinstance(node, ast.UnaryOp):
        op = _UNARY_OPS.get(type(node.op))
        if op is None:
            raise SpecError(
                f"{_op_name(node.op)} is not allowed in an expression", loc,
            )
        return UnaryOp(op=op, operand=_convert(node.operand, loc))
    if isinstance(node, ast.BinOp):
        return _binop(node, loc)
    if isinstance(node, ast.BoolOp):
        return BoolOp(
            op="and" if isinstance(node.op, ast.And) else "or",
            operands=tuple(_convert(v, loc) for v in node.values),
        )
    if isinstance(node, ast.Compare):
        return _compare(node, loc)
    if isinstance(node, ast.Call):
        raise SpecError(
            f"not supported yet: {_call_name(node)} — this version has no "
            "functions in expressions",
            loc,
        )
    raise SpecError(
        f"{type(node).__name__} is not allowed in an expression", loc,
    )


def _constant(node: ast.Constant, loc: Location) -> Expr:
    """Convert a literal, refusing the ones this language does not have."""
    value = node.value
    if isinstance(value, bool):
        return BoolLiteral(value=value)
    if isinstance(value, int):
        return IntLiteral(value=value)
    if isinstance(value, str):
        return StrLiteral(value=value)
    if isinstance(value, bytes):
        return BytesLiteral(value=value)
    if isinstance(value, float):
        raise SpecError(
            f"{value!r} is a floating-point literal, and this language has no "
            "floating-point type; '/' already floors",
            loc,
        )
    if value is None:
        raise SpecError("None is not a value in an expression", loc)
    raise SpecError(f"{value!r} is not a valid literal", loc)


def _reference(node: ast.expr, loc: Location) -> Ref:
    """Convert a name or a dotted path into a :class:`Ref`."""
    parts: list[str] = []
    current: ast.expr = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if not isinstance(current, ast.Name):
        raise SpecError(
            "a reference must be a name or a dotted path, e.g. 'header.length'",
            loc,
        )
    parts.append(current.id)
    parts.reverse()

    scope = "this"
    if parts[0] in SCOPE_WORDS:
        scope = parts[0]
        parts = parts[1:]
        if not parts:
            raise SpecError(f"{scope!r} on its own is not a reference", loc)
    return Ref(scope=scope, path=tuple(parts))


def _binop(node: ast.BinOp, loc: Location) -> BinOp:
    """Convert an arithmetic or bitwise operation, guarding shift counts."""
    op = _BIN_OPS.get(type(node.op))
    if op is None:
        raise SpecError(f"{_op_name(node.op)} is not allowed in an expression", loc)
    left, right = _convert(node.left, loc), _convert(node.right, loc)
    if op in ("<<", ">>"):
        _check_shift(right, loc)
    return BinOp(op=op, left=left, right=right)


def _check_shift(count: Expr, loc: Location) -> None:
    """Bound a literal shift count.

    A shift is the one operator that turns a short expression into an
    arbitrarily large integer, so a constant count is bounded before anything
    evaluates it.  ``-1`` is a unary minus applied to a literal rather than a
    negative literal, so the check looks through one.
    """
    if isinstance(count, UnaryOp) and count.op == "-" \
            and isinstance(count.operand, IntLiteral):
        raise SpecError(
            f"a shift count cannot be negative, got -{count.operand.value}", loc,
        )
    if isinstance(count, IntLiteral) and count.value > MAX_SHIFT:
        raise SpecError(
            f"shift count {count.value} exceeds the {MAX_SHIFT}-bit limit", loc,
        )


def _compare(node: ast.Compare, loc: Location) -> Compare:
    """Convert a comparison, refusing the chained form."""
    if len(node.ops) != 1:
        raise SpecError(
            "a chained comparison is not allowed; write it as two comparisons "
            "joined by 'and'",
            loc,
        )
    op = _CMP_OPS.get(type(node.ops[0]))
    if op is None:
        raise SpecError(
            f"{_op_name(node.ops[0])} is not allowed in an expression", loc,
        )
    return Compare(
        op=op,
        left=_convert(node.left, loc),
        right=_convert(node.comparators[0], loc),
    )


def _op_name(op: ast.AST) -> str:
    """Name an operator the way a spec author would say it."""
    return {
        "Pow": "'**'", "MatMult": "'@'", "In": "'in'", "NotIn": "'not in'",
        "Is": "'is'", "IsNot": "'is not'", "UAdd": "unary '+'",
    }.get(type(op).__name__, f"'{type(op).__name__}'")


def _call_name(node: ast.Call) -> str:
    """Name a called function, for the not-supported-yet message."""
    if isinstance(node.func, ast.Name):
        return f"a call to {node.func.id!r}"
    if isinstance(node.func, ast.Attribute):
        return f"a call to {node.func.attr!r}"
    return "a function call"


# ── walking ───────────────────────────────────────────────────────────────────

def references(expr: Expr) -> Iterator[Ref]:
    """Yield every reference in *expr*, in source order.

    What the checker walks to prove a field only reads fields decoded before
    it.

    Args:
        expr: The expression to walk.

    Yields:
        Each :class:`Ref`, possibly repeated.

    """
    if isinstance(expr, Ref):
        yield expr
    elif isinstance(expr, UnaryOp):
        yield from references(expr.operand)
    elif isinstance(expr, (BinOp, Compare)):
        yield from references(expr.left)
        yield from references(expr.right)
    elif isinstance(expr, BoolOp):
        for operand in expr.operands:
            yield from references(operand)


# ── typing ────────────────────────────────────────────────────────────────────

_ARITHMETIC: frozenset[str] = frozenset({"+", "-", "*", "/", "%",
                                         "&", "|", "^", "<<", ">>"})
_ORDERING: frozenset[str] = frozenset({"<", "<=", ">", ">="})


def type_of(expr: Expr, resolve: Callable[[Ref], ExprType], loc: Location) -> ExprType:
    """Return the type of *expr*, or raise saying why it has none.

    The spec is not consulted here: *resolve* supplies the type of a
    reference, which is what keeps this module independent of the spec tree
    and testable on its own.

    Args:
        expr: The expression to type.
        resolve: Called with each :class:`Ref` to get its type.  It should
            raise :class:`~packeteer.protospec.errors.SpecError` for a
            reference that does not resolve.
        loc: Where in the spec the expression is, for error messages.

    Returns:
        The expression's type.

    Raises:
        SpecError: If the expression is not well typed.  There is no coercion,
            so mixing types is an error rather than a conversion.

    """
    if isinstance(expr, IntLiteral):
        return ExprType.INT
    if isinstance(expr, StrLiteral):
        return ExprType.STR
    if isinstance(expr, BytesLiteral):
        return ExprType.BYTES
    if isinstance(expr, BoolLiteral):
        return ExprType.BOOL
    if isinstance(expr, Ref):
        return resolve(expr)
    if isinstance(expr, UnaryOp):
        return _type_unary(expr, resolve, loc)
    if isinstance(expr, BinOp):
        return _type_binop(expr, resolve, loc)
    if isinstance(expr, BoolOp):
        for operand in expr.operands:
            _want(type_of(operand, resolve, loc), ExprType.BOOL,
                  f"an operand of {expr.op!r}", loc)
        return ExprType.BOOL
    return _type_compare(expr, resolve, loc)


def _type_unary(expr: UnaryOp, resolve: Callable[[Ref], ExprType],
                loc: Location) -> ExprType:
    """Type a unary operation."""
    operand = type_of(expr.operand, resolve, loc)
    if expr.op == "not":
        _want(operand, ExprType.BOOL, "the operand of 'not'", loc)
        return ExprType.BOOL
    _want(operand, ExprType.INT, f"the operand of {expr.op!r}", loc)
    return ExprType.INT


def _type_binop(expr: BinOp, resolve: Callable[[Ref], ExprType],
                loc: Location) -> ExprType:
    """Type an arithmetic or bitwise operation."""
    for side, operand in (("left", expr.left), ("right", expr.right)):
        _want(type_of(operand, resolve, loc), ExprType.INT,
              f"the {side} operand of {expr.op!r}", loc)
    return ExprType.INT


def _type_compare(expr: Compare, resolve: Callable[[Ref], ExprType],
                  loc: Location) -> ExprType:
    """Type a comparison.  Ordering is integer-only; equality needs one type."""
    left = type_of(expr.left, resolve, loc)
    right = type_of(expr.right, resolve, loc)
    if expr.op in _ORDERING:
        _want(left, ExprType.INT, f"the left operand of {expr.op!r}", loc)
        _want(right, ExprType.INT, f"the right operand of {expr.op!r}", loc)
    elif left is not right:
        raise SpecError(
            f"{expr.op!r} compares {left.value} with {right.value}; both sides "
            "must be the same type, and there is no coercion",
            loc,
        )
    return ExprType.BOOL


def _want(actual: ExprType, expected: ExprType, what: str, loc: Location) -> None:
    """Raise unless *actual* is *expected*."""
    if actual is expected:
        return
    hint = ""
    if expected is ExprType.BOOL and actual is ExprType.INT:
        # The mistake this language is most likely to provoke, since most
        # languages would have said yes.
        hint = " — there is no truthiness; write '!= 0'"
    raise SpecError(
        f"{what} is {actual.value}, expected {expected.value}{hint}", loc,
    )


# ── printing ──────────────────────────────────────────────────────────────────

_PRECEDENCE: dict[str, int] = {
    "or": 1, "and": 2, "not": 3,
    "==": 4, "!=": 4, "<": 4, "<=": 4, ">": 4, ">=": 4,
    "|": 5, "^": 6, "&": 7, "<<": 8, ">>": 8,
    "+": 9, "-": 9, "*": 10, "/": 10, "%": 10,
}
_UNARY_PRECEDENCE: int = 11


def unparse(expr: Expr) -> str:
    """Render *expr* back to source, parenthesised only where needed.

    Used by ``protocol show`` and by error messages, so that what a reader is
    shown is the expression they wrote rather than a tree.

    Args:
        expr: The expression to render.

    Returns:
        The expression as source text.

    """
    return _render(expr, 0)


def _render(expr: Expr, outer: int) -> str:
    """Render *expr*, wrapping it when *outer* binds tighter than it does."""
    if isinstance(expr, IntLiteral):
        return str(expr.value)
    if isinstance(expr, BoolLiteral):
        return "true" if expr.value else "false"
    if isinstance(expr, StrLiteral):
        return repr(expr.value)
    if isinstance(expr, BytesLiteral):
        return repr(expr.value)
    if isinstance(expr, Ref):
        prefix = "" if expr.scope == "this" else f"{expr.scope}."
        return prefix + ".".join(expr.path)
    if isinstance(expr, UnaryOp):
        space = " " if expr.op == "not" else ""
        rendered = f"{expr.op}{space}{_render(expr.operand, _UNARY_PRECEDENCE)}"
        return _wrap(rendered, _UNARY_PRECEDENCE, outer)
    if isinstance(expr, BoolOp):
        level = _PRECEDENCE[expr.op]
        joined = f" {expr.op} ".join(_render(o, level + 1) for o in expr.operands)
        return _wrap(joined, level, outer)
    level = _PRECEDENCE[expr.op]
    rendered = (f"{_render(expr.left, level)} {expr.op} "
                f"{_render(expr.right, level + 1)}")
    return _wrap(rendered, level, outer)


def _wrap(rendered: str, level: int, outer: int) -> str:
    """Parenthesise *rendered* when the enclosing operator binds tighter."""
    return f"({rendered})" if level < outer else rendered
