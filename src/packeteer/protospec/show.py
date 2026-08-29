"""Print the field tree a spec describes.

The fastest way to find out whether a spec says what its author meant, and the
first thing to reach for when one someone else wrote does not do what you
expected.  Nested units are expanded in place, so the tree is the message
rather than a set of definitions to assemble in your head.

It deliberately does **not** require the spec to check.  A spec with faults is
exactly when a reader most wants to see what it currently describes, so an
unknown unit or enum is shown as unresolved rather than raising.
"""
from __future__ import annotations

import textwrap

from packeteer.protospec.errors import SpecError
from packeteer.protospec.expr import parse, unparse
from packeteer.protospec.spec import (
    BytesType,
    CountOf,
    Endian,
    Field,
    FieldType,
    Fixed,
    FromExpr,
    IntType,
    Location,
    Remaining,
    Size,
    SizeOf,
    Spec,
    StringType,
    Switch,
    Unit,
    UnitRef,
)

__all__ = ["render"]

#: Width the tree is wrapped to.  Doc text is the only thing long enough to
#: need it, and an unwrapped paragraph makes the tree unreadable.
WIDTH = 88

_BRANCH = "├── "
_LAST = "└── "
_THROUGH = "│   "
_BLANK = "    "


def render(spec: Spec, *, docs: bool = True) -> str:
    """Return the field tree *spec* describes, as text.

    Args:
        spec: The spec to render.
        docs: Whether to include each field's ``doc`` text beneath it.

    Returns:
        The rendered tree, without a trailing newline.

    """
    lines = [_header(spec)]
    if spec.enums:
        lines.append("")
        lines += [_enum_line(name, spec) for name in sorted(spec.enums)]
    lines.append("")

    entry = spec.units.get(spec.entry)
    if entry is None:
        lines.append(f"{spec.entry} (undefined)")
        return "\n".join(lines)

    lines.append(entry.name)
    if docs and entry.doc:
        lines += _doc_lines(entry.doc, "  ")
    lines += _unit_lines(entry, spec, prefix="", seen=(entry.name,), docs=docs)
    return "\n".join(lines)


def _doc_lines(doc: str, indent: str) -> list[str]:
    """Return *doc* wrapped to :data:`WIDTH`, indented under its field."""
    width = max(WIDTH - len(indent), 24)
    wrapped: list[str] = []
    for paragraph in doc.strip().splitlines():
        if not paragraph.strip():
            continue
        wrapped += textwrap.wrap(paragraph.strip(), width=width) or [""]
    return [indent + line for line in wrapped]


def _header(spec: Spec) -> str:
    """Return the one-line summary: what it is, and when it is used."""
    parts = [f"input: {spec.input.value}", f"over: {spec.over.value}"]
    if spec.ports:
        parts.append(f"ports: {', '.join(str(p) for p in sorted(spec.ports))}")
    parts.append(f"entry: {spec.entry}")
    return f"{spec.name} {spec.version} — {', '.join(parts)}"


def _enum_line(name: str, spec: Spec) -> str:
    """Return one enum as ``enum name: 0=a, 1=b``."""
    members = spec.enums[name].members
    body = ", ".join(f"{value}={label}" for value, label in sorted(members.items()))
    return f"enum {name}: {body}"


def _unit_lines(unit: Unit, spec: Spec, prefix: str,
                seen: tuple[str, ...], docs: bool) -> list[str]:
    """Return the lines for *unit*'s fields, expanding nested units in place."""
    lines: list[str] = []
    for index, fld in enumerate(unit.fields):
        last = index == len(unit.fields) - 1
        lines.append(prefix + (_LAST if last else _BRANCH)
                     + _field_line(fld, spec, seen))
        child = prefix + (_BLANK if last else _THROUGH)
        if docs and fld.doc:
            lines += _doc_lines(fld.doc, child + "  ")
        lines += _nested_lines(fld.type, spec, child, seen, docs)
    return lines


def _nested_lines(field_type: FieldType, spec: Spec, prefix: str,
                  seen: tuple[str, ...], docs: bool) -> list[str]:
    """Return the lines for whatever *field_type* contains."""
    if isinstance(field_type, UnitRef):
        nested = spec.units.get(field_type.unit)
        if nested is None or field_type.unit in seen:
            # An undefined or recursive unit is shown, not expanded — the
            # marker is on the field line itself.
            return []
        return _unit_lines(nested, spec, prefix, (*seen, field_type.unit), docs)

    if isinstance(field_type, Switch):
        lines: list[str] = []
        arms = sorted(field_type.arms.items())
        entries = [(f"case {value}", arm) for value, arm in arms]
        if field_type.default is not None:
            entries.append(("default", field_type.default))
        for index, (label, arm) in enumerate(entries):
            last = index == len(entries) - 1
            lines.append(prefix + (_LAST if last else _BRANCH)
                         + f"{label}: {_type_text(arm, spec, seen)}")
            lines += _nested_lines(arm, spec, prefix + (_BLANK if last else _THROUGH),
                                   seen, docs)
        return lines
    return []


def _unsupported_at(fld: Field, spec: Spec) -> list[str]:
    """Return the constructs on *fld* this version cannot compile.

    The loader stands something compilable in for a construct it cannot
    handle, so without this the tree would show the stand-in as though the
    author had written it — `show` would quietly misreport the spec.
    """
    return [
        item.construct for item in spec.unsupported
        if item.loc.path == fld.loc.path or item.loc.path.startswith(fld.loc.path + ".")
    ]


def _field_line(fld: Field, spec: Spec, seen: tuple[str, ...] = ()) -> str:
    """Return one field's line: its name, type, and everything qualifying it.

    *seen* is the units already on the path, so that a unit containing itself
    is labelled rather than silently left unexpanded.
    """
    name = fld.name if fld.name is not None else "(anonymous)"
    head = f"{name}: {_type_text(fld.type, spec, seen)}"
    if fld.const is not None:
        # Part of the type rather than a qualifier of it, so one space.
        head += f" = {_const_text(fld.const.value)}"
    parts = [head]

    if fld.repeat is not None:
        parts.append(f"×{_expr_text(fld.repeat.expr, fld.loc)}")
    if fld.derive is not None:
        rule = "size_of" if isinstance(fld.derive, SizeOf) else "count_of"
        parts.append(f"(derived: {rule} {fld.derive.field})")
    elif isinstance(fld.derive, CountOf):     # pragma: no cover - defensive
        parts.append("(derived)")
    if fld.sensitive:
        parts.append("[sensitive]")
    unsupported = _unsupported_at(fld, spec)
    if unsupported:
        parts.append(f"(not supported yet: {', '.join(sorted(set(unsupported)))})")
    return "  ".join(parts)


def _type_text(field_type: FieldType, spec: Spec, seen: tuple[str, ...]) -> str:
    """Return a field type as the short text the tree shows."""
    if isinstance(field_type, IntType):
        sign = "i" if field_type.signed else "u"
        text = f"{sign}{field_type.bits}"
        if field_type.endian is Endian.LITTLE and field_type.bits > 8:
            text += " le"
        if field_type.enum is not None:
            known = "" if field_type.enum in spec.enums else " (undefined)"
            text += f" enum {field_type.enum}{known}"
        return text
    if isinstance(field_type, BytesType):
        return f"bytes[{_size_text(field_type.size)}]"
    if isinstance(field_type, StringType):
        return f"string[{_size_text(field_type.size)}] {field_type.encoding}"
    if isinstance(field_type, UnitRef):
        if field_type.unit not in spec.units:
            return f"→ {field_type.unit} (undefined)"
        if field_type.unit in seen:
            return f"→ {field_type.unit} (recursive)"
        return f"→ {field_type.unit}"
    if isinstance(field_type, Switch):
        return f"switch on {_expr_text(field_type.on, None)}"
    return type(field_type).__name__


def _size_text(size: Size) -> str:
    """Return a size as it appears inside the brackets."""
    if isinstance(size, Fixed):
        return str(size.length)
    if isinstance(size, FromExpr):
        return _expr_text(size.expr, None)
    if isinstance(size, Remaining):
        return "rest"
    return "?"


def _expr_text(source: str, loc: Location | None) -> str:
    """Return an expression as its author wrote it.

    Round-tripped through the parser so that what is shown is what the spec
    means, but falling back to the raw source when it does not parse — `show`
    is most useful on a spec that does not yet check.
    """
    try:
        return unparse(parse(source, loc or Location(path="")))
    except SpecError:
        return source


def _const_text(value: object) -> str:
    """Return a constant the way a spec author would recognise it."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return hex(value) if value > 9 else str(value)
    return repr(value)
