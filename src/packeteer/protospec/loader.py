"""Read a protocol spec from YAML or JSON into a :class:`~.spec.Spec`.

JSON is read with the standard library, so a spec always loads.  YAML needs
the optional ``yaml`` extra (``pip install packeteer[yaml]``) and is only
needed to *compile* — a module compiled from a spec imports nothing but
packeteer and the standard library.

This module reads structure, not meaning.  It refuses a spec that cannot be
read *as a spec* — a missing required key, a value of the wrong shape — and
leaves everything needing the spec to be understood to the checker, which
collects every fault rather than stopping at the first.

Constructs kober has and this version does not implement are neither refused
nor silently dropped: they are recorded on :attr:`~.spec.Spec.unsupported` so
the checker can report *not supported yet* and name them.
"""
from __future__ import annotations

import json
import os
from typing import Any

from packeteer.protospec.errors import SpecError
from packeteer.protospec.spec import (
    BytesType,
    Const,
    Count,
    CountOf,
    Derive,
    Endian,
    EnumDef,
    Field,
    FieldType,
    Fixed,
    FromExpr,
    InputShape,
    IntType,
    Location,
    Remaining,
    Size,
    SizeOf,
    Spec,
    StringType,
    Switch,
    Transport,
    Unit,
    UnitRef,
    Unsupported,
)

__all__ = ["load", "loads", "from_mapping"]

_MAX_INT_BITS = 64

# Constructs kober defines that this version reads but does not implement.
# Recorded rather than refused, so the checker can say "not supported yet".
_UNSUPPORTED_TYPES: dict[str, str] = {
    "computed": "a value derived from earlier fields at decode time",
    "pointer":  "read a type at an offset and carry on — needs a compression "
                "model to encode",
    "select":   "a question asked across a repeated field",
}
_UNSUPPORTED_SIZES: dict[str, str] = {
    "terminated": "a size ending at a delimiter rather than a declared length",
}
_UNSUPPORTED_REPEATS: dict[str, str] = {
    "until":  "repeat until a condition holds after each element",
    "to_end": "repeat to the end of the enclosing run",
}
_UNSUPPORTED_KEYS: dict[str, str] = {
    "params": "unit parameters",
    "emit":   "kober's output granularity, which packeteer has no use for",
}


def load(path: str | os.PathLike[str]) -> Spec:
    """Read a spec from a file.

    The format is chosen from the suffix: ``.json`` is read with the standard
    library, ``.yaml`` and ``.yml`` need the ``yaml`` extra.

    Args:
        path: Path to the spec file.

    Returns:
        The loaded :class:`~.spec.Spec`.

    Raises:
        SpecError: If the file cannot be read, is not valid JSON or YAML, or
            is not a well-formed spec.

    """
    text = _read(path)
    suffix = os.fspath(path).rsplit(".", 1)[-1].lower()
    fmt = "json" if suffix == "json" else "yaml"
    return loads(text, fmt=fmt, source=os.fspath(path))


def loads(text: str, *, fmt: str = "yaml", source: str | None = None) -> Spec:
    """Read a spec from a string.

    Args:
        text: The spec source.
        fmt: ``"yaml"`` or ``"json"``.
        source: File name to name in error messages.

    Returns:
        The loaded :class:`~.spec.Spec`.

    Raises:
        SpecError: If *text* is not valid in *fmt*, or is not a well-formed
            spec.

    """
    root = Location(path="", source=source)
    if fmt == "json":
        try:
            data = json.loads(text)
        except ValueError as exc:
            raise SpecError(f"not valid JSON: {exc}", root) from exc
    elif fmt == "yaml":
        data = _parse_yaml(text, root)
    else:
        raise SpecError(f"unknown spec format {fmt!r}; expected 'yaml' or 'json'", root)
    return from_mapping(data, source=source)


def _read(path: str | os.PathLike[str]) -> str:
    """Return the text of *path*, as a spec-shaped error if it cannot be read."""
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read()
    except OSError as exc:
        raise SpecError(f"cannot read spec: {exc}",
                        Location(path="", source=os.fspath(path))) from exc


def _parse_yaml(text: str, root: Location) -> Any:
    """Parse YAML, keeping line numbers on every mapping it contains."""
    try:
        import yaml
    except ImportError as exc:  # pragma: no cover - depends on the environment
        raise SpecError(
            "reading a YAML spec needs the 'yaml' extra: "
            "pip install packeteer[yaml].  JSON specs need no extra.",
            root,
        ) from exc

    class _LineLoader(yaml.SafeLoader):
        """A SafeLoader whose mappings remember which line they started on."""

    def _mapping(loader: Any, node: Any) -> _LinedDict:
        mapping = _LinedDict(loader.construct_mapping(node, deep=True))
        mapping.line = node.start_mark.line + 1     # yaml counts from zero
        return mapping

    _LineLoader.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping,
    )
    try:
        return yaml.load(text, Loader=_LineLoader)
    except yaml.YAMLError as exc:
        raise SpecError(f"not valid YAML: {exc}", root) from exc


class _LinedDict(dict):
    """A mapping that remembers the source line it started on.

    The line travels on the object rather than in a side table keyed by
    ``id()``: a side table either leaks (holding every mapping alive so its id
    stays valid) or reports the wrong line once an id is reused.
    """

    __slots__ = ("line",)

    line: int | None


def _line_of(value: Any) -> int | None:
    """Return the source line of *value*, when it came from YAML."""
    return getattr(value, "line", None)


def _at(loc: Location, value: Any) -> Location:
    """Return *loc* with *value*'s source line attached, when it has one."""
    line = _line_of(value)
    return loc.at_line(line) if line is not None else loc


def _require(data: Any, key: str, loc: Location) -> Any:
    """Return ``data[key]``, or raise naming what is missing."""
    if not isinstance(data, dict) or key not in data:
        raise SpecError(f"missing required key {key!r}", loc)
    return data[key]


def _as_mapping(value: Any, loc: Location, what: str) -> dict[str, Any]:
    """Return *value* as a mapping, or raise naming what it should have been."""
    if not isinstance(value, dict):
        raise SpecError(f"{what} must be a mapping, not {type(value).__name__}", loc)
    return value


def _as_str(value: Any, loc: Location, what: str) -> str:
    """Return *value* as a string, or raise naming what it should have been."""
    if not isinstance(value, str):
        raise SpecError(f"{what} must be a string, not {type(value).__name__}", loc)
    return value


def _as_int(value: Any, loc: Location, what: str) -> int:
    """Return *value* as an integer, or raise naming what it should have been."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise SpecError(f"{what} must be an integer, not {type(value).__name__}", loc)
    return value


def _enum_value(cls: Any, value: Any, loc: Location, what: str) -> Any:
    """Return the *cls* member named by *value*, or raise listing the members."""
    text = _as_str(value, loc, what)
    try:
        return cls(text)
    except ValueError as exc:
        allowed = ", ".join(repr(m.value) for m in cls)
        raise SpecError(f"{what} must be one of {allowed}, not {text!r}", loc) from exc


# ── the spec tree ─────────────────────────────────────────────────────────────

def from_mapping(data: Any, *, source: str | None = None) -> Spec:
    """Build a :class:`~.spec.Spec` from already-parsed data.

    The entry point for a caller who has their own YAML or JSON reader, and
    the one :func:`load` and :func:`loads` both end in.

    Args:
        data: The parsed spec, a mapping.
        source: File name to name in error messages.

    Returns:
        The loaded :class:`~.spec.Spec`.

    Raises:
        SpecError: If *data* is not a well-formed spec.

    """
    root = _at(Location(path="", source=source), data)
    _as_mapping(data, root, "a spec")
    unsupported: list[Unsupported] = []

    for key, note in _UNSUPPORTED_KEYS.items():
        if key in data:
            unsupported.append(Unsupported(key, root.child(key), note))

    units_data = _as_mapping(_require(data, "units", root), root.child("units"), "units")
    units: dict[str, Unit] = {}
    for unit_name, unit_data in units_data.items():
        loc = _at(root.child("units").child(str(unit_name)), unit_data)
        units[str(unit_name)] = _unit(str(unit_name), unit_data, loc, unsupported)

    enums: dict[str, EnumDef] = {}
    for enum_name, members in _as_mapping(
        data.get("enums", {}), root.child("enums"), "enums",
    ).items():
        loc = _at(root.child("enums").child(str(enum_name)), members)
        enums[str(enum_name)] = _enum_def(str(enum_name), members, loc)

    ports = data.get("ports", [])
    if not isinstance(ports, (list, tuple)):
        raise SpecError("ports must be a list of integers", root.child("ports"))

    return Spec(
        name=_as_str(_require(data, "name", root), root.child("name"), "name"),
        version=str(_require(data, "version", root)),
        entry=_as_str(_require(data, "entry", root), root.child("entry"), "entry"),
        units=units,
        over=_enum_value(Transport, data.get("over", "either"),
                         root.child("over"), "over"),
        ports=frozenset(
            _as_int(p, root.child("ports").child(f"[{i}]"), "a port")
            for i, p in enumerate(ports)
        ),
        enums=enums,
        input=_enum_value(InputShape, data.get("input", "datagram"),
                          root.child("input"), "input"),
        doc=data.get("doc"),
        unsupported=tuple(unsupported),
        loc=root,
    )


def _enum_def(name: str, members: Any, loc: Location) -> EnumDef:
    """Build one enum definition."""
    mapping = _as_mapping(members, loc, f"enum {name!r}")
    return EnumDef(
        name=name,
        members={
            _int_key(value, loc, f"a value of enum {name!r}"):
                _as_str(label, loc, f"a label of enum {name!r}")
            for value, label in mapping.items()
        },
        loc=loc,
    )


def _unit(name: str, data: Any, loc: Location, unsupported: list[Unsupported]) -> Unit:
    """Build one unit and its fields."""
    mapping = _as_mapping(data, loc, f"unit {name!r}")
    for key, note in _UNSUPPORTED_KEYS.items():
        if key in mapping:
            unsupported.append(Unsupported(f"unit.{key}", loc.child(key), note))

    fields_data = _require(mapping, "fields", loc)
    if not isinstance(fields_data, (list, tuple)):
        raise SpecError(f"unit {name!r}: fields must be a list", loc.child("fields"))

    fields = tuple(
        _field(item, _at(loc.child("fields").child(f"[{i}]"), item), unsupported)
        for i, item in enumerate(fields_data)
    )
    return Unit(name=name, fields=fields, loc=loc, doc=mapping.get("doc"))


def _field(data: Any, loc: Location, unsupported: list[Unsupported]) -> Field:
    """Build one field."""
    mapping = _as_mapping(data, loc, "a field")
    raw_name = mapping.get("name")
    # `name: null` is kober's anonymous field — reserved bits that are decoded
    # and re-encoded but never named.
    name = None if raw_name is None else _as_str(raw_name, loc, "a field name")

    field_type = _field_type(_require(mapping, "type", loc), loc.child("type"),
                             unsupported)
    return Field(
        name=name,
        type=field_type,
        loc=loc,
        repeat=_repeat(mapping.get("repeat"), loc.child("repeat"), unsupported),
        const=None if "const" not in mapping else Const(value=mapping["const"]),
        derive=_derive(mapping.get("derive"), loc.child("derive")),
        sensitive=bool(mapping.get("sensitive", False)),
        doc=mapping.get("doc"),
    )


def _field_type(data: Any, loc: Location, unsupported: list[Unsupported]) -> FieldType:
    """Build one field's type, recording constructs this version cannot compile."""
    mapping = _as_mapping(data, loc, "a field type")
    if len(mapping) != 1:
        raise SpecError(
            f"a field type names exactly one construct, not {len(mapping)}", loc,
        )
    (kind, body), = mapping.items()

    if kind in _UNSUPPORTED_TYPES:
        unsupported.append(Unsupported(kind, loc, _UNSUPPORTED_TYPES[kind]))
        # Stand in for it so loading can finish and the checker can report
        # every fault at once rather than only the first.
        return BytesType(size=Remaining())

    if kind == "int":
        return _int_type(body, loc)
    if kind == "bytes":
        return BytesType(size=_size(body, loc, unsupported))
    if kind == "string":
        body_map = _as_mapping(body, loc, "a string type")
        return StringType(size=_size(body_map, loc, unsupported),
                          encoding=body_map.get("encoding", "utf-8"))
    if kind == "unit":
        return _unit_ref(body, loc, unsupported)
    if kind == "switch":
        return _switch(body, loc, unsupported)
    raise SpecError(f"unknown field type {kind!r}", loc)


def _int_type(body: Any, loc: Location) -> IntType:
    """Build an integer type."""
    mapping = _as_mapping(body, loc, "an int type")
    bits = _as_int(_require(mapping, "bits", loc), loc.child("bits"), "bits")
    if not 1 <= bits <= _MAX_INT_BITS:
        raise SpecError(f"bits must be 1 to {_MAX_INT_BITS}, not {bits}",
                        loc.child("bits"))
    return IntType(
        bits=bits,
        signed=bool(mapping.get("signed", False)),
        endian=_enum_value(Endian, mapping.get("endian", "big"),
                           loc.child("endian"), "endian"),
        enum=mapping.get("enum"),
    )


def _size(body: Any, loc: Location, unsupported: list[Unsupported]) -> Size:
    """Build the size of a `bytes` or `string` field."""
    mapping = _as_mapping(body, loc, "a sized type")
    if "size" not in mapping:
        raise SpecError("a bytes or string field needs a size", loc)
    return _size_value(mapping["size"], loc.child("size"), unsupported)


def _size_value(size: Any, loc: Location, unsupported: list[Unsupported]) -> Size:
    """Build one size, in any of the forms kober accepts.

    ``4`` and ``{fixed: 4}`` are the same thing; ``{expr: "n"}`` reads the
    length from an earlier field; ``{remaining: true}`` takes the rest of the
    run; ``{terminated: {...}}`` is delimiter framing, which this version
    records as unsupported rather than refusing outright.
    """
    if isinstance(size, bool):
        raise SpecError("a size must be an integer or a mapping", loc)
    if isinstance(size, int):
        return Fixed(length=size)

    mapping = _as_mapping(size, loc, "a size")
    if len(mapping) != 1:
        raise SpecError(f"a size names exactly one form, not {len(mapping)}", loc)
    (kind, body), = mapping.items()

    if kind in _UNSUPPORTED_SIZES:
        unsupported.append(Unsupported(f"size.{kind}", loc, _UNSUPPORTED_SIZES[kind]))
        # Stand in for it so loading finishes and the checker can report every
        # fault at once rather than only the first.
        return Remaining()
    if kind == "fixed":
        return Fixed(length=_as_int(body, loc, "a fixed size"))
    if kind == "expr":
        return FromExpr(expr=_as_str(body, loc, "a size expression"))
    if kind == "remaining":
        return Remaining()
    raise SpecError(
        f"unknown size {kind!r}; expected 'fixed', 'expr', 'remaining' "
        f"or 'terminated'", loc,
    )


def _unit_ref(body: Any, loc: Location, unsupported: list[Unsupported]) -> UnitRef:
    """Build a reference to another unit.

    ``{unit: name}`` and ``{unit: {name: name}}`` are the same thing.  The
    second form may also carry ``args``, which is kober's unit parameters and
    is recorded as unsupported.
    """
    if isinstance(body, str):
        return UnitRef(unit=body)
    mapping = _as_mapping(body, loc, "a unit reference")
    if mapping.get("args"):
        unsupported.append(Unsupported(
            "unit.args", loc.child("args"), _UNSUPPORTED_KEYS["params"],
        ))
    return UnitRef(unit=_as_str(_require(mapping, "name", loc),
                                loc.child("name"), "a unit name"))


def _int_key(value: Any, loc: Location, what: str) -> int:
    """Return a mapping key as an integer, accepting its string spelling.

    JSON object keys are always strings, so ``{"1": ...}`` and YAML's
    ``{1: ...}`` have to mean the same key — for switch cases and for enum
    values alike.
    """
    if isinstance(value, bool):
        raise SpecError(f"{what} must be an integer", loc)
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError as exc:
            raise SpecError(f"{what} must be an integer, not {value!r}", loc) from exc
    raise SpecError(f"{what} must be an integer, not {type(value).__name__}", loc)


def _restore_on_key(mapping: dict[str, Any], loc: Location) -> dict[str, Any]:
    """Restore the ``on`` key that YAML turned into ``True``.

    ``on`` is a YAML 1.1 boolean, so ``on: kind`` parses as ``{True: "kind"}``
    — and ``on`` is a switch's dispatch key, which puts the trap on one of the
    most common constructs in the language.  Requiring ``"on"`` in quotes
    would work and would be a papercut every author hits exactly once, so the
    boolean is read back as the key it was written as.

    The repair is deliberately narrow, and matches kober's: only this mapping,
    only a ``True`` key, only when a real ``on`` is not already there.
    ``False`` is left alone — no spelling of ``off`` was ever meant to be a key
    here — and JSON, which has no such coercion, is unaffected.
    """
    if True not in mapping:
        return mapping
    if "on" in mapping:
        raise SpecError(
            "a switch has both 'on' and an unquoted on/yes/true key", loc,
        )
    return {("on" if key is True else key): value for key, value in mapping.items()}


def _switch(body: Any, loc: Location, unsupported: list[Unsupported]) -> Switch:
    """Build a switch and its cases."""
    mapping = _restore_on_key(_as_mapping(body, loc, "a switch"), loc)
    cases_data = _as_mapping(_require(mapping, "cases", loc),
                             loc.child("cases"), "switch cases")
    arms = {
        _int_key(value, loc.child("cases"), "a switch case value"):
            _field_type(arm, loc.child("cases").child(str(value)), unsupported)
        for value, arm in cases_data.items()
    }
    default = mapping.get("default")
    return Switch(
        on=_as_str(_require(mapping, "on", loc), loc.child("on"), "a switch selector"),
        arms=arms,
        default=None if default is None
        else _field_type(default, loc.child("default"), unsupported),
    )


def _repeat(data: Any, loc: Location,
            unsupported: list[Unsupported]) -> Count | None:
    """Build a repeat, recording the forms this version cannot compile."""
    if data is None:
        return None
    mapping = _as_mapping(data, loc, "a repeat")
    for key, note in _UNSUPPORTED_REPEATS.items():
        if key in mapping:
            unsupported.append(Unsupported(f"repeat.{key}", loc.child(key), note))
            return None
    if "count" not in mapping:
        raise SpecError(
            "a repeat names one of 'count', 'until' or 'to_end'", loc,
        )
    return Count(expr=_as_str(mapping["count"], loc.child("count"),
                              "a repeat count"))


def _derive(data: Any, loc: Location) -> Derive | None:
    """Build a derivation."""
    if data is None:
        return None
    mapping = _as_mapping(data, loc, "a derive")
    if len(mapping) != 1:
        raise SpecError(
            f"a derive names exactly one rule, not {len(mapping)}", loc,
        )
    (rule, target), = mapping.items()
    name = _as_str(target, loc, f"the target of {rule!r}")
    if rule == "size_of":
        return SizeOf(field=name)
    if rule == "count_of":
        return CountOf(field=name)
    raise SpecError(
        f"unknown derive rule {rule!r}; expected 'size_of' or 'count_of'", loc,
    )
