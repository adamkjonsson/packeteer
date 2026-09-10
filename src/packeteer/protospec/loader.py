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
from dataclasses import dataclass, replace
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
    Fill,
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

# Known keys, by where they appear.  Anything else is a typo, and a typo that
# loads and does nothing is a decoder that silently does the wrong thing — so
# an unknown key is refused rather than ignored.  This is kober's rule.
_SPEC_KEYS: frozenset[str] = frozenset({
    "name", "version", "entry", "units", "enums", "over", "ports", "input",
    "doc", "endian", *_UNSUPPORTED_KEYS,
})
_UNIT_KEYS: frozenset[str] = frozenset({
    "fields", "doc", "endian", *_UNSUPPORTED_KEYS,
})
_SWITCH_KEYS: frozenset[str] = frozenset({"dispatch", "cases", "default"})

# A field's keys come from three sets that share no member, which is what lets
# a type kind and a repeat kind be written directly on the field rather than
# inside a ``type:`` or ``repeat:`` wrapper.  This is kober's rule, and the
# disjointness is asserted by the test suite rather than assumed.
_FIELD_OWN_KEYS: frozenset[str] = frozenset({
    "name", "type", "repeat", "const", "derive", "sensitive", "doc",
    "condition",
})
#: ``bits`` names the integer kind, because the word says what the number
#: counts: ``int: 8`` is shorter and cannot say whether the 8 is bits or bytes.
_TYPE_KINDS: frozenset[str] = frozenset({
    "bits", "int", "bytes", "string", "unit", "switch", *_UNSUPPORTED_TYPES,
})
_REPEAT_KINDS: frozenset[str] = frozenset({"count", *_UNSUPPORTED_REPEATS})
_FIELD_KEYS: frozenset[str] = _FIELD_OWN_KEYS | _TYPE_KINDS | _REPEAT_KINDS


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


def _yaml_hint(value: Any) -> str:
    """Explain a value YAML's implicit typing has probably mangled.

    YAML 1.1 reads ``on``, ``off``, ``yes`` and ``no`` as booleans and
    ``1.10`` as a number, so an author who wrote either as text gets something
    else.  packeteer reads specs as ordinary YAML 1.1 rather than reinterpreting
    the document — a spec has to mean the same thing to every YAML tool that
    opens it — so the answer is to name the coercion and say to quote it.  This
    is kober's approach, and the message is deliberately close to kober's.
    """
    if isinstance(value, bool):
        return " (YAML reads on/off/yes/no/true/false as booleans; quote it)"
    if isinstance(value, float):
        return " (YAML reads 1.10 as a number, not a string; quote it)"
    return ""


def _reject_unknown(mapping: dict[str, Any], known: frozenset[str],
                    what: str, loc: Location) -> None:
    """Refuse a key that is not in *known*.

    A misspelled key that loads and does nothing produces a decoder that
    silently does the wrong thing, which is worse than one that will not load.
    """
    unknown = sorted(str(k) for k in mapping if str(k) not in known)
    if not unknown:
        return
    listed = ", ".join(repr(k) for k in unknown)
    raise SpecError(
        f"{what} has no key {listed}; known keys are "
        f"{', '.join(repr(k) for k in sorted(known))}",
        loc,
    )


def _reject_unknown_field_key(mapping: dict[str, Any], loc: Location) -> None:
    """Refuse a field key, naming the set each allowed key belongs to.

    A field's keys come from three sets, and printing them as one flat list
    would say nothing about *why* each is allowed — which matters most for the
    lifted kinds, where an author needs to know that ``bits`` is a type and
    ``count`` a repetition rather than that both happen to be legal.
    """
    unknown = sorted(str(k) for k in mapping if str(k) not in _FIELD_KEYS)
    if not unknown:
        return
    listed = ", ".join(repr(k) for k in unknown)
    groups = (
        ("a field's own keys", _FIELD_OWN_KEYS),
        ("a type kind", _TYPE_KINDS),
        ("a repeat kind", _REPEAT_KINDS),
    )
    known = "; ".join(
        f"{label}: {', '.join(repr(k) for k in sorted(keys))}"
        for label, keys in groups
    )
    raise SpecError(f"a field has no key {listed}; known keys are — {known}", loc)


def _require(data: Any, key: str, loc: Location) -> Any:
    """Return ``data[key]``, or raise naming what is missing."""
    if not isinstance(data, dict) or key not in data:
        raise SpecError(f"missing required key {key!r}", loc)
    return data[key]


def _as_mapping(value: Any, loc: Location, what: str) -> dict[str, Any]:
    """Return *value* as a mapping, or raise naming what it should have been."""
    if not isinstance(value, dict):
        raise SpecError(
            f"{what} must be a mapping, not {type(value).__name__}"
            f"{_yaml_hint(value)}", loc,
        )
    return value


def _as_str(value: Any, loc: Location, what: str) -> str:
    """Return *value* as a string, or raise naming what it should have been."""
    if not isinstance(value, str):
        raise SpecError(
            f"{what} must be a string, not {type(value).__name__}"
            f"{_yaml_hint(value)}", loc,
        )
    return value


def _as_int(value: Any, loc: Location, what: str) -> int:
    """Return *value* as an integer, or raise naming what it should have been."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise SpecError(
            f"{what} must be an integer, not {type(value).__name__}"
            f"{_yaml_hint(value)}", loc,
        )
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

@dataclass(frozen=True)
class _Ctx:
    """Loader state that descends with the spec tree.

    One record rather than a parameter per value: the alternative is changing
    every constructor's signature each time the format grows something that
    inherits, and carrying a longer argument list forever.  It is private to
    this module — nothing in the model or the public API learns about it.

    Attributes:
        unsupported: Accumulator for constructs kober has and this version
            does not implement.  Shared by reference, so a nested type records
            into the same list the spec is built from.
        endian: Byte order an integer takes when it does not say.  Set from the
            document, overridden by a unit, overridden by the field itself.

    """

    unsupported: list[Unsupported]
    endian: Endian = Endian.BIG

    def inherit(self, mapping: dict[str, Any], loc: Location) -> _Ctx:
        """Return a context carrying *mapping*'s ``endian``, if it states one."""
        if "endian" not in mapping:
            return self
        value = _enum_value(Endian, mapping["endian"], loc.child("endian"), "endian")
        return replace(self, endian=value)

    def record(self, construct: str, loc: Location, note: str) -> None:
        """Note a construct this version reads but cannot compile."""
        self.unsupported.append(Unsupported(construct, loc, note))


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
    _reject_unknown(data, _SPEC_KEYS, "a spec", root)
    # Byte order resolves field -> unit -> document -> big, and is folded into
    # each integer as the spec loads, so nothing downstream can tell which
    # spelling was used.
    ctx = _Ctx(unsupported=[]).inherit(data, root)

    for key, note in _UNSUPPORTED_KEYS.items():
        if key in data:
            ctx.record(key, root.child(key), note)

    units_data = _as_mapping(_require(data, "units", root), root.child("units"), "units")
    units: dict[str, Unit] = {}
    for unit_name, unit_data in units_data.items():
        loc = _at(root.child("units"), unit_data)
        name = _as_str(unit_name, loc, "a unit name")
        units[name] = _unit(name, unit_data, loc.child(name), ctx)

    enums: dict[str, EnumDef] = {}
    for enum_name, members in _as_mapping(
        data.get("enums", {}), root.child("enums"), "enums",
    ).items():
        loc = _at(root.child("enums"), members)
        name = _as_str(enum_name, loc, "an enum name")
        enums[name] = _enum_def(name, members, loc.child(name))

    ports = data.get("ports", [])
    if not isinstance(ports, (list, tuple)):
        raise SpecError("ports must be a list of integers", root.child("ports"))

    return Spec(
        name=_as_str(_require(data, "name", root), root.child("name"), "name"),
        version=_as_str(_require(data, "version", root),
                        root.child("version"), "version"),
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
        unsupported=tuple(ctx.unsupported),
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


def _unit(name: str, data: Any, loc: Location, ctx: _Ctx) -> Unit:
    """Build one unit and its fields."""
    mapping = _as_mapping(data, loc, f"unit {name!r}")
    _reject_unknown(mapping, _UNIT_KEYS, f"unit {name!r}", loc)
    for key, note in _UNSUPPORTED_KEYS.items():
        if key in mapping:
            ctx.record(f"unit.{key}", loc.child(key), note)
    # A unit's byte order overrides the document's for the fields below it.
    ctx = ctx.inherit(mapping, loc)

    fields_data = _require(mapping, "fields", loc)
    if not isinstance(fields_data, (list, tuple)):
        raise SpecError(f"unit {name!r}: fields must be a list", loc.child("fields"))

    fields = tuple(
        _field(item, _at(loc.child("fields").child(f"[{i}]"), item), ctx)
        for i, item in enumerate(fields_data)
    )
    return Unit(name=name, fields=fields, loc=loc, doc=mapping.get("doc"))


def _lifted(mapping: dict[str, Any], kinds: frozenset[str], wrapper: str,
            what: str, loc: Location) -> tuple[str, Any] | None:
    """Return the one lifted *kinds* key on a field, or ``None`` if there is none.

    A tagged construct's kind may be written on the field rather than inside
    its wrapper, which is unambiguous because a field's three key sets share no
    member.  Exactly one kind is allowed; the wrapper and a lifted kind
    together are refused rather than merged, since there is no sensible reading
    of a field that names its type twice.
    """
    present = sorted(k for k in mapping if str(k) in kinds)
    if not present:
        return None
    if len(present) > 1:
        listed = ", ".join(repr(k) for k in present)
        raise SpecError(
            f"a field names {len(present)} {what} kinds ({listed}); it may "
            f"name only one", loc,
        )
    kind = present[0]
    if wrapper in mapping:
        raise SpecError(
            f"a field has both {kind!r} and {wrapper!r}; {kind!r} is the "
            f"short form of {wrapper}: {{{kind}: …}} and the two cannot be "
            f"combined", loc,
        )
    return kind, mapping[kind]


def _field(data: Any, loc: Location, ctx: _Ctx) -> Field:
    """Build one field."""
    mapping = _as_mapping(data, loc, "a field")
    _reject_unknown_field_key(mapping, loc)
    raw_name = mapping.get("name")
    # `name: null` is kober's anonymous field — reserved bits that are decoded
    # and re-encoded but never named.
    name = None if raw_name is None else _as_str(raw_name, loc, "a field name")

    lifted_type = _lifted(mapping, _TYPE_KINDS, "type", "type", loc)
    if lifted_type is None:
        field_type = _field_type(_require(mapping, "type", loc),
                                 loc.child("type"), ctx)
    else:
        kind, body = lifted_type
        field_type = _one_type(kind, body, loc.child(kind), ctx)

    lifted_repeat = _lifted(mapping, _REPEAT_KINDS, "repeat", "repeat", loc)
    if lifted_repeat is None:
        repeat = _repeat(mapping.get("repeat"), loc.child("repeat"), ctx)
    else:
        kind, body = lifted_repeat
        repeat = _one_repeat(kind, body, loc.child(kind), ctx)

    return Field(
        name=name,
        type=field_type,
        loc=loc,
        repeat=repeat,
        const=None if "const" not in mapping else Const(value=mapping["const"]),
        condition=None if "condition" not in mapping else _as_str(
            mapping["condition"], loc.child("condition"), "a condition"),
        derive=_derive(mapping.get("derive"), loc.child("derive")),
        sensitive=bool(mapping.get("sensitive", False)),
        doc=mapping.get("doc"),
    )


def _field_type(data: Any, loc: Location, ctx: _Ctx) -> FieldType:
    """Build one field's type from a ``type:`` wrapper, or from a switch arm.

    The long form: a tagged mapping naming exactly one construct.  A field may
    also lift the kind key onto itself, which reaches :func:`_one_type`
    directly — both spellings build the identical type, so nothing downstream
    can tell which was used.
    """
    mapping = _as_mapping(data, loc, "a field type")
    if len(mapping) != 1:
        raise SpecError(
            f"a field type names exactly one construct, not {len(mapping)}", loc,
        )
    (kind, body), = mapping.items()
    return _one_type(str(kind), body, loc, ctx)


def _one_type(kind: str, body: Any, loc: Location, ctx: _Ctx) -> FieldType:
    """Build the type named by *kind*, whether it was lifted or wrapped."""
    if kind in _UNSUPPORTED_TYPES:
        ctx.record(kind, loc, _UNSUPPORTED_TYPES[kind])
        # Stand in for it so loading can finish and the checker can report
        # every fault at once rather than only the first.
        return BytesType(size=Remaining())

    # `bits: 16` is the integer kind spelled by what the number counts.
    if kind == "bits":
        return _int_type({"bits": body}, loc, ctx)
    if kind == "int":
        return _int_type(body, loc, ctx)
    if kind == "bytes":
        return BytesType(size=_size(body, loc, ctx))
    if kind == "string":
        body_map = _as_mapping(_sized_body(body), loc, "a string type")
        return StringType(size=_size(body_map, loc, ctx),
                          encoding=body_map.get("encoding", "utf-8"))
    if kind == "unit":
        return _unit_ref(body, loc, ctx)
    if kind == "switch":
        return _switch(body, loc, ctx)
    raise SpecError(f"unknown field type {kind!r}", loc)


def _sized_body(body: Any) -> Any:
    """Expand a bare ``bytes``/``string`` body into the size it names.

    ``{bytes: 4}`` and ``{bytes: {size: 4}}`` are the same thing: a scalar
    where a mapping is expected fills in the one key that matters.
    """
    if isinstance(body, bool) or not isinstance(body, (int, str, dict)):
        return body
    if isinstance(body, dict):
        return body
    return {"size": body}


def _int_type(body: Any, loc: Location, ctx: _Ctx) -> IntType:
    """Build an integer type.

    ``{int: 8}`` is a bare width — a scalar where a mapping is expected fills
    in the one key that matters, which for an integer is ``bits``.

    Byte order falls back to the enclosing unit's, then the document's, then
    ``big``.  ``signed`` deliberately does **not** inherit: a protocol is
    little-endian, it is not *signed*.  Byte order is a property of the format
    as a whole where signedness is a property of what one field means.
    """
    if not isinstance(body, bool) and isinstance(body, int):
        body = {"bits": body}
    mapping = _as_mapping(body, loc, "an int type")
    bits = _as_int(_require(mapping, "bits", loc), loc.child("bits"), "bits")
    if not 1 <= bits <= _MAX_INT_BITS:
        raise SpecError(f"bits must be 1 to {_MAX_INT_BITS}, not {bits}",
                        loc.child("bits"))
    endian = (ctx.endian if "endian" not in mapping
              else _enum_value(Endian, mapping["endian"],
                               loc.child("endian"), "endian"))
    return IntType(
        bits=bits,
        signed=bool(mapping.get("signed", False)),
        endian=endian,
        enum=mapping.get("enum"),
    )


#: kober writes a delimiter beside ``size`` rather than under it, so
#: ``{string: {delimiter: "\r\n"}}`` is its short spelling of
#: ``{size: {terminated: {delimiter: "\r\n"}}}``.  ``consume``, ``required``
#: and ``within`` sit alongside it.
_TERMINATED_KEYS: frozenset[str] = frozenset({
    "delimiter", "consume", "required", "within",
})


def _size(body: Any, loc: Location, ctx: _Ctx) -> Size:
    """Build the size of a `bytes` or `string` field."""
    mapping = _as_mapping(_sized_body(body), loc, "a sized type")
    if "size" not in mapping:
        # Delimiter framing written the short way is still delimiter framing:
        # report it as the construct it is rather than as a missing size.
        if _TERMINATED_KEYS & {str(k) for k in mapping}:
            ctx.record("size.terminated", loc, _UNSUPPORTED_SIZES["terminated"])
            return Remaining()
        raise SpecError("a bytes or string field needs a size", loc)
    return _size_value(mapping["size"], loc.child("size"), ctx)


def _size_value(size: Any, loc: Location, ctx: _Ctx) -> Size:
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
        ctx.record(f"size.{kind}", loc, _UNSUPPORTED_SIZES[kind])
        # Stand in for it so loading finishes and the checker can report every
        # fault at once rather than only the first.
        return Remaining()
    if kind == "fixed":
        return Fixed(length=_as_int(body, loc, "a fixed size"))
    if kind == "expr":
        return FromExpr(expr=_as_str(body, loc, "a size expression"))
    if kind == "remaining":
        return Remaining()
    if kind == "fill":
        return Fill()
    raise SpecError(
        f"unknown size {kind!r}; expected 'fixed', 'expr', 'remaining', "
        f"'fill' or 'terminated'", loc,
    )


def _unit_ref(body: Any, loc: Location, ctx: _Ctx) -> UnitRef:
    """Build a reference to another unit.

    ``{unit: name}`` and ``{unit: {name: name}}`` are the same thing.  The
    second form may also carry ``args``, which is kober's unit parameters and
    is recorded as unsupported.
    """
    if isinstance(body, str):
        return UnitRef(unit=body)
    mapping = _as_mapping(body, loc, "a unit reference")
    if mapping.get("args"):
        ctx.record("unit.args", loc.child("args"), _UNSUPPORTED_KEYS["params"])
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
    raise SpecError(
            f"{what} must be an integer, not {type(value).__name__}"
            f"{_yaml_hint(value)}", loc,
        )


def _reject_renamed_on(mapping: dict[str, Any], loc: Location) -> None:
    """Refuse a switch still written with the old ``on`` dispatch key.

    ``on`` is a YAML 1.1 boolean, so ``on: kind`` parses as ``{True: "kind"}``
    and never reaches this function as a string at all — which is why both
    spellings are checked.  packeteer read the boolean back as the key it was
    written as until 0.13.0; kober renamed the key instead, and one construct
    with two spellings across two projects that claim one dialect is worse than
    the papercut the repair avoided.

    ``False`` is not consulted: no spelling of ``off`` was ever meant to be a
    key here.
    """
    if "dispatch" in mapping:
        return
    if "on" in mapping or True in mapping:
        raise SpecError(
            "a switch dispatches on 'dispatch', not 'on'; the key was renamed "
            "in 0.13.0 to match kober, because YAML 1.1 reads an unquoted "
            "'on:' as the boolean true",
            loc,
        )


def _switch(body: Any, loc: Location, ctx: _Ctx) -> Switch:
    """Build a switch and its cases."""
    mapping = _as_mapping(body, loc, "a switch")
    _reject_renamed_on(mapping, loc)
    _reject_unknown(mapping, _SWITCH_KEYS, "a switch", loc)
    cases_data = _as_mapping(_require(mapping, "cases", loc),
                             loc.child("cases"), "switch cases")
    arms = {
        _int_key(value, loc.child("cases"), "a switch case value"):
            _field_type(arm, loc.child("cases").child(str(value)), ctx)
        for value, arm in cases_data.items()
    }
    default = mapping.get("default")
    return Switch(
        dispatch=_as_str(_require(mapping, "dispatch", loc),
                         loc.child("dispatch"), "a switch selector"),
        arms=arms,
        default=None if default is None
        else _field_type(default, loc.child("default"), ctx),
    )


def _repeat(data: Any, loc: Location, ctx: _Ctx) -> Count | None:
    """Build a repeat from a ``repeat:`` wrapper.

    A field may also lift the repeat kind onto itself, which reaches
    :func:`_one_repeat` directly; both spellings build the identical repeat.
    """
    if data is None:
        return None
    mapping = _as_mapping(data, loc, "a repeat")
    present = sorted(k for k in mapping if str(k) in _REPEAT_KINDS)
    if not present:
        raise SpecError(
            "a repeat names one of 'count', 'until' or 'to_end'", loc,
        )
    if len(present) > 1:
        listed = ", ".join(repr(k) for k in present)
        raise SpecError(
            f"a repeat names {len(present)} kinds ({listed}); it may name "
            f"only one", loc,
        )
    kind = present[0]
    return _one_repeat(kind, mapping[kind], loc.child(kind), ctx)


def _one_repeat(kind: str, body: Any, loc: Location, ctx: _Ctx) -> Count | None:
    """Build the repeat named by *kind*, whether it was lifted or wrapped.

    An unimplemented kind is recorded rather than refused, so it is reported as
    *not supported yet* whichever spelling was used — a construct this version
    lacks must not become an *unknown key* merely because it was written short.
    """
    if kind in _UNSUPPORTED_REPEATS:
        ctx.record(f"repeat.{kind}", loc, _UNSUPPORTED_REPEATS[kind])
        return None
    return Count(expr=_as_str(body, loc, "a repeat count"))


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
