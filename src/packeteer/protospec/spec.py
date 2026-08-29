"""The shape of a protocol spec, once loaded.

A spec describes an application protocol declaratively: what its messages
look like on the wire, which transport and ports carry them, and how to derive
the fields that a sender computes rather than chooses.  Everything here is
frozen data — :mod:`packeteer.protospec.loader` produces it,
``check`` validates it, and ``codegen`` turns it into a Python module
implementing :class:`packeteer.protocols.AppProtocol`.

The dialect is a **superset of kober's**: kober's keys keep kober's meaning,
and packeteer adds five of its own — ``over``, ``ports``, ``const``,
``derive`` and ``sensitive``.  A kober spec therefore loads and describes a
decoder; adding ``derive`` lines is what makes it describe an encoder too.

Two declarations are easy to confuse and are independent:

* :attr:`Spec.input` — kober's, the **stream shape** the spec is written
  against (:class:`InputShape`).
* :attr:`Spec.over` — packeteer's, **which transport** carries it
  (:class:`Transport`).

DNS is the example that makes the difference plain: it is
``input: datagram, over: udp`` over UDP and ``input: stream, over: tcp`` over
TCP, because a TCP DNS message declares its own length and a UDP one does not.

Constructs this version does not implement are not errors at load time.  They
are recorded as :class:`Unsupported` so the checker can say *not supported
yet* and name them, rather than *unknown key* — the difference between "this
will work later" and "you typed something wrong", which is what a reader
pasting in a kober spec needs to know.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Mapping, Union

__all__ = [
    "BytesType",
    "Const",
    "Count",
    "CountOf",
    "Derive",
    "Endian",
    "EnumDef",
    "Field",
    "FieldType",
    "Fixed",
    "FromExpr",
    "InputShape",
    "IntType",
    "Location",
    "Remaining",
    "Size",
    "SizeOf",
    "Spec",
    "StringType",
    "Switch",
    "Transport",
    "Unit",
    "UnitRef",
    "Unsupported",
]


# ── where something is ────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Location:
    """Where in a spec something is.

    The dotted *path* is always available and is often the more useful of the
    two, since it names the construct rather than a line that may have moved.
    *line* is filled in for YAML, whose parser reports positions, and is
    ``None`` for JSON, whose parser does not.

    Attributes:
        path: Dotted path to the construct, e.g.
            ``"units.reading.fields[2]"``.
        line: 1-based line number, when the source format supplies one.
        source: File the spec was read from, when it came from a file.

    """

    path: str
    line: int | None = None
    source: str | None = None

    def child(self, step: str) -> Location:
        """Return the location of *step* within this one.

        Args:
            step: A key name, or an index like ``"[2]"``.

        Returns:
            A new :class:`Location`, keeping *line* and *source*.

        """
        joined = f"{self.path}{step}" if step.startswith("[") else f"{self.path}.{step}"
        return Location(path=joined.lstrip("."), line=self.line, source=self.source)

    def at_line(self, line: int | None) -> Location:
        """Return this location with *line* attached.

        Args:
            line: 1-based line number, or ``None`` to leave it unset.

        Returns:
            A new :class:`Location`.

        """
        return Location(path=self.path, line=line, source=self.source)

    def __str__(self) -> str:
        where = self.source or "<spec>"
        if self.line is not None:
            return f"{where}:{self.line}: {self.path}"
        return f"{where}: {self.path}"


# ── declarations ──────────────────────────────────────────────────────────────

class InputShape(Enum):
    """The stream shape a spec is written against.

    kober's key, with kober's meaning.  It decides how a message is framed,
    not which transport carries it — see :class:`Transport`.
    """

    DATAGRAM = "datagram"
    STREAM = "stream"
    EITHER = "either"


class Transport(Enum):
    """Which transport carries the protocol.

    packeteer's, and the same vocabulary as
    :attr:`packeteer.protocols.AppProtocol.over`, which it becomes.
    """

    UDP = "udp"
    TCP = "tcp"
    EITHER = "either"


class Endian(Enum):
    """Byte order of an integer field."""

    BIG = "big"
    LITTLE = "little"


# ── sizes ─────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Fixed:
    """A size given as a constant number of bytes.

    Attributes:
        length: Byte count.

    """

    length: int


@dataclass(frozen=True)
class FromExpr:
    """A size read from an earlier field.

    The expression is held as source text here; parsing and typing it is the
    expression language's job.

    Attributes:
        expr: The expression source, e.g. ``"length"`` or ``"length - 2"``.

    """

    expr: str


@dataclass(frozen=True)
class Remaining:
    """A size covering the rest of the enclosing run of bytes."""


Size = Union[Fixed, FromExpr, Remaining]


# ── repeats ───────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Count:
    """Repeat a field a number of times given by an expression.

    Attributes:
        expr: The expression source, e.g. ``"qdcount"``.

    """

    expr: str


# ── field types ───────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class IntType:
    """An integer of any width from 1 to 64 bits.

    Attributes:
        bits: Width in bits, 1 to 64.
        signed: Whether the value is two's-complement signed.
        endian: Byte order.  Ignored for widths under 8 bits.
        enum: Name of the enum that labels its values, or ``None``.

    """

    bits: int
    signed: bool = False
    endian: Endian = Endian.BIG
    enum: str | None = None


@dataclass(frozen=True)
class BytesType:
    """An opaque run of bytes.

    Attributes:
        size: How long it is.

    """

    size: Size


@dataclass(frozen=True)
class StringType:
    """Text, decoded from a run of bytes.

    Attributes:
        size: How long it is.
        encoding: Codec name, as understood by :meth:`bytes.decode`.

    """

    size: Size
    encoding: str = "utf-8"


@dataclass(frozen=True)
class UnitRef:
    """An instance of another unit.

    Attributes:
        unit: The referenced unit's name.

    """

    unit: str


@dataclass(frozen=True)
class Switch:
    """Choose a type from the value of an earlier field.

    A value with no arm and no *default* leaves the region undecoded, which
    surfaces as an opaque payload rather than a guess.

    Attributes:
        on: Expression source selecting the arm.
        arms: Type to use, by selector value.
        default: Type for a value no arm matches, or ``None`` to leave the
            region undecoded.

    """

    on: str
    arms: Mapping[int, FieldType]
    default: FieldType | None = None


FieldType = Union[IntType, BytesType, StringType, UnitRef, Switch]


# ── packeteer's additions ─────────────────────────────────────────────────────

@dataclass(frozen=True)
class SizeOf:
    """Derive a field's value from the encoded length of another.

    Attributes:
        field: Name of the field whose encoded byte length this holds.

    """

    field: str


@dataclass(frozen=True)
class CountOf:
    """Derive a field's value from the number of elements in a repeated field.

    Attributes:
        field: Name of the repeated field this counts.

    """

    field: str


Derive = Union[SizeOf, CountOf]


@dataclass(frozen=True)
class Const:
    """A value the encoder writes and the decoder checks.

    A mismatch on decode raises, which is what leaves someone else's traffic
    on a shared port as an opaque payload rather than a mangled message.

    Attributes:
        value: The required value — an integer for an integer field, bytes for
            a bytes field, text for a string field.

    """

    value: int | bytes | str


# ── the tree ──────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Field:
    """One field of a unit.

    Attributes:
        name: Field name, or ``None`` for an anonymous field — reserved bits
            that are decoded and re-encoded but not named.
        type: What it holds.
        loc: Where it is in the spec.
        repeat: How many times it occurs, or ``None`` for exactly once.
        const: A value the encoder writes and the decoder checks, or ``None``.
        derive: How the encoder computes it, or ``None`` when the value is the
            author's to choose.
        sensitive: Whether ``packeteer sanitise`` should redact it.
        doc: Free-text description.

    """

    name: str | None
    type: FieldType
    loc: Location
    repeat: Count | None = None
    const: Const | None = None
    derive: Derive | None = None
    sensitive: bool = False
    doc: str | None = None


@dataclass(frozen=True)
class Unit:
    """A named group of fields.

    Attributes:
        name: The unit's name, as referenced by :class:`UnitRef`.
        fields: Its fields, in wire order.
        loc: Where it is in the spec.
        doc: Free-text description.

    """

    name: str
    fields: tuple[Field, ...]
    loc: Location
    doc: str | None = None


@dataclass(frozen=True)
class EnumDef:
    """Named values for an integer field.

    Attributes:
        name: The enum's name, as referenced by :attr:`IntType.enum`.
        members: Label, by value.
        loc: Where it is in the spec.

    """

    name: str
    members: Mapping[int, str]
    loc: Location


@dataclass(frozen=True)
class Unsupported:
    """A construct this version reads but does not implement.

    Recorded rather than refused, so that the checker can report *not
    supported yet* and name it.  A spec written for kober will usually carry
    a few.

    Attributes:
        construct: What it is, e.g. ``"pointer"`` or ``"repeat.until"``.
        loc: Where it is in the spec.
        note: Why it is not implemented, for the message the checker prints.

    """

    construct: str
    loc: Location
    note: str = ""


@dataclass(frozen=True)
class Spec:
    """A complete protocol description.

    Attributes:
        name: Protocol name.  Becomes
            :attr:`packeteer.protocols.AppProtocol.name`, and so the
            packet-spec section key.
        version: Spec version, free-form.
        entry: Name of the unit one message consists of.
        units: Every unit, by name.
        over: Which transport carries it.
        ports: Ports that identify it.
        enums: Every enum, by name.
        input: The stream shape the spec is written against.
        doc: Free-text description.
        unsupported: Constructs present in the source that this version reads
            but does not implement.
        loc: Where the spec came from.

    """

    name: str
    version: str
    entry: str
    units: Mapping[str, Unit]
    over: Transport
    ports: frozenset[int]
    enums: Mapping[str, EnumDef] = field(default_factory=dict)
    input: InputShape = InputShape.DATAGRAM
    doc: str | None = None
    unsupported: tuple[Unsupported, ...] = ()
    loc: Location = Location(path="")
