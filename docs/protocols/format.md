# Spec Format Reference

A **protocol spec** describes an application protocol declaratively: what its
messages look like on the wire, which transport and ports carry them, and how
to compute the fields a sender derives rather than chooses.
`packeteer protocol compile` turns one into a Python module that
{doc}`registers an AppProtocol <../guide/adding-a-protocol>`, after which
packeteer parses, builds, serialises and redacts that protocol exactly as it
does DNS, DHCP or HTTP.

A spec is YAML or JSON.  JSON loads from the standard library; YAML needs the
optional extra:

```console
$ pip install 'packeteer[yaml]'
```

```yaml
name: sensor
version: "1.0"
input: datagram
entry: reading
over: udp
ports: [9000]
doc: Field telemetry from the shed sensors.

enums:
  kind: {0: temperature, 1: humidity, 2: pressure}

units:
  reading:
    fields:
      - {name: magic,   bits: 16, const: 0x5345}
      - {name: count,   bits: 8, derive: {count_of: samples}}
      - {name: samples, unit: sample, count: count}

  sample:
    fields:
      - {name: kind,   int: {bits: 8, enum: kind}}
      - {name: length, bits: 8, derive: {size_of: value}}
      - {name: value,  bytes: {size: {expr: "length"}}, sensitive: true}
```

---

(protocols-scope)=
## What a spec can and cannot describe

**One message per packet payload.**  packeteer decodes one packet at a time,
and its guarantee is that a capture rebuilds byte for byte.  A protocol whose
messages span TCP segments has no packet-level identity to reconstruct, so
reassembling one could never participate in `parse` → edit → `build` — see
[`input`](#input) below.  Such a protocol is
[kober](https://github.com/adamkjonsson/zipline-kober)'s, not packeteer's.

**Binary framing, not delimiters.**  A field's length comes from a constant, an
earlier field, the rest of the message, or the rest less a fixed trailer
([`fill`](#fill)).  A field that ends at a byte
sequence — an HTTP header line ending at `\r\n` — is not expressible.

Constructs kober has that this version does not implement are reported by
`packeteer protocol check` as **not supported yet**, naming them, rather than
as unknown keys:

| Construct | Why not |
|---|---|
| `pointer` | Decoding one is straightforward; *encoding* one needs a compression model, and packeteer's own DNS encoder declines to compress |
| `select` | A question asked across a repeated field — what HTTP needs to decide its own framing |
| `computed` | A value derived at decode time; `derive` is the encode-direction answer and covers the cases that matter here |
| `{size: {terminated: …}}`, `{string: {delimiter: …}}` | Delimiter framing, in either spelling |
| `repeat: {until: …}`, `repeat: {to_end: true}` | Repeat by condition, or to the end of the run |
| unit `params:` / `{unit: {args: …}}` | Unit parameters — see [kober's dialect](#protocols-kober) |
| unit `confirm:` / `reject:` | A guard spanning several fields, evaluated once the unit is decoded.  [`const`](#const) covers the single-field case, and [`condition`](#condition) guards one field rather than abandoning a unit |
| recursion | A recursive unit has no statically known size, which both the encoder and the framing checks need |

---

(protocols-kober)=
## Relationship to kober's dialect

The dialect is a **superset of
[kober](https://github.com/adamkjonsson/zipline-kober)'s**.  kober's keys keep
kober's meaning, and packeteer adds four of its own — [`over`](#over),
[`ports`](#ports), [`derive`](#derive) and [`sensitive`](#sensitive) — which
are what a spec needs in order to describe an **encoder**, and what a decoder
never had to have.

[`const`](#const) was packeteer's fifth until kober `0.2.0` adopted it: a magic
number is how *any* decoder refuses traffic that is not its own, so it turned
out not to be an encoder's key at all.  It is now shared, and means the same
thing in both.

A kober spec therefore loads here and describes the same messages; adding
`derive` lines is what makes it describe an encoder too.

**This is enforced rather than intended.**  kober's own shipped examples are
held under `src/tests/kober/`, pinned to a released version, and
`src/tests/test_kober_dialect.py` asserts the outcome for each — including the
refusals and the exact constructs reported as *not supported yet*, so a change
in either dialect shows up as a failing test rather than as a stale sentence
here.  kober vendors packeteer's specs the same way, so the two projects notice
each other moving.

Keys that are kober's alone are **recognised and declined**, never read as
typos:

| Key | Where | Why it has no meaning here |
|---|---|---|
| `confirm`, `reject` | unit | Guards evaluated once a unit is decoded.  A condition spanning more than one field, which [`const`](#const) cannot express — **not supported yet** |
| `emit` | document, unit, field | kober's output granularity.  packeteer writes a packet spec, which has no such axis |
| `params`, `{unit: {args: …}}` | unit | Unit parameters — **not supported yet** |

An unknown key is still an error.  These simply stopped being unknown, which is
strictly more informative than either accepting them silently or rejecting them
as misspellings.

---

## Top level

| Key | Default | Description |
|-----|---------|-------------|
| `name` | *(required)* | Protocol name.  Becomes the registered protocol's name, and so the packet-spec section key — see [`name`](#name) |
| `version` | *(required)* | Spec version, free-form.  **Quote it**: unquoted `1.10` is the number 1.1 in YAML, not the text `"1.10"` |
| `entry` | *(required)* | Name of the unit one message consists of |
| `units` | *(required)* | Every unit, by name — see [Units](#units) |
| `enums` | `{}` | Named values for integer fields — see [Enums](#enums) |
| `over` | `either` | Which transport carries it: `udp`, `tcp`, `either` |
| `ports` | `[]` | Transport ports that identify it |
| `endian` | `big` | Byte order for every integer below, unless it says otherwise — see [`endian`](#endian) |
| `input` | `datagram` | The stream shape the spec is written against — see [`input`](#input) |
| `doc` | — | Free-text description.  Becomes the generated module's docstring |

(name)=
### `name`

Doubles as the packet-spec section key, so a protocol named `sensor` makes
`packeteer parse` emit a `"sensor"` object beside `"network"` and
`"transport"`, and `packeteer build` read it back.  It is also the attribute
the decoded message is reached by — `pkt.sensor` on a parsed packet,
`.sensor(msg)` on the builder — so it has three constraints, and
`packeteer protocol check` refuses a spec that breaks any of them:

- **A plain Python identifier**: letters, digits and underscores, not
  starting with a digit, not a keyword.  `acme-sensor` is not one;
  `acme_sensor` is.
- **Not starting with an underscore**, which marks a private attribute.
- **Not reserved**: none of the structural keys in {doc}`../packet-spec/format`
  — `ethernet`, `network`, `transport`, `payload` and the rest — and none of
  the public names on `ParsedPacket` or `PacketBuilder`, such as `tcp`,
  `build` or `timestamp`, which a protocol so named would shadow.

The namespace is flat, because the same string is a section key and an
attribute and neither can hold a dot.  A library of protocols keeps them
apart with a prefix in each spec's own `name:` — `acme_sensor`, `acme_rpc` —
and a second registration of the same name is refused naming the collision,
so a clash is loud rather than a silent shadow.

(over)=
(ports)=
### `over` and `ports`

What decides when the protocol is used.  A packet whose source or destination
port is claimed, on a matching transport, is handed to this protocol's decoder;
the destination port is consulted first.

**A port claim is a weak signal**, and deliberately so.  A decoder that raises
leaves the bytes as an opaque payload and parsing carries on, which is what
makes claiming a busy port survivable.  Give the entry unit a
[`const`](#const) so a mismatch is recognised rather than mangled.

(endian)=
### `endian`

Byte order resolves **field → unit → document → `big`**, and network order is
the default because the protocols this was written for are on a wire.

```yaml
endian: little          # every integer below, unless it says otherwise

units:
  header:
    fields:
      - {name: magic, bits: 32}
      - {name: version, bits: 16}
      - {name: crc, int: {bits: 32, endian: big}}   # the exception, stated
```

A unit may state its own, overriding the document's for the fields under it.

It exists because of what the alternative costs.  A field needing `endian` must
write `int: {bits: 32, endian: little}`, so **no integer field in a
little-endian spec could use [`bits:`](#shorthands) at all** — which is most
formats not on a wire: a filesystem structure, a USB descriptor, a capture
container.

Resolution happens **when the spec loads** and is folded into each field, so a
spec written with an inherited default builds a spec equal to one with `endian`
on every integer.  It is a shorthand, not a feature.

The cost is that a field's meaning depends on a distant line: `bits: 32` no
longer says how it is read.  `packeteer protocol show` prints the **resolved**
byte order, so the question has a one-command answer:

```console
$ packeteer protocol show container.yaml
header
├── magic: u32 le
├── version: u16 le
└── crc: u32
```

Note what does **not** inherit: `signed`.  A protocol is little-endian; it is
not *signed*.  Byte order is a property of the format as a whole, where
signedness is a property of what an individual field means.

`endian` beside `bits:` at field level is an unknown-key error — the key is on
the document and the unit, and an individual integer still says it inside
`int: {…}`.

(input)=
### `input`

kober's key, with kober's meaning: the **stream shape** the spec is written
against — `datagram`, `stream`, or `either`.

It is a different axis from [`over`](#over), which is the **transport**.  DNS
is the example that makes the difference plain: it is `input: datagram, over:
udp` over UDP, and `input: stream, over: tcp` over TCP, because a TCP DNS
message declares its own length and a UDP one does not.

**`input: stream` is refused by `packeteer protocol compile`.**  A stream
protocol's messages span packets — see [scope](#protocols-scope).  A spec whose
messages each fit in one packet should say `input: datagram`, which is the
default.

---

(units)=
## Units

A unit is a named group of fields, decoded in order.  `entry` names the one a
whole message is.

```yaml
units:
  reading:
    doc: One datagram — a header and a run of samples.
    fields:
      - {name: magic, bits: 16, const: 0x5345}
```

| Key | Default | Description |
|-----|---------|-------------|
| `fields` | *(required)* | The unit's fields, in wire order |
| `endian` | *(the document's)* | Byte order for this unit's integers — see [`endian`](#endian) |
| `doc` | — | Free-text description |

---

## Fields

| Key | Default | Description |
|-----|---------|-------------|
| `name` | *(required)* | Field name.  Must be a Python identifier, since it becomes an attribute.  `null` makes the field anonymous — decoded and re-encoded, but not named |
| *a type kind* | *(required)* | What it holds, written on the field — see [How a field is written](#shorthands) |
| `type` | — | The long form of a type kind — see [Types](#types) |
| *a repeat kind* | — | How many times it occurs, written on the field |
| `repeat` | — | The long form of a repeat kind — see [`repeat`](#repeat) |
| `condition` | — | A guard: the field is present only when it holds — see [`condition`](#condition) |
| `const` | — | A value written on encode and checked on decode — see [`const`](#const) |
| `derive` | — | How the encoder computes it — see [`derive`](#derive) |
| `sensitive` | `false` | Whether `packeteer sanitise` redacts it — see [`sensitive`](#sensitive) |
| `doc` | — | Free-text description |

A field may only reference fields **decoded before it**.  A forward reference
is refused by `check`, naming the field and where it was declared.

(types)=
### Types

A type names exactly one construct.

(shorthands)=
#### How a field is written

**A field says what it decodes on the field itself**, with the kind as one of
its keys.  That is the spelling the shipped examples use and the one to write:

```yaml
- {name: qdcount, bits: 16}
- {name: questions, unit: question, count: qdcount}
- {name: body, bytes: {size: {expr: "length"}}}
```

Underneath it every construct is a **tagged mapping naming the kind**, and the
lines above are three rules over that.  Each builds the *identical* spec —
nothing downstream can tell which spelling was used — so a document may mix
them freely.

**1. A tagged construct's kind lifts into the field**, for its type and for its
repetition alike:

```yaml
- {name: count, type: {int: {bits: 8}}}                          # the same
- {name: count, int: {bits: 8}}

- {name: samples, type: {unit: sample}, repeat: {count: count}}  # the same
- {name: samples, unit: sample, count: count}
```

This is unambiguous because a field's keys come from **three sets that share no
member**:

| | Keys |
|---|---|
| **A field's own** | `name`, `const`, `condition`, `derive`, `sensitive`, `doc`, and the `type`/`repeat` wrappers |
| **A type kind** | `bits`, `int`, `bytes`, `string`, `unit`, `switch` |
| **A repeat kind** | `count` |

**2. A scalar where a mapping is expected fills in the one key that matters.**

```yaml
- {name: body, bytes: {size: {fixed: 4}}}   # long
- {name: body, bytes: {size: 4}}            # a bare size is `fixed`
- {name: body, bytes: 4}                    # a bare bytes/string body is its size
- {name: n, int: 8}                         # a bare int body is its width
- {name: q, unit: question}                 # a bare unit body is its name
```

**3. `bits` names the integer kind**, because the word says what the number
counts.  `int: 8` is a character shorter and cannot say whether the 8 is bits
or bytes — Kaitai's `u8` means eight *bytes* — and sub-byte fields are the
ordinary case here rather than the exotic one.

##### Strictness is unchanged

Exactly one key must name a type kind, and at most one a repeat kind — a
repetition is optional where a type is not.  Two kinds of the same construct is
an error, a lifted kind beside its own wrapper (`count:` with `repeat:`) is an
error, and a key in none of the three sets is still an error, reported with the
set each allowed key belongs to rather than as one flat list.

##### When the long form is needed

It is the fallback rather than the norm, and there are three occasions for it:

- **A body carrying a second key.**  `int: {bits: 4, enum: opcode}`, not
  `{int: 4, enum: opcode}` — `enum`, `signed` or `endian` beside `bits:` is an
  unknown-key error, which is loud rather than quiet.
- **A type inside a construct rather than on a field.**  A [`switch`](#switch)'s
  cases are written `type:`-style, since only a field has the three key sets
  that make lifting unambiguous.
- **Readability**, where a wrapper says more than a lifted key does.

Each entry below leads with the short spelling and gives the long one beside
it.

#### `int`

```yaml
- {name: qr, bits: 1}                                # the common case
- {name: op, int: {bits: 4, enum: opcode}}           # a second key
- {name: id, type: {int: {bits: 16, signed: false}}} # the long form
```

| Key | Default | Description |
|-----|---------|-------------|
| `bits` | *(required)* | Width, 1 to 64.  Sub-byte fields are read most-significant bit first, and consecutive ones must add up to whole bytes |
| `signed` | `false` | Two's-complement when `true` |
| `endian` | *(the unit's, else the document's, else `big`)* | `big` or `little`.  Meaningless below 8 bits, and ignored there — see [`endian`](#endian) |
| `enum` | — | Name of the enum labelling its values |

#### `bytes` and `string`

```yaml
- {name: b, bytes: 4}                                     # a bare body is its size
- {name: b, bytes: {size: {expr: "length"}}}
- {name: s, string: {size: {remaining: true}, encoding: ascii}}
- {name: b, type: {bytes: {size: 4}}}                     # the long form
```

| Size form | Meaning |
|---|---|
| `4` | Exactly four bytes — shorthand for `{fixed: 4}` |
| `{fixed: 4}` | The same |
| `{expr: "n * 2"}` | An integer [expression](#expressions), read from earlier fields |
| `{remaining: true}` | Everything left in the message — see [run-relative sizes](#run-relative) |
| `{fill: true}` | Everything left, **less what the fields after it claim** — see [`fill`](#fill) |
| `{terminated: …}` | Delimiter framing — **not supported yet** |

`string` takes an `encoding` as well, defaulting to `utf-8`.  A `bytes` field
reaches a packet spec as a hex string.

(fill)=
##### `fill`

A body between a header and a fixed footer, which nothing else here can say:

```yaml
- {name: count,     bits: 8}
- {name: data,      bytes: {size: {fill: true}}}
- {name: data_type, bits: 32}
```

`data` is everything left except the four bytes `data_type` still needs.

**The trailing width must be computable from the spec alone**, or the spec is
refused, because a guessed boundary is what `check` exists to prevent.  An
integer contributes its `bits`, a `fixed`-sized `bytes` or `string` its length,
and a nested unit the sum of its fields.  Refused, each naming the field
responsible: a trailing field the spec does not fix a width for — a repeat, a
dynamic size, a [`condition`](#condition), or a `switch` — a second `fill` in
the same unit, a `fill` that repeats, and a trailer that is not a whole number
of bytes.

A message too short to hold the fields after a `fill` is a **truncation** and
raises, rather than yielding an empty body.

(run-relative)=
##### `remaining` and `fill` are measured against the message

Both read to the end of the message rather than to the end of their unit, so
**neither may have anything decoded after it**:

- a field after a `remaining` in the same unit is refused — `remaining` takes
  its bytes too, so there is no input such a spec decodes;
- a unit *containing* either, at any depth, may only be referenced from the
  last position of its own unit.  The property is transitive.

The second is the one worth knowing, because the offending unit looks correct
on its own:

```yaml
units:
  m:
    fields:
      - {name: body, unit: inner}       # refused: `trailer` follows
      - {name: trailer, bits: 32}
  inner:
    fields:
      - {name: data, bytes: {size: {remaining: true}}}
```

`data` *is* the last field of `inner`, and `inner` is perfectly correct as long
as nothing follows it.  Only the reference site shows the fault.

#### `unit`

```yaml
- {name: s, unit: sample}                 # the common case
- {name: s, type: {unit: sample}}         # the long form
- {name: s, type: {unit: {name: sample}}}
```

All three mean the same.  `{unit: {name: x, args: […]}}` is kober's unit
parameters, which are **not supported yet**.

(switch)=
#### `switch`

```yaml
- name: body
  switch:
    dispatch: "kind"
    cases:
      1: {int: {bits: 8}}
      2: {bytes: {size: 2}}
    default: {bytes: {size: {remaining: true}}}
```

A case's value is a **type**, so it is written as a tagged mapping and nothing
lifts inside it: `{int: {bits: 8}}`, not `bits: 8`.  Only a field has the three
key sets that make lifting unambiguous.

| Key | Default | Description |
|-----|---------|-------------|
| `dispatch` | *(required)* | An integer [expression](#expressions) selecting the case |
| `cases` | *(required)* | The type to use, by value |
| `default` | — | The type for a value no case matches |

**Without a `default`, a value no case matches makes the message
undecodable** — the decoder raises and the bytes stay an opaque payload.  That
is often what you want, so `check` warns rather than refusing, to make it a
choice rather than an oversight.

```{note}
**The key was `on` until 0.13.0.**  A spec still written that way is refused
with a message naming the rename, whether or not the `on` was quoted.

An unquoted `on:` is a YAML 1.1 boolean, so it never reaches the loader as a
string at all — which is why the key was renamed rather than repaired, and why
quoting it is not a workaround.  kober renamed it for the same reason, and one
construct with two spellings across two projects claiming one dialect is worse
than the papercut a repair avoids.
```

(repeat)=
### `repeat`

```yaml
- {name: questions, unit: question, count: qdcount}                 # the same
- {name: questions, type: {unit: question}, repeat: {count: qdcount}}
```

The count is an integer [expression](#expressions).  `until` and `to_end` — in
either spelling — are **not supported yet**, and are reported as such rather
than as unknown keys.

A repeated field has no value an expression can read: the language has no list
type, so referencing one is refused.

(const)=
### `const`

```yaml
- {name: magic, bits: 16, const: 0x5345}
```

The value is the field's default, and **decoding raises when the bytes
disagree**.  That is the point: a port claim is weak, so a magic number is what
keeps another protocol's traffic on the same port an opaque payload instead of
a mangled message.

An explicit override is still written on encode, so deliberately malformed
traffic can be built — packeteer generates it on purpose.

(condition)=
### `condition`

```yaml
- {name: flags, bits: 8}
- {name: extra, bits: 16, condition: "flags == 1"}
- {name: tail,  bits: 8}
```

A boolean [expression](#expressions).  **A field whose guard is false is
absent, not empty**: it consumes nothing, so `tail` above is read from the byte
straight after `flags`.

The guard is **authoritative in both directions**, which is what keeps encode
and decode agreeing about what is on the wire:

- **decode** — the guard is evaluated against the fields already read; when it
  is false the field is not read and its attribute is `None`;
- **encode** — the guard is evaluated against the object; when it is false
  nothing is written, *even if the attribute holds a value*.  Setting `extra`
  by hand on a message whose `flags` is 0 does not put it on the wire;
- **`to_spec`** — an absent field's key is omitted, the way a derived field's
  is.

A conditional field compiles to `T | None`, and a repeated one to
`list[T] | None`, where `None` means *absent*.

Two consequences worth knowing:

**A conditional field has no fixed width**, because whether it occupies its
width or nothing is not knowable from the spec.  Anything needing a static
layout refuses it rather than guessing — notably the `input: stream` prefix
check, which needs a length field at a known offset.

**A `derive` may not name a conditional field.**  An absent field has no length
and no elements, and a derivation cannot say whether it is deriving from
nothing or from an empty value, so `check` refuses it.

(derive)=
### `derive`

```yaml
- {name: count,  bits: 8, derive: {count_of: samples}}
- {name: length, bits: 8, derive: {size_of: value}}
```

| Rule | Meaning |
|---|---|
| `size_of: <field>` | The named field's encoded length in bytes.  The target must be a `bytes`, `string` or `unit` field |
| `count_of: <field>` | How many elements the named repeated field has |

A derived field compiles to `int | None`, where `None` means *compute it*:

- **encode** writes the computed value, unless the object carries an override,
  which is written verbatim;
- **decode** clears the field when the capture agrees with the derivation, and
  keeps the captured value when it does not;
- **`to_spec`** omits the key when the field is `None`.

So a well-formed capture produces a spec with no redundant lengths and counts,
and a capture whose length disagrees with its data records the disagreement and
rebuilds byte for byte.  This is the rule `transport.length` and
`transport.checksum` follow — see
{ref}`packet-spec-transport-overrides`.

```{note}
A length used to **read** its target can never disagree with it: exactly that
many bytes were read, so the derivation always matches and the field is always
cleared.  `derive` earns its keep when the target is read some other way — as
`{remaining: true}` or `{fill: true}`, at a fixed size, or where one length
covers several fields.

A [`condition`](#condition) on the target is the one case `derive` refuses: an
absent field has no length and no elements, and a derivation cannot say whether
it is deriving from nothing or from an empty value.
```

(sensitive)=
### `sensitive`

```yaml
- {name: value, bytes: {size: {expr: "length"}}, sensitive: true}
```

Marks a field `packeteer sanitise` redacts.  The compiler emits a redaction
function from these annotations and puts it on the protocol, so a compiled
protocol is sanitised exactly like a built-in.

What each type becomes:

| Type | Redacted to |
|---|---|
| `string` | `"[redacted]"` |
| `bytes` | zeros of the same length — a `size` field elsewhere may derive from it |
| `int` | `0` |
| a unit, or a `switch` arm | every leaf beneath it, blanked by the same rules |

A field of a unit type that is *not* itself marked is still followed into, so
annotating a field deep in a nested unit is enough; and a `repeat`ed field is
redacted element by element.

```{warning}
**A field that carries anything identifying and is not marked is not
redacted.**  Only what is annotated is touched — marking nothing and expecting
the compiler to guess would make `sanitise` useless on the very protocol you
added in order to see your traffic.

A spec that marks **no** field at all is the case worth knowing about: the
protocol declares
{attr}`~packeteer.protocols.AppProtocol.redacts_nothing`, and `packeteer
sanitise` warns once per capture that the section passed through untouched.
That warning is the only thing standing between you and a file that looks
sanitised and is not, so do not silence it without reading it.
```

`packeteer sanitise` also scans every string in an application section for
email addresses and names, whether the field is marked or not, and reports
what it finds.  A report is not a redaction: it tells you a field wants
`sensitive: true`.

---

(enums)=
## Enums

```yaml
enums:
  kind: {0: temperature, 1: humidity, 2: pressure}
```

Labels for an integer field's values, referenced by
`{int: {bits: 8, enum: kind}}`.  They appear in `packeteer protocol show`
output.  Values may be written as numbers or as their string spelling, since
JSON object keys are always strings.

---

(expressions)=
## Expressions

Wherever a spec needs a value it cannot know in advance — a size, a repeat
count, a switch selector, a [`condition`](#condition) — it is written as an
expression string.

```yaml
size:      {expr: "header.length * 4"}
count:     "qdcount"
dispatch:  "length >> 6"
condition: "flags.qr == 0"
```

Most are integer expressions; a `condition` is the one that must be boolean.

| | |
|---|---|
| Arithmetic | `+` `-` `*` `/` `%` |
| Bitwise | `&` `\|` `^` `~` `<<` `>>` |
| Comparison | `==` `!=` `<` `<=` `>` `>=` |
| Boolean | `and` `or` `not` |
| Literals | `42`, `0x2a`, `0b101010`, `'text'`, `true`, `false` |

Precedence is Python's, because the parser is Python's — `ast.parse` in
expression mode against a whitelist.  That is why there are no calls, no
indexing and no comprehensions: they are absent from the whitelist and refused
by name.

**Four types and no coercion**: `int`, `str`, `bytes`, `bool`.  Arithmetic and
ordering are integer-only, equality needs both sides to be the same type, and
`and`/`or`/`not` need booleans — `qdcount and …` is an error rather than a test
for non-zero, and the message says to write `!= 0`.

`/` floors, because there is no floating-point type; a float literal is refused
rather than truncated.

### Scoping

| Prefix | Resolves against |
|---|---|
| *(none)* or `this.` | The containing unit |
| `parent.` | The unit that referenced this one |
| `root.` | The entry unit |

A dotted path descends into a nested unit: `header.length` reads the `length`
field of the `header` field's unit.

kober's three functions — `to_int`, `trim`, `lower` — are **not supported
yet**, and a call is reported as such rather than as a syntax error.
