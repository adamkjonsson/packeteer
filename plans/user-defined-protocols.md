# Plan — user-defined application protocols from YAML

*Written 2026-08-28. Status: **evaluation accepted, nothing filed, nothing
started.** Seven open questions, all listed under
[Open questions](#open-questions) and none of them blocking the first
milestone.*

The idea comes from [zipline-kober](https://github.com/adamkjonsson/zipline-kober),
which compiles a YAML protocol description into a Python decoder. The question
put to this plan was whether packeteer should do the same: let a user describe
their own application protocol in YAML, compile it, and then have `packeteer`
parse and generate that protocol in pcap form the way it already does DNS,
DHCP, and HTTP.

**It is viable, and it is three milestones, not one.** The first of them
(v0.10.0) is worth shipping whether or not the rest ever happens, which is why
it is first.

| Milestone | What lands | Size |
|---|---|---|
| **v0.10.0** | The app-protocol registry. DNS/DHCP/HTTP stop being hardwired and become the first three entries in a table. No YAML anywhere. | ~800 changed, ~400 new |
| **v0.11.0** | The spec language, the checker, and the compiler. `packeteer protocol check\|show\|compile`. Binary datagram protocols only. | ~3,300 new |
| **v0.12.0** | Compiled protocols become first-class: sanitisation, `stream --payload`, CLI loading, docs, conformance suite. | ~1,800 new |

Roughly **6,000 lines net new against a 22k-line library** — the largest
feature the project has taken on. The milestone split exists so that each one
is independently defensible if the next never happens.

---

## The constraint that shapes all three

**kober is decode-only. packeteer cannot be.**

kober turns bytes into records and stops. packeteer's whole value is the round
trip — `parse` → edit the spec → `build`, byte-identical — and the last
milestone spent four issues (#68, #86, #87, and the derived-field work in #68)
defending exactly that property. A spec that only decodes delivers half of
packeteer: a protocol you can read out of a capture and then cannot write back.

So the compiler emits an **encoder as well as a decoder**, and the encoder has
two problems the decoder does not:

1. **Derived fields must be computed, not read.** A length prefix, a repeat
   count, a checksum: on decode these are read and (at most) checked; on encode
   they must be produced from the data beside them. kober's `computed:` reads
   and never writes, so it is not the same construct.

2. **A capture that disagrees with the derivation must survive.** packeteer's
   existing rule — record a derived field *only when the capture disagrees with
   what the builder would compute* — is what makes malformed captures
   round-trip. It is implemented by hand today in
   `_clear_derivable_transport_fields`
   ([parse/core.py:751](../src/packeteer/parse/core.py#L751)), it is why
   `transport.length` and `transport.checksum` were added in 0.9.0, and it is
   spelled out in the comment in
   [parse/udp.py:36](../src/packeteer/parse/udp.py#L36). For generated
   protocols it has to be *generated*, once, correctly, for every derived field.
   This is the single most important thing in the whole plan.

A second constraint, smaller but sharp: **the built-in three will not be
regenerated from YAML.** DNS needs compression pointers, HTTP needs
delimiter framing and a question asked across repeated headers
(kober's `select`), and both are hand-tuned in ways a generic engine will not
reproduce — the mDNS QU/cache-flush bits, HTTP's conditional `Content-Length`.
The YAML engine is for **users' protocols**. packeteer will carry two
app-layer mechanisms indefinitely, and the registry in v0.10.0 is what stops
that from being two *unrelated* mechanisms.

---

## What an application protocol is in packeteer today

DNS, DHCP and HTTP each touch eight places. Nothing is registered; every one
of them is a hardwired reference.

| Concern | Where it lives now | Wired how |
|---|---|---|
| Dataclasses + encoder | [generate/dns.py](../src/packeteer/generate/dns.py) (417 lines) | — |
| Decoder → same dataclasses | [parse/dns.py](../src/packeteer/parse/dns.py) (291) | — |
| Builder convenience | [builder.py:1334](../src/packeteer/generate/builder.py#L1334) | method per protocol |
| Port-triggered decode | [parse/core.py:497](../src/packeteer/parse/core.py#L497) | `_DNS_PORTS` frozenset + a hand-written chain at [core.py:841-843](../src/packeteer/parse/core.py#L841-L843) |
| Object → spec section | [to_config.py:719](../src/packeteer/parse/to_config.py#L719) | `isinstance` ladder in `update_config` |
| Spec section → object | [__main__.py:216](../src/packeteer/__main__.py#L216) | `if "dns" in spec:` at two sites ([650](../src/packeteer/__main__.py#L650), [951](../src/packeteer/__main__.py#L951)) |
| PII rules | [sanitise.py:425](../src/packeteer/sanitise.py#L425) | fixed `_sanitise_app_layers` |
| Docs | `docs/packet-spec/format.md` §`dns`, §`dhcp`, §`http` | — |

About 1,000 lines per protocol. A generated protocol that does not produce all
eight is second-class: buildable but not parseable, or parseable but not
sanitisable.

Two of those rows are already wrong on the project's own terms.
`_build_dns_from_spec`, `_build_dhcp_from_spec` and `_build_http_from_spec`
([__main__.py:216–330](../src/packeteer/__main__.py#L216)) are spec↔object
mapping living in the CLI, which CLAUDE.md forbids twice over ("keep
`__main__.py` as lean as possible", "all functionality implemented in the CLI
is easily available from the API"). Fixing that is not optional for this
feature — a compiled module needs a `from_spec` and it cannot live in
`__main__.py`.

---

# v0.10.0 — the registry

**No YAML. No compiler. No new spec keys.** This milestone writes down the
contract that an application protocol satisfies, converts the three built-ins
to satisfy it explicitly, and replaces every hardwired dispatch with a table
lookup. If the YAML work is never done, this still leaves the codebase better:
it removes a CLAUDE.md violation, deletes three copies of the same `if` ladder,
and gives users a documented way to plug in a hand-written protocol.

### The contract

New top-level module `src/packeteer/protocols.py`, alongside `pcap.py`,
`filter.py` and `sanitise.py`. **It must import neither `generate` nor
`parse`** — both need it, and `parse` already imports `generate`
(`parse/dns.py` imports `generate.dns`), so the registry has to sit below both.

```python
@dataclass(frozen=True)
class AppProtocol:
    """One application-layer protocol packeteer can parse, build and serialise."""

    name:     str                       # "dns" — also the packet-spec section key
    over:     str                       # "udp" | "tcp" | "either"
    ports:    frozenset[int]
    messages: tuple[type, ...]          # dataclasses update_config dispatches on

    decode:    Callable[[bytes, str], object]        # (payload, transport) -> message
    encode:    Callable[[object, str], bytes]        # (message, transport) -> payload
    to_spec:   Callable[[object], dict[str, Any]]    # message -> spec section
    from_spec: Callable[[dict[str, Any]], object]    # spec section -> message
    sanitise:  Callable[[dict[str, Any], _Replacer, SanitiseOptions], None] | None = None


def register(proto: AppProtocol) -> None: ...
def registered() -> tuple[AppProtocol, ...]: ...
def for_port(port: int, transport: str) -> AppProtocol | None: ...
def for_section(name: str) -> AppProtocol | None: ...
def for_message(obj: object) -> AppProtocol | None: ...
```

`register` rejects, loudly:

- a `name` that collides with a reserved packet-spec key — `ethernet`, `arp`,
  `sll`, `sll2`, `mpls`, `pseudowire`, `pppoe`, `etherip`, `ipip`, `gre`,
  `vxlan`, `geneve`, `gtpu`, `ah`, `esp`, `network`, `transport`, `payload`,
  `metadata`, `packet_metadata` (the full list is the `##` headings of
  `docs/packet-spec/format.md`);
- a `name` already registered;
- a port already claimed for the same transport;
- a message type already claimed.

The `transport` argument threaded through `decode`/`encode` is what DNS needs
for its TCP length prefix (RFC 1035 §4.2.2) — today that is the `tcp=` keyword
on `PacketBuilder.dns`. Making it part of the contract rather than a
per-protocol keyword is what lets a generated protocol declare `over: either`.

### The assembly layer

New package `src/packeteer/app/` — `dns.py`, `dhcp.py`, `http.py`,
`__init__.py`. Each module assembles one `AppProtocol` from parts that already
exist, and owns the two functions that currently have no home:

- **`from_spec`** — moved verbatim out of `__main__.py` (`_build_dns_from_spec`
  and friends, ~115 lines total), made public as
  `packeteer.app.dns.from_spec`. This is the CLAUDE.md fix.
- **`to_spec`** — a thin public wrapper over the existing `_apply_dns` in
  `to_config.py`, returning the section instead of mutating a config.

`app/__init__.py` calls `register()` for the three, and is imported from
`packeteer/__init__.py` so the built-ins are always present.

### The four dispatch sites, rewritten

**1. Decode** — [parse/core.py:841-843](../src/packeteer/parse/core.py#L841-L843)
becomes one lookup instead of three sequential attempts:

```python
if decode_app and isinstance(t, (TCPHeader, UDPHeader)):
    transport = "tcp" if isinstance(t, TCPHeader) else "udp"
    proto = (protocols.for_port(t.dst_port, transport)
             or protocols.for_port(t.src_port, transport))
    if proto is not None and remaining:
        try:
            pkt.app = proto.decode(remaining, transport)
            pkt.app_protocol = proto.name
            remaining = b""
        except (ValueError, struct.error, UnicodeDecodeError):
            pass            # not ours after all — leave it as payload
```

`ParsedPacket` gains `app: object | None` and `app_protocol: str | None`. The
existing `dns` / `dhcp` / `http` attributes **stay**, populated alongside
`app` for the built-ins — they are released public API and there is no reason
to break them. That keeps this milestone free of `Breaking:` markers.

The `except` clause is doing real work and needs a test: a payload on port
9000 that a registered protocol rejects must come back as `payload`, exactly
as a malformed DNS packet on port 53 does today.

**2. Object → spec** — the `isinstance` ladder in `update_config`
([to_config.py:860-880](../src/packeteer/parse/to_config.py#L860)) keeps its
header cases and loses its three app cases to:

```python
proto = protocols.for_message(layer)
if proto is not None:
    config[proto.name] = proto.to_spec(layer)
```

**3. Spec → builder** — both sites in `__main__.py`
([650](../src/packeteer/__main__.py#L650),
[951](../src/packeteer/__main__.py#L951)) become the same loop, and the loop
belongs in the API rather than the CLI:

```python
def apply_app_section(b: PacketBuilder, spec: dict, transport: str) -> PacketBuilder | None:
    for proto in protocols.registered():
        if proto.name in spec:
            return b.payload(data=proto.encode(proto.from_spec(spec[proto.name]), transport))
    return None
```

Note this drops the current `elif` precedence between `dns` / `dhcp` / `http`
in favour of registration order. Two app sections in one packet spec is
already meaningless; make it an **error** rather than silently taking the
first, and say so in the changelog.

**4. Sanitise** — `_sanitise_app_layers`
([sanitise.py:563](../src/packeteer/sanitise.py#L563)) becomes:

```python
for proto in protocols.registered():
    if proto.sanitise is not None and proto.name in pkt:
        proto.sanitise(pkt[proto.name], r, opts)
```

### Builder

Add one generic method beside the three existing ones:

```python
def app(self, msg: object) -> "PacketBuilder":
    """Set the payload to a serialised message of any registered protocol."""
```

It resolves `msg`'s type through `protocols.for_message`, infers the transport
from the layer stack already on the builder, and raises `TypeError` naming the
type if nothing is registered for it. `.dns()`, `.dhcp()` and `.http()` stay
exactly as they are — they are documented, they have keyword arguments of
their own, and rewriting them as `app()` wrappers buys nothing.

### Tests

- `register()` rejects each of the four collision classes, with the message
  naming what collided.
- A hand-written toy protocol registered in a test, then: built from a packet
  spec, parsed back out of the resulting pcap, round-tripped
  `build → parse → build` to identical bytes, and sanitised.
- Every existing DNS/DHCP/HTTP test passes unchanged — this milestone is
  behaviour-preserving for the built-ins, and that is the acceptance criterion.
- `pkt.dns is pkt.app` for a DNS packet; `pkt.app_protocol == "dns"`.
- A registered protocol whose `decode` raises leaves `pkt.payload` intact.
- Two app sections in one packet spec is a clean error, not a silent pick.

### Changelog

Under `Added`: `packeteer.protocols` with `AppProtocol` / `register` /
`registered`, `ParsedPacket.app` and `.app_protocol`, `PacketBuilder.app`, and
`packeteer.app.dns.from_spec` / `to_spec` (with `dhcp`, `http`) as public API.
Under `Changed`: two app-layer sections in one packet spec is now an error.
Under `Documentation`: a new "writing a protocol by hand" page — the registry
is a supported extension point from the day it exists, not just plumbing for
v0.11.0.

### Undecided

See [Q1](#q1) (relocate the built-ins' implementations, or only their dispatch)
and [Q5](#q5) (does a user protocol get a named `ParsedPacket` attribute).
Neither blocks starting.

---

# v0.11.0 — the language and the compiler

New package `src/packeteer/protospec/`. Three CLI verbs. The output is a
Python module that registers an `AppProtocol` — so this milestone is *only*
about producing something the v0.10.0 contract already accepts.

### The subset, chosen deliberately

| In | Out (deferred, and why) |
|---|---|
| `int` — 1 to 64 bits, signed/unsigned, either endianness, optional enum | **compression pointers** — decode is kober's `pointer:`, but *encoding* one requires a compression model; packeteer's own DNS encoder declines to compress |
| `bytes` / `string` — fixed size, or sized by an earlier field | **delimiter framing** (`until b"\r\n\r\n"`) — the text-protocol path, and half of HTTP |
| `unit` — nested, no recursion in v1 | **`select`** — a question asked across a repeated field; HTTP's chunked-vs-length framing needs it |
| `repeat: {count: <field>}` | **checksum derivations** — needs a pluggable algorithm table and a coverage expression |
| `switch` on an earlier field, no default → the region stays `payload` | **messages spanning TCP segments** — see below |
| `const:` — encode writes it, decode checks it | recursion, `params:`, `pointer`, `to_end` repeats |
| `derive: {size_of: …}` / `{count_of: …}` | |
| `sensitive:` (consumed in v0.12.0) | |

**The TCP limitation is the one to state loudest.** v1 protocols are
**datagram-shaped: one message per packet payload**. That is what
`parse_packet` hands to a decoder, and reassembling a message across segments
means teaching the decoder to be a stream consumer — a different and larger
feature. UDP request/response protocols work fully; TCP works only when each
segment carries a whole message. `check` should warn when `over: tcp` is
declared without a self-delimiting length prefix at the front of the entry
unit, because that is the shape that will disappoint someone.

The subset is chosen against the actual user story — *"our telemetry protocol
on UDP 9000"* — and against a useful honesty test: **DNS and HTTP are not
expressible in it.** If that ever stops being true, the built-ins can be
reconsidered. Until then they stay hand-written, as stated up front.

### The spec

```yaml
name: sensor
version: "1.0"
entry: reading
over: udp
ports: [9000]
doc: Field telemetry from the shed sensors.

enums:
  kind: {0: temperature, 1: humidity, 2: pressure}

units:
  reading:
    doc: One datagram — a header and a run of samples.
    fields:
      - {name: magic,   type: {int: {bits: 16}}, const: 0x5345}
      - {name: version, type: {int: {bits: 8}}}
      - {name: count,   type: {int: {bits: 8}}, derive: {count_of: samples}}
      - {name: samples, type: {unit: sample}, repeat: {count: count}}

  sample:
    fields:
      - {name: kind,     type: {int: {bits: 8, enum: kind}}}
      - {name: length,   type: {int: {bits: 8}}, derive: {size_of: value}}
      - {name: value,    type: {bytes: {size: length}}, sensitive: true}
      - {name: reading,  type: {int: {bits: 32, signed: true, endian: little}}}
```

Four keys are packeteer's and are not in kober, each earning its place:

- **`over:` / `ports:`** — the binding that makes decoding automatic. Without
  it a compiled protocol would have to be wired up by hand, which is the thing
  v0.10.0 exists to avoid.
- **`const:`** — encode writes it, decode *checks* it. This is the
  "does this payload actually belong to me" test, and it matters precisely
  because port numbers are a weak claim: a magic mismatch must raise so the
  registry's `except` clause leaves the bytes as `payload`.
- **`derive:`** — the encode-direction answer. `size_of: <field>` (encoded byte
  length) and `count_of: <field>` (elements of a repeated field) in v1.
- **`sensitive:`** — the sanitisation annotation, consumed in v0.12.0 but part
  of the grammar from the start so specs written against v0.11.0 do not need
  revisiting.

### The derived-field rule, stated once

For every field carrying `derive:`, the generated code does exactly this:

- **encode** — ignore whatever the message object holds and write the derived
  value, *unless* the object carries an explicit override, in which case write
  the override. The dataclass field is therefore `int | None = None`, meaning
  "derive it".
- **decode** — read the value. If it equals what the derivation would produce,
  set the attribute to `None`. If it differs, keep the captured value.
- **`to_spec`** — omit the key when the attribute is `None`.

The consequence is the property this whole feature stands on: a well-formed
capture produces a *clean* spec with no redundant length and count fields, and
a **malformed** capture — a length field that lies — produces a spec that
records the lie and rebuilds it byte-for-byte. That is the same rule
`transport.length` and `transport.checksum` follow after 0.9.0, applied by a
compiler instead of by hand.

### Modules

| File | Purpose | Est. |
|---|---|---|
| `protospec/spec.py` | Frozen dataclasses for the grammar | 450 |
| `protospec/loader.py` | JSON (stdlib) and YAML (optional extra) → `Spec`, with source positions for error messages | 250 |
| `protospec/expr.py` | The expression language: field refs, arithmetic, comparison. Deliberately smaller than kober's 1,039 lines — no function table in v1 | 350 |
| `protospec/check.py` | Static validation before any data exists, in **both** directions | 700 |
| `protospec/codegen.py` | `Spec` → Python source | 1,300 |
| `protospec/errors.py` | `SpecError`, `CheckError`, `CompileError` | 100 |
| `__main__.py` | Three verbs | 200 |

`check` reports every fault it can find rather than stopping at the first — the
behaviour kober demonstrates and the reason a spec gets fixed in one pass. Its
bidirectional obligation is the new part: on top of kober's checks (a field may
only reference fields decoded before it; unknown enums; unreachable units) it
must also refuse **specs that decode but cannot encode** — a `derive:` naming
a field that is not sized or counted by it, a `switch` whose selector is itself
derived from the switched region, a `bytes` field sized by an expression that
cannot be inverted.

### The generated module

```python
# Generated by packeteer 0.11.0 from sensor.yaml (spec sensor 1.0).
# Do not edit; edit the spec and recompile.
from __future__ import annotations
...

@dataclass
class Sample:
    kind: int = 0
    length: int | None = None      # derived: size_of(value)
    value: bytes = b""
    reading: int = 0

@dataclass
class Reading:
    magic: int = 0x5345            # const
    version: int = 0
    count: int | None = None       # derived: count_of(samples)
    samples: list[Sample] = field(default_factory=list)

def encode(msg: Reading, transport: str = "udp") -> bytes: ...
def decode(data: bytes, transport: str = "udp") -> Reading: ...
def to_spec(msg: Reading) -> dict[str, Any]: ...
def from_spec(section: dict[str, Any]) -> Reading: ...

PROTOCOL = AppProtocol(name="sensor", over="udp", ports=frozenset({9000}), ...)
register(PROTOCOL)
```

Import it and it works — `PacketBuilder().ethernet().ip(...).udp(dst_port=9000)
.app(Reading(samples=[...]))`, and `packeteer parse` produces a `"sensor"`
section in the spec.

### Safety of generated code

Three rules, taken straight from kober's `pygen.py` because they are correct
and the failure mode is severe — author-supplied text reaching Python source:

1. **Names are validated against a whitelist, never silently renamed.** A spec
   field that is not a Python identifier, or a Python keyword, or that collides
   with a generated name, is a `CompileError`. A decoder whose field quietly
   changed name is worse than one that will not compile.
2. **Nothing is interpolated.** `doc:` strings and enum labels become escaped
   literals and escaped docstrings.
3. **`codegen` runs `ast.parse` on its own output before writing it**, so a
   generator bug is a refusal rather than a broken module on someone's disk.

### Dependencies

packeteer has **zero runtime dependencies** and keeps them. JSON specs work
from the stdlib; YAML is an optional extra (`pip install packeteer[yaml]`),
needed only to *compile* — a generated module imports nothing but `packeteer`
and the stdlib. This is kober's answer and it is the right one.

### Tests

- **Round-trip properties, generated per spec and run over random messages:**
  `decode(encode(m)) == m` and `encode(decode(b)) == b`. The second is the one
  that matters and the one that catches derived-field bugs.
- **The lying-length capture** — a hand-built payload whose length field
  disagrees with its data: decode records it, `to_spec` emits it, `from_spec`
  → `encode` reproduces the original bytes exactly.
- **`const` mismatch** → `ValueError` → the packet keeps its `payload` section
  when parsed through `packeteer parse`.
- **`check` refuses** each documented fault class, reporting all of them in one
  pass, with the spec's line number.
- **`codegen` refuses** every hostile name: keywords, non-identifiers,
  collisions, and a `doc:` string containing `"""`.
- Three real specs in `examples/protocols/` exercised end to end: the sensor
  protocol above, a length-prefixed TCP protocol, and one using `switch`.
- Truncated input at every byte offset of a valid message raises cleanly rather
  than returning a half-built object.

### Changelog

`Added`: the `packeteer protocol` verb group, the `protospec` API, the spec
format reference, the `yaml` extra.

---

# v0.12.0 — first-class citizenship

v0.11.0 leaves a compiled protocol working but hand-imported. This milestone
makes it indistinguishable from a built-in.

### Sanitisation — the one place silence is harmful

A protocol that fails to build is merely incomplete. A protocol whose fields
flow through `packeteer sanitise` untouched is a **PII leak**, and the whole
point of that command is that it is trustworthy.

`sensitive: true` compiles to a generated `sanitise` function that redacts the
field the way `_sanitise_http` redacts header values. The harder question is
the default for fields with **no** annotation, which is [Q4](#q4). The
recommendation there is: sanitise what is annotated, and **warn** — through the
existing `PersonalDataWarning` machinery — the first time a spec with no
`sensitive:` annotations anywhere passes through `sanitise`. Silence is the one
outcome that must not be available.

The existing UTF-8 PII scanner (`_scan_utf8_payload`) should also run over
generated `string` fields, which is where a name or an email will actually be.

### Loading without an import

`packeteer parse`/`build` need to find a compiled protocol. Three mechanisms,
in increasing order of how much they should be trusted:

- `packeteer --protocol ./sensor.py` (repeatable) — explicit, per invocation.
- A `"protocols": ["./sensor.py"]` key in the packet spec — so a spec is
  self-describing and `parse` → `build` works without re-passing the flag.
- `PACKETEER_PROTOCOLS`, colon-separated — for a shell that always wants them.

All three import Python from a path, which is a real consideration for a tool
people point at untrusted captures. It is no worse than `import` (the user
names the file), but the docs must say plainly that a protocol module is code
and is trusted as code, and `--protocol` must never be inferred from the
capture's contents.

### `stream --payload`

`packeteer stream --payload http|vpn`
([__main__.py:2295](../src/packeteer/__main__.py#L2295)) becomes
`--payload <registered name>`, so a user protocol can drive a generated
conversation. This is cheap because [session.py](../src/packeteer/generate/session.py)
already takes bytes — `TCPSession.send()` / `UDPSession.send()` need nothing
new. What it needs is a way for the spec to say *what messages to send*, which
is a `--protocol-messages sensor.json` file of spec sections rather than
anything new in the protocol grammar. Keep the grammar out of it.

### Docs

- `docs/protocols/format.md` — the spec reference, on the scale of
  `docs/packet-spec/format.md` (~1,100 lines today).
- `docs/protocols/index.md` — a walkthrough, spec to pcap.
- `docs/guide/parsing.md` and `generating.md` gain the registry.
- `docs/packet-spec/format.md` gains a section on user protocol sections.

### The conformance suite

A generic harness that takes any registered protocol — built-in or generated —
and asserts the eight contract properties against it. The built-ins run under
it too, which is what stops the two mechanisms from drifting.

### Changelog

`Added`: `--protocol`, the `protocols` spec key, `sensitive:`,
`stream --payload <name>`. `Changed`: `--payload` accepts any registered name
(not breaking — `http` and `vpn` still work).

---

## Open questions

None block v0.10.0. Q1 and Q5 should be settled before it ships; Q2, Q3, Q6
before v0.11.0 starts.

<a id="q1"></a>
**Q1 — Do the built-ins' *implementations* move into `app/`, or only their
dispatch?** Moving `_apply_dns` out of `to_config.py` and `_sanitise_dns` out
of `sanitise.py` gives one file per protocol and a clean model, at the cost of
~400 lines of churn in two of the most carefully tested modules in the project,
and a possible import cycle with `sanitise`'s `_Replacer`.
*Recommendation: dispatch only in v0.10.0.* `app/dns.py` references the
existing private helpers and owns just `from_spec` (which has to move
regardless). Revisit once a generated protocol exists to compare against.

<a id="q2"></a>
**Q2 — Compile only, or also interpret?** kober compiles for a ~20× decode
speedup over large `.zpf` files. packeteer decodes one message per packet and
is not bound there, so *its* argument for compiling is different: the module is
a readable, reviewable, vendorable artifact whose dataclasses users construct
directly, which is exactly how packeteer's app layers already feel. An
interpreter (`--protocol sensor.yaml`, no compile step) would be a genuinely
nicer first five minutes.
*Recommendation: compile only in v0.11.0.* An interpreter is a second
implementation of the same semantics and the place where the two silently
diverge. If the ergonomics prove to matter, `--protocol sensor.yaml` can
compile to a cache directory instead.

<a id="q3"></a>
**Q3 — Superset of kober's dialect, or deliberately distinct?** A superset
means a kober spec decodes in packeteer unchanged and gains encoding with a
`derive:` line — attractive, given the two projects already trade issues in
both directions (#81–#83 came from kober). The risk is two dialects that look
identical and differ in semantics, which is worse than either alone.
*Recommendation: superset, and say so in the docs*, with `check` reporting
kober constructs that v1 does not implement as "not supported yet" rather than
"unknown key".

<a id="q4"></a>
**Q4 — What does `sanitise` do with unannotated fields of a generated
protocol?** Options: nothing (silent, dangerous); zero everything not marked
safe (safe, and makes the command useless on the protocol you added precisely
to see it); or annotate-and-warn.
*Recommendation: annotate, plus a one-shot warning when a spec carries no
annotations at all.* Decide before v0.12.0, but land the `sensitive:` grammar
in v0.11.0 either way.

<a id="q5"></a>
**Q5 — Does a user protocol get its own `ParsedPacket` attribute?** `pkt.app`
is honest and statically typed; `pkt.sensor` is what people will try first, and
costs a `__getattr__` on a frozen-ish dataclass plus a hole in the type
annotations.
*Recommendation: `pkt.app` only.* `pkt.app_protocol == "sensor"` is the
discriminator, and it keeps `ParsedPacket` fully annotated as CLAUDE.md
requires.

<a id="q6"></a>
**Q6 — Is one-message-per-packet acceptable for v1?** It rules out any TCP
protocol whose messages span segments. Stated up front so nobody discovers it
after writing a spec.

<a id="q7"></a>
**Q7 — Where do compiled modules go by default?** `--out` only, or a
packeteer-managed cache?
*Recommendation: `--out` only, defaulting to `./<name>.py`.* The generated
file is meant to be committed and reviewed; hiding it in a cache works against
that.

---

## Cross-cutting

- **Semver.** v0.10.0 needs no `Breaking:` marker — `ParsedPacket.dns` and the
  three builder methods survive untouched — except for the two-app-sections
  error, which is a behaviour change worth an entry. The generated-module shape
  enters the compatibility contract in v0.11.0: **a module generated by
  0.11.0 must keep importing under 0.12.0.** Stamp `packeteer 0.11.0` in the
  generated header and test an old generated module against the current tree.

- **Issues.** None filed. Suggested: one per v0.10.0 dispatch site (registry,
  `parse` dispatch, `to_config` dispatch, the `__main__.py` extraction) since
  they land independently; one per `protospec` module for v0.11.0; one per
  integration point for v0.12.0. Issues close at release, not at merge
  (CLAUDE.md).

- **kober.** Do not vendor it and do not depend on it — it is unreleased, and
  more than half of it (`stage.py`, `cursor.py`, `emit.py`, `runtime.py`, most
  of `decoder.py` — roughly 2,400 lines) is zipline's byte-citation and
  coverage model, which packeteer has no use for. What transfers is the design,
  and largely the text, of `spec.py`, `check.py`, `expr.py`, `loader.py` and
  `errors.py` — about 3,100 of its 10,500 lines. `pygen.py` (2,921 lines) is
  the right template for *emitting safe Python* and the wrong output shape.
  Same author, so licensing is not the question; release cadence is.

- **Ruff.** `protospec/codegen.py` will strain `max-statements = 200` and
  `max-branches = 20`. Split the emitters per construct rather than raising the
  limits — CLAUDE.md forbids relaxing `ruff.toml` to silence a warning.

- **The standing cost.** After all three milestones packeteer has two
  app-layer mechanisms — hand-written built-ins and compiled user protocols —
  and will keep both. The conformance suite in v0.12.0 is the thing that keeps
  them honest with each other. That cost should be accepted openly now rather
  than discovered later as an argument for regenerating DNS from YAML, which
  will not work.
