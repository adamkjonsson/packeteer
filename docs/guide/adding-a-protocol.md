# Adding an application protocol

packeteer ships with DNS, DHCP and HTTP.  If your traffic carries something
else — a proprietary telemetry format, an internal RPC, a protocol packeteer
has never heard of — you can register it and have it treated exactly like a
built-in: decoded out of a capture, written into a packet spec, built back
into bytes, and redacted by `packeteer sanitise`.

There is nothing privileged about the three built-ins.  They are registered
through the same interface described here, in
{mod}`packeteer.app`.

```{note}
**There are two routes, and this is the second one.**  Most protocols are
easier to describe in YAML and compile — see {doc}`../protocols/index`.  Write
one by hand when the spec language cannot express yours: delimiter framing,
compression pointers, a message spanning packets, or anything needing code.
The two produce the same thing, and packeteer cannot tell them apart, and
**both are permanent** — DNS, DHCP and HTTP are not expressible in the spec
subset, which is why they are hand-written and will stay so.
```

## The contract

An application protocol is a {class}`~packeteer.protocols.AppProtocol`: what
identifies it on the wire, what message types it produces, and four callables
that move a message between three representations.

```
                 decode                 to_spec
    bytes  ─────────────────▶  message  ─────────────────▶  spec section
      ▲                          │  ▲                            │
      └──────────────────────────┘  └────────────────────────────┘
                 encode                       from_spec
```

Each pair is an inverse of the other, and that is the whole obligation:
`decode` then `encode` must give back the bytes you started with, and
`to_spec` then `from_spec` must give back an equal message.  That round trip
is what makes `parse` → edit → `build` work, and it is the property worth
testing first.

## A worked example

Say your sensors send UDP datagrams on port 9000: a two-byte magic number, a
one-byte reading count, then that many records of `{kind, value}`.

### 1. The message type

Any class will do; a dataclass gives you equality for free, which the round
trip test needs.

```python
from dataclasses import dataclass, field

@dataclass
class Reading:
    version: int = 1
    samples: list[tuple[int, int]] = field(default_factory=list)
```

### 2. Encode and decode

Both take the transport name as a second argument.  Most protocols ignore it;
it exists because DNS needs a length prefix over TCP and not over UDP, and a
protocol declaring `over="either"` has to be told which it is dealing with.

```python
import struct

MAGIC = 0x5345

def encode(msg: Reading, transport: str = "udp") -> bytes:
    out = struct.pack("!HBB", MAGIC, msg.version, len(msg.samples))
    for kind, value in msg.samples:
        out += struct.pack("!BI", kind, value)
    return out

def decode(payload: bytes, transport: str = "udp") -> Reading:
    magic, version, count = struct.unpack_from("!HBB", payload)
    if magic != MAGIC:
        raise ValueError(f"not a sensor datagram: magic {magic:#06x}")
    samples = [struct.unpack_from("!BI", payload, 4 + i * 5) for i in range(count)]
    return Reading(version=version, samples=samples)
```

**`decode` raising is not a failure.** Claiming a port is a weak signal —
someone else's traffic will land on it eventually — so a decoder that rejects
the bytes leaves them in {attr}`~packeteer.parse.core.ParsedPacket.payload` as
an opaque payload and parsing carries on.  Check something: a magic number, a
version, a length that has to add up.  A decoder that accepts anything will
mangle the first unrelated packet it sees.

`ValueError` and `struct.error` are caught.  Anything else propagates, so
raise one of those.

### 3. To and from a packet spec

A spec section is plain JSON-compatible data — dicts, lists, strings, numbers,
bools.  Bytes have no JSON representation, so encode them as hex the way the
built-in sections do.

```python
def to_spec(msg: Reading) -> dict:
    return {
        "version": msg.version,
        "samples": [{"kind": k, "value": v} for k, v in msg.samples],
    }

def from_spec(section: dict) -> Reading:
    return Reading(
        version=section.get("version", 1),
        samples=[(s["kind"], s["value"]) for s in section.get("samples", [])],
    )
```

Use `.get()` with defaults.  A spec is something a person edits by hand, and
`from_spec` should not fail on a missing optional key.

### 4. Redaction

If your protocol can carry anything identifying — a hostname, a device serial,
a username — write a `sanitise` callable.  It edits the section in place.

```python
def sanitise(section: dict, replacer, options) -> None:
    if "owner" in section:
        section["owner"] = "[redacted]"
```

This one is optional, and **that is the dangerous one to leave out**.  A
protocol registered without it flows through `packeteer sanitise` completely
untouched, and the command reports success.  For everything else in packeteer
an unregistered protocol means a feature you do not get; here it means data
you meant to remove is still there.  If in doubt, redact.

If your protocol genuinely carries nothing identifying, say so out loud rather
than by omission:

```python
register(AppProtocol(..., redacts_nothing=True))
```

`packeteer sanitise` then warns that the section was not redacted, instead of
passing it through in silence.  A compiled protocol sets this automatically
when its spec marks no field `sensitive:`.

### 5. Register it

```python
from packeteer.protocols import AppProtocol, register

register(AppProtocol(
    name="sensor",
    over="udp",                       # "udp", "tcp", or "either"
    ports=frozenset({9000}),
    messages=(Reading,),
    decode=decode,
    encode=encode,
    to_spec=to_spec,
    from_spec=from_spec,
    sanitise=sanitise,
))
```

`name` doubles as the packet-spec section key, so this protocol's data appears
under `"sensor"` beside `"network"` and `"transport"`.  It may not collide
with a key that describes packet structure — `ethernet`, `network`,
`transport`, `payload` and the rest of the `##` headings in
{doc}`../packet-spec/format` — and `register` refuses a name, port or message
type another protocol already claims, naming what collided.

## What you get

Everything the built-ins get.  Parsing:

```python
from packeteer.parse import parse_packet

pkt = parse_packet(frame)
pkt.app             # Reading(version=1, samples=[(2, 21)])
pkt.app_protocol    # "sensor"
```

Building, either from an object or from a spec:

```python
from packeteer.generate import PacketBuilder

frame = (PacketBuilder()
    .ethernet()
    .ip(src="10.0.0.1", dst="10.0.0.2")
    .udp(dst_port=9000)
    .app(Reading(samples=[(2, 21)]))
    .build())
```

And the command line, with no packeteer changes at all:

```console
$ packeteer parse capture.pcap
...
      "transport": { "src_port": 51000, "dst_port": 9000 },
      "sensor": { "version": 1, "samples": [ { "kind": 2, "value": 21 } ] }
...

$ packeteer sanitise spec.json -o clean.json
$ packeteer build spec.json --pcap out.pcap
```

## Where to register

Registration is a side effect of importing your module, so something has to
import it before the protocol is used.  In a script or a test, import it at
the top.  In a package, import it from your `__init__`.

On the command line, `--load-protocol` does it:

```console
$ packeteer parse --load-protocol ./sensor.py capture.pcap
```

It is repeatable, accepted before or after the subcommand, and mirrored by the
`PACKETEER_PROTOCOLS` environment variable and by a `"protocols"` key in a
packet spec.  {func}`packeteer.protocols.load_module` is the same thing from
the API.

A protocol module is **code**, and registering one runs it.  Treat a protocol
someone sends you the way you would treat any other Python they send you.

## The round trip, tested

The one test worth writing before any other:

```python
def test_round_trip():
    msg = Reading(version=1, samples=[(2, 21), (3, 1013)])
    assert decode(encode(msg, "udp"), "udp") == msg
    assert from_spec(to_spec(msg)) == msg

    frame = (PacketBuilder().ethernet()
             .ip(src="10.0.0.1", dst="10.0.0.2").udp(dst_port=9000)
             .app(msg).build())
    assert parse_packet(frame).app == msg
```

If those pass, `packeteer parse` → edit the JSON → `packeteer build` works for
your protocol, which is the point of registering it.

### Or check the whole contract at once

{func}`packeteer.conformance.check_protocol` holds a protocol to everything
packeteer's own built-ins are held to — the round trips above, plus the ones
easy to forget: that a section survives `json.dumps`, that a truncated message
raises instead of decoding into a half-built object, that the registry
resolves it by message type and by port, and that a whole packet built with
`.app()` rebuilds byte for byte through its spec.

```python
from packeteer import conformance, protocols

failures = conformance.check_protocol(
    protocols.for_section("sensor"),
    [Reading(version=1, samples=[(2, 21)])],
)
assert not failures, "\n".join(failures)
```

It returns every failure rather than raising at the first, and it is the same
function packeteer runs over DNS, DHCP, HTTP and the example specs.  On its
first run it found two defects in packeteer itself, which is the argument for
using it.

## Replacing a built-in

`register` refuses a name or port that is already claimed, so to take over one
of the built-ins — HTTP on a different set of ports, say, or your own DNS
decoder — remove it first:

```python
from packeteer import protocols

protocols.unregister("http")
protocols.register(my_http)
```

{func}`~packeteer.app.register_builtins` will not put it back: it skips names
that are already taken, so your replacement survives anything that imports
`packeteer.app` later.

## Limits worth knowing

**One message per packet payload.**  A decoder is handed the payload of a
single packet.  A protocol whose messages span TCP segments needs reassembly
that packeteer does not do for you — reassemble first, then decode.

**One application section per packet spec.**  A packet has one application
payload; a spec carrying two sections is an error naming both.

**Ports are the only trigger.**  There is no content sniffing.  If your
protocol runs on a port you cannot predict, parse the payload yourself from
{attr}`~packeteer.parse.core.ParsedPacket.payload`.
