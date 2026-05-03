# Coverage-guided fuzzing with Atheris

This page describes how to pair packeteer with
[Atheris](https://github.com/google/atheris), Google's coverage-guided Python
fuzzer, to test decoder robustness beyond what packeteer's built-in mutations
cover.

## Deterministic vs. coverage-guided fuzzing

packeteer's {func}`~packeteer.fuzz.fuzz` and {func}`~packeteer.fuzz.fuzz_bytes`
apply a fixed vocabulary of known bad patterns — boundary values, pathological
flag combinations, wrong checksum fields — and produce them deterministically.
Every run with the same input and the same seed produces the same set of
variants.  This is reliable for regression testing and CI, but it is bounded:
it can only find problems that a human thought to encode in the mutation tables.

Coverage-guided fuzzing explores the input space differently.  Each input is fed
to the target function; the fuzzer records which branches execute.  Inputs that
reach *new* branches are retained and preferentially mutated.  Over time the
corpus converges on a set of inputs that exercises every reachable branch, and
any input that causes an unhandled exception is reported as a finding.

The two approaches are complementary:

| | packeteer built-in | Atheris |
|---|---|---|
| Coverage | Fixed vocabulary of known bad patterns | Full input space, guided by branch coverage |
| Reproducibility | Always deterministic | Deterministic only with a fixed seed |
| Speed | Instant | Requires warm-up time to build corpus |
| Findings | Known edge-case classes | Arbitrary, including unforeseen combinations |
| Dependencies | None | Requires Atheris installation |

## Installation

```bash
pip install atheris
```

Atheris links against LibFuzzer.  On macOS, install from the pre-built wheel;
on Linux, it may need to be compiled against a Clang toolchain.  See the
[Atheris README](https://github.com/google/atheris) for platform details.

## Pattern 1: fuzzing the pcap reader

This tests that `read_pcap` handles any byte sequence gracefully.  The contract
is that it either returns a `PcapFile` or raises `ValueError`, and never crashes
with an unhandled `struct.error`, `OverflowError`, or similar.

```python
# fuzz_pcap_reader.py
import io
import sys

import atheris
from packeteer.pcap import read_pcap


@atheris.instrument_func
def TestOneInput(data: bytes) -> None:
    try:
        read_pcap(file_object=io.BytesIO(data))
    except ValueError:
        pass  # expected for malformed input


atheris.Setup(sys.argv, TestOneInput)
atheris.instrument_all()
atheris.Fuzz()
```

Seed the corpus with real pcap and pcapng files so Atheris starts from valid
file structures and mutates toward interesting boundary conditions, rather than
spending its early iterations on the four-byte magic number check:

```bash
mkdir corpus/
cp tests/fixtures/*.pcap corpus/
python fuzz_pcap_reader.py corpus/ -max_total_time=300
```

This pattern is most useful after changes to the pcap reader — for example,
after adding support for a new block type or magic number.

## Pattern 2: fuzzing the packet parser

This tests that `parse_packet` handles arbitrary raw bytes gracefully across
all frame types and protocol combinations.

```python
# fuzz_parser.py
import sys

import atheris
from atheris import FuzzedDataProvider

from packeteer.parse.core import parse_packet
from packeteer.pcap import LINKTYPE_ETHERNET, LINKTYPE_RAW


@atheris.instrument_func
def TestOneInput(data: bytes) -> None:
    fdp = FuzzedDataProvider(data)
    link_type = LINKTYPE_RAW if fdp.ConsumeBool() else LINKTYPE_ETHERNET
    payload = fdp.ConsumeBytes(fdp.remaining_bytes())
    try:
        parse_packet(payload, link_type=link_type)
    except ValueError:
        pass


atheris.Setup(sys.argv, TestOneInput)
atheris.instrument_all()
atheris.Fuzz()
```

`FuzzedDataProvider` splits the fuzzer-supplied bytes into typed fields.  The
first byte selects the link type, giving Atheris a branch point at the very
start and causing it to explore both the raw-IP and Ethernet parsing paths
independently.

Seed the corpus by extracting raw packet bytes from existing captures.  The
leading `\x00` byte in each seed file stands for the `ConsumeBool` link-type
selector (false → `LINKTYPE_ETHERNET`):

```python
# generate_seeds.py
import os
from packeteer.pcap import read_pcap

os.makedirs("corpus", exist_ok=True)
result = read_pcap(path="capture.pcap")
for i, (data, _, _) in enumerate(result.packets):
    open(f"corpus/pkt{i:04d}.bin", "wb").write(b"\x00" + data)
```

## Pattern 3: fuzzing application-layer decoders

This is the most productive target when building an application that processes
network traffic.  Atheris supplies the application-layer payload; packeteer
wraps it in a valid network frame; the combined result is fed to your decoder.

The split of responsibilities is clean:

- **Atheris** — explores the application payload space and tracks coverage
  inside the decoder to guide mutations toward unexplored branches.
- **packeteer** — provides stable, well-formed Ethernet/IP/transport headers
  so the decoder always receives a realistic frame regardless of what Atheris
  sends as payload.

```python
# fuzz_my_protocol.py
import sys

import atheris
from packeteer.generate import PacketBuilder

import my_protocol  # the decoder under test


@atheris.instrument_func
def TestOneInput(data: bytes) -> None:
    # Build a complete Ethernet/IP/UDP frame with the fuzz input as the payload.
    # Only the application layer varies; the network headers are always valid.
    raw_frame = (
        PacketBuilder()
        .ethernet()
        .ip(src="10.0.0.2", dst="10.0.0.1")
        .udp(src_port=5000, dst_port=5001)
        .payload(data=data)
        .build()
    )
    try:
        my_protocol.decode(raw_frame)
    except (ValueError, my_protocol.DecodeError):
        pass  # expected; any other exception is a finding


atheris.Setup(sys.argv, TestOneInput)
atheris.instrument_all()
atheris.Fuzz()
```

For a TCP-based decoder, substitute `.tcp(src_port=…, dst_port=…)` for
`.udp(…)`.  For decoders that expect encapsulated traffic (VLAN, GRE, etc.),
use the same `encap=` options available to the stream generators.

### Why the network framing matters

Without the packeteer wrapping you could fuzz `my_protocol.decode` directly
with raw payload bytes.  The wrapping adds two things:

1. **Realistic test conditions** — if the decoder calls `parse_packet` or an
   equivalent to strip headers before reaching the application layer, that
   path is exercised.  Fuzzing bare payload bytes bypasses it entirely.

2. **Reproducible pcap output** — any crash-inducing input `data` can be
   wrapped by packeteer and written to a `.pcap` file for inspection in
   Wireshark or replay with `packeteer build`.

## Building a seed corpus

A seed corpus provides Atheris with valid inputs to start mutating from, which
dramatically shortens the time to first coverage.

**From a live capture** — if you can record real traffic, extract the raw
application payloads directly:

```python
# extract_payloads.py
import os
from packeteer.parse.core import parse_packet
from packeteer.pcap import read_pcap

os.makedirs("corpus", exist_ok=True)
result = read_pcap(path="capture.pcap")
for i, (data, _, _) in enumerate(result.packets):
    pkt = parse_packet(data)
    if pkt.payload:
        open(f"corpus/payload{i:04d}.bin", "wb").write(
            bytes.fromhex(pkt.payload.data)
        )
```

**From packeteer's stream generators** — for synthetic traffic, generate a
stream and extract the data segments:

```python
# generate_seeds_from_stream.py
import os
from packeteer.generate.udp_stream import generate_udp_stream, UDPStreamConfig
from packeteer.parse.core import parse_packet

os.makedirs("corpus", exist_ok=True)
stream = generate_udp_stream(
    client_ip="10.0.0.2", server_ip="10.0.0.1",
    server_port=5001,
    config=UDPStreamConfig(seed=0),
)
for i, pkt in enumerate(stream.packets):
    parsed = parse_packet(pkt.raw)
    if parsed.payload:
        open(f"corpus/seg{i:04d}.bin", "wb").write(
            bytes.fromhex(parsed.payload.data)
        )
```

**From packeteer's built-in mutations** — pre-populate the corpus with the
deterministic mutations packeteer already knows about so Atheris inherits
known interesting inputs from the start:

```python
# seed_from_fuzz_bytes.py
import os
from packeteer.fuzz import fuzz_bytes, FuzzOptions
from packeteer.generate import PacketBuilder

os.makedirs("corpus", exist_ok=True)

# Build a valid seed packet and extract its payload
raw = (PacketBuilder()
       .ethernet()
       .ip(src="10.0.0.2", dst="10.0.0.1")
       .udp(src_port=5000, dst_port=5001)
       .payload(size=32)
       .build())
payload = raw[42:]  # skip Ethernet + IP + UDP headers

open("corpus/valid.bin", "wb").write(payload)

for label, corrupted_frame in fuzz_bytes(raw, FuzzOptions(seed=0)):
    name = label.replace(" ", "_").replace(":", "").replace("/", "_")
    open(f"corpus/{name}.bin", "wb").write(corrupted_frame[42:])
```

The combination is effective: packeteer seeds the corpus with known interesting
patterns; Atheris then explores beyond them guided by coverage.

## Instrumentation scope

`atheris.instrument_all()` applies coverage tracking to every Python module
imported in the process, including packeteer's parser and builder internals.
This is appropriate for Patterns 1 and 2, where the goal is to find bugs inside
packeteer itself.

For Pattern 3, the target is your own decoder.  If packeteer's internal branches
dominate the coverage signal and distract the fuzzer from your code, restrict
instrumentation with the `include_packages` argument:

```python
atheris.instrument_all(include_packages=["my_protocol"])
```

Or instrument only the specific functions you want to cover:

```python
@atheris.instrument_func
def my_decoder(raw: bytes) -> dict: ...

@atheris.instrument_func
def TestOneInput(data: bytes) -> None: ...
# No atheris.instrument_all() call
```

This keeps the coverage signal focused on the code under test and lets the
fuzzer converge faster.
