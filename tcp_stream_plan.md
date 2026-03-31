# TCP Stream Generator — Implementation Plan

## New files
- `src/packet_generator/tcp_stream.py` — all stream logic
- `src/tests/test_stream.py` — test suite

`src/packet_generator/__init__.py` gets 3 new exports. No other existing files change.

---

## Data model

**`TCPEndpoint`** (internal) — tracks live state for one side:
```python
@dataclass
class TCPEndpoint:
    ip: str; port: int; mac: str
    isn: int; seq: int; ack: int
    window: int = 65535
```

**`TCPStreamPacket`** (exported) — one packet's worth of data + metadata:
```python
@dataclass
class TCPStreamPacket:
    raw: bytes          # fully-assembled packet bytes
    ts_sec: int
    ts_usec: int
    direction: str      # "c2s" or "s2c"
    flags: int
    seq: int
    ack: int
    payload_len: int
    label: str          # "SYN", "DATA[3]", "FIN-ACK", etc.
```

**`TCPStream`** (exported) — the result:
```python
@dataclass
class TCPStream:
    packets: list[TCPStreamPacket]
    def to_pcap_tuples(self) -> list[tuple[bytes, int, int]]: ...
    def client_packets(self) -> list[TCPStreamPacket]: ...
    def server_packets(self) -> list[TCPStreamPacket]: ...
```

---

## Entry point signature

```python
def generate_tcp_stream(
    *,
    client_ip: str, server_ip: str,
    client_port: int = 54321, server_port: int = 80,
    client_mac: str = "00:00:00:00:00:01",
    server_mac: str = "00:00:00:00:00:02",
    num_data_packets: int = 10,
    payload_sizes: list[int] | None = None,   # explicit; overrides distribution params
    min_payload: int = 40, max_payload: int = 1460,
    payload_distribution: str = "uniform",    # "uniform" | "bimodal" | "fixed"
    client_isn: int | None = None,            # random if None
    server_isn: int | None = None,
    client_options: TCPOptions | None = None, # SYN-time TCP options
    server_options: TCPOptions | None = None,
    include_ethernet: bool = True,
    ip_ttl: int = 64,
    window: int = 65535,
    base_time: float | None = None,           # time.time() if None
    inter_packet_gap: float = 0.001,
    packet_hooks: list[Callable] | None = None,
) -> TCPStream:
```

---

## Packet sequence produced

| # | Sender | Flags | Label |
|---|--------|-------|-------|
| 0 | client | SYN | `"SYN"` |
| 1 | server | SYN+ACK | `"SYN-ACK"` |
| 2 | client | ACK | `"ACK"` |
| 3…N+2 | client | PSH+ACK | `"DATA[0]"` … `"DATA[N-1]"` |
| N+3 | server | ACK | `"ACK"` |
| N+4 | client | FIN+ACK | `"FIN-ACK"` |
| N+5 | server | ACK | `"ACK"` |
| N+6 | server | FIN+ACK | `"FIN-ACK"` |
| N+7 | client | ACK | `"ACK"` |

Total: `num_data_packets + 7` packets. Data flows client→server only for the initial
implementation; bidirectional exchange can be added later via a `data_direction` parameter.

---

## Sequence number tracking

```python
def _advance_seq(ep, flags, payload_len):
    consumed = payload_len
    if flags & TCP_SYN: consumed += 1
    if flags & TCP_FIN: consumed += 1
    ep.seq = (ep.seq + consumed) % (2**32)
```

After each sent packet the peer's `ack` is set to the sender's updated `seq`. This is
the only place seq/ack state changes, keeping it easy to reason about.

---

## Payload size variation

A private `_payload_sizes()` helper returns a `list[int]` of length `num_data_packets`:

| `payload_distribution` | Behaviour |
|---|---|
| `"uniform"` | `random.randint(min_payload, max_payload)` per packet |
| `"bimodal"` | 70% small (near `min_payload`), 30% large (near `max_payload`) |
| `"fixed"` | all `max_payload` |
| *(explicit)* | `payload_sizes` list used as-is; `ValueError` if wrong length |

---

## Extensibility for future error injection

`packet_hooks` is a list of `Callable[[TCPStreamPacket, int], TCPStreamPacket | None]`.
Each hook receives `(packet, index)` and returns a modified packet or `None` to drop it.
Future anomalies will live in a separate `stream_anomalies.py` and be passed in:

```python
stream = generate_tcp_stream(..., packet_hooks=[drop_packet(5), corrupt_checksum(7)])
```

`TCPStreamPacket.raw` is plain `bytes` and `stream.packets` is a plain `list`, so callers
can also mutate, reorder, or insert entries after generation without any special API.

---

## Tests (≈30 methods across 10 groups)

| Group | What is tested |
|---|---|
| 1. Handshake structure | flags, direction, label for packets 0–2 |
| 2. Teardown structure | last 4 packets match FIN/ACK pattern |
| 3. Seq/ack correctness | server ACK = client ISN+1, data seq advances by payload length, FIN consumes 1, 32-bit wrap-around |
| 4. Packet count | `num_data_packets + 7` total; `num_data_packets=0` works |
| 5. Payload variation | explicit sizes, uniform within bounds, fixed |
| 6. Bytes validity | all `raw` are `bytes`, Ethernet header present/absent correctly |
| 7. pcap integration | `to_pcap_tuples()` format, round-trip through `write_pcap` |
| 8. Timestamps | monotonically increasing, `base_time` respected |
| 9. IPv6 | IPv6 addresses work without changes (builder already handles it) |
| 10. Hooks | drop hook removes packet, mutate hook changes `raw` |

---

## Critical files

| File | Status |
|---|---|
| `src/packet_generator/tcp_stream.py` | Create (new) |
| `src/tests/test_stream.py` | Create (new) |
| `src/packet_generator/__init__.py` | Edit — add 3 exports |
