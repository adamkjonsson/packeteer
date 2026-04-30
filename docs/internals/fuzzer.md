# Fuzzer internals

`packeteer/fuzz.py` implements `fuzz()` and `fuzz_bytes()`, which produce
adversarial packet variants for decoder robustness testing.

## Design goals

- **Two complementary domains** — spec-level mutations produce well-formed (but
  deliberately unusual) packets by operating on the JSON packet spec dict;
  byte-level mutations produce structurally invalid encodings that a spec-based
  builder cannot represent by operating on raw serialised bytes.
- **Single options object** — the same `FuzzOptions` instance can be passed to
  both `fuzz()` and `fuzz_bytes()`.  Each function silently ignores mutation
  names irrelevant to its domain, so callers do not need to maintain separate
  option objects.
- **Non-destructive** — `fuzz()` never modifies the input config.  Each
  `FuzzVariant.spec` is an independent `copy.deepcopy` of the source packet,
  and only then the mutation is applied.
- **Deterministic with a seed** — both functions accept `FuzzOptions.seed`.
  The random state is initialised from it once at the start of each call, so
  the same seed always produces the same output regardless of Python version or
  run order.

## Public types

### `FuzzOptions`

```python
@dataclass
class FuzzOptions:
    mutations: list[str] = field(default_factory=lambda: list(ALL_MUTATION_NAMES))
    count: int = 10
    seed: int | None = None
```

`ALL_MUTATION_NAMES` is defined later in the same module.  The
`default_factory` lambda captures the name by reference and is only called at
instantiation time, by which point the module is fully loaded.  Each
`FuzzOptions()` call therefore gets its own independent list, preventing
accidental mutation of a shared default.

### `FuzzVariant`

```python
@dataclass
class FuzzVariant:
    source_idx: int        # zero-based index in config["packets"]
    mutation:   str        # mutation type name, e.g. "boundary"
    label:      str        # human-readable description of the change
    spec:       dict       # mutated single-packet spec dict (deep copy)
```

`FuzzVariant.spec` has the same shape as one element of `config["packets"]`.
It can be wrapped in `{"packets": [v.spec]}` and passed directly to
`packeteer build` or `PacketBuilder`.

## Spec-level mutations

### Mutation registry

`_MUTATIONS` is an `OrderedDict`-style plain dict that maps mutation name
strings to callables of type `_MutFn`:

```python
_MutFn = Callable[
    [dict[str, Any], random.Random],
    list[tuple[str, dict[str, Any]]],
]

_MUTATIONS: dict[str, _MutFn] = {
    "boundary":      _boundary,
    "reserved-bits": _reserved_bits,
    "tcp-flags":     _tcp_flags,
    "truncate":      _truncate,
    "extend":        _extend,
}
```

`MUTATION_NAMES` is derived from `tuple(_MUTATIONS)`, so the canonical order
of names always matches the registration order.

`fuzz()` iterates `config["packets"]` in order, then for each source packet
iterates `options.mutations`, looks each name up in `_MUTATIONS` (silently
skipping byte-level names), calls the function, and wraps each returned
`(label, variant_dict)` pair in a `FuzzVariant`.

### `_boundary`

Iterates four pre-built tables:

| Table | Fields covered |
|-------|---------------|
| `_NETWORK_BOUNDARY` | `ttl` [0, 1, 254, 255], `tos` [0, 255], `identification` [0, 65535], `fragment_offset` [0, 8191] |
| `_PORT_BOUNDARY` | `src_port` and `dst_port` [0, 1, 65534, 65535] for TCP/UDP/SCTP |
| `_TCP_BOUNDARY` | `window`, `seq`, `ack`, `urgent_ptr` at their 16-bit or 32-bit extremes |
| `_ICMP_BOUNDARY` | `type`, `code`, `identifier`, `sequence` [0, 255] or [0, 65535] |
| `_SCTP_BOUNDARY` | `verification_tag` [0, 0xFFFFFFFF] |

For each `(field, values)` entry: if the field is absent from the packet dict,
the table entry is skipped entirely (no KeyError, no empty variant).  When
present, one `copy.deepcopy` is taken per value and the field is overwritten.

### `_reserved_bits`

Produces up to four variants per packet:

1. **IPv4 evil bit** — sets bit 2 of `network["flags"]` (RFC 3514) using a
   bitwise OR.  The existing flags are preserved; only the reserved bit is
   added.  Only emitted if `"flags"` is present in `"network"`.
2. **DF+MF simultaneously** — sets `network["flags"]` to `0b011`.  This
   combination is RFC-invalid (a fragment that must not be fragmented).
3. **TCP reserved nibble = 1** — sets `transport["reserved"]` to 1.  Only
   emitted for TCP packets (checked via `_pkt_proto`).
4. **TCP reserved nibble = 7** — sets `transport["reserved"]` to 7 (all three
   reserved bits set).

### `_tcp_flags`

Returns immediately with an empty list if the packet is not TCP.  Otherwise
emits one variant per entry in `_TCP_FLAG_COMBOS`:

```python
_TCP_FLAG_COMBOS: list[tuple[str, int]] = [
    ("SYN+FIN",         0x03),
    ("SYN+RST",         0x06),
    ("FIN+RST",         0x05),
    ("SYN+FIN+PSH",     0x0B),
    ("null (no flags)", 0x00),
    ("FIN only",        0x01),
    ("all flags",       0xFF),
    ("PSH+URG no ACK",  0x28),
    ("RST+ACK+URG",     0x34),
    ("ECE+CWR",         0xC0),
]
```

Each variant is a deep copy with `transport["flags"]` overwritten.

### `_truncate`

Reads the payload hex string via `_get_hex_payload(pkt)`, which returns `None`
if the payload is absent, has a non-hex encoding, or has a non-string `data`
field — in all these cases `_truncate` returns `[]`.  The payload length is
`len(hex_data) // 2` (two hex chars per byte).

Up to four variants are produced (each only if the resulting length would be
strictly shorter than the original and greater than the previous cut-point):

1. Payload removed entirely — `pkt.pop("payload", None)`.
2. 1 byte — `hex_data[:2]`.
3. 25% — `hex_data[:keep_25 * 2]` where `keep_25 = max(1, byte_len // 4)`.
   Emitted only if `keep_25 < byte_len` and `keep_25 > 1`.
4. 50% — `hex_data[:keep_50 * 2]` where `keep_50 = max(1, byte_len // 2)`.
   Emitted only if `keep_50 < byte_len`, `keep_50 > 1`, and `keep_50 != keep_25`
   (deduplication for very short payloads).

### `_extend`

Appends extra bytes after the existing payload.  If no payload is present the
base hex string is `""`, so the mutation still produces variants (pure padding
packets).

Zero-append sizes: `[1, 4, 8, 64, 512]` — five variants with `"00" * n`
appended to the hex string.  A sixth variant appends 16 random bytes drawn from
the per-call `rng` instance.

`_set_hex_payload(pkt, data)` is used for all writes: it sets `payload["data"]`
and removes the `"encoding"` key if present, keeping the spec in hex-payload
canonical form.

## Byte-level mutations

### VLAN-aware IP offset — `_ip_header_offset`

All three byte-level mutation helpers need to find the IPv4 header in the raw
bytes.  `_ip_header_offset(raw)` handles standard Ethernet and 802.1Q / 802.1ad
tagged frames:

```
Ethernet:        bytes  0–13   → EtherType at bytes 12–13
802.1Q (0x8100): bytes 14–17  → inner EtherType at bytes 16–17 (+4 per tag)
802.1ad (0x88A8): same stride
```

The function reads the EtherType at offset 12, then advances by 4 bytes for
each VLAN tag (0x8100 or 0x88A8).  It returns `offset` if the final EtherType
is 0x0800 (IPv4), or `-1` for any non-IPv4 or too-short frame.

All three helpers check the return value and return `[]` immediately on `-1`.

### `_raw_bit_flip`

Produces `count` variants.  For each:

1. Copy `raw` into a `bytearray`.
2. Pick a random bit index in `[0, len(ba) * 8)` using `rng.randrange`.
3. XOR the byte at `bit_idx // 8` with `1 << (bit_idx % 8)`.
4. Return `(f"bit-flip #{i+1}: byte {byte} bit {bit}", bytes(ba))`.

The per-call `rng` instance ensures both reproducibility (when seeded) and
independence between `fuzz_bytes` calls on the same data.

### `_raw_wrong_checksum`

Uses `struct.unpack_from` / `struct.pack_into` to read and overwrite checksum
fields at known byte offsets relative to the IP header start (`ip_off`):

| Field | Offset | Condition |
|-------|--------|-----------|
| IP header checksum | `ip_off + 10` | always (IPv4) |
| TCP checksum | `ip_off + ihl + 16` | `proto == 6` and frame long enough |
| UDP checksum | `ip_off + ihl + 6` | `proto == 17` and frame long enough |

`ihl = (raw[ip_off] & 0x0F) * 4` (IP Header Length field, in bytes).

For the IP checksum: three variants — `0x0000`, `0xffff`, and
`existing ^ 0xFFFF` (bitwise inverse, labelled `"inverted"`).

For TCP/UDP: two variants each — `0x0000` and `0xffff`.

### `_raw_wrong_length`

Targets the IP total-length field at `ip_off + 2` and, for UDP, the UDP length
field at `ip_off + ihl + 4`:

| Label | Value |
|-------|-------|
| `0` | `0` |
| `ihl_only` | `ihl` (header only, no payload) |
| `actual-1` | `max(0, actual - 1)` |
| `actual+1` | `(actual + 1) & 0xFFFF` |
| `0xffff` | `0xFFFF` |

For UDP length, `ihl_only` is replaced by `7` (one byte below the minimum
valid UDP header length of 8).

### `fuzz_bytes` dispatch

```python
byte_muts = {m for m in options.mutations if m in set(BYTE_MUTATION_NAMES)}
rng = random.Random(options.seed)

if "bit-flip"        in byte_muts: results.extend(_raw_bit_flip(raw, rng, options.count))
if "wrong-checksum"  in byte_muts: results.extend(_raw_wrong_checksum(raw))
if "wrong-length"    in byte_muts: results.extend(_raw_wrong_length(raw))
```

The three mutations are applied in a fixed order and their results concatenated.
Spec-level names are filtered out before this point by the set intersection with
`BYTE_MUTATION_NAMES`.
