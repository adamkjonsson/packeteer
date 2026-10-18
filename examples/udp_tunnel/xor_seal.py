r"""A toy tunnel wrapper for ``packeteer stream --udp-tunnel``.

**This is not cryptography.**  It XORs each inner packet with a keystream
from SHA-256 and appends a 4-byte tag, so that it behaves like a sealing
tunnel — opaque, stateful, and able to tell a corrupted datagram from a good
one — without being one.  Never use it to protect anything.  Write a real
wrapper (WireGuard, OpenVPN, your own) in the same shape.

It shows what a wrapper can do with :func:`packeteer.generate.tunnel_stream`
calling it once per inner packet, in wire order:

- a **handshake** on the first call, one message each way, before the first
  sealed packet;
- a **counter per direction**, so a retransmitted inner segment is sealed
  again with a fresh counter, as a real tunnel does;
- a **rekey** every ``rekey_after`` packets, which starts a new epoch and
  resets both counters.

Every datagram starts with a 10-byte header — type, epoch, 64-bit counter —
and ends with the tag.  :func:`open_datagram` is the inverse, for a test or
a decoder to check against.

Usage::

    packeteer stream --protocol udp --payload dns --protocol-messages dns.json \\
        --client-ip 10.0.0.2 --server-ip 10.0.0.1 --server-port 53 --packets 20 \\
        --udp-tunnel 198.51.100.7 203.0.113.9 --tunnel-port 51820 \\
        --tunnel-module examples/udp_tunnel/xor_seal.py \\
        --tunnel-arg key=secret --tunnel-arg rekey_after=8 \\
        --tunnel-corruption 0.1 --seed 7 --pcap tunnel.pcap
"""
from __future__ import annotations

import hashlib
import struct
from collections.abc import Sequence

#: Message types, the first byte of every datagram.
INIT, RESPONSE, REKEY, DATA = 1, 2, 3, 4

_HEADER = struct.Struct(">BBQ")  # type, epoch, counter
_TAG_LEN = 4


def _keystream(key: bytes, epoch: int, direction: str, counter: int, length: int) -> bytes:
    """Return *length* bytes of keystream for one sealed packet."""
    out = b""
    block = 0
    while len(out) < length:
        out += hashlib.sha256(
            key + _HEADER.pack(epoch, block % 256, counter) + direction.encode(),
        ).digest()
        block += 1
    return out[:length]


def _tag(key: bytes, data: bytes) -> bytes:
    """Return the 4-byte tag over a header and its body."""
    return hashlib.sha256(key + b"tag" + data).digest()[:_TAG_LEN]


class XorSeal:
    """Seals each inner packet under a per-direction counter, rekeying as it goes.

    Attributes:
        key: The shared key.
        rekey_after: Sealed packets per epoch, both directions together.
        epoch: The current epoch, from 0.

    """

    def __init__(self, key: bytes, rekey_after: int) -> None:
        if rekey_after < 1:
            raise ValueError(f"rekey_after must be at least 1, got {rekey_after}")
        self.key = key
        self.rekey_after = rekey_after
        self.epoch = 0
        self._counters = {"c2s": 0, "s2c": 0}
        self._sealed_this_epoch = 0
        self._started = False

    def _control(self, kind: int) -> bytes:
        header = _HEADER.pack(kind, self.epoch, 0)
        return header + _tag(self.key, header)

    def _seal(self, inner: bytes, direction: str) -> bytes:
        counter = self._counters[direction]
        self._counters[direction] += 1
        header = _HEADER.pack(DATA, self.epoch, counter)
        stream = _keystream(self.key, self.epoch, direction, counter, len(inner))
        body = header + bytes(a ^ b for a, b in zip(inner, stream, strict=True))
        return body + _tag(self.key, body)

    def wrap(self, inner: bytes, direction: str, timestamp: float) -> Sequence[tuple[str, bytes]]:
        """Return the handshake or rekey this point needs, then the sealed packet."""
        out: list[tuple[str, bytes]] = []
        if not self._started:
            self._started = True
            out += [("c2s", self._control(INIT)), ("s2c", self._control(RESPONSE))]
        elif self._sealed_this_epoch >= self.rekey_after:
            self.epoch = (self.epoch + 1) % 256
            self._counters = {"c2s": 0, "s2c": 0}
            self._sealed_this_epoch = 0
            out.append(("c2s", self._control(REKEY)))
        out.append((direction, self._seal(inner, direction)))
        self._sealed_this_epoch += 1
        return out


def open_datagram(key: bytes, payload: bytes, direction: str) -> bytes | None:
    """Return the inner packet a ``DATA`` datagram carries.

    ``None`` for a control message (INIT, RESPONSE, REKEY) with a good tag.

    Raises:
        ValueError: If the tag does not verify — the datagram was corrupted,
            or sealed under another key.

    """
    if len(payload) < _HEADER.size + _TAG_LEN:
        raise ValueError("too short to be a sealed datagram")
    body, tag = payload[:-_TAG_LEN], payload[-_TAG_LEN:]
    if _tag(key, body) != tag:
        raise ValueError("tag does not verify")
    kind, epoch, counter = _HEADER.unpack_from(body)
    if kind != DATA:
        return None
    sealed = body[_HEADER.size:]
    stream = _keystream(key, epoch, direction, counter, len(sealed))
    return bytes(a ^ b for a, b in zip(sealed, stream, strict=True))


def make_wrapper(args: dict[str, str]) -> XorSeal:
    """Return the wrapper ``--tunnel-arg key=... rekey_after=...`` describes."""
    return XorSeal(
        key=args.get("key", "packeteer").encode(),
        rekey_after=int(args.get("rekey_after", "1000")),
    )
