# Stream Encapsulation Types

The `packeteer.generate.stream_encap` module provides descriptor dataclasses for
wrapping generated streams in encapsulation layers.  Pass one or a list of
these to the `encap` parameter of any stream generator.

There are two categories:

- **Tag-based** (`VLANEncap`, `QinQEncap`, `MPLSEncap`, `PPPoEEncap`) insert
  layer-2 tags; the stream's own transport (TCP/UDP/SCTP) stays on the wire.
- **Tunnel** (`GREEncap`, `EtherIPEncap`, `IPIPEncap`, `VXLANEncap`,
  `GeneveEncap`, `GTPUEncap`, `AHEncap`, `ESPEncap`) add their own outer headers
  and carry the whole stream as *inner* traffic.  This is why every stream
  generator accepts every tunnel — e.g. wrapping a TCP stream in `VXLANEncap`
  tunnels the TCP conversation inside VXLAN, with TCP as the inner protocol.
  `VXLANEncap`, `GeneveEncap`, and `GTPUEncap` always use an outer UDP datagram
  (port 4789 / 6081 / 2152) regardless of the inner stream protocol; they never
  run over TCP or SCTP.  `GTPUEncap` carries the inner IP directly (no inner
  Ethernet frame).  The IPsec tunnels carry the inner IP directly too:
  `AHEncap` keeps the inner stack visible (AH is integrity-only), while
  `ESPEncap` **scrambles** the whole inner stack into high-entropy ciphertext (a
  stand-in for encryption), so a stream wrapped in `ESPEncap` parses back as
  opaque ESP with no structured headers leaking — exactly like real encrypted
  traffic.  The scramble is deterministic, so a seeded stream stays reproducible.

See {doc}`../guide/generating` for usage examples and combination rules.

---

## VLAN (802.1Q)

```{eval-rst}
.. autoclass:: packeteer.generate.stream_encap.VLANEncap
   :members:
```

```{eval-rst}
.. autoclass:: packeteer.generate.stream_encap.QinQEncap
   :members:
```

---

## MPLS

```{eval-rst}
.. autoclass:: packeteer.generate.stream_encap.MPLSEncap
   :members:
```

---

## PPPoE

```{eval-rst}
.. autoclass:: packeteer.generate.stream_encap.PPPoEEncap
   :members:
```

---

## Tunnels

```{eval-rst}
.. autoclass:: packeteer.generate.stream_encap.GREEncap
   :members:
```

```{eval-rst}
.. autoclass:: packeteer.generate.stream_encap.EtherIPEncap
   :members:
```

```{eval-rst}
.. autoclass:: packeteer.generate.stream_encap.IPIPEncap
   :members:
```

```{eval-rst}
.. autoclass:: packeteer.generate.stream_encap.VXLANEncap
   :members:
```

```{eval-rst}
.. autoclass:: packeteer.generate.stream_encap.GeneveEncap
   :members:
```

```{eval-rst}
.. autoclass:: packeteer.generate.stream_encap.GTPUEncap
   :members:
```

```{eval-rst}
.. autoclass:: packeteer.generate.stream_encap.AHEncap
   :members:
```

```{eval-rst}
.. autoclass:: packeteer.generate.stream_encap.ESPEncap
   :members:
```

---

## Type aliases

```{eval-rst}
.. autodata:: packeteer.generate.stream_encap.StreamEncap
.. autodata:: packeteer.generate.stream_encap.EncapSpec
```
