# Fragmentation

Low-level IPv4 and IPv6 fragmentation functions.  For the high-level
`PacketBuilder.fragment(mtu)` method and full usage examples see
{doc}`../cli/build`.

---

## IPv4

```{eval-rst}
.. autofunction:: packeteer.generate.fragmentation.fragment_ipv4
```

---

## IPv6

```{eval-rst}
.. autofunction:: packeteer.generate.fragmentation.fragment_ipv6
```

---

## Reassembly

The parse-side counterpart.  These take raw frames and return raw frames, so
they compose with `read_pcap` / `open_pcap` on one side and `parse_packet` on
the other.  See {doc}`../guide/defragmenting` for the reassembly policies —
overlap handling, timeouts, and memory limits.

```{eval-rst}
.. autofunction:: packeteer.parse.defragment.defragment
```

```{eval-rst}
.. autofunction:: packeteer.parse.defragment.defragment_ipv4
```

```{eval-rst}
.. autofunction:: packeteer.parse.defragment.defragment_ipv6
```

```{eval-rst}
.. autoclass:: packeteer.parse.defragment.Defragmenter
   :members:
```

```{eval-rst}
.. autoclass:: packeteer.parse.defragment.IncompleteDatagram
   :members:
```
