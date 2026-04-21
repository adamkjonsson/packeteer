# Stream Generators

**Import:** All classes and functions on this page are exported from `packeteer.generate`, e.g. `from packeteer.generate import generate_tcp_stream, TCPStreamConfig`.

`packeteer.generate` provides three stream generators — TCP, UDP, and SCTP — each
producing a typed stream object whose `.packets` list can be written to pcap,
pcapng, or packet spec, or inspected and modified before output.

See {doc}`../stream/index` for usage examples, encapsulation, and CLI equivalents.

---

## TCP

```{eval-rst}
.. autofunction:: packeteer.generate.tcp_stream.generate_tcp_stream
   :no-index:
```

```{eval-rst}
.. autoclass:: packeteer.generate.tcp_stream.TCPStream
   :members:
   :no-index:
```

```{eval-rst}
.. autoclass:: packeteer.generate.tcp_stream.TCPStreamPacket
   :members:
   :no-index:
```

```{eval-rst}
.. autoclass:: packeteer.generate.tcp_stream.TCPStreamConfig
   :members:
   :no-index:
```

---

## UDP

```{eval-rst}
.. autofunction:: packeteer.generate.udp_stream.generate_udp_stream
   :no-index:
```

```{eval-rst}
.. autoclass:: packeteer.generate.udp_stream.UDPStream
   :members:
   :no-index:
```

```{eval-rst}
.. autoclass:: packeteer.generate.udp_stream.UDPStreamPacket
   :members:
   :no-index:
```

---

## SCTP

```{eval-rst}
.. autofunction:: packeteer.generate.sctp_stream.generate_sctp_stream
   :no-index:
```

```{eval-rst}
.. autoclass:: packeteer.generate.sctp_stream.SCTPStream
   :members:
   :no-index:
```

```{eval-rst}
.. autoclass:: packeteer.generate.sctp_stream.SCTPStreamPacket
   :members:
   :no-index:
```

---

## Session builders

See {doc}`../synthetic/index` for usage examples and workflows.

```{eval-rst}
.. autoclass:: packeteer.generate.session.TCPSession
   :members:
   :no-index:
```

```{eval-rst}
.. autoclass:: packeteer.generate.session.UDPSession
   :members:
   :no-index:
```

```{eval-rst}
.. autoclass:: packeteer.generate.session.SCTPSession
   :members:
   :no-index:
```

---

## Standalone protocol helpers

```{eval-rst}
.. autofunction:: packeteer.generate.session.tcp_handshake
   :no-index:
```

```{eval-rst}
.. autofunction:: packeteer.generate.session.tcp_teardown
   :no-index:
```

```{eval-rst}
.. autofunction:: packeteer.generate.session.sctp_handshake
   :no-index:
```
