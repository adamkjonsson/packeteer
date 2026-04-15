# Stream Generators

`packeteer.generator` provides three stream generators — TCP, UDP, and SCTP — each
producing a typed stream object whose `.packets` list can be written to pcap,
pcapng, or packet spec, or inspected and modified before output.

See {doc}`../stream/index` for usage examples, encapsulation, and CLI equivalents.

---

## TCP

```{eval-rst}
.. autofunction:: packeteer.generator.tcp_stream.generate_tcp_stream
   :no-index:
```

```{eval-rst}
.. autoclass:: packeteer.generator.tcp_stream.TCPStream
   :members:
   :no-index:
```

```{eval-rst}
.. autoclass:: packeteer.generator.tcp_stream.TCPStreamPacket
   :members:
   :no-index:
```

```{eval-rst}
.. autoclass:: packeteer.generator.tcp_stream.TCPStreamConfig
   :members:
   :no-index:
```

---

## UDP

```{eval-rst}
.. autofunction:: packeteer.generator.udp_stream.generate_udp_stream
   :no-index:
```

```{eval-rst}
.. autoclass:: packeteer.generator.udp_stream.UDPStream
   :members:
   :no-index:
```

```{eval-rst}
.. autoclass:: packeteer.generator.udp_stream.UDPStreamPacket
   :members:
   :no-index:
```

---

## SCTP

```{eval-rst}
.. autofunction:: packeteer.generator.sctp_stream.generate_sctp_stream
   :no-index:
```

```{eval-rst}
.. autoclass:: packeteer.generator.sctp_stream.SCTPStream
   :members:
   :no-index:
```

```{eval-rst}
.. autoclass:: packeteer.generator.sctp_stream.SCTPStreamPacket
   :members:
   :no-index:
```
