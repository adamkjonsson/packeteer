# Stream Generators

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
