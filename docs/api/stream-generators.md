# Stream Generators

`packet_generator` provides three stream generators — TCP, UDP, and SCTP — each
producing a typed stream object whose `.packets` list can be written to pcap,
pcapng, or JSON config, or inspected and modified before output.

See {doc}`../stream/index` for usage examples, encapsulation, and CLI equivalents.

---

## TCP

```{eval-rst}
.. autofunction:: packet_generator.tcp_stream.generate_tcp_stream
   :no-index:
```

```{eval-rst}
.. autoclass:: packet_generator.tcp_stream.TCPStream
   :members:
   :no-index:
```

```{eval-rst}
.. autoclass:: packet_generator.tcp_stream.TCPStreamPacket
   :members:
   :no-index:
```

---

## UDP

```{eval-rst}
.. autofunction:: packet_generator.udp_stream.generate_udp_stream
   :no-index:
```

```{eval-rst}
.. autoclass:: packet_generator.udp_stream.UDPStream
   :members:
   :no-index:
```

```{eval-rst}
.. autoclass:: packet_generator.udp_stream.UDPStreamPacket
   :members:
   :no-index:
```

---

## SCTP

```{eval-rst}
.. autofunction:: packet_generator.sctp_stream.generate_sctp_stream
   :no-index:
```

```{eval-rst}
.. autoclass:: packet_generator.sctp_stream.SCTPStream
   :members:
   :no-index:
```

```{eval-rst}
.. autoclass:: packet_generator.sctp_stream.SCTPStreamPacket
   :members:
   :no-index:
```
