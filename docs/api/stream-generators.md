# Stream Generators

**Import:** All classes and functions on this page are exported from `packeteer.generate`, e.g. `from packeteer.generate import generate_tcp_stream, TCPStreamConfig`.

`packeteer.generate` provides three stream generators — TCP, UDP, and SCTP — each
producing a typed stream object whose `.packets` list can be written to pcap,
pcapng, or packet spec, or inspected and modified before output.

See {doc}`../guide/generating` for usage examples and encapsulation, and {doc}`../cli/stream` for CLI equivalents.

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

```{eval-rst}
.. autoclass:: packeteer.generate.udp_stream.UDPStreamConfig
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

```{eval-rst}
.. autoclass:: packeteer.generate.sctp_stream.SCTPStreamConfig
   :members:
   :no-index:
```

---

## Multiple sessions

{func}`~packeteer.generate.session_mix.generate_session_mix` produces several
independent sessions — each its own IP pair, start-time offset, and seed — and
interleaves them into one timestamp-sorted :class:`~packeteer.generate.session_mix.CombinedStream`.
The protocol is chosen by the type of the supplied config.
{func}`~packeteer.generate.session_mix.merge_streams` is the underlying
primitive for combining streams you have built yourself.

```{eval-rst}
.. autofunction:: packeteer.generate.session_mix.generate_session_mix
   :no-index:
```

```{eval-rst}
.. autofunction:: packeteer.generate.session_mix.merge_streams
   :no-index:
```

```{eval-rst}
.. autoclass:: packeteer.generate.session_mix.CombinedStream
   :members:
   :no-index:
```

---

## Application-layer payloads

Payload generators produce realistic application traffic instead of random
bytes.  {func}`~packeteer.generate.payloads.http.generate_http_stream`
simulates a REST client — random HTTP/1.1 request/response exchanges rendered
onto one or more TCP connections — returning a
:class:`~packeteer.generate.session_mix.CombinedStream`.  This powers
`packeteer stream --payload http`.

```{eval-rst}
.. autofunction:: packeteer.generate.payloads.http.generate_http_stream
   :no-index:
```

```{eval-rst}
.. autoclass:: packeteer.generate.payloads.http.HTTPRestConfig
   :members:
   :no-index:
```

```{eval-rst}
.. autofunction:: packeteer.generate.payloads.http.generate_http_conversation
   :no-index:
```

{func}`~packeteer.generate.payloads.vpn.generate_vpn_stream` simulates a fictive
binary VPN: a key-exchange channel (three-message handshake per epoch) and a
CTR-mode data channel, each on its own UDP port.

```{eval-rst}
.. autofunction:: packeteer.generate.payloads.vpn.generate_vpn_stream
   :no-index:
```

```{eval-rst}
.. autoclass:: packeteer.generate.payloads.vpn.VPNConfig
   :members:
   :no-index:
```

The conversation model and the TCP/UDP renderers are reusable for future
payload types:

```{eval-rst}
.. autoclass:: packeteer.generate.payloads.base.AppMessage
   :members:
   :no-index:
```

```{eval-rst}
.. autofunction:: packeteer.generate.payloads.base.render_tcp_session
   :no-index:
```

```{eval-rst}
.. autofunction:: packeteer.generate.payloads.base.render_udp_session
   :no-index:
```

---

## Session builders

See {doc}`../guide/generating` for usage examples and workflows.

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
