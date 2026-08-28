# Application protocols

**Import:** `from packeteer.protocols import AppProtocol, register`

`packeteer.protocols` is the registry of application-layer protocols packeteer
knows how to decode, build, serialise and redact.  DNS, DHCP and HTTP are
registered by {mod}`packeteer.app`; anything a caller registers is treated
identically.

See {doc}`../guide/adding-a-protocol` for a worked example.

The module imports only the standard library — both `packeteer.generate` and
`packeteer.parse` depend on it, and `packeteer.sanitise` and
`packeteer.filter` import nothing else from packeteer — so an `AppProtocol`
holds callables rather than modules.

---

## `AppProtocol`

A frozen dataclass describing one application protocol.  The four callables in
the second group are the contract; see {doc}`../guide/adding-a-protocol` for a
worked example.

| Field | Type | Description |
|-------|------|-------------|
| `name` | `str` | Short identifier, and the packet-spec section key — `"dns"` produces a `"dns"` object in a spec.  May not be one of the structural keys in {doc}`../packet-spec/format`. |
| `over` | `str` | `"udp"`, `"tcp"`, or `"either"` for a protocol that runs over both, as DNS does |
| `ports` | `frozenset[int]` | Transport ports that identify it.  A weak signal: `decode` raising is what settles a collision, so claiming a busy port is survivable. |
| `messages` | `tuple` of classes | The message classes this protocol decodes to and encodes from.  {func}`~packeteer.protocols.for_message` dispatches on them, so they may not be shared with another protocol. |

| Callable | Signature | Description |
|----------|-----------|-------------|
| `decode` | `(payload, transport) -> message` | Raises `ValueError` or `struct.error` when *payload* is not this protocol after all, which leaves the bytes as an opaque payload |
| `encode` | `(message, transport) -> payload` | *transport* is what lets DNS add its 2-byte length prefix over TCP (RFC 1035 §4.2.2) without a protocol-specific argument |
| `to_spec` | `(message) -> dict` | The object written under `name` in a packet spec |
| `from_spec` | `(dict) -> message` | The inverse |
| `sanitise` | `(section, replacer, options) -> None` | Redacts the section in place.  **`None` means nothing is redacted** — a protocol registered without one flows through {func}`~packeteer.sanitise.sanitise` untouched. |

`AppProtocol.carries(transport)` returns whether the protocol can be carried
over `"tcp"` or `"udp"` — `True` when `over` is that transport or `"either"`.

```{eval-rst}
.. autofunction:: packeteer.protocols.register
   :no-index:
```

```{eval-rst}
.. autofunction:: packeteer.protocols.unregister
   :no-index:
```

```{eval-rst}
.. autofunction:: packeteer.protocols.registered
   :no-index:
```

```{eval-rst}
.. autofunction:: packeteer.protocols.for_port
   :no-index:
```

```{eval-rst}
.. autofunction:: packeteer.protocols.for_section
   :no-index:
```

```{eval-rst}
.. autofunction:: packeteer.protocols.for_message
   :no-index:
```

---

## The built-ins

**Import:** `from packeteer.app import dns, dhcp, http`

Each module assembles one protocol from the encoder in `packeteer.generate`
and the decoder in `packeteer.parse`, and owns the packet-spec mapping in both
directions.  `packeteer.app.dns.from_spec` and `to_spec` — and their `dhcp`
and `http` counterparts — are the public way to move between a spec section
and a message object.

```{eval-rst}
.. autofunction:: packeteer.app.apply_app_section
   :no-index:
```

```{eval-rst}
.. autofunction:: packeteer.app.register_builtins
   :no-index:
```

```{eval-rst}
.. autofunction:: packeteer.app.dns.from_spec
   :no-index:
```

```{eval-rst}
.. autofunction:: packeteer.app.dns.to_spec
   :no-index:
```
