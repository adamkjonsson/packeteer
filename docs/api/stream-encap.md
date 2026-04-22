# Stream Encapsulation Types

The `packeteer.generate.stream_encap` module provides descriptor dataclasses for
wrapping generated streams in encapsulation layers.  Pass one or a list of
these to the `encap` parameter of any stream generator.

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

---

## Type aliases

```{eval-rst}
.. autodata:: packeteer.generate.stream_encap.StreamEncap
.. autodata:: packeteer.generate.stream_encap.EncapSpec
```
