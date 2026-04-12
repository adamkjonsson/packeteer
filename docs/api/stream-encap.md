# Stream Encapsulation Types

The `packet_generator.stream_encap` module provides descriptor dataclasses for
wrapping generated streams in encapsulation layers.  Pass one or a list of
these to the `encap` parameter of any stream generator.

See {doc}`../stream/python-api` for usage examples and combination rules.

---

## VLAN (802.1Q)

```{eval-rst}
.. autoclass:: packet_generator.stream_encap.VLANEncap
   :members:
```

```{eval-rst}
.. autoclass:: packet_generator.stream_encap.QinQEncap
   :members:
```

---

## MPLS

```{eval-rst}
.. autoclass:: packet_generator.stream_encap.MPLSEncap
   :members:
```

---

## PPPoE

```{eval-rst}
.. autoclass:: packet_generator.stream_encap.PPPoEEncap
   :members:
```

---

## Tunnels

```{eval-rst}
.. autoclass:: packet_generator.stream_encap.GREEncap
   :members:
```

```{eval-rst}
.. autoclass:: packet_generator.stream_encap.EtherIPEncap
   :members:
```

```{eval-rst}
.. autoclass:: packet_generator.stream_encap.IPIPEncap
   :members:
```

---

## Type aliases

```{eval-rst}
.. autodata:: packet_generator.stream_encap.StreamEncap
.. autodata:: packet_generator.stream_encap.EncapSpec
```
