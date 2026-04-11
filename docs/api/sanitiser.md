# Sanitiser

`replacer.sanitise` replaces sensitive fields in a packet config dict with
deterministic synthetic values drawn from IANA-reserved address ranges.  The
original dict is never modified.

See {doc}`../sanitiser` for the full feature description and CLI equivalent.

---

```{eval-rst}
.. autoclass:: replacer.SanitiseOptions
   :members:
   :no-index:
```

```{eval-rst}
.. autofunction:: replacer.sanitise
   :no-index:
```
