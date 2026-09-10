"""Describe an application protocol in YAML, and compile it to Python.

A spec says what a protocol's messages look like on the wire; the compiler
turns one into a module implementing
:class:`packeteer.protocols.AppProtocol`, so a protocol described this way is
parsed, built, serialised and redacted exactly like a built-in.  See
:mod:`packeteer.protospec.spec` for the shape of a spec, and
:doc:`../guide/adding-a-protocol` for the hand-written alternative.

The dialect is a superset of `kober <https://github.com/adamkjonsson/zipline-kober>`_'s:
kober's keys keep kober's meaning, and packeteer adds ``over`` and ``ports``,
which say when a protocol is used, plus ``derive`` and ``sensitive``, which are
what a spec needs in order to describe an **encoder** — something a decoder
never had to.  ``const`` was packeteer's too until kober 0.2.0 adopted it, and
is now shared.
"""
from __future__ import annotations

from packeteer.protospec.check import CheckResult, Diagnostic, check
from packeteer.protospec.codegen import compile_spec
from packeteer.protospec.errors import SpecError
from packeteer.protospec.loader import from_mapping, load, loads
from packeteer.protospec.show import render
from packeteer.protospec.spec import Spec

__all__ = [
    "Spec",
    "SpecError",
    "CheckResult",
    "Diagnostic",
    "check",
    "compile_spec",
    "render",
    "load",
    "loads",
    "from_mapping",
]
