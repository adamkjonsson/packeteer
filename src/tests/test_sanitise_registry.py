"""Sanitisation dispatches through the registry (#101).

The isolation tests here run in a subprocess on purpose.  Under pytest every
other test module has already imported ``packeteer.parse``, so nothing run
in-process can show what ``packeteer.sanitise`` does on its own — which is
precisely the case that regresses if the lazy import in
:func:`packeteer.sanitise.sanitise` is ever moved to module level.
"""
from __future__ import annotations

import pathlib
import subprocess
import sys
import unittest

from packeteer import protocols
from packeteer.sanitise import SanitiseOptions, sanitise

_SRC = str(pathlib.Path(protocols.__file__).parent.parent)

_DNS_SPEC = {
    "packets": [{
        "network": {"src": "10.1.2.3", "dst": "10.4.5.6", "protocol": "udp"},
        "transport": {"dst_port": 53},
        "dns": {"id": 4660, "questions": [{"name": "secret.example.com."}]},
    }],
}


def _run(body: str) -> str:
    """Run *body* in a fresh interpreter and return its stdout."""
    code = f"import sys; sys.path.insert(0, {_SRC!r})\n{body}"
    out = subprocess.run([sys.executable, "-c", code],
                         capture_output=True, text=True, check=True)
    return out.stdout.strip()


class TestSanitiseAloneStillRedacts(unittest.TestCase):
    """The trap: an empty registry would redact nothing, and say nothing."""

    def test_importing_only_sanitise_still_redacts_a_dns_section(self) -> None:
        name = _run(f"""
from packeteer.sanitise import sanitise
spec = {_DNS_SPEC!r}
print(sanitise(spec)["packets"][0]["dns"]["questions"][0]["name"])
""")
        self.assertNotIn("secret", name)
        self.assertNotIn("example", name)

    def test_it_does_not_pull_in_the_parser(self) -> None:
        """The lazy import must reach `app`, and stop there."""
        loaded = _run(f"""
import sys
from packeteer.sanitise import sanitise
sanitise({_DNS_SPEC!r})
print("packeteer.parse" in sys.modules, "packeteer.app" in sys.modules)
""")
        self.assertEqual(loaded, "False True")

    def test_importing_sanitise_does_not_register_anything_by_itself(self) -> None:
        """Registration happens when `sanitise` is called, not at import."""
        registered = _run("""
import packeteer.sanitise
from packeteer import protocols
print(len(protocols.registered()))
""")
        self.assertEqual(registered, "0")


class TestRegisteredProtocolsAreSanitised(unittest.TestCase):

    def _proto(self, **overrides: object) -> protocols.AppProtocol:
        fields: dict[str, object] = {
            "name": "sensor", "over": "udp", "ports": frozenset({9000}),
            "messages": (dict,),
            "decode": lambda p, t: {}, "encode": lambda m, t: b"",
            "to_spec": lambda m: {}, "from_spec": lambda s: {},
        }
        fields.update(overrides)
        return protocols.AppProtocol(**fields)

    def test_a_registered_sanitiser_runs(self) -> None:
        def _redact(section: dict, replacer: object, options: object) -> None:
            section["owner"] = "[redacted]"

        protocols.register(self._proto(sanitise=_redact))
        self.addCleanup(protocols.unregister, "sensor")
        spec = {"packets": [{"sensor": {"owner": "Adam", "value": 1}}]}
        clean = sanitise(spec)
        self.assertEqual(clean["packets"][0]["sensor"]["owner"], "[redacted]")
        self.assertEqual(clean["packets"][0]["sensor"]["value"], 1)
        self.assertEqual(spec["packets"][0]["sensor"]["owner"], "Adam")

    def test_a_protocol_without_a_sanitiser_passes_through_untouched(self) -> None:
        """Documented, and the reason `sanitise=None` is a deliberate choice."""
        protocols.register(self._proto())
        self.addCleanup(protocols.unregister, "sensor")
        spec = {"packets": [{"sensor": {"owner": "Adam"}}]}
        self.assertEqual(sanitise(spec)["packets"][0]["sensor"]["owner"], "Adam")


class TestBuiltInsUnchanged(unittest.TestCase):

    def test_dns_names_are_still_replaced(self) -> None:
        clean = sanitise(_DNS_SPEC)
        name = clean["packets"][0]["dns"]["questions"][0]["name"]
        self.assertNotIn("secret", name)

    def test_dns_ids_still_follow_the_option(self) -> None:
        self.assertEqual(sanitise(_DNS_SPEC)["packets"][0]["dns"]["id"], 4660)
        clean = sanitise(_DNS_SPEC, SanitiseOptions(dns_ids=True))
        self.assertEqual(clean["packets"][0]["dns"]["id"], 0)


if __name__ == "__main__":
    unittest.main()
