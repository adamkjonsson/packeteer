"""A module loaded by path can import the modules beside it (#203).

A tunnel's cipher is shared by the wrapper that seals and the decoder that
opens, so it lives in one file beside both.  A module executed by path did
not have its directory on `sys.path`, so `from wg_crypto import ...` failed.
The directory is appended, never put first, so a file beside the module
named like a standard-library module is never imported in its place.  The
same rule holds for `--tunnel-module` and `--load-protocol`.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
import uuid
from pathlib import Path

from packeteer import protocols
from packeteer.generate import load_wrapper

#: A standard-library module nothing in packeteer imports, so a test can
#: drop it from `sys.modules` and watch where it is imported from.
_STDLIB_DECOY = "colorsys"


class _Directory(unittest.TestCase):
    """A fresh directory, and `sys.path` and `sys.modules` put back after."""

    def setUp(self) -> None:
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir, True)
        saved_path = list(sys.path)
        self.addCleanup(lambda: sys.path.__setitem__(slice(None), saved_path))
        saved = sys.modules.get(_STDLIB_DECOY)
        self.addCleanup(self._restore, saved)
        # A unique sibling name, so no earlier import satisfies this one.
        self.sibling = f"sibling_{uuid.uuid4().hex[:8]}"

    @staticmethod
    def _restore(saved: object) -> None:
        if saved is None:
            sys.modules.pop(_STDLIB_DECOY, None)
        else:
            sys.modules[_STDLIB_DECOY] = saved

    def _write(self, name: str, body: str) -> Path:
        path = self.dir / name
        path.write_text(textwrap.dedent(body))
        return path

    def _sibling(self) -> None:
        self._write(f"{self.sibling}.py", 'PREFIX = b"shared:"\n')

    def _decoy(self) -> None:
        """Write a file beside the module named like the standard library's."""
        self._write(f"{_STDLIB_DECOY}.py", 'raise RuntimeError("the decoy was imported")\n')
        sys.modules.pop(_STDLIB_DECOY, None)


class TestATunnelModule(_Directory):

    def _wrapper(self) -> Path:
        return self._write("seal.py", f"""
            import {_STDLIB_DECOY}
            from {self.sibling} import PREFIX

            class Seal:
                def wrap(self, inner, direction, timestamp):
                    return [(direction, PREFIX + inner)]

            def make_wrapper(args):
                return Seal()
        """)

    def test_it_imports_the_module_beside_it(self) -> None:
        self._sibling()
        wrapper = load_wrapper(self._wrapper())
        self.assertEqual(wrapper.wrap(b"x", "c2s", 0.0), [("c2s", b"shared:x")])

    def test_a_file_beside_it_never_stands_in_for_the_standard_library(self) -> None:
        self._sibling()
        self._decoy()
        load_wrapper(self._wrapper())
        imported = Path(sys.modules[_STDLIB_DECOY].__file__)
        self.assertNotEqual(imported.parent, self.dir)

    def test_the_directory_is_appended_once(self) -> None:
        self._sibling()
        path = self._wrapper()
        load_wrapper(path)
        load_wrapper(path)
        self.assertEqual(sys.path.count(str(self.dir)), 1)
        self.assertNotEqual(sys.path[0], str(self.dir))


class TestAProtocolModule(_Directory):

    def test_it_imports_the_module_beside_it(self) -> None:
        """A protocol split across files, as #203 suggests for --load-protocol."""
        self._sibling()
        name = f"split_{self.sibling}"
        module = self._write(f"{name}.py", f"""
            from packeteer.app import dns
            from packeteer.protocols import AppProtocol, register
            from {self.sibling} import PREFIX

            assert PREFIX == b"shared:"
            register(AppProtocol(
                name="{name}", over="udp", ports=frozenset({{40999}}), messages=(),
                decode=dns.decode, encode=dns.encode,
                to_spec=dns.to_spec, from_spec=dns.from_spec,
                redacts_nothing=True,
            ))
        """)
        added = protocols.load_module(module)
        self.addCleanup(protocols.unregister, name)
        # Importing `packeteer.app` may register the built-ins in the same
        # call, in a process that had not yet; this one is what matters.
        self.assertIn(name, [p.name for p in added])


class TestTheIssuesCommand(_Directory):

    def test_stream_with_a_tunnel_module_that_imports_its_sibling(self) -> None:
        self._sibling()
        self._decoy()
        module = self._write("seal_sib.py", f"""
            import {_STDLIB_DECOY}
            from {self.sibling} import PREFIX

            class Seal:
                def wrap(self, inner, direction, timestamp):
                    return [(direction, PREFIX + inner)]

            def make_wrapper(args):
                return Seal()
        """)
        done = subprocess.run(
            [sys.executable, "-m", "packeteer", "stream", "--protocol", "udp",
             "--client-ip", "10.0.0.1", "--server-ip", "10.0.0.2", "--packets", "2",
             "--udp-tunnel", "1.1.1.1", "2.2.2.2", "--tunnel-port", "51820",
             "--tunnel-module", str(module), "--seed", "1",
             "--pcap", str(self.dir / "t.pcap")],
            capture_output=True, text=True, check=False, cwd=tempfile.gettempdir(),
        )
        self.assertEqual(done.returncode, 0, done.stderr)


if __name__ == "__main__":
    unittest.main()
