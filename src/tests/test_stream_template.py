"""Tests for the `packeteer stream` config template.

The template is hand-written prose, so the risk is drift: an option gets added
to the CLI and nobody remembers the template.  These tests make that a build
failure rather than a discovery.
"""
from __future__ import annotations

import argparse
import configparser
import os
import re
import tempfile
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import packeteer.__main__ as cli
from packeteer.generate import stream_config_template

#: Matches an example assignment at the start of a line, commented or not.
_EXAMPLE = re.compile(r"^#\s?([a-z0-9_]+)\s*=\s*(.*)$")
_LIVE = re.compile(r"^([a-z0-9_]+)\s*=\s*(.*)$")


def _documented_keys(template: str) -> set[str]:
    """Return every config key the template shows an example for."""
    keys = set()
    for line in template.splitlines():
        match = _EXAMPLE.match(line) or _LIVE.match(line)
        if match and match.group(1) in cli._STREAM_PARAMS:
            keys.add(match.group(1))
    return keys


def _uncomment_all(template: str) -> str:
    """Return the template with every commented example turned on.

    Later duplicates are skipped — a key may appear twice, once as a worked
    example inside the prose.
    """
    seen: set[str] = set()
    out: list[str] = []
    for line in template.splitlines():
        match = _EXAMPLE.match(line)
        if match and match.group(1) in cli._STREAM_PARAMS and match.group(1) not in seen:
            seen.add(match.group(1))
            out.append(f"{match.group(1)} = {match.group(2)}")
        else:
            out.append(line)
    return "\n".join(out)


class TestTemplateCompleteness(unittest.TestCase):
    """Every recognised config key must be documented."""

    def test_no_recognised_key_is_undocumented(self):
        # If this fails, a new stream option was added without a template
        # entry — add one to src/packeteer/generate/stream.ini.template.
        missing = set(cli._STREAM_PARAMS) - _documented_keys(stream_config_template())
        self.assertEqual(missing, set(), f"undocumented config keys: {sorted(missing)}")

    def test_template_documents_nothing_unrecognised(self):
        template = stream_config_template()
        mentioned = {
            m.group(1)
            for line in template.splitlines()
            if (m := (_EXAMPLE.match(line) or _LIVE.match(line)))
        }
        # Anything that looks like a key but is not one would mislead a reader.
        unknown = {k for k in mentioned if k not in cli._STREAM_PARAMS}
        self.assertEqual(unknown, set())


class TestTemplateValidity(unittest.TestCase):
    """The template must work when a user edits it the obvious way."""

    def _load(self, text: str) -> dict:
        fd, path = tempfile.mkstemp(suffix=".ini")
        with os.fdopen(fd, "w") as f:
            f.write(text)
        try:
            return cli._load_stream_config(path)
        finally:
            os.remove(path)

    def test_template_parses_as_ini(self):
        parser = configparser.ConfigParser()
        parser.read_string(stream_config_template())
        self.assertIn("stream", parser)

    def test_shipped_defaults_load(self):
        config = self._load(stream_config_template())
        self.assertEqual(config["client_ip"], "10.0.0.1")
        self.assertEqual(config["server_ip"], "10.0.0.2")

    def test_every_documented_example_is_valid(self):
        # Uncommenting any example must not produce an error: no trailing
        # prose on the assignment line, and every value of the right type.
        config = self._load(_uncomment_all(stream_config_template()))
        dests = {spec[0] for spec in cli._STREAM_PARAMS.values()}
        self.assertEqual(set(config) - dests, set())
        self.assertGreater(len(config), 60)

    def test_examples_have_no_trailing_prose(self):
        # The failure mode this guards: '# vlan_pcp = 0   Priority Code Point'
        # reads as the value '0   Priority Code Point' once uncommented.
        offenders = []
        for line in stream_config_template().splitlines():
            match = _EXAMPLE.match(line)
            if not match or match.group(1) not in cli._STREAM_PARAMS:
                continue
            converter = cli._STREAM_PARAMS[match.group(1)][1]
            if converter is bool:
                continue
            try:
                converter(match.group(2))
            except (ValueError, TypeError):
                offenders.append(line)
        self.assertEqual(offenders, [])


class TestTemplateGeneratesAStream(unittest.TestCase):
    """The template is a working starting point, not just documentation."""

    def test_template_plus_an_output_path_produces_packets(self):
        from packeteer.pcap import read_pcap
        directory = tempfile.mkdtemp()
        pcap_path = os.path.join(directory, "out.pcap")
        text = stream_config_template().replace(
            "# pcap = out.pcap", f"pcap = {pcap_path}", 1,
        )
        ini_path = os.path.join(directory, "stream.ini")
        Path(ini_path).write_text(text)

        args = cli._load_stream_config(ini_path)
        namespace = argparse.Namespace(config=ini_path, write_config=None, **args)
        for dest, _, default in cli._STREAM_PARAMS.values():
            if not hasattr(namespace, dest):
                setattr(namespace, dest, default)
        cli._cmd_stream(namespace)

        self.assertGreater(len(read_pcap(path=pcap_path).packets), 0)


class TestWriteConfigFlag(unittest.TestCase):
    """packeteer stream --write-config."""

    def test_writes_the_template_to_a_file(self):
        directory = tempfile.mkdtemp()
        path = os.path.join(directory, "template.ini")
        cli._cmd_stream(argparse.Namespace(write_config=path))
        self.assertEqual(Path(path).read_text(), stream_config_template())

    def test_dash_writes_to_stdout(self):
        with patch("sys.stdout", new_callable=StringIO) as out:
            cli._cmd_stream(argparse.Namespace(write_config="-"))
        self.assertEqual(out.getvalue(), stream_config_template())

    def test_unwritable_path_exits(self):
        with self.assertRaises(SystemExit):
            cli._cmd_stream(
                argparse.Namespace(write_config="/nonexistent/dir/template.ini"),
            )


class TestTemplateAPI(unittest.TestCase):
    def test_returns_text_from_package_data(self):
        template = stream_config_template()
        self.assertIn("[stream]", template)
        self.assertTrue(template.endswith("\n"))

    def test_exported_from_packeteer_generate(self):
        from packeteer import generate
        self.assertIn("stream_config_template", generate.__all__)


if __name__ == "__main__":
    unittest.main()
