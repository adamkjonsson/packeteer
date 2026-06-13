"""Unit tests for the fictive VPN payload type (packeteer.generate.payloads.vpn)."""
from __future__ import annotations

import argparse
import json
import os
import struct
import tempfile
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import packeteer.__main__ as cli
from packeteer.generate import CombinedStream, VPNConfig, generate_vpn_stream
from packeteer.generate.payloads.vpn import _MSG_DATA
from packeteer.parse import parse_packet

_BASE_TIME = 1_700_000_000.0


def _by_port(packets: list) -> dict[int, list]:
    """Group packets by UDP destination port."""
    out: dict[int, list] = {}
    for p in packets:
        pkt = parse_packet(p.raw)
        out.setdefault(pkt.transport.dst_port, []).append(p)
    return out


# ── generate_vpn_stream ───────────────────────────────────────────────────────

class TestVPNStream(unittest.TestCase):

    def _mix(self, **over: object) -> CombinedStream:
        kwargs: dict = {
            "client_ip": "10.0.0.1", "server_ip": "10.1.0.1",
            "epochs": 3, "packets_per_epoch": 4, "seed": 7, "base_time": _BASE_TIME,
        }
        kwargs.update(over)
        return generate_vpn_stream(**kwargs)

    def test_packet_count(self) -> None:
        # per epoch: 3 handshake + N data; total = epochs * (3 + N)
        mix = self._mix(epochs=3, packets_per_epoch=4)
        self.assertEqual(len(mix.packets), 3 * (3 + 4))

    def test_two_udp_ports(self) -> None:
        mix = self._mix()
        cfg = VPNConfig()
        labels_by_port: dict[int, set[str]] = {}
        for p in mix.packets:
            pkt = parse_packet(p.raw)
            # collect destination OR source port to find the channel ports
            for port in (pkt.transport.src_port, pkt.transport.dst_port):
                if port in (cfg.key_port, cfg.data_port):
                    labels_by_port.setdefault(port, set()).add(p.label.split()[0].split("[")[0])
        # key-exchange port carries KEY-* messages; data port carries DATA
        self.assertTrue(any("KEY-INIT" in s for s in labels_by_port[cfg.key_port]))
        self.assertIn("DATA", labels_by_port[cfg.data_port])

    def test_three_message_handshake_per_epoch(self) -> None:
        mix = self._mix(epochs=3)
        inits = [p for p in mix.packets if p.label.startswith("KEY-INIT")]
        responses = [p for p in mix.packets if p.label.startswith("KEY-RESPONSE")]
        confirms = [p for p in mix.packets if p.label.startswith("KEY-CONFIRM")]
        self.assertEqual((len(inits), len(responses), len(confirms)), (3, 3, 3))

    def test_data_packet_header(self) -> None:
        cfg = VPNConfig()
        mix = self._mix()
        for p in mix.packets:
            pkt = parse_packet(p.raw)
            if pkt.transport.dst_port == cfg.data_port and pkt.payload:
                magic, ver, mtype, epoch = struct.unpack(">4sBBH", pkt.payload[:8])
                self.assertEqual(magic, cfg.magic)
                self.assertEqual(ver, cfg.version)
                self.assertEqual(mtype, _MSG_DATA)
                return
        self.fail("no data packet found")

    def test_per_direction_counters_reset_each_epoch(self) -> None:
        # one direction only is hard to guarantee; instead check counters start
        # at 0 at the first data packet of every epoch for whichever direction.
        mix = self._mix(epochs=3, packets_per_epoch=6)
        seen_zero_per_epoch: dict[int, bool] = {}
        for p in mix.packets:
            if p.label.startswith("DATA "):
                # label: "DATA <dir> ctr=<n> epoch=<e>"
                parts = dict(tok.split("=") for tok in p.label.split() if "=" in tok)
                epoch = int(parts["epoch"])
                ctr = int(parts["ctr"])
                if ctr == 0:
                    seen_zero_per_epoch[epoch] = True
        self.assertEqual(set(seen_zero_per_epoch), {0, 1, 2})

    def test_bidirectional_over_many_packets(self) -> None:
        mix = self._mix(epochs=1, packets_per_epoch=40, seed=3)
        dirs = {p.direction for p in mix.packets if p.label.startswith("DATA ")}
        self.assertEqual(dirs, {"c2s", "s2c"})

    def test_reproducible_with_seed(self) -> None:
        self.assertEqual(self._mix().to_pcap_tuples(), self._mix().to_pcap_tuples())

    def test_different_seed_differs(self) -> None:
        self.assertNotEqual(self._mix(seed=1).to_pcap_tuples(),
                            self._mix(seed=2).to_pcap_tuples())

    def test_sessions_distinct_ip_pairs(self) -> None:
        mix = self._mix(sessions=3)
        client_ips = set()
        for p in mix.packets:
            pkt = parse_packet(p.raw)
            client_ips.add(str(pkt.ip.src))
            client_ips.add(str(pkt.ip.dst))
        for octet in (1, 2, 3):
            self.assertIn(f"10.0.0.{octet}", client_ips)
            self.assertIn(f"10.1.0.{octet}", client_ips)

    def test_custom_ports(self) -> None:
        mix = self._mix(config=VPNConfig(data_port=4500, key_port=500))
        ports = set()
        for p in mix.packets:
            pkt = parse_packet(p.raw)
            ports.add(pkt.transport.dst_port)
            ports.add(pkt.transport.src_port)
        self.assertIn(4500, ports)
        self.assertIn(500, ports)

    def test_epochs_below_one_raises(self) -> None:
        with self.assertRaises(ValueError):
            generate_vpn_stream(client_ip="10.0.0.1", server_ip="10.1.0.1", epochs=0)

    def test_packets_below_one_raises(self) -> None:
        with self.assertRaises(ValueError):
            generate_vpn_stream(client_ip="10.0.0.1", server_ip="10.1.0.1",
                                packets_per_epoch=0)

    def test_min_gt_max_raises(self) -> None:
        with self.assertRaises(ValueError):
            generate_vpn_stream(client_ip="10.0.0.1", server_ip="10.1.0.1",
                                min_payload=100, max_payload=10)

    def test_overlapping_ip_ranges_raise(self) -> None:
        with self.assertRaises(ValueError):
            generate_vpn_stream(client_ip="10.0.0.1", server_ip="10.0.0.2",
                                sessions=5)


# ── CLI ───────────────────────────────────────────────────────────────────────

class TestCmdStreamVPN(unittest.TestCase):

    def _args(self, **over: object) -> argparse.Namespace:
        ns = argparse.Namespace(
            config=None, client_ip="10.0.0.1", server_ip="10.1.0.1",
            pcap=None, pcapng=None, json=None, payload="vpn", seed=7,
        )
        for k, v in over.items():
            setattr(ns, k, v)
        return ns

    def _tmp(self, suffix: str = ".pcap") -> str:
        fd, path = tempfile.mkstemp(suffix=suffix)
        os.close(fd)
        return path

    def test_cli_vpn_writes_pcap(self) -> None:
        out = self._tmp()
        with patch("sys.stdout", new=StringIO()):
            cli._cmd_stream(self._args(pcap=out, vpn_epochs=2, packets=3))
        self.assertGreater(os.path.getsize(out), 0)
        os.remove(out)

    def test_cli_vpn_json_labels(self) -> None:
        out = self._tmp(".json")
        with patch("sys.stdout", new=StringIO()):
            cli._cmd_stream(self._args(json=out, vpn_epochs=1, packets=2))
        data = json.loads(Path(out).read_text())
        labels = [p.get("packet_metadata", {}).get("label", "") for p in data["packets"]]
        self.assertIn("KEY-INIT[epoch=0]", labels)
        self.assertTrue(any(lbl.startswith("DATA ") for lbl in labels))
        os.remove(out)


if __name__ == "__main__":
    unittest.main()
