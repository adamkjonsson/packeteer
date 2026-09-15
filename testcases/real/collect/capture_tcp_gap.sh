#!/usr/bin/env bash
#
# Collect the receiver-side TCP captures in this corpus.  Kept here so the
# corpus records how they were made, not just what they hold -- see
# MANIFEST.md, "Inducing what you cannot wait for".
#
# Same three throwaway namespaces as tcp_lossy_ts.pcap -- client, router,
# server -- with the impairment on the router, but tcpdump runs on the
# *client's* device, downstream of it, so the file holds what a receiver
# sees: the hole, the segments held out of order behind it, and the segment
# that fills it.  One file per mode, each from a fresh set of namespaces:
#
#   gap      tcp_gap_ts.pcap      netem loss: the fill is a retransmission
#                                 and carries a NEWER TSval than the
#                                 out-of-order segments it completes  (#158)
#   reorder  tcp_reorder_ts.pcap  a slow path for ~1 in 16 segments: the
#                                 fill is the original, delayed, and carries
#                                 an OLDER TSval  (#158)
#   corrupt  tcp_corrupt_ts.pcap  netem corrupt: the damaged copy reaches the
#                                 receiver, fails its checksum, is dropped
#                                 there, and the clean resend follows  (#160)
#   wrap     tcp_wrap_ts.pcap     a session whose sequence numbers pass
#                                 through 2^32, with the last 2 KiB before
#                                 the wrap on the slow path so originals from
#                                 before it arrive after segments from after
#                                 it  (#161)
#
# Why "reorder" is not `netem reorder`: a veth sender puts a whole congestion
# window on the wire inside one 1 ms TSval tick, and netem's reorder only
# lets a packet jump ahead of the packets queued in front of it -- its own
# burst-mates, which share its TSval.  An original that arrives with an
# OLDER TSval than its successors has to be held back past the *next* burst,
# i.e. by more than an RTT.  So the reorder and wrap runs use a two-band prio
# qdisc: band 0 is the normal DELAY, band 1 is DELAY + REORDER_DELAY, and a
# u32 filter on the TCP sequence number picks what goes down the slow band.
# The sender's fast retransmit of those bytes carries the same sequence
# number, so it takes the slow band too and arrives after the original as a
# plain repeat -- which is the point: the original fills.
#
# Why "wrap" needs no luck: Linux's ISN is siphash(4-tuple) + (realtime_ns
# >> 6), so for a FIXED 4-tuple it climbs at 15.625 M/s and sweeps the whole
# space every ~275 s.  The client probes once from a fixed source port, reads
# the server's ISN, closes with an RST (no TIME_WAIT, so the tuple is free),
# and connects again at the instant the clock reaches 2^32 - SIZE/2.
#
# Why "corrupt" turns TX checksum offload off: on a veth every packet's
# checksum is wrong for a reason that means nothing (offload).  This file
# exists for ONE checksum failure that means what it says, so the rest have
# to verify -- and then `sanitise` recomputes the good ones for the new
# addresses and carries the bad one verbatim, which is what a consumer
# needs.  It turns scatter-gather off too, or netem only ever damages a
# header: it flips a bit in the skb's linear part, and the payload is not
# there.
#
# The three rules from MANIFEST.md are followed: impairment downstream of the
# capture point (true by construction here), GSO off on the sender, and a
# 20 ms delay so the TSval clock ticks.  Each capture is checked with tshark
# before the script reports success, and the check fails loudly if the file
# does not contain the shape it exists for.
#
# Two things this script learned, both of which produce a plausible-looking
# file when got wrong:
#
#   - tcpdump's TPACKET_V3 holds packets in a block for up to a second, so
#     stopping it right after the transfer loses the tail (165 of 198 packets
#     written, and tcpdump's own log is the only place that says so).  Hence
#     --immediate-mode, a two-second settle, and the log check below.
#   - `netem reorder` cannot produce an older TSval: see above.
#
# Usage:   sudo testcases/real/collect/capture_tcp_gap.sh [OUT_DIR]
#
# Writes the unsanitised originals (and tcpdump's log beside each) to OUT_DIR,
# default ~/packeteer-captures/originals -- outside the repository, as the
# manifest's first rule requires.  Refuses to overwrite a file that is there
# unless FORCE=1, since the committed captures were sanitised from these.
# Needs iproute2, tcpdump, tshark and python3; ethtool for the corrupt mode.
#
# Tunables (environment):
#   ONLY=gap|reorder|corrupt|wrap   collect one mode; default is all four
#   LOSS=10%             loss on the router's client-facing leg (gap)
#   CORRUPT=3%           corruption on the same leg (corrupt)
#   DELAY=20ms           one-way delay on each leg (in ms; the slow band adds)
#   REORDER_DELAY=50ms   extra delay on the slow band (reorder, wrap); must
#                        exceed an RTT (2 x DELAY) or the retransmit wins
#   SIZE=65536           bytes the server sends
#   PORT=8443            server port
#   CLIENT_PORT=40000    the client's fixed source port (wrap)
#
# Afterwards, per the manifest: sanitise, compare against the original by
# hand, byte-scan, and add the manifest row.  The script prints the commands.

set -euo pipefail

OUT_DIR="${1:-$HOME/packeteer-captures/originals}"
ONLY="${ONLY:-}"
LOSS="${LOSS:-10%}"
CORRUPT="${CORRUPT:-3%}"
DELAY="${DELAY:-20ms}"
REORDER_DELAY="${REORDER_DELAY:-50ms}"
SIZE="${SIZE:-65536}"
PORT="${PORT:-8443}"
CLIENT_PORT="${CLIENT_PORT:-40000}"
FORCE="${FORCE:-0}"

NS_CLIENT=client
NS_ROUTER=router
NS_SERVER=server
MTU=576          # -> MSS 536, the same 524-byte segments as tcp_lossy_ts

die() { echo "error: $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "run me with sudo"
for tool in ip tc tcpdump tshark python3; do
    command -v "$tool" >/dev/null || die "$tool is not on PATH"
done
HAVE_ETHTOOL=0
command -v ethtool >/dev/null && HAVE_ETHTOOL=1

# If SUDO_USER is set, resolve OUT_DIR relative to *their* home, not root's.
if [[ -n "${SUDO_USER:-}" && "$OUT_DIR" == "$HOME"* && "$HOME" == /root ]]; then
    OUT_DIR="$(getent passwd "$SUDO_USER" | cut -d: -f6)/packeteer-captures/originals"
fi
mkdir -p "$OUT_DIR"

for ns in $NS_CLIENT $NS_ROUTER $NS_SERVER; do
    ip netns list | grep -qx "$ns" && die "netns '$ns' already exists; not touching it"
done

SERVER_PID=""
TCPDUMP_PID=""
FAILED=()
cleanup() {
    [[ -n "$TCPDUMP_PID" ]] && kill -INT "$TCPDUMP_PID" 2>/dev/null && wait "$TCPDUMP_PID" 2>/dev/null || true
    [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null && wait "$SERVER_PID" 2>/dev/null || true
    TCPDUMP_PID=""
    SERVER_PID=""
    for ns in $NS_CLIENT $NS_ROUTER $NS_SERVER; do
        ip netns del "$ns" 2>/dev/null || true
    done
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Topology
#
#   client (10.0.2.2) vc <--> vr2 (10.0.2.1) router (10.0.1.1) vr1 <--> vs (10.0.1.2) server
#
# The server sends; the data crosses vr2 towards the client, which is where
# the impairment is queued.  The capture is on vc.
# ---------------------------------------------------------------------------
build_topology() {
    local mode="$1"

    ip netns add $NS_CLIENT
    ip netns add $NS_ROUTER
    ip netns add $NS_SERVER

    ip link add vc type veth peer name vr2
    ip link add vs type veth peer name vr1
    ip link set vc  netns $NS_CLIENT
    ip link set vs  netns $NS_SERVER
    ip link set vr1 netns $NS_ROUTER
    ip link set vr2 netns $NS_ROUTER

    ip -n $NS_CLIENT addr add 10.0.2.2/24 dev vc
    ip -n $NS_SERVER addr add 10.0.1.2/24 dev vs
    ip -n $NS_ROUTER addr add 10.0.2.1/24 dev vr2
    ip -n $NS_ROUTER addr add 10.0.1.1/24 dev vr1

    for spec in "$NS_CLIENT vc" "$NS_SERVER vs" "$NS_ROUTER vr1" "$NS_ROUTER vr2"; do
        set -- $spec
        ip -n "$1" link set dev "$2" mtu $MTU
        # Rule 2: no segmentation offload, or the file shows "segments" no
        # wire carried.
        ip -n "$1" link set dev "$2" gso_max_segs 1
        if [[ $HAVE_ETHTOOL -eq 1 ]]; then
            # And no receive coalescing on the far side, which is the
            # receiver-side hazard the manifest names.
            ip netns exec "$1" ethtool -K "$2" gro off gso off tso off >/dev/null 2>&1 || true
        fi
        ip -n "$1" link set dev "$2" up
    done
    if [[ "$mode" == corrupt ]]; then
        # Real checksums on every packet, so the corrupted one is the only
        # one that fails.  See the header.
        ip netns exec $NS_SERVER ethtool -K vs tx off >/dev/null
        ip netns exec $NS_CLIENT ethtool -K vc tx off >/dev/null
        # And no scatter-gather on the sender: netem flips a bit in the
        # skb's LINEAR part, and Linux TCP keeps payload in page frags, so
        # with SG on every corruption lands in a header (4 of 4, first
        # attempt).  Without SG the stack linearises each skb at transmit
        # and the router forwards it that way.
        ip netns exec $NS_SERVER ethtool -K vs sg off >/dev/null
    fi
    for ns in $NS_CLIENT $NS_ROUTER $NS_SERVER; do
        ip -n "$ns" link set lo up
    done

    ip netns exec $NS_ROUTER sysctl -qw net.ipv4.ip_forward=1
    ip -n $NS_CLIENT route add default via 10.0.2.1
    ip -n $NS_SERVER route add default via 10.0.1.1

    # Rule 3 on both legs; the impairment only on the leg that carries the
    # data towards the receiver (rule 1: downstream of the capture point is
    # automatic here, but it still has to be on the router, not on vs).
    ip netns exec $NS_ROUTER tc qdisc add dev vr1 root netem delay "$DELAY"
    local SLOW_DELAY="$(( ${DELAY%ms} + ${REORDER_DELAY%ms} ))ms"
    case "$mode" in
        gap)
            ip netns exec $NS_ROUTER tc qdisc add dev vr2 root netem delay "$DELAY" loss "$LOSS"
            ;;
        corrupt)
            ip netns exec $NS_ROUTER tc qdisc add dev vr2 root netem delay "$DELAY" corrupt "$CORRUPT"
            ;;
        reorder|wrap)
            # Two bands, everything in band 0 by default (priomap all 0).
            ip netns exec $NS_ROUTER tc qdisc add dev vr2 root handle 1: prio bands 2 \
                priomap 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
            ip netns exec $NS_ROUTER tc qdisc add dev vr2 parent 1:1 handle 10: netem delay "$DELAY"
            ip netns exec $NS_ROUTER tc qdisc add dev vr2 parent 1:2 handle 20: netem delay "$SLOW_DELAY"
            local value mask
            if [[ "$mode" == reorder ]]; then
                # Sequence numbers with bits 9-12 clear: seq mod 8192 < 512,
                # which at 524 bytes a segment is about one segment in
                # sixteen, never two in a row.
                value=0x00000000; mask=0x00001e00
            else
                # The last 2 KiB before 2^32: seq >= 0xfffff800, three or
                # four consecutive segments from just before the wrap.
                value=0xfffff800; mask=0xfffff800
            fi
            # Offset 24 is the sequence number when the IP header carries no
            # options.
            ip netns exec $NS_ROUTER tc filter add dev vr2 parent 1: protocol ip prio 1 u32 \
                match ip protocol 6 0xff \
                match ip sport "$PORT" 0xffff \
                match u32 "$value" "$mask" at 24 \
                flowid 1:2
            ;;
    esac

    # Prime ARP so the capture is TCP from the first frame, like its twin.
    ip netns exec $NS_CLIENT ping -c3 -i 0.2 -W2 10.0.1.2 >/dev/null 2>&1 || true
}

start_server() {
    ip netns exec $NS_SERVER python3 - "$PORT" "$SIZE" <<'PY' &
import socket, sys
port, size = int(sys.argv[1]), int(sys.argv[2])
body = bytes(range(256)) * (size // 256 + 1)
body = body[:size]
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("10.0.1.2", port))
srv.listen(1)
print("READY", flush=True)
while True:
    conn, _ = srv.accept()
    # The wrap mode's ISN probe connects and resets without asking for
    # anything; serve the first connection that does ask.
    req = b""
    try:
        while not req.endswith(b"\r\n"):
            chunk = conn.recv(64)
            if not chunk:
                break
            req += chunk
    except ConnectionResetError:
        req = b""
    if not req:
        conn.close()
        continue
    conn.sendall(body)
    conn.shutdown(socket.SHUT_WR)
    while conn.recv(4096):
        pass
    conn.close()
    break
srv.close()
PY
    SERVER_PID=$!
    # Wait for the listener.
    for _ in $(seq 50); do
        ip netns exec $NS_SERVER ss -ltn "sport = :$PORT" | grep -q LISTEN && return
        sleep 0.1
    done
    die "server did not start listening"
}

# Wrap mode: read the server's ISN for the fixed 4-tuple, and print the
# wall-clock time at which connecting again will draw one SIZE/2 bytes below
# 2^32.  TCP_REPAIR lets the client read its own rcv_nxt, which is the peer's
# ISN + 1; SO_LINGER 0 closes with an RST so the tuple leaves no TIME_WAIT.
#
# Two probes, not one: the second, a few seconds before the target,
# re-anchors the estimate and measures the clock's rate over the whole wait,
# so a stepped or slewed clock costs seconds of extrapolation rather than
# minutes.  (Two attempts landed a constant 2.8 s short with the rate exactly
# nominal, which was not the clock at all: the probe was reading the client's
# own write_seq -- TCP_RECV_QUEUE is 1, not 2 -- and the two ISNs share the
# clock but not the hash.)  The waiting happens here, before tcpdump starts.
probe_isn() {
    ip netns exec $NS_CLIENT python3 - "$PORT" "$SIZE" "$CLIENT_PORT" <<'PY'
import socket, struct, sys, time
port, size, client_port = (int(a) for a in sys.argv[1:4])
TCP_REPAIR, TCP_REPAIR_QUEUE, TCP_QUEUE_SEQ, TCP_RECV_QUEUE = 19, 20, 21, 1
NOMINAL = 15_625_000       # ISN units per second: realtime_ns >> 6
MARGIN = 6.0               # seconds before the target for the second probe


def probe():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("10.0.2.2", client_port))
    t = time.time()
    s.connect(("10.0.1.2", port))
    s.setsockopt(socket.IPPROTO_TCP, TCP_REPAIR, 1)
    s.setsockopt(socket.IPPROTO_TCP, TCP_REPAIR_QUEUE, TCP_RECV_QUEUE)
    isn = (struct.unpack("I", s.getsockopt(socket.IPPROTO_TCP, TCP_QUEUE_SEQ, 4))[0] - 1) & 0xFFFFFFFF
    s.setsockopt(socket.IPPROTO_TCP, TCP_REPAIR, 0)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    s.close()
    return isn, t


target = (1 << 32) - size // 2
isn0, t0 = probe()
wait = ((target - isn0) & 0xFFFFFFFF) / NOMINAL
print(f"   probe 1: server ISN {isn0}, want {target}; about {wait:.1f}s away", file=sys.stderr)
if wait < MARGIN + 2:
    wait += (1 << 32) / NOMINAL        # too close to call: take the next lap
time.sleep(wait - MARGIN)
isn1, t1 = probe()
rate = ((isn1 - isn0) & 0xFFFFFFFF) / (t1 - t0)
left = ((target - isn1) & 0xFFFFFFFF) / rate
print(f"   probe 2: server ISN {isn1} after {t1 - t0:.1f}s, clock runs at {rate / 1e6:.3f} M/s; "
      f"connecting in {left:.1f}s", file=sys.stderr)
print(f"{t1 + left:.6f}")
PY
}

run_client() {
    local client_port="${1:-}" connect_at="${2:-}"
    ip netns exec $NS_CLIENT python3 - "$PORT" "$SIZE" "$client_port" "$connect_at" <<'PY'
import socket, sys, time
port, size = int(sys.argv[1]), int(sys.argv[2])
client_port = int(sys.argv[3]) if sys.argv[3] else None
connect_at = float(sys.argv[4]) if sys.argv[4] else None
want = (bytes(range(256)) * (size // 256 + 1))[:size]
s = socket.socket()
s.settimeout(60)
if client_port:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("10.0.2.2", client_port))
if connect_at:
    # Coarse sleep, then spin for the last 50 ms: the ISN clock moves 15 625
    # units per ms, and a sleep on a VM can overshoot by several ms -- a
    # 2 ms spin window landed 3.5 ms (54 KB) late.
    while (left := connect_at - time.time()) > 0.05:
        time.sleep(left - 0.05)
    while time.time() < connect_at:
        pass
s.connect(("10.0.1.2", port))
s.sendall(b"GET\r\n")
got = bytearray()
while True:
    chunk = s.recv(65536)
    if not chunk:
        break
    got += chunk
s.close()
if bytes(got) != want:
    sys.exit(f"client received {len(got)} bytes, expected {size}, or the pattern is wrong")
print(f"client received {len(got)} bytes intact")
PY
}

start_capture() {
    local pcap="$1" filter="$2"
    # --immediate-mode: otherwise TPACKET_V3 holds packets in a block for up
    # to a second and the tail of the transfer is lost when tcpdump is
    # stopped.
    ip netns exec $NS_CLIENT tcpdump -i vc --nano -U --immediate-mode -s 0 -w "$pcap" \
        "$filter" >"$pcap.log" 2>&1 &
    TCPDUMP_PID=$!
    for _ in $(seq 50); do
        grep -q "listening on" "$pcap.log" 2>/dev/null && { sleep 0.3; return; }
        sleep 0.1
    done
    die "tcpdump did not start; see $pcap.log"
}

stop_capture() {
    sleep 2     # let the FIN exchange, and anything delayed, land
    kill -INT "$TCPDUMP_PID"
    wait "$TCPDUMP_PID" || true
    TCPDUMP_PID=""
}

# ---------------------------------------------------------------------------
# Check the file holds the shape it is for.  Replays the capture through a
# receiver's eyes: a segment whose checksum fails is dropped on arrival, a
# hole opens when a segment arrives past rcv_nxt, later segments are held
# behind it, and the segment that closes the hole is the "fill".  The fill's
# TSval against the held segments' TSvals is the whole point of #158; the
# damaged copy against its resend is #160's; the numbering across 2^32 is
# #161's.
# ---------------------------------------------------------------------------
read -r -d '' ANALYSE_PY <<'PY' || true
import re
import sys

expect, mtu, log, size = sys.argv[1], int(sys.argv[2]), sys.argv[3], int(sys.argv[4])
MASK = 0xFFFFFFFF
HALF = 1 << 31


def after(a, b):
    """RFC 1982: is sequence number *a* after *b*?"""
    return 0 < ((a - b) & MASK) < HALF


counts = {label: n for n, label in re.findall(
    r"(\d+) packets (captured|received by filter|dropped by kernel)", open(log).read())}

rows = []
unrecognised = 0
for line in sys.stdin:
    f = line.rstrip("\n").split("\t")
    if len(f) < 13:
        continue
    if not f[5]:
        unrecognised += 1          # captured, but tshark could not see TCP in it
        continue
    rows.append(dict(
        no=int(f[0]), flen=int(f[1]), src=f[2], syn=f[3] == "1", fin=f[4] == "1",
        seq=int(f[5]), ack=int(f[6]), ln=int(f[7]),
        tsval=int(f[8]) if f[8] else None, tsecr=int(f[9]) if f[9] else None,
        tcp_ok=f[10], ip_ok=f[11], payload=f[12],
    ))
if not rows:
    sys.exit("no TCP packets in the capture")

server = "10.0.1.2"
data = [r for r in rows if r["src"] == server and r["ln"] > 0]
acks = [r for r in rows if r["src"] != server and r["ln"] == 0 and not r["syn"]]
if not data:
    sys.exit("no data segments from the server")

problems = []
if counts.get("captured") != counts.get("received by filter") or counts.get("dropped by kernel") != "0":
    problems.append(f"tcpdump wrote {counts.get('captured')} of {counts.get('received by filter')} packets "
                    f"({counts.get('dropped by kernel')} dropped): the tail of the transfer is missing")
biggest = max(r["flen"] for r in rows)
if biggest > mtu + 14:
    problems.append(f"a {biggest}-byte frame: segmentation/receive offload is on")
if len({r["tsval"] for r in data}) < 2:
    problems.append("every data TSval is identical: the delay is not taking effect")

# Checksums.  tshark's status: 0 bad, 1 good, 2 unverified.
bad = [r for r in rows if r["tcp_ok"] == "0" or r["ip_ok"] == "0"]
good = [r for r in rows if r["tcp_ok"] == "1" and r["ip_ok"] != "0"]

# The receiver's replay.  In the corrupt mode a data segment whose checksum
# fails never reached the stack, so it opens no hole and fills none: it is
# recorded as corrupted and skipped.  In the other modes every checksum
# fails, for the offload reason the header explains, and says nothing.
rcv_nxt = data[0]["seq"]
held = {}                 # seq -> segment, arrived out of order, not yet in order
holes_opened = 0
fills_newer = fills_older = fills_tied = 0
strictly_newer = strictly_older = 0
fills = []
fill_lines = []
overlaps = 0
corrupted = []
for seg in data:
    if expect == "corrupt" and (seg["tcp_ok"] == "0" or seg["ip_ok"] == "0"):
        corrupted.append(seg)
        continue
    if seg["seq"] == rcv_nxt:
        seg["in_order"] = True
        if held:
            beyond = [h for s, h in held.items() if after(s, seg["seq"])]
            if beyond:
                fills.append(seg)
                # Against everything a reassembler has committed past the
                # hole.  A resend that recovered a loss is newer than all of
                # it; an original that was merely delayed is older than all
                # of it.  Segments the sender put out in the same 1 ms tick
                # tie, and are reported rather than counted either way.
                held_ts = [h["tsval"] for h in beyond]
                newer_than = sum(1 for t in held_ts if t < seg["tsval"])
                older_than = sum(1 for t in held_ts if t > seg["tsval"])
                ties = len(held_ts) - newer_than - older_than
                if older_than == 0 and newer_than > 0:
                    fills_newer += 1
                    strictly_newer += ties == 0
                    kind = "NEWER than what was committed past it"
                elif newer_than == 0 and older_than > 0:
                    fills_older += 1
                    strictly_older += ties == 0
                    kind = "OLDER than what was committed past it"
                else:
                    fills_tied += 1
                    kind = "undecidable"
                seg["beyond"] = beyond
                fill_lines.append(
                    f"    frame {seg['no']:>3} seq {(seg['seq'] - data[0]['seq']) & MASK:>6} TSval {seg['tsval']}: "
                    f"{len(beyond)} held beyond it -- newer than {newer_than}, older than {older_than}, "
                    f"same tick as {ties}: {kind}")
        rcv_nxt = (rcv_nxt + seg["ln"]) & MASK
        while rcv_nxt in held:
            rcv_nxt = (rcv_nxt + held.pop(rcv_nxt)["ln"]) & MASK
    elif after(seg["seq"], rcv_nxt):
        if not held:
            holes_opened += 1
        if seg["seq"] in held:
            overlaps += 1
        else:
            held[seg["seq"]] = seg
    else:
        overlaps += 1

# Dup ACKs: a pure ACK from the client repeating the previous pure ACK's number.
dup_acks = 0
last = None
for a in acks:
    if last is not None and a["ack"] == last and not a["fin"]:
        dup_acks += 1
    last = a["ack"]


def answering_ack(seg):
    """The first receiver ACK after *seg* that covers it, or None."""
    end = (seg["seq"] + seg["ln"]) & MASK
    for a in acks:
        if a["no"] > seg["no"] and (a["ack"] == end or after(a["ack"], end)):
            return a
    return None


# Does the ACK that answers a fill echo the fill's TSval?
echoed = sum(1 for fill in fills
             if (a := answering_ack(fill)) is not None and a["tsecr"] == fill["tsval"])

print(f"  packets            {len(rows)}   (largest frame {biggest} bytes"
      + (f", {unrecognised} not recognisable as TCP" if unrecognised else "") + ")")
print(f"  checksums          {len(good)} verify, {len(bad)} fail, {len(rows) - len(good) - len(bad)} unverifiable")
print(f"  data segments      {len(data)}, {len(fills)} of them fill a hole; {overlaps} repeats of bytes already held"
      + (f"; {len(corrupted)} dropped at the receiver for a bad checksum" if corrupted else ""))
print(f"  holes opened       {holes_opened}")
print("  fill TSval vs what was committed past it:")
print(f"    newer (loss recovered)   {fills_newer}, of which {strictly_newer} with no same-tick tie")
print(f"    older (delayed original) {fills_older}, of which {strictly_older} with no same-tick tie")
print(f"    undecidable              {fills_tied}")
print(f"  ACK answering fill echoes its TSval: {echoed} / {len(fills)}")
for line in fill_lines:
    print(line)
print(f"  duplicate ACKs     {dup_acks}")

if expect == "corrupt":
    # Every failing checksum should be a corruption, and every corruption
    # should be followed by a clean resend with a later clock whose ACK
    # echoes the resend.
    if len(bad) > len(corrupted):
        problems.append(f"{len(bad) - len(corrupted)} packets fail their checksum without being corrupted data: "
                        "is TX checksum offload still on?")
    if not corrupted and not unrecognised:
        problems.append("no data segment reached the receiver with a failing checksum")
    in_header = unrecognised      # a frame tshark cannot read was hit in a header
    in_payload = 0
    for seg in corrupted:
        resend = next((d for d in data if d["no"] > seg["no"] and d["seq"] == seg["seq"]
                       and d["tcp_ok"] != "0" and d["ip_ok"] != "0"), None)
        if resend is None:
            problems.append(f"frame {seg['no']}: the corrupted segment was never resent clean")
            continue
        where = "payload" if resend["payload"] != seg["payload"] else "a header"
        if where == "payload":
            in_payload += 1
        else:
            in_header += 1
        clock = "later" if resend["tsval"] > seg["tsval"] else "NOT later"
        if clock != "later":
            problems.append(f"frame {seg['no']}: the resend's TSval is not later")
        # RFC 7323 4.3: the ACK echoes the segment that advanced the left
        # edge.  A resend that arrived in order is that segment; one that
        # arrived behind another hole is not, and its covering ACK echoes
        # whatever filled that hole.
        if resend.get("in_order"):
            a = answering_ack(resend)
            echo = "echoes the resend" if a is not None and a["tsecr"] == resend["tsval"] else "DOES NOT echo the resend"
            if echo != "echoes the resend":
                problems.append(f"frame {seg['no']}: the ACK covering the resend does not echo its TSval")
        else:
            echo = "arrived behind another hole, so its covering ACK echoes that hole's fill"
        print(f"    frame {seg['no']:>3} seq {(seg['seq'] - data[0]['seq']) & MASK:>6}: bit flipped in {where}; "
              f"clean resend at frame {resend['no']} with a {clock} TSval; {echo}")
    print(f"  corruptions        {len(corrupted) + unrecognised}: {in_payload} in payload, {in_header} in a header"
          + (f" ({unrecognised} of them beyond tshark's recognition)" if unrecognised else ""))
    if corrupted and not in_payload:
        problems.append("no corruption landed in payload, so no two copies of a range differ in their bytes")
elif expect == "wrap":
    synack = next((r for r in rows if r["src"] == server and r["syn"]), None)
    if synack is None:
        problems.append("no SYN-ACK from the server")
    else:
        isn = synack["seq"]
        before = (MASK + 1 - isn) & MASK
        wrapped = [d for d in data if d["seq"] < HALF]         # numerically small: after the wrap
        pre = [d for d in data if d["seq"] >= HALF]
        acks_wrapped = [a for a in acks if a["ack"] < HALF]
        print(f"  ISN                {isn}: {before} bytes before 2^32 (transfer is {size})")
        print(f"  data segments      {len(pre)} before the wrap, {len(wrapped)} after")
        print(f"  receiver ACKs      {len(acks_wrapped)} of {len(acks)} carry a wrapped number")
        if not (0 < before < size):
            problems.append("the ISN does not sit inside the transfer: the sequence numbers do not wrap")
        # Item 1: post-wrap segments carry later TSvals than pre-wrap
        # ORIGINALS.  Resends of pre-wrap bytes are sent after the wrap and
        # carry the clock of that moment, which is the disagreement item 3
        # is about, so only the first copy of each pre-wrap range counts.
        firsts = {}
        for d in pre:
            firsts.setdefault(d["seq"], d)
        newest_pre = max(d["tsval"] for d in firsts.values()) if firsts else None
        later = sum(1 for d in wrapped if newest_pre is not None and d["tsval"] >= newest_pre)
        print(f"  post-wrap segments with a TSval no older than any pre-wrap original: {later} / {len(wrapped)}")
        if wrapped and later < len(wrapped):
            problems.append("a post-wrap segment carries an older TSval than a pre-wrap original")
        if not acks_wrapped:
            problems.append("the receiver's ACK numbers never wrapped")
        crossing = [f for f in fills if f["seq"] >= HALF and any(h["seq"] < HALF for h in f["beyond"])]
        print(f"  pre-wrap originals arriving after post-wrap segments: {len(crossing)}")
        if not crossing:
            problems.append("no original from before the wrap arrived after a segment from after it")
elif expect == "newer" and fills_newer == 0:
    problems.append("no fill carries a newer TSval than the segments it completes: no loss was recovered after a gap")
elif expect == "older" and fills_older == 0:
    problems.append("no fill carries an older TSval than the segments it completes: nothing was reordered")

if held:
    problems.append(f"{len(held)} segments never came into order: the transfer is incomplete")
if fills and echoed < len(fills):
    problems.append(f"{len(fills) - echoed} fills were answered by an ACK echoing some other TSval")
for p in problems:
    print(f"  PROBLEM: {p}")
sys.exit(1 if problems else 0)
PY

analyse() {
    local pcap="$1" expect="$2"
    tshark -r "$pcap" -T fields -E separator=/t \
        -o tcp.check_checksum:TRUE -o ip.check_checksum:TRUE \
        -e frame.number -e frame.len -e ip.src -e tcp.flags.syn -e tcp.flags.fin \
        -e tcp.seq_raw -e tcp.ack_raw -e tcp.len \
        -e tcp.options.timestamp.tsval -e tcp.options.timestamp.tsecr \
        -e tcp.checksum.status -e ip.checksum.status -e tcp.payload \
        2>/dev/null \
    | python3 -c "$ANALYSE_PY" "$expect" "$MTU" "$pcap.log" "$SIZE"
}

collect() {
    local name="$1" mode="$2" expect="$3"
    local pcap="$OUT_DIR/$name.pcap"
    local filter="tcp and port $PORT" client_port="" connect_at=""
    if [[ -e "$pcap" && "$FORCE" != 1 ]]; then
        echo "== $name: skipped, $pcap exists (FORCE=1 to overwrite it)"
        echo
        return
    fi
    case "$mode" in
        gap)     echo "== $name  (router's client-facing leg: netem delay $DELAY loss $LOSS)" ;;
        corrupt) echo "== $name  (router's client-facing leg: netem delay $DELAY corrupt $CORRUPT; TX checksum offload off)"
                 [[ $HAVE_ETHTOOL -eq 1 ]] || die "the corrupt mode needs ethtool"
                 # A flipped bit in a port or the ethertype would hide the
                 # damaged frame from a tighter filter.
                 filter="not arp and not ip6" ;;
        reorder) echo "== $name  (router's client-facing leg: delay $DELAY, ~1 in 16 segments delayed $DELAY + $REORDER_DELAY)" ;;
        wrap)    echo "== $name  (ISN steered to $((SIZE / 2)) bytes before 2^32; the last 2 KiB before it delayed $DELAY + $REORDER_DELAY)" ;;
    esac
    build_topology "$mode"
    start_server
    if [[ "$mode" == wrap ]]; then
        connect_at="$(probe_isn)"
        client_port="$CLIENT_PORT"
    fi
    start_capture "$pcap" "$filter"
    run_client "$client_port" "$connect_at"
    stop_capture
    cleanup
    trap cleanup EXIT
    if [[ -n "${SUDO_USER:-}" ]]; then
        chown "$SUDO_USER" "$pcap" "$pcap.log"
    fi
    echo "   wrote $pcap"
    analyse "$pcap" "$expect" || FAILED+=("$name")
    echo
}

case "$ONLY" in
    "")      collect tcp_gap_ts     gap     newer
             collect tcp_reorder_ts reorder older
             collect tcp_corrupt_ts corrupt corrupt
             collect tcp_wrap_ts    wrap    wrap ;;
    gap)     collect tcp_gap_ts     gap     newer ;;
    reorder) collect tcp_reorder_ts reorder older ;;
    corrupt) collect tcp_corrupt_ts corrupt corrupt ;;
    wrap)    collect tcp_wrap_ts    wrap    wrap ;;
    *)       die "ONLY must be gap, reorder, corrupt or wrap" ;;
esac

if [[ ${#FAILED[@]} -gt 0 ]]; then
    echo "FAILED: ${FAILED[*]} -- see the lines above" >&2
    exit 1
fi

cat <<EOF
Next, per testcases/real/MANIFEST.md, for each file (as yourself, not root):

  .venv/bin/packeteer sanitise $OUT_DIR/NAME.pcap --pcap testcases/real/NAME.pcap
  tshark -r $OUT_DIR/NAME.pcap -T fields -e ip.src -e eth.src | sort -u   # and confirm none survive in the sanitised copy
  add '!testcases/real/NAME.pcap' to .gitignore and a row to MANIFEST.md
EOF
