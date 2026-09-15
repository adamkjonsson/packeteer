#!/usr/bin/env bash
#
# Collect the receiver-side captures #158 asked for: tcp_gap_ts.pcap and
# tcp_reorder_ts.pcap.  Kept here so the corpus records how they were made,
# not just what they hold -- see MANIFEST.md, "Inducing what you cannot wait
# for".
#
# Same three throwaway namespaces as tcp_lossy_ts.pcap -- client, router,
# server -- with tc netem on the router, but tcpdump runs on the *client's*
# device, downstream of the impairment, so the file holds what a receiver
# sees: the hole, the segments held out of order behind it, and the resend
# that fills it.
#
# Two files come out, each from a fresh set of namespaces:
#
#   tcp_gap_ts.pcap      netem loss  -- the fill is a retransmission, and
#                                       carries a NEWER TSval than the
#                                       out-of-order segments it completes
#   tcp_reorder_ts.pcap  a slow path for ~1 in 16 segments -- the fill is
#                                       the original, delayed, and carries an
#                                       OLDER TSval
#
# Why the second one is not `netem reorder`: a veth sender puts a whole
# congestion window on the wire inside one 1 ms TSval tick, and netem's
# reorder only lets a packet jump ahead of the packets queued in front of
# it -- its own burst-mates, which share its TSval.  An original that arrives
# with an OLDER TSval than its successors has to be held back past the *next*
# burst, i.e. by more than an RTT.  So the reorder run uses a two-band prio
# qdisc: band 0 is the normal 20 ms, band 1 is 20 ms + REORDER_DELAY, and a
# u32 filter on the TCP sequence number sends every ~16th segment down the
# slow band.  The sender's fast retransmit of those bytes carries the same
# sequence number, so it takes the slow band too and arrives after the
# original as a plain repeat -- which is the point: the original fills.
#
# The three rules from testcases/real/MANIFEST.md are followed: impairment
# downstream of the capture point (true by construction here), GSO off on the
# sender, and a 20 ms delay so the TSval clock ticks.  Each capture is checked
# with tshark before the script reports success, and the check fails loudly
# if the file does not contain the shape it exists for.
#
# Usage:   sudo testcases/real/collect/capture_tcp_gap.sh [OUT_DIR]
#
# Writes the unsanitised originals (and tcpdump's log beside each) to OUT_DIR,
# default ~/packeteer-captures/originals -- outside the repository, as the
# manifest's first rule requires.  Needs iproute2, tcpdump, tshark and
# python3; ethtool if present.
#
# Tunables (environment):
#   LOSS=10%      loss on the router's client-facing leg (tcp_gap_ts)
#   REORDER_DELAY=50ms   extra delay on the slow band (tcp_reorder_ts); must
#                 exceed an RTT (2 x DELAY) or the retransmit wins the race
#   DELAY=20ms    one-way delay on each leg (in ms; the reorder run adds them)
#   SIZE=65536    bytes the server sends
#   PORT=8443
#   ONLY=gap|reorder   collect just one of the two
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
# Afterwards, per the manifest: sanitise, compare against the original by
# hand, byte-scan, and add the manifest row.  The script prints the commands.

set -euo pipefail

OUT_DIR="${1:-$HOME/packeteer-captures/originals}"
LOSS="${LOSS:-10%}"
REORDER_DELAY="${REORDER_DELAY:-50ms}"
DELAY="${DELAY:-20ms}"
SIZE="${SIZE:-65536}"
PORT="${PORT:-8443}"
ONLY="${ONLY:-}"

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
        loss)
            ip netns exec $NS_ROUTER tc qdisc add dev vr2 root netem delay "$DELAY" loss "$LOSS"
            ;;
        reorder)
            # Two bands, everything in band 0 by default (priomap all 0).
            ip netns exec $NS_ROUTER tc qdisc add dev vr2 root handle 1: prio bands 2 \
                priomap 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
            ip netns exec $NS_ROUTER tc qdisc add dev vr2 parent 1:1 handle 10: netem delay "$DELAY"
            ip netns exec $NS_ROUTER tc qdisc add dev vr2 parent 1:2 handle 20: netem delay "$SLOW_DELAY"
            # Server -> client TCP whose sequence number has bits 9-12 clear:
            # seq mod 8192 < 512, which at 524 bytes a segment is about one
            # segment in sixteen, never two in a row.  Offset 24 is the
            # sequence number when the IP header carries no options.
            ip netns exec $NS_ROUTER tc filter add dev vr2 parent 1: protocol ip prio 1 u32 \
                match ip protocol 6 0xff \
                match ip sport "$PORT" 0xffff \
                match u32 0x00000000 0x00001e00 at 24 \
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
conn, _ = srv.accept()
req = b""
while not req.endswith(b"\r\n"):
    chunk = conn.recv(64)
    if not chunk:
        break
    req += chunk
conn.sendall(body)
conn.shutdown(socket.SHUT_WR)
while conn.recv(4096):
    pass
conn.close()
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

run_client() {
    ip netns exec $NS_CLIENT python3 - "$PORT" "$SIZE" <<'PY'
import socket, sys
port, size = int(sys.argv[1]), int(sys.argv[2])
want = (bytes(range(256)) * (size // 256 + 1))[:size]
s = socket.create_connection(("10.0.1.2", port), timeout=30)
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
    local pcap="$1"
    # --immediate-mode: otherwise TPACKET_V3 holds packets in a block for up
    # to a second and the tail of the transfer is lost when tcpdump is
    # stopped.
    ip netns exec $NS_CLIENT tcpdump -i vc --nano -U --immediate-mode -s 0 -w "$pcap" \
        "tcp and port $PORT" >"$pcap.log" 2>&1 &
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
# receiver's eyes: a hole opens when a segment arrives past rcv_nxt, later
# segments are held behind it, and the segment that closes the hole is the
# "fill".  The fill's TSval against the held segments' TSvals is the whole
# point of #158.
# ---------------------------------------------------------------------------
read -r -d '' ANALYSE_PY <<'PY' || true
import sys
expect, mtu, log = sys.argv[1], int(sys.argv[2]), sys.argv[3]
import re
counts = {label: n for n, label in re.findall(r"(\d+) packets (captured|received by filter|dropped by kernel)", open(log).read())}
rows = []
for line in sys.stdin:
    f = line.rstrip("\n").split("\t")
    if len(f) < 10 or not f[5]:
        continue
    rows.append(dict(
        no=int(f[0]), flen=int(f[1]), src=f[2], syn=f[3] == "1", fin=f[4] == "1",
        seq=int(f[5]), ack=int(f[6]), ln=int(f[7]),
        tsval=int(f[8]) if f[8] else None, tsecr=int(f[9]) if f[9] else None,
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

rcv_nxt = data[0]["seq"]
held = {}                 # seq -> segment, arrived out of order, not yet in order
holes_opened = 0
fills_newer = fills_older = fills_tied = 0
strictly_newer = strictly_older = 0
fills = []
fill_lines = []
overlaps = 0
for seg in data:
    if seg["seq"] == rcv_nxt:
        if held:
            beyond = [h for s, h in held.items() if s > seg["seq"]]
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
                fill_lines.append(
                    f"    frame {seg['no']:>3} seq {seg['seq'] - data[0]['seq'] + 1:>6} TSval {seg['tsval']}: "
                    f"{len(beyond)} held beyond it -- newer than {newer_than}, older than {older_than}, "
                    f"same tick as {ties}: {kind}")
        rcv_nxt += seg["ln"]
        while rcv_nxt in held:
            rcv_nxt += held.pop(rcv_nxt)["ln"]
    elif seg["seq"] > rcv_nxt:
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

# Does the ACK that answers a fill echo the fill's TSval?
echoed = 0
for fill in fills:
    end = fill["seq"] + fill["ln"]
    for a in acks:
        if a["no"] > fill["no"] and a["ack"] >= end:
            if a["tsecr"] == fill["tsval"]:
                echoed += 1
            break

print(f"  packets            {len(rows)}   (largest frame {biggest} bytes)")
print(f"  data segments      {len(data)}, {len(fills)} of them fill a hole; {overlaps} repeats of bytes already held")
print(f"  holes opened       {holes_opened}")
print(f"  fill TSval vs what was committed past it:")
print(f"    newer (loss recovered)   {fills_newer}, of which {strictly_newer} with no same-tick tie")
print(f"    older (delayed original) {fills_older}, of which {strictly_older} with no same-tick tie")
print(f"    undecidable              {fills_tied}")
print(f"  ACK answering fill echoes its TSval: {echoed} / {len(fills)}")
for line in fill_lines:
    print(line)
print(f"  duplicate ACKs     {dup_acks}")
if held:
    problems.append(f"{len(held)} segments never came into order: the transfer is incomplete")
if expect == "newer" and fills_newer == 0:
    problems.append("no fill carries a newer TSval than the segments it completes: no loss was recovered after a gap")
if expect == "older" and fills_older == 0:
    problems.append("no fill carries an older TSval than the segments it completes: nothing was reordered")
if fills and echoed < len(fills):
    problems.append(f"{len(fills) - echoed} fills were answered by an ACK echoing some other TSval")
for p in problems:
    print(f"  PROBLEM: {p}")
sys.exit(1 if problems else 0)
PY

analyse() {
    local pcap="$1" expect="$2"
    tshark -r "$pcap" -T fields -E separator=/t \
        -e frame.number -e frame.len -e ip.src -e tcp.flags.syn -e tcp.flags.fin \
        -e tcp.seq_raw -e tcp.ack_raw -e tcp.len \
        -e tcp.options.timestamp.tsval -e tcp.options.timestamp.tsecr \
        2>/dev/null \
    | python3 -c "$ANALYSE_PY" "$expect" "$MTU" "$pcap.log"
}

collect() {
    local name="$1" mode="$2" expect="$3"
    local pcap="$OUT_DIR/$name.pcap"
    case "$mode" in
        loss)    echo "== $name  (router's client-facing leg: netem delay $DELAY loss $LOSS)" ;;
        reorder) echo "== $name  (router's client-facing leg: delay $DELAY, ~1 in 16 segments delayed $DELAY + $REORDER_DELAY)" ;;
    esac
    build_topology "$mode"
    start_server
    start_capture "$pcap"
    run_client
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
    "")      collect tcp_gap_ts     loss    newer
             collect tcp_reorder_ts reorder older ;;
    gap)     collect tcp_gap_ts     loss    newer ;;
    reorder) collect tcp_reorder_ts reorder older ;;
    *)       die "ONLY must be gap or reorder" ;;
esac

if [[ ${#FAILED[@]} -gt 0 ]]; then
    echo "FAILED: ${FAILED[*]} -- the file(s) are kept, but do not hold what #158 asks for; see the PROBLEM lines" >&2
    exit 1
fi

cat <<EOF
Next, per testcases/real/MANIFEST.md, for each file (as yourself, not root):

  .venv/bin/packeteer sanitise $OUT_DIR/NAME.pcap --pcap testcases/real/NAME.pcap
  tshark -r $OUT_DIR/NAME.pcap -T fields -e ip.src -e eth.src | sort -u   # and confirm none survive in the sanitised copy
  add '!testcases/real/NAME.pcap' to .gitignore and a row to MANIFEST.md
EOF
