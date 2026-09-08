"""
core.preflight — Pre-flight L2 environment reconnaissance.

Passive (and one semi-passive) checks that identify active switch security
controls before committing to a noisy attack module.

Controls detected
-----------------
  BPDU Guard / Root Guard     → blocks: stp, mstp, swspoof
  Dynamic ARP Inspection (DAI)→ blocks: arp, impers
  DHCP Snooping               → blocks: dhcp, dhcp-starve
  Port Security               → blocks: cam, mac

Run via:  sudo python3 rapidstrike.py preflight -i eth0 [--gateway GW_IP]
"""

import time
from typing import Optional

from scapy.all import ARP, Ether, STP, Dot1Q, sniff, send

NAME        = "preflight"
DESCRIPTION = "Passive L2 mitigation reconnaissance before committing to attacks"
ATTCK_ID    = "—"          # reconnaissance, not attack


# ── Framework interface ────────────────────────────────────────────────────────

def register(subparsers, add_engagement_args):
    p = subparsers.add_parser(
        NAME,
        help=DESCRIPTION,
        description=__doc__,
    )
    p.add_argument("-i", "--iface", required=True, help="Interface to probe, e.g. eth0")
    p.add_argument("-g", "--gateway",  default=None,
                   help="Gateway IP (enables DAI probe; semi-active — sends 1 ARP)")
    p.add_argument("--bpdu-timeout",  type=int, default=8,
                   help="Seconds to listen for STP BPDUs (default 8, ≥2 hello intervals)")
    p.add_argument("--mac-timeout",   type=int, default=10,
                   help="Seconds to passively observe MAC diversity (default 10)")
    add_engagement_args(p)
    p.set_defaults(func=run)


def run(args, logger) -> int:
    report = run_all(
        iface=args.iface,
        gateway_ip=getattr(args, "gateway", None),
        bpdu_timeout=getattr(args, "bpdu_timeout", 8),
        mac_timeout=getattr(args, "mac_timeout", 10),
        logger=logger,
    )
    _print_summary(report, logger)
    return 0


# ── Individual checks ─────────────────────────────────────────────────────────

def check_bpdu(iface: str, timeout: int = 8) -> dict:
    """
    Passively listen for STP/RSTP/MSTP BPDUs on the 802.1D multicast address.

    Interpretation
    ~~~~~~~~~~~~~~
    * BPDUs heard, regular hello (≈2s):
        STP is running. BPDU Guard *may* be armed on access ports.
        If it is, sending our own BPDU will put the port err-disabled
        within milliseconds. Test on a sacrificial port first.

    * BPDUs heard, irregular or rare:
        Possible BPDU Filter (passes BPDUs upstream but suppresses replies).

    * No BPDUs:
        BPDU Filter active, unmanaged switch, or loop-free single-switch segment.
        STP attacks unlikely to have effect anyway.
    """
    result = {
        "bpdu_seen":      False,
        "count":          0,
        "root_priority":  65535,
        "root_mac":       None,
        "version":        None,
        "hello_interval": None,
    }
    timestamps = []

    def _cb(pkt):
        if STP not in pkt:
            return
        timestamps.append(time.time())
        result["bpdu_seen"] = True
        result["count"] += 1
        result["version"] = getattr(pkt[STP], "version", "?")
        pri = pkt[STP].rootid
        if pri < result["root_priority"]:
            result["root_priority"] = pri
            result["root_mac"] = str(pkt[STP].rootmac)

    sniff(iface=iface, filter="ether dst 01:80:c2:00:00:00",
          prn=_cb, timeout=timeout, store=0)

    if len(timestamps) >= 2:
        intervals = [timestamps[i+1] - timestamps[i]
                     for i in range(len(timestamps) - 1)]
        result["hello_interval"] = round(sum(intervals) / len(intervals), 2)

    return result


def probe_dai(iface: str, gateway_ip: str, timeout: int = 6) -> dict:
    """
    Semi-active DAI probe: send one gratuitous ARP with a spoofed MAC
    claiming to be the gateway, then listen to see if any host on the
    segment receives and re-broadcasts it.

    If DAI is active, the switch drops the frame at hardware before
    forwarding — nothing echoes it back.

    **Sends exactly 1 ARP frame. Active but minimal footprint.**
    """
    probe_mac = "02:de:ad:be:ef:01"

    probe_pkt = (
        Ether(src=probe_mac, dst="ff:ff:ff:ff:ff:ff") /
        ARP(op=1, hwsrc=probe_mac, psrc=gateway_ip,
            hwdst="ff:ff:ff:ff:ff:ff", pdst=gateway_ip)
    )
    send(probe_pkt, iface=iface, verbose=False)

    echoed = [False]

    def _cb(pkt):
        if (ARP in pkt and
                pkt[ARP].psrc == gateway_ip and
                pkt[ARP].hwsrc == probe_mac):
            echoed[0] = True

    sniff(iface=iface, filter="arp", prn=_cb, timeout=timeout, store=0)

    return {
        "dai_blocking": not echoed[0],
        "probe_mac":    probe_mac,
        "verdict": (
            "DAI LIKELY ACTIVE — spoofed ARP was not echoed (dropped at switch)."
            if not echoed[0] else
            "DAI NOT DETECTED — ARP frame was echoed; injection may succeed."
        ),
    }


def check_mac_diversity(iface: str, timeout: int = 10) -> dict:
    """
    Passively count unique source MACs visible on the segment.

    Port Security limits the number of MACs learned per port.
    Very low diversity (< 4–5 MACs) on a segment with known multiple
    hosts suggests aggressive filtering.
    """
    macs: set = set()
    _SKIP = {"ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"}

    def _cb(pkt):
        if Ether in pkt:
            src = pkt[Ether].src.lower()
            if src not in _SKIP:
                macs.add(src)

    sniff(iface=iface, prn=_cb, timeout=timeout, store=0)

    count = len(macs)
    return {
        "unique_macs": count,
        "macs": sorted(macs),
        "port_security_likely": count < 4,
        "verdict": (
            f"Only {count} unique MACs seen — Port Security may be enforced "
            f"(or segment is very quiet)."
            if count < 4 else
            f"{count} unique MACs observed — segment appears normal."
        ),
    }


def check_dhcp_snooping(iface: str, timeout: int = 12) -> dict:
    """
    Passively detect DHCP Snooping by listening for DHCP OFFERs/ACKs.
    If the DHCP server is on a trusted port only, we should see valid
    server-to-client traffic. If Snooping is active, offers sourced from
    untrusted ports (like ours) would be dropped silently.

    This check is entirely passive — it only listens.
    """
    offers_seen = [0]

    def _cb(pkt):
        from scapy.all import DHCP
        if DHCP in pkt:
            msg = next((v for k, v in pkt[DHCP].options if k == "message-type"), None)
            if msg in (2, 5):   # OFFER or ACK
                offers_seen[0] += 1

    sniff(iface=iface, filter="udp and (port 67 or port 68)",
          prn=_cb, timeout=timeout, store=0)

    return {
        "dhcp_offers_seen": offers_seen[0],
        "verdict": (
            f"{offers_seen[0]} DHCP OFFER/ACK frames observed — "
            "DHCP traffic is flowing normally; snooping may or may not be active."
            if offers_seen[0] > 0 else
            "No DHCP OFFER/ACK seen — server may be on trusted port only, "
            "or DHCP Snooping is silently dropping untrusted frames."
        ),
    }


# ── Composite runner ──────────────────────────────────────────────────────────

def run_all(
    iface:        str,
    gateway_ip:   Optional[str] = None,
    bpdu_timeout: int = 8,
    mac_timeout:  int = 10,
    logger        = None,
) -> dict:
    """Run all checks sequentially; return combined report dict."""
    _log = logger.info if logger else print
    report: dict = {}

    # ── 1. STP / BPDU ────────────────────────────────────────────────────────
    _log("[Preflight] Listening for STP BPDUs on %s (%ds)...", iface, bpdu_timeout)
    bpdu = check_bpdu(iface, timeout=bpdu_timeout)
    report["bpdu"] = bpdu
    if bpdu["bpdu_seen"]:
        _log("[Preflight] STP active | root_priority=%d mac=%s hello≈%.1fs ver=%s",
             bpdu["root_priority"], bpdu["root_mac"],
             bpdu["hello_interval"] or 2.0, bpdu["version"])
        _log("[Preflight] WARNING: BPDU Guard may be active on access ports. "
             "Sending BPDU will cause immediate err-disabled. Test on sacrificial port.")
    else:
        _log("[Preflight] No STP BPDUs heard. BPDU Filter active, or unmanaged switch.")

    # ── 2. DAI (semi-active) ─────────────────────────────────────────────────
    if gateway_ip:
        _log("[Preflight] Probing DAI against gateway %s (sends 1 ARP)...", gateway_ip)
        dai = probe_dai(iface, gateway_ip, timeout=6)
        report["dai"] = dai
        _log("[Preflight] %s", dai["verdict"])
    else:
        _log("[Preflight] Skipping DAI probe — provide --gateway to enable.")

    # ── 3. MAC diversity / Port Security ─────────────────────────────────────
    _log("[Preflight] Observing MAC diversity on %s (%ds)...", iface, mac_timeout)
    mac_div = check_mac_diversity(iface, timeout=mac_timeout)
    report["mac_diversity"] = mac_div
    _log("[Preflight] %s", mac_div["verdict"])

    # ── 4. DHCP Snooping ─────────────────────────────────────────────────────
    _log("[Preflight] Listening for DHCP traffic (12s)...")
    dhcp_snoop = check_dhcp_snooping(iface, timeout=12)
    report["dhcp_snooping"] = dhcp_snoop
    _log("[Preflight] %s", dhcp_snoop["verdict"])

    return report


def _print_summary(report: dict, logger=None):
    """Print a human-readable risk summary with go/no-go recommendations."""
    _log = logger.info if logger else print
    _log("")
    _log("=" * 70)
    _log("  PREFLIGHT SUMMARY")
    _log("=" * 70)

    bpdu = report.get("bpdu", {})
    dai  = report.get("dai", {})
    mac  = report.get("mac_diversity", {})

    risks = []
    if bpdu.get("bpdu_seen"):
        risks.append("STP active → BPDU Guard risk (stp/mstp/swspoof may err-disable port)")
    else:
        risks.append("No STP → STP attack has no effect; skip stp/mstp/swspoof")

    if dai.get("dai_blocking"):
        risks.append("DAI LIKELY ACTIVE → arp/impers will be blocked at switch hardware")
    elif "dai_blocking" in dai:
        risks.append("No DAI detected → arp/impers should succeed")

    if mac.get("port_security_likely"):
        risks.append("Port Security likely → cam/mac will trigger err-disabled immediately")
    else:
        risks.append("MAC diversity normal → cam/mac should proceed unblocked")

    for r in risks:
        _log("  [!] %s", r)

    _log("=" * 70)
    _log("")
