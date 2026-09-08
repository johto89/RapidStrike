"""
Shared low-level helpers used across attack modules.

Keeping these in one place avoids the copy/paste divergence the standalone
scripts had (each one re-implemented root checks, MAC resolution, etc.).
"""

import os
import sys

try:
    from scapy.all import ARP, Ether, srp, get_if_hwaddr
except ImportError:
    sys.exit("[!] scapy is required: pip install scapy --break-system-packages")


def require_root():
    """Raw sockets need CAP_NET_RAW / root. Fail fast with a clear message."""
    if hasattr(os, "getuid") and os.getuid() != 0:
        sys.exit("[!] Root privileges are required (raw sockets).")


def iface_mac(iface: str) -> str:
    return get_if_hwaddr(iface)


def resolve_mac(ip: str, iface: str, timeout: int = 3):
    """
    Resolve the real MAC of an IP via an ARP request on the wire, deliberately
    bypassing the local ARP cache (which may already be poisoned).
    Returns None if no reply.
    """
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    answered, _ = srp(pkt, timeout=timeout, iface=iface, verbose=False)
    if answered:
        return answered[0][1].hwsrc
    return None


def set_ip_forward(enabled: bool):
    """Toggle IPv4 forwarding so intercepted traffic can still transit
    (turns a pure DoS into a transparent MITM)."""
    with open("/proc/sys/net/ipv4/ip_forward", "w") as fh:
        fh.write("1" if enabled else "0")


# IPv4 <-> int helpers (used by the DHCP pool allocator)
def ip_to_int(ip: str) -> int:
    a, b, c, d = (int(x) for x in ip.split("."))
    return (a << 24) | (b << 16) | (c << 8) | d


def int_to_ip(n: int) -> str:
    return ".".join(str((n >> shift) & 0xFF) for shift in (24, 16, 8, 0))
