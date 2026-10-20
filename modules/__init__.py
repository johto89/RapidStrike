"""
RapidStrike module registry.
To add a new module: create a file in modules/, implement NAME/DESCRIPTION/ATTCK_ID
with register() + run(), then import and add it to the MODULES list below.
"""
from core import preflight as _pf_core  # noqa: F401 — registered below via sys

from . import (
    arp,
    bgp,
    cam,
    cdp,
    dhcp,
    dhcp_starve,
    dvlan,
    eigrp,
    hsrp,
    icmp_redir,
    impers,
    ldp,
    lldp,
    llmnr,
    mac,
    mpls,
    mstp,
    ospf,
    pvlan,
    ra,
    rip,
    stp,
    swspoof,
    vlan,
    vrrp,
    vtp,
)

# Wrap core.preflight as a pseudo-module so it appears in the CLI list
import types as _types
_preflight_mod = _types.SimpleNamespace(
    NAME=_pf_core.NAME,
    DESCRIPTION=_pf_core.DESCRIPTION,
    ATTCK_ID=_pf_core.ATTCK_ID,
    register=_pf_core.register,
    run=_pf_core.run,
)

MODULES = [
    # ── Reconnaissance (run first) ────────────────────────────────────────────
    _preflight_mod,
    # ── L2 / Switching ────────────────────────────────────────────────────────
    arp,
    cam,
    cdp,
    dhcp,
    dhcp_starve,
    dvlan,
    impers,
    lldp,
    mac,
    mstp,
    pvlan,
    stp,
    swspoof,
    vlan,
    vtp,
    # ── Routing protocols ─────────────────────────────────────────────────────
    bgp,
    eigrp,
    hsrp,
    vrrp,
    ospf,
    rip,
    ra,
    icmp_redir,
    ldp,
    llmnr,
    mpls,
]
