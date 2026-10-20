# RapidStrike

**Layer 2 / Routing assessment toolkit for internal pentest — Kali-native**

RapidStrike bundles 27 L2–L3 attack modules under a single CLI, with every run
written to an audit log tagged by engagement ID. Use it for customer demos and
network-admin training: each module maps to one concrete misconfiguration that
can be fixed immediately.

> Authorized (RoE/SoW) use only. See [TUTORIAL.md](TUTORIAL.md) for the lesson-by-lesson guide.

## Why RapidStrike?

| Manual approach | RapidStrike |
|-----------------|-------------|
| Scattered one-off Scapy scripts, everyone different | One syntax: `rapidstrike.py <module> -i eth0 ...` |
| No idea if the network is hardened | `preflight` probes BPDU Guard / DAI / Port Security first |
| Demo dies halfway | Every module has `--dry-run` / `--count` for lab validation |
| No evidence | `rapidstrike_audit.log` ships with the report |

## 27 Modules

| Group | Modules | One-line meaning |
|-------|---------|------------------|
| Recon | `preflight` | BPDU listen / MAC count / DAI probe — run first |
| L2 MITM | `arp`, `icmp-redir`, `impers` | Seize the gateway: ARP poison / ICMP redirect / CAM+ARP |
| L2 infra | `cam`, `stp`, `mstp`, `mac` | Flood switch into hub / claim root bridge / spoof MAC |
| VLAN | `vlan`, `dvlan`, `pvlan`, `swspoof`, `vtp` | Scan VLANs / double-tag hop / Private-VLAN bypass / fake trunk / VTP DB overwrite |
| DHCP | `dhcp-starve`, `dhcp` | Drain the real pool → serve rogue gateway |
| Discovery | `cdp`, `lldp` | Flood neighbor tables, poison NMS |
| FHRP | `hsrp`, `vrrp` | Claim virtual-gateway Active/Master |
| Routing | `rip`, `eigrp`, `ospf`, `bgp` | Inject false routes to pull traffic via attacker |
| IPv6 / Name | `ra`, `llmnr` | Rogue SLAAC RA / LLMNR-mDNS poison for NetNTLMv2 |
| MPLS | `mpls`, `ldp` | MPLS label-stack inject / LDP label-mapping LFIB poison |

## Requirements

| Need | Details |
|------|---------|
| OS | Linux Kali/Ubuntu, Python 3.9+, `pip install -r requirements.txt` (only `scapy`) |
| Privileges | root / `CAP_NET_RAW`, NIC in target VLAN, promiscuous mode on |
| Lab | GNS3/EVE-NG + IOS 15.x for pre-demo validation |

## Quick Start — 3 commands

```bash
sudo python3 rapidstrike.py --no-banner list
sudo python3 rapidstrike.py preflight -i eth0 --gateway 192.168.1.1

# Simplest MITM example
sudo python3 rapidstrike.py arp -i eth0 -t 192.168.1.100 -g 192.168.1.1
```

Each module needs only 3 mandatory parameters — see the cheat-sheet in
[TUTORIAL.md Sec 5](TUTORIAL.md#section-5-cheat-sheet--three-parameters-per-module).

## Defense

Cisco + Juniper sample configs per attack type live in
[TUTORIAL.md Sec 12](TUTORIAL.md#section-12-hardening--cisco--juniper-with-notes).
Other vendors (Aruba / Huawei / MikroTik) — see Sec 13 for lookup keywords.

## Security & legal

- Written RoE mandatory; bound runs with `--count` / `--duration`; restore ARP/topology after demos.
- `rapidstrike_audit.log` is your authorization evidence — attach it to the report.
