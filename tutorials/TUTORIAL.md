# RapidStrike TUTORIAL — L2–L3 Network Protocol Security

Training material for network/security admins: understand **why the protocol is
wrong** so you configure and monitor it right. Assumes TCP/IP, OSI, and basic
CLI on at least one vendor.

> Use rapidstrike.py as a controlled validation tool in lab/maintenance windows
> under RoE. Each section: theory → conceptual exploit conditions → detection
> invariant → minimal validation command → fix.
>
> Per-attack split: `tutorials/00-index.md` … `tutorials/12-mpls-vrf-hop.md` —
> one file per attack type with Theory → Demo → Defense (Cisco + Juniper).

---

## Table of Contents

- [Section 1: Executive summary](#section-1-executive-summary)
- [Section 2: Scope, audience, threat model](#section-2-scope-audience-threat-model)
- [Section 3: Foundational trust model — 5 implicit assumptions](#section-3-foundational-trust-model--5-implicit-assumptions)
- [Section 4: Setup and preflight-first workflow](#section-4-setup-and-preflight-first-workflow)
- [Section 5: Cheat-sheet — three parameters per module](#section-5-cheat-sheet--three-parameters-per-module)
- [Section 6: Layer 2 — ARP / CAM / STP / VLAN / CDP-LLDP](#section-6-layer-2--arp--cam--stp--vlan--cdp-lldp)
- [Section 7: L3 edge — DHCP and FHRP](#section-7-l3-edge--dhcp-and-fhrp)
- [Section 8: Routing — RIP / EIGRP / OSPF / BGP](#section-8-routing--rip--eigrp--ospf--bgp)
- [Section 9: IPv6 and name resolution — RA / LLMNR](#section-9-ipv6-and-name-resolution--ra--llmnr)
- [Section 10: MPLS-VPN and the PE-CE boundary](#section-10-mpls-vpn-and-the-pe-ce-boundary)
- [Section 11: Layered defense architecture — 4 principles](#section-11-layered-defense-architecture--4-principles)
- [Section 12: Hardening — Cisco + Juniper with notes](#section-12-hardening--cisco--juniper-with-notes)
- [Section 13: Other vendors — lookup guide](#section-13-other-vendors--lookup-guide)
- [Section 14: Detection, monitoring, hunting](#section-14-detection-monitoring-hunting)
- [Section 15: Rollout and verification](#section-15-rollout-and-verification)
- [Section 16: Sample lab attack chains](#section-16-sample-lab-attack-chains)
- [Section 17: Appendix A — technique ↔ assumption ↔ defense ↔ detection](#section-17-appendix-a--technique--assumption--defense--detection)
- [Section 18: Appendix B — references and reliability](#section-18-appendix-b--references-and-reliability)

---

## Section 1: Executive summary

Most enterprise foundation protocols (ARP, STP, DHCP, HSRP/VRRP, RIP/EIGRP/OSPF,
LLMNR, RA) were designed when the physical LAN boundary was the trust boundary.
Result: they authenticate message **format** but not message **origin**. Any entity
able to send packets on the right segment is implicitly trusted as a legitimate
control-plane member.

This is an **architectural trust-model flaw**, not one product's implementation bug.
No single feature closes it. Effective defense is a layered architecture on four
principles: authenticate control-message origin, least privilege on access ports,
separate control plane from data plane, and monitor state invariants. Hardening
(DAI, DHCP Snooping, BPDU Guard, Port Security, routing auth, RA Guard) is the
enforcement layer; detection/monitoring compensates where enforcement is missing
or bypassed. Strategically, fine-grained segmentation and L2 zero-trust (802.1X/NAC)
fix the root by removing the "same segment means trusted" assumption itself.

---

## Section 2: Scope, audience, threat model

**Audience:** network/security admins who need to know why the protocol fails in
order to configure it correctly.

**Threat model:** an internal on-path actor — a compromised host, a rogue device
on an access port, a VM in the same VLAN, or BYOD. Capabilities: arbitrary
Ethernet on its own segment, broadcast/multicast observation, participation in
whatever control protocols the port permits. No switch/router admin rights, no
valid auth keys, no crossing a correctly filtered L3 boundary.

Three consequence classes used as the cross-cutting taxonomy:

1. **Redirection** — steering flows through the actor to sniff/tamper: ARP, ICMP
   Redirect, FHRP, routing, RA.
2. **Segmentation bypass** — breaking VLAN/VRF boundaries: VLAN hopping,
   double-tagging, MPLS label injection.
3. **Disruption** — exhausting finite resources or seizing control roles: CAM
   overflow, DHCP starvation, STP churn.

**Boundary:** Sec 12 configs are all defensive, applied on devices you administer.
Exploit descriptions stop at conditions and mechanisms sufficient to design
countermeasures and detection signatures.

---

## Section 3: Foundational trust model — 5 implicit assumptions

Ethernet/IP was built for mutually trusting parties. The goal was connectivity
and fast recovery, not resisting an insider. When modern networks place mutually
distrusting parties on shared L2/L3, the assumption breaks but the protocols
did not change.

| # | Implicit assumption | Protocols relying on it | Violation (conceptual) |
|---|---------------------|-------------------------|------------------------|
| 1 | A frame from a valid physical port carries valid content | ARP, DHCP, STP, CDP/LLDP | Forged frames from any port; no field binds content to source identity |
| 2 | First responder wins | ARP, DHCP, LLMNR/NBT-NS, mDNS | Same-segment actor always wins the timing race |
| 3 | Priority/metric reflects admin intent | STP, HSRP/VRRP, RIP/EIGRP/OSPF | Priority is self-declared, unbound to authority |
| 4 | Control-plane members are configured infra devices | OSPF/EIGRP adjacency, LDP, FHRP | No mandatory shared secret → anyone speaking correctly becomes a peer |
| 5 | Separation labels (VLAN tag, MPLS label, VRF) are assigned by trusted infra | 802.1Q, QinQ, MPLS | If the edge trusts externally set labels, labels become attacker input |

Defense mapping: DAI restores (1) for ARP via trusted bindings; MD5/keychain
restores (4) for routing; RA Guard + BPDU Guard restore (1)+(3) by refusing control
roles on access; DHCP Snooping restores (2) via trusted/untrusted ports.

---

## Section 4: Setup and preflight-first workflow

```bash
cd RapidStrike
pip install -r requirements.txt --break-system-packages
sudo python3 rapidstrike.py --no-banner list
ip link set eth0 promisc on
```

Mandatory workflow per session:

```
1. Verify written RoE naming the segment.
2. Run preflight before any attack — detects BPDU Guard / DAI / Port Security.
3. Pick viable modules from preflight output.
4. Run with --engagement-id / --operator / --client; submit rapidstrike_audit.log.
5. Restore ARP/topology after the demo (arp self-restores on Ctrl-C).
```

```bash
sudo python3 rapidstrike.py preflight -i eth0 --gateway 192.168.1.1
# DAI LIKELY ACTIVE → arp/impers blocked in hardware; few MACs → Port Security, cam/mac will err-disable
```

---

## Section 5: Cheat-sheet — three parameters per module

| Module | Params to remember | Template |
|--------|-------------------|----------|
| `arp` | `-i -t -g` | `arp -i eth0 -t 192.168.1.100 -g 192.168.1.1` |
| `icmp-redir` | `-t -g --victim-net --attacker-ip` | `icmp-redir -i eth0 -t 192.168.1.100 -g 192.168.1.1 --victim-net 10.0.0.0/24 --attacker-ip 192.168.1.50` |
| `cam` | `-i` | `cam -i eth0 --count 100000 --rate 8000` |
| `stp` | `-i` | `stp -i eth0 --bridge-priority 0 --count 15` |
| `mstp` | `-i` | `mstp -i eth0 --bridge-priority 0 --instance-id 0 --count 30` |
| `mac` | `-i` | `mac -i eth0 --vendor cisco --target-ip 192.168.1.1` |
| `vlan` | `-i` | `vlan -i eth0 --vlans "10,20,30,99" --count 1` |
| `dvlan` | `--outer --inner --target-ip` | `dvlan -i eth0 --outer-vlan 1 --inner-vlan 99 --target-ip 10.99.0.1` |
| `pvlan` | `--target-ip` | `pvlan -i eth0 --target-ip 10.0.0.100 --mode isolated` |
| `swspoof` | `-i` | `swspoof -i eth0 --duration 120` |
| `dhcp-starve` | `-i` | `dhcp-starve -i eth0 --workers 16` |
| `dhcp` | `--pool --gateway --dns --server-ip` | `dhcp -i eth0 --pool 192.168.1.150-192.168.1.200 --gateway 192.168.1.50 --dns 192.168.1.50 --server-ip 192.168.1.50` |
| `cdp/lldp` | `-i` | `lldp -i eth0 --count 100` |
| `hsrp` | `--virtual-ip` | `hsrp -i eth0 --group 1 --virtual-ip 192.168.1.1` |
| `vrrp` | `--virtual-ip` | `vrrp -i eth0 --vrid 1 --virtual-ip 192.168.1.1` |
| `rip` | `-n -s -m` | `rip -n 10.0.0.0 -s 192.168.1.50 -i eth0 -m 1 --dry-run` |
| `eigrp` | `--asn -n -s` | `eigrp -i eth0 --asn 100 -n 10.0.0.0/24 -s 192.168.1.50 --dry-run` |
| `ospf` | `-v -n -i` | `ospf -v 10.0.0.1 -n 10.0.0.2 -i eth0` |
| `bgp` | `--peer-ip --peer-as --local-as --router-id --prefix --next-hop` | `bgp --peer-ip 10.0.0.1 --peer-as 65001 --local-as 65099 --router-id 10.0.0.99 --prefix 192.168.10.0/24 --next-hop 10.0.0.99 --mode subprefix --dry-run` |
| `ra` | `-i` | `ra -i eth0 --prefix fd00:6666::/64` |
| `llmnr` | `-i --spoof-ip` | `llmnr -i eth0 --spoof-ip 192.168.1.50 --duration 300` |
| `mpls` | `-i --mode` | `mpls -i eth0 --mode scan --timeout 20` |

`--count/--interval/--duration/--dry-run` are safety bounds — always set them for demos.

---

## Section 6: Layer 2 — ARP / CAM / STP / VLAN / CDP-LLDP

Four steps per protocol: original design → violated assumption → conditions → invariant.

**6.1 ARP (RFC 826).** Hosts learn from Replies, Requests, and gratuitous ARPs even
unsolicited. No field binds MAC to IP; new cache entries overwrite old ones
(violates 1+2). Condition: same broadcast domain, asserting a false IP→MAC mapping
(usually gateway→self). Invariant: (IP,MAC) pairs must be stable and consistent at
every observation point; gateway MAC flips, one MAC claiming many IPs, or gratuitous
storms are anomalous → DAI enforces via bindings.

**6.2 CAM.** Switches learn MAC/port with a finite table (thousands–tens of
thousands). Assumes few stable MACs per port — no default per-port cap. Full table →
fail-open flooding like a hub (serving redirection). Invariant: 1–2 MACs per access
port; learning spikes or table-full are direct signals → Port Security per-port caps.

**6.3 STP (802.1D/w).** Root is the lowest Bridge ID (priority+MAC). Trusts every
BPDU on every port and treats priority as admin intent (violates 1+3). Priority 0
wins root, pulling L2 paths toward the actor or churning topology. Condition: port
accepts BPDUs with no bridge-role refusal. Invariant: access ports must never
receive BPDUs → BPDU Guard err-disables instantly; unplanned root changes warn;
Root Guard pins the root direction.

**6.4 VLAN/DTP (802.1Q).** Double-tag: switch 1 strips the outer (matching native),
switch 2 reads the inner into the target VLAN — one-way but enough to cross.
Root cause: trusting externally set tags (violates 5). DTP abuse: auto ports
negotiate into trunks yielding all VLANs. Conditions: native matches attacker's
VLAN; port not hard-set to access/nonegotiate. Invariant: access ports never trunk
and never handle tagged frames → static access + nonegotiate, native = an unused
VLAN (e.g. 999).

**6.5 CDP/LLDP.** Self-announce model, IOS, port, native VLAN, mgmt IP to everyone
on the port — disclosure by design. Free recon for CVE lookup, VLAN-hop prep, mgmt
targeting. Invariant: endpoint-facing access has no legitimate discovery traffic
(except LLDP-MED phones) → disable CDP/LLDP transmit on access.

Lab validation: `cam --count 100000` + peer Wireshark sees all traffic;
`stp --bridge-priority 0` + `show spanning-tree vlan 1` root flips;
`vlan --vlans "10,20,30"`.

---

## Section 7: L3 edge — DHCP and FHRP

The two bootstrap parameters of every host: where its IP comes from, and who its
gateway is. Owning either owns the subnet's egress choke point.

**7.1 DHCP (RFC 2131 DORA).** Clients accept the first syntactically valid OFFER
with no server authentication. OFFER carries gateway (opt 3) + DNS (opt 6) → the
server controls next-hop and name resolution (violates 2). Two mechanisms: rogue
server (OFFER pointing gateway/DNS at the actor) + starvation (draining the legit
pool with many MACs so the rogue wins the race). Condition: same broadcast domain,
OFFERs not blocked from the actor's port. Invariant: OFFER/ACK valid only from
known-server ports → DHCP Snooping trusted/untrusted, building the IP–MAC–port–VLAN
binding that DAI + IP Source Guard consume.

**7.2 FHRP (HSRP/VRRP RFC 5798).** Routers share a virtual IP, electing
Active/Master by self-declared priority; default is unauthenticated or meaningless
plaintext (violates 3+4). Max priority seizes the virtual IP = the subnet gateway.
Invariant: stable known FHRP membership; new members or Active/Master moving to a
strange MAC violate it → MD5/keychain + role-change monitoring.

Validation: `dhcp-starve --workers 16` + `dhcp --pool ... --gateway <attacker>`;
`hsrp --group 1 --virtual-ip 192.168.1.1` + `show standby brief` demotion.

---

## Section 8: Routing — RIP / EIGRP / OSPF / BGP

| Protocol | Abused best-path rule | Default trust | Risk |
|----------|----------------------|---------------|------|
| RIP | Lower hop metric wins | Unauthenticated updates | Low — legacy |
| EIGRP | Better composite metric wins | Unauthenticated adjacency | Medium — common in Cisco shops |
| OSPF | Newer LSA (higher seq) overwrites | Unauthenticated adjacency | High — timing-sensitive, area/AS blast radius |
| BGP | Longest-prefix match wins | TCP session, possibly no MD5 | Highest — inter-AS blast radius |

**RIP:** false low-metric route pulls flows. Fix: RIPv2 MD5.
**EIGRP:** correct AS/K-values/subnet hello becomes a neighbor, injecting favorable
metrics. Fast convergence spreads lies fast. Fix: md5 + key-chain on af-interface.
**OSPF link-state:** high-seq LSAs rewrite topology, bending everyone's SPF; errors
cause wide re-computation (redirection + disruption). Fix: message-digest auth +
passive-interface everywhere adjacency is unneeded (especially access).
**BGP:** a more-specific (subprefix) always beats the covering prefix; unauthorized
sessions or mis-announced prefixes divert ranges (route hijacks). Multi-layer fix:
TCP MD5/AO + both-direction prefix-lists + maximum-prefix + RPKI/ROA. No layer
replaces another.

Hard rule: user-facing interfaces are passive (no routing hellos); every remaining
adjacency is authenticated. Validate in lab first: `rip --probe --dry-run`,
`eigrp --dry-run`, `ospf -v -n -i`, `bgp --mode subprefix --dry-run`.

---

## Section 9: IPv6 and name resolution — RA / LLMNR

Networks that "don't use" them are still exposed because OS defaults enable them.

**9.1 RA/SLAAC (RFC 4861/4862).** IPv6 routers advertise prefix + gateway; hosts
self-address and set default routes from heard RAs, unauthenticated (violates 1+2)
on an IPv6 control plane IPv4-only admins rarely watch. IPv6 preference means one
rogue RA seizes egress even on IPv4 networks. Invariant: RAs only from known
routers/uplinks; access-port RAs violate it → RA Guard drops; watch for surprise
IPv6 defaults.

**9.2 LLMNR (RFC 4795)/NBT-NS/mDNS.** DNS miss → segment-wide broadcast asking
"who is HOSTNAME?", first answer trusted (violates 2). False answers start auth
handshakes with the actor, leaking NetNTLMv2 for offline cracking or relay without
SMB/LDAP signing. The classic L2-foothold-to-identity chain. Invariant + fix: with
proper internal DNS, disable LLMNR/NBT-NS via GPO (removes the vector), scope mDNS
by VLAN; enable SMB/LDAP signing + channel binding to kill the relay branch. A host
answering many different names signals poisoning.

Validation: `ra --prefix fd00:6666::/64` + `ip -6 route` pointing at fe80::1;
`llmnr --spoof-ip <attacker>` for NetNTLMv2 in an isolated lab.

---

## Section 10: MPLS-VPN and the PE-CE boundary

Customer separation via labels + VPN identifiers, not physics — all trust sits in
the edge. LDP distributes core labels; MP-BGP VPNv4 attaches RD/RT steering routes
into per-customer VRFs; core packets carry stacked labels (outer to the egress PE,
inner to the VRF).

Violated assumption (5): safe iff the PE never trusts CE/endpoint-set labels and
always imposes the right label per customer interface. If the PE accepts MPLS
frames from the CE side and forwards by them, the CE picks the VRF → cross-customer
hop. Joint conditions: (a) PE-CE interface accepts labeled frames (instead of plain
IP it labels itself); (b) the target VRF label is known/guessable. Standard PE-CE
is plain IP (no `mpls ip` toward CE), hence safe by default; risk comes from
misconfig or CSC/inter-AS options B–C. Invariants: no 0x8847/0x8848 from CE
direction (drop at edge); LDP only among trusted core + MD5; label switching only
on core links. Lower likelihood than L2/FHRP in most enterprises, severe on
occurrence. Validation: `mpls --mode scan` first — no labels/LDP means stop;
`inject --dry-run`.

---

## Section 11: Layered defense architecture — 4 principles

Every control instantiates one principle (restoring one lost assumption). Strongest
controls sit at access (where the actor stands) to refuse control roles up front;
distribution/core add auth for legitimate control relationships; monitoring runs
across everything as the safety net.

- Authenticate control-message origin (adjacency/session/FHRP/LDP auth).
- Least privilege on access (hard access, nonegotiate, disable surplus discovery).
- Separate control/data (passive-interfaces, trusted/untrusted, MPLS EtherType filters).
- Monitor invariants (observed vs approved control state).

Foundation beneath all: fine segmentation + NAC/802.1X fixes the root by removing
location-based trust.

---

## Section 12: Hardening — Cisco + Juniper with notes

All configs apply to devices you administer. Each block notes which invariant it
restores + operational trade-offs.

### 12.1 Port Security + Storm — vs CAM/MAC flooding (A1)

Cisco IOS:
```
interface GigabitEthernet1/0/1
 switchport mode access
 switchport port-security
 switchport port-security maximum 2
 switchport port-security violation restrict
 switchport port-security aging time 5
 storm-control broadcast level 5.00
 storm-control action trap
```
Juniper JunOS:
```
set switch-options interface ge-0/0/1 interface-mac-limit 2 packet-action drop
set ethernet-switching-options storm-control interface ge-0/0/1 bandwidth-level 5000
```
Restores "few MACs per access". Max 2 stops floods at source; restrict logs instead
of err-disable to avoid self-DoS; storm caps broadcasts. Trade-off: phone+PC needs
2–3; aging must match roaming.

### 12.2 DHCP Snooping + DAI — vs rogue DHCP + ARP spoof (A1,2)

Cisco:
```
ip dhcp snooping
ip dhcp snooping vlan 10,20
no ip dhcp snooping information option
!
ip arp inspection vlan 10,20
interface GigabitEthernet1/0/24
 description UPLINK-TO-DHCP-SERVER
 ip dhcp snooping trust
 ip arp inspection trust
interface range GigabitEthernet1/0/1 - 23
 ip arp inspection limit rate 15
```
Juniper:
```
set vlans V10 forwarding-options dhcp-security
set vlans V10 forwarding-options dhcp-security arp-inspection
set vlans V10 forwarding-options dhcp-security interface ge-0/0/24 static-ip trusted
```
Snooping restores "OFFERs only from trusted" + builds bindings; DAI uses them to
restore ARP. Mandatory order: Snooping before DAI; static-IP hosts need static ARP
ACLs; over-tight rate limits drop legitimate ARPs.

### 12.3 IP Source Guard — blocks source-IP spoofing

Cisco:
```
interface range GigabitEthernet1/0/1 - 23
 ip verify source
```
Forces source IP to match the Snooping binding (DAI covers ARP, IPSG covers IP
source). Requires Snooping.

### 12.4 BPDU Guard + Root Guard — vs STP (A1,3)

Cisco:
```
spanning-tree portfast default
spanning-tree portfast bpduguard default
!
interface GigabitEthernet1/0/1
 switchport mode access
 spanning-tree portfast
 spanning-tree bpduguard enable
 switchport nonegotiate
!
interface GigabitEthernet1/0/24
 spanning-tree guard root
```
Juniper:
```
set protocols rstp interface ge-0/0/1 edge
set protocols rstp bpdu-block-on-edge
set protocols rstp interface ge-0/0/24 no-root-port
```
Restores "access never receives BPDUs". Plugging a legit switch into access will
err-disable — needs a controlled recovery process.

### 12.5 VLAN/DTP (A5)

Cisco:
```
interface GigabitEthernet1/0/1
 switchport mode access
 switchport access vlan 10
 switchport nonegotiate
 no cdp enable
!
interface GigabitEthernet1/0/24
 switchport trunk native vlan 999
 switchport trunk allowed vlan 10,20
```
Native 999 assigned to no endpoint kills double-tagging. Juniper has no DTP, just
disable LLDP on access:
`set protocols lldp interface ge-0/0/1 disable`

### 12.6 FHRP auth (A3,4)

Cisco HSRP MD5:
```
interface Vlan10
 standby 1 ip 192.168.10.1
 standby 1 priority 110
 standby 1 preempt
 standby 1 authentication md5 key-string 7 <encrypted-key>
```
Plaintext auth is worthless — only MD5/keychain counts. Modern JunOS prefers
firewall filters limiting VRRP sources over legacy auth fields.

### 12.7 Routing auth + passive (A4)

Cisco OSPF+EIGRP+BGP:
```
router ospf 1
 passive-interface default
 no passive-interface GigabitEthernet0/1
 area 0 authentication message-digest
interface GigabitEthernet0/1
 ip ospf message-digest-key 1 md5 7 <encrypted-key>
!
router eigrp 100
 address-family ipv4 unicast autonomous-system 100
 af-interface default
 passive-interface
 af-interface GigabitEthernet0/1
 no passive-interface
 authentication mode md5
 authentication key-chain EIGRP-KEY
!
router bgp 65001
 neighbor 10.0.0.2 password 7 <encrypted-key>
 neighbor 10.0.0.2 prefix-list PL-IN in
 neighbor 10.0.0.2 maximum-prefix 1000 restart 5
```
Juniper:
```
set protocols ospf area 0.0.0.0 interface ge-0/0/1 authentication md5 1 key "<secret>"
set protocols ospf area 0.0.0.0 interface ge-0/0/0.0 passive
set protocols bgp group PE-CE neighbor 10.0.0.2 authentication-key "<secret>"
set policy-options prefix-list PL-IN 192.168.0.0/16
```
Forgetting to un-passive an uplink kills legit adjacency — check neighbors after
every change.

### 12.8 RA Guard + DHCPv6 (A1,2)

Cisco:
```
ipv6 nd raguard policy HOST-POLICY
 device-role host
interface range GigabitEthernet1/0/1 - 23
 ipv6 nd raguard attach-policy HOST-POLICY
```
Juniper: `set vlans V10 forwarding-options dhcp-security neighbor-discovery-inspection`
Apply even on "IPv4-only" networks — hosts still run IPv6.

### 12.9 Disable surplus discovery + naming

Cisco:
```
interface range GigabitEthernet1/0/1 - 23
 no cdp enable
 no lldp transmit
 no lldp receive
```
GPO for LLMNR/NBT-NS: `DNS Client > Turn off multicast name resolution = Enabled`.
Keep LLDP-MED only where IP phones need it.

---

## Section 13: Other vendors — lookup guide

| Vendor | Keywords |
|--------|----------|
| Aruba CX/AOS-CX | `port-access`, `arp inspection`, `dhcpv4-snooping`, `spanning-tree bpdu-guard`, `ipv6 ra-guard`, `router ospf authentication` |
| Huawei VRP | `port-security`, `dhcp snooping`, `arp anti-attack check user-bind`, `stp bpdu-protection`, `vrrp authentication-mode md5` |
| MikroTik RouterOS | `bridge port bpdu-guard`, DHCP snooping + add-arp, OSPF authentication, BGP tcp-md5-key |
| HPE Procurve | `port-security`, `dhcp-snooping`, `arp-protect`, `spanning-tree bpdu-protection` |

Same principles everywhere: cap MACs, trust DHCP, bind ARP/IP, refuse bridge/router
roles on access, authenticate every adjacency, block surplus RA/discovery at the edge.

---

## Section 14: Detection, monitoring, hunting

Config covers only what is enabled; detection shortens dwell time. One invariant
per technique is the signature.

| Technique | Source | Signature |
|-----------|--------|-----------|
| ARP spoof | DAI syslog, host ARP, Zeek | DAI drops on untrusted; gateway MAC flip; one MAC many IPs |
| CAM flood | counters, SNMP, syslog | MAC/port at max; violations; learning spike |
| STP | syslog, traps | BPDU Guard err-disable; unplanned root change; topology-change surge |
| Rogue DHCP | Snooping syslog | OFFER/ACK drops on untrusted; strange server MAC |
| Starvation | DHCP logs | Sudden pool drain; many MACs per port |
| VLAN/DTP | logs, trunk state | access→trunking; double-tagged frames; DTP on access |
| FHRP | syslog, SNMP | state to strange IP/MAC; odd coup/resign |
| Routing | neighbor syslog | off-inventory adjacency; auth failures; surprise LSA/route; max-prefix warns |
| Rogue RA | RA Guard, NDP monitor | access RA drops; new v6 defaults; strange RA source |
| LLMNR | logs, PCAP, Zeek | queries after GPO off; one host answering many names |

Three signal tiers: (1) on-device — syslog/traps, cheapest and most accurate;
(2) on-wire — SPAN to Zeek baselines (IP–MAC, DHCP servers, RA routers) + Suricata
packet patterns; (3) on-endpoint — ARP caches, v4/v6 routes, fallback name queries
via EDR.

Hunt hypotheses: ARP (IPs with >1 MAC/24h), gateway (gateway IP/MAC set vs
inventory), adjacency (live vs approved neighbors), naming (responders after GPO
off). Most valuable asset: an inventory of "legitimate control roles"
(which gateways/DHCP/routers/root).

---

## Section 15: Rollout and verification

Wrong order self-DoSes: DAI without bindings drops legit ARP; forgotten un-passive
kills adjacency; tight max drops phones.

Dependency-respecting order:

```
1. Normalize access: mode access + nonegotiate + static VLAN (low-risk base).
2. Discovery/RA hygiene: surplus CDP/LLDP off, RA Guard, GPO off LLMNR/NBT-NS.
3. DHCP Snooping + correct trusted ports (DHCP uplinks), wait for stable bindings.
4. DAI + IPSG after bindings stable; prep static ARP ACLs for static IPs.
5. Port Security + Storm (realistic max, restrict first).
6. BPDU + Root Guard with recovery runbook.
7. Routing auth + passive-interface on core; check each adjacency.
8. FHRP auth on virtual-gateway SVIs.
9. (MPLS) edge EtherType filters + LDP auth.
```

Rollbacks: pilot one switch/VLAN; restrict/log before hard enforce; keep
console/out-of-band so you cannot lock yourself out.

| Control | Confirm on | Confirm no false-positive |
|---------|-----------|---------------------------|
| Snooping | `show ip dhcp snooping binding`; untrusted OFFER drops | legit clients get IPs |
| DAI | `show ip arp inspection statistics` counts bad-ARP drops | static IPs (ACL) pass |
| IPSG | off-binding source IPs drop | DHCP hosts fine |
| PortSec | `show port-security` violations correct | phone+PC on one port works |
| BPDU Guard | access BPDU → err-disable+log | uplinks unaffected |
| OSPF/EIGRP | neighbors only legit; auth-fails logged | legit adjacencies up |
| passive | access sends no hellos | uplinks still neighbor |
| FHRP auth | keyless members can't elect | legit Active/Standby stable |
| RA Guard | access RAs drop+log | uplink RAs pass |

Bundle before/after logs + show outputs as compliance evidence and detection baselines.

---

## Section 16: Sample lab attack chains

```bash
# Basic MITM
sudo python3 rapidstrike.py preflight -i eth0 --gateway 192.168.1.1
sudo python3 rapidstrike.py arp -i eth0 -t 192.168.1.100 -g 192.168.1.1 &
tcpdump -i eth0 host 192.168.1.100 -w /tmp/victim.pcap
# DHCP
sudo python3 rapidstrike.py dhcp-starve -i eth0 --workers 16 &
sudo python3 rapidstrike.py dhcp -i eth0 --pool 192.168.1.150-192.168.1.200 --gateway 192.168.1.50 --dns 192.168.1.50 --server-ip 192.168.1.50
# Virtual gateway
sudo python3 rapidstrike.py hsrp -i eth0 --group 1 --virtual-ip 192.168.1.1
# Routing lab
sudo python3 rapidstrike.py rip -n 10.0.0.0 -s 192.168.1.50 -i eth0 --probe --dry-run
```

---

## Section 17: Appendix A — technique ↔ assumption ↔ defense ↔ detection

A = violated assumption number(s) from Sec 3.

| Technique | A | Primary enforcement | Primary detection |
|-----------|---|---------------------|-------------------|
| ARP spoof | 1,2 | DAI + binding | IP changes MAC; multi-IP MAC |
| CAM flood | 1 | Port Security max | per-port MAC cap hit |
| STP hijack | 1,3 | BPDU + Root Guard | access BPDU; root change |
| Double-tag | 5 | separate native + allowed | double-tagged frames |
| DTP spoof | 1 | access + nonegotiate | access trunking |
| CDP/LLDP | 1 | off on access | discovery on access |
| Rogue DHCP | 2 | Snooping trust | untrusted OFFER |
| Starvation | 1,2 | PortSec + rate limit | pool drain; MACs/port |
| HSRP/VRRP | 3,4 | FHRP MD5 | state to strange IP |
| RIP/EIGRP | 4 | auth + passive | off-inventory adjacency |
| OSPF LSA | 4 | auth + passive | strange neighbor/LSA |
| BGP hijack | 4 | MD5 + prefix-list + max-prefix + RPKI | strange prefix; max-prefix warn |
| Rogue RA | 1,2 | RA Guard host | access RA; new v6 route |
| LLMNR | 2 | GPO off + signing | post-GPO queries; responder |
| MPLS inject | 5 | EtherType filter + LDP auth | MPLS from CE |

---

## Section 18: Appendix B — references and reliability

| Mechanism | Standard |
|-----------|----------|
| ARP | RFC 826 |
| DHCP | RFC 2131, 2132 |
| DHCPv6 | RFC 8415 |
| STP/RSTP/MSTP | IEEE 802.1D/w/s |
| VLAN | IEEE 802.1Q |
| LLDP | IEEE 802.1AB |
| VRRP | RFC 5798 |
| OSPF/auth | RFC 2328, RFC 5709 |
| BGP | RFC 4271; TCP-AO 5925; RPKI 6480, 6811 |
| NDP/SLAAC | RFC 4861, 4862; SEND 3971; RA Guard 6105 |
| LLMNR | RFC 4795 |
| MPLS | RFC 3031; L3VPN 4364; LDP 5036 |
| NAC | IEEE 802.1X |

CLI (especially JunOS) varies by release — cross-check the device's version docs
before production. First verification points: modern-JunOS VRRP auth → firewall
filters; Juniper DHCP-security syntax differs between old EX and ELS.
