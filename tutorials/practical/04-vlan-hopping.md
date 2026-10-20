# 04 — VLAN hopping (`vlan`, `dvlan`, `pvlan`, `swspoof`)

**Theory.** Double-tag (QinQ abuse) exploits native-VLAN stripping: switch 1
removes the outer tag, switch 2 forwards by the inner tag into the target VLAN
(one-way, enough to cross). Violates A5 (edge trusts external labels). DTP abuse:
auto ports negotiate into trunks yielding all VLANs. PVLAN bypass abuses
proxy-ARP/community roles.

**Demo attack.**
```bash
sudo python3 rapidstrike.py vlan -i eth0 --vlans "10,20,30,99" --count 1
sudo python3 rapidstrike.py dvlan -i eth0 --outer-vlan 1 --inner-vlan 99 --target-ip 10.99.0.1
sudo python3 rapidstrike.py swspoof -i eth0 --duration 120
# success: ping to another-VLAN IP with no trunk
```

**Defense.**
Cisco:
```
interface Gi1/0/1
 switchport mode access
 switchport access vlan 10
 switchport nonegotiate
interface Gi1/0/24
 switchport trunk native vlan 999
 switchport trunk allowed vlan 10,20
```
Native 999 assigned to nobody kills double-tag. Juniper has no DTP — just
`set protocols lldp interface ge-0/0/1 disable`. Detection: access→trunk
transitions, double-tagged frames, DTP on access.
