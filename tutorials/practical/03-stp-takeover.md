# 03 — STP / MSTP root takeover (`stp`, `mstp`)

**Theory.** STP (802.1D/w/s) elects root by lowest Bridge ID (priority+MAC) and
trusts every BPDU on every port; priority is self-declared (A1+A3). Priority 0
wins root, pulling L2 paths toward the actor or churning topology (30s legacy outage).

**Demo attack.**
```bash
sudo python3 rapidstrike.py stp -i eth0 --bridge-priority 0 --count 15
sudo python3 rapidstrike.py mstp -i eth0 --bridge-priority 0 --instance-id 0 --count 30
# success: `show spanning-tree vlan 1` root flips to attacker MAC
```

**Defense.**
Cisco:
```
spanning-tree portfast default
spanning-tree portfast bpduguard default
interface Gi1/0/1
 switchport mode access
 spanning-tree bpduguard enable
 switchport nonegotiate
interface Gi1/0/24
 spanning-tree guard root
```
Juniper:
```
set protocols rstp interface ge-0/0/1 edge
set protocols rstp bpdu-block-on-edge
set protocols rstp interface ge-0/0/24 no-root-port
```
Restores "access never receives BPDUs". Detection: BPDU-Guard err-disable,
unplanned root change, topology-change counter surge.
