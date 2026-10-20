# 06 — Discovery abuse (`cdp`, `lldp`)

**Theory.** CDP (Cisco) / LLDP (802.1AB) self-announce model, IOS, port, native
VLAN, mgmt IP to everyone on the port — disclosure by design (A1). Free recon for
CVE lookup, VLAN-hop prep, mgmt targeting; flooding poisons NMS topology.

**Demo attack.**
```bash
sudo python3 rapidstrike.py cdp -i eth0 --count 1000
sudo python3 rapidstrike.py lldp -i eth0 --chassis-id "Cisco-Catalyst-9300-01" --count 100
# training point: capture shows switch model + native VLAN for free
```

**Defense.**
Cisco access:
```
interface range Gi1/0/1 - 23
 no cdp enable
 no lldp transmit
 no lldp receive
```
Juniper: `set protocols lldp interface ge-0/0/1 disable`. Keep LLDP-MED only for
IP phones. Detection: any discovery frames on endpoint access.
