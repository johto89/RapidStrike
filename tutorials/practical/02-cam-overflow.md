# 02 — CAM overflow / MAC spoofing (`cam`, `mac`)

**Theory.** The switch CAM table is finite (thousands). It assumes few stable
MACs per port with no default cap (A1). Flooding random source MACs fills it;
the switch fail-opens, flooding unicast to all ports in the VLAN — a hub for
passive capture. `mac` spoofs vendor OUIs to beat MAC ACLs / pollute SIEM.

**Demo attack.**
```bash
sudo python3 rapidstrike.py cam -i eth0 --count 100000 --rate 8000
sudo python3 rapidstrike.py mac -i eth0 --vendor cisco --target-ip 192.168.1.1
# success: peer Wireshark sees foreign-VLAN traffic during the flood window
```

**Defense.**
Cisco:
```
interface Gi1/0/1
 switchport mode access
 switchport port-security maximum 2
 switchport port-security violation restrict
 storm-control broadcast level 5.00
```
Juniper:
```
set switch-options interface ge-0/0/1 interface-mac-limit 2 packet-action drop
```
Restores "few MACs per access". Use restrict (not shutdown) at first; phone+PC
needs 2–3. Detection: per-port MAC at max, Port-Security violations, learning-rate spike.
