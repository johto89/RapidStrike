# 12 — MPLS / VRF hop (`mpls`)

**Theory.** Customer separation via labels + RD/RT into VRFs, not physics (A5).
Safe iff the PE never trusts CE-set labels and imposes per-interface labels. If a
PE-CE interface accepts labeled frames, the CE picks the VRF → cross-customer hop.
Standard PE-CE is plain IP (no `mpls ip` toward CE), safe by default; risk from
misconfig or CSC/inter-AS B–C.

**Demo attack.**
```bash
sudo python3 rapidstrike.py mpls -i eth0 --mode scan --timeout 20
sudo python3 rapidstrike.py mpls -i eth0 --mode inject --label 100 --target-ip 10.0.0.1 --dry-run
# scan first: no 0x8847/LDP means stop — the PE filters correctly
```

**Defense.** Filter MPLS EtherTypes on customer interfaces, label-switch only core
links, LDP MD5 between PE/P:
Cisco `mpls ldp neighbor <ip> password <key>`; Juniper
`set protocols ldp session <ip> authentication-key "<secret>"`.
Detection: MPLS frames from CE direction, LDP sessions toward customers.
