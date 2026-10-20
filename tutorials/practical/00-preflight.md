# 00 — Preflight (mandatory first)

**Theory.** You cannot pick an attack blind. Preflight passively listens for
BPDUs (STP topology/root), counts MACs (Port Security signal), watches DHCP
(snooping trust), plus one semi-active spoofed-ARP probe for DAI. Violated
assumption probed: A1 (port-valid ⇒ content-valid).

**Demo.**
```bash
sudo python3 rapidstrike.py preflight -i eth0 --gateway 192.168.1.1
# DAI LIKELY ACTIVE → skip arp/impers; few MACs → skip cam/mac; BPDU seen → stp risky
```

**Defense.** Preflight is defensive recon — no hardening itself. If it flags
BPDU Guard/DAI/Port Security, your defenses in files 01–04 are working.
Ship `rapidstrike_audit.log` as evidence.
