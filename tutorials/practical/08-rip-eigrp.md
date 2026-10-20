# 08 — RIP / EIGRP injection (`rip`, `eigrp`)

**Theory.** Distance-vector trusts metrics: lower hop-count (RIP) or better
composite metric (EIGRP) wins. Default adjacencies unauthenticated (A4). Correct
AS/K-values/subnet hello becomes a neighbor; false metrics pull flows. EIGRP risk
higher (common in Cisco estates, fast convergence spreads lies).

**Demo attack.**
```bash
sudo python3 rapidstrike.py rip -n 10.0.0.0 -s 192.168.1.50 -i eth0 -m 1 --dry-run
sudo python3 rapidstrike.py eigrp -i eth0 --asn 100 -n 10.0.0.0/24 -s 192.168.1.50 --dry-run
# always --dry-run first; then --probe to beat the live metric by 1
```

**Defense.**
Cisco:
```
router eigrp 100
 address-family ipv4 unicast autonomous-system 100
  af-interface Gi0/1
   authentication mode md5
   authentication key-chain EIGRP-KEY
```
+ passive-interface everywhere unneeded + RIPv2 MD5. Juniper equivalent auth.
Detection: off-inventory adjacency, auth-fail logs, surprise routes.
