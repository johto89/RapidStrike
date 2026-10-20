# 10 — BGP hijack (`bgp`)

**Theory.** BGP best-path's sharpest rule is longest-prefix match: a subprefix
always beats its cover (A4). Unauthorized sessions or mis-announced prefixes
divert ranges inter-AS. Needs peer acceptance, so the bar is higher but blast
radius is the largest.

**Demo attack.**
```bash
sudo python3 rapidstrike.py bgp --peer-ip 10.0.0.1 --peer-as 65001 --local-as 65099 --router-id 10.0.0.99 --prefix 192.168.10.0/24 --next-hop 10.0.0.99 --mode subprefix --dry-run
# then --duration 600 with IP forwarding; withdraws cleanly on exit
```

**Defense (layered, none replaces another).**
Cisco:
```
router bgp 65001
 neighbor 10.0.0.2 password 7 <key>
 neighbor 10.0.0.2 prefix-list PL-IN in
 neighbor 10.0.0.2 maximum-prefix 1000 restart 5
```
Juniper: auth-key + prefix-list. Ecosystem: RPKI/ROA. Detection: strange
prefixes/NEXT_HOP, max-prefix warnings, unauthorized peer IPs.
