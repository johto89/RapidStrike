# 09 — OSPF LSA injection (`ospf`)

**Theory.** Link-state: routers flood LSAs describing links; highest sequence
number overwrites (A4). A forged high-seq LSA bends everyone's SPF for the area.
Timing-sensitive (hello/dead must match); errors cause area-wide re-computation
(redirection + disruption).

**Demo attack.**
```bash
sudo python3 rapidstrike.py ospf -v 10.0.0.1 -n 10.0.0.2 -i eth0
# lab-only against matching IOS; MD5 networks need -k <key>
```

**Defense.**
Cisco:
```
router ospf 1
 passive-interface default
 no passive-interface Gi0/1
 area 0 authentication message-digest
interface Gi0/1
 ip ospf message-digest-key 1 md5 7 <key>
```
Juniper: `set protocols ospf area 0.0.0.0 interface ge-0/0/1 authentication md5 1 key "<secret>"`
+ passive on access. Detection: strange neighbors, auth fails, surprise LSAs.
