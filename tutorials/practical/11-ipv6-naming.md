# 11 — Rogue RA / LLMNR-mDNS poisoning (`ra`, `llmnr`)

**Theory.** Hosts prefer IPv6: one rogue RA (RFC 4861) seizes egress even on
"IPv4-only" nets (A1+A2). LLMNR/NBT-NS/mDNS: DNS miss → segment broadcast, first
answer trusted (A2) → false answers start auth handshakes leaking NetNTLMv2 for
crack-offline or relay without SMB/LDAP signing. The classic L2→identity chain.

**Demo attack.**
```bash
sudo python3 rapidstrike.py ra -i eth0 --prefix fd00:6666::/64
sudo python3 rapidstrike.py llmnr -i eth0 --spoof-ip 192.168.1.50 --duration 300
# success: `ip -6 route` via fe80::1; NetNTLMv2 hashes in isolated lab
```

**Defense.**
Cisco RA Guard:
```
ipv6 nd raguard policy HOST-POLICY
 device-role host
interface range Gi1/0/1 - 23
 ipv6 nd raguard attach-policy HOST-POLICY
```
Juniper: `... neighbor-discovery-inspection`. Apply even on IPv4-only nets.
GPO: `DNS Client > Turn off multicast name resolution = Enabled` + SMB/LDAP
signing + channel binding. Detection: access RA drops, surprise v6 defaults,
post-GPO queries, one host answering many names.
