# 01 — ARP spoofing / ICMP Redirect / Impersonation (`arp`, `icmp-redir`, `impers`)

**Theory.** ARP (RFC 826) has no source authentication; caches learn from any
Reply/Request/gratuitous and newest overwrites oldest. Violates A1+A2
(first-responder wins). ICMP Redirect steers a host's next-hop the same way.
`impers` combines CAM + ARP poisoning (black_hole DoS / white_hole intercept).

**Demo attack (lab only).**
```bash
sudo python3 rapidstrike.py arp -i eth0 -t 192.168.1.100 -g 192.168.1.1 --interval 5 --jitter 3
sudo python3 rapidstrike.py icmp-redir -i eth0 -t 192.168.1.100 -g 192.168.1.1 --victim-net 10.0.0.0/24 --attacker-ip 192.168.1.50
# success: victim `arp -a` maps gateway to attacker MAC; tcpdump sees victim flows
```

**Defense.**
Cisco:
```
ip dhcp snooping
ip dhcp snooping vlan 10,20
ip arp inspection vlan 10,20
interface Gi1/0/24
 ip dhcp snooping trust
 ip arp inspection trust
```
Juniper:
```
set vlans V10 forwarding-options dhcp-security
set vlans V10 forwarding-options dhcp-security arp-inspection
```
Order matters: Snooping first (builds binding), DAI second. Static-IP hosts need
static ARP ACLs. Detection: DAI drops on untrusted, gateway MAC flip, one MAC
claiming many IPs (DAI syslog / Zeek).
