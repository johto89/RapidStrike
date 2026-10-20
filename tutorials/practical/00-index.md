# Tutorials index — 12 attack types (24 modules)

| # | File | Modules | Class |
|---|------|---------|-------|
| 00 | `00-preflight.md` | preflight | recon (mandatory first) |
| 01 | `01-arp-spoofing.md` | arp, icmp-redir, impers | redirection |
| 02 | `02-cam-overflow.md` | cam, mac | disruption → redirection |
| 03 | `03-stp-takeover.md` | stp, mstp | redirection + disruption |
| 04 | `04-vlan-hopping.md` | vlan, dvlan, pvlan, swspoof | segmentation bypass |
| 05 | `05-dhcp-attacks.md` | dhcp-starve, dhcp | redirection + disruption |
| 06 | `06-discovery-abuse.md` | cdp, lldp | recon / NMS poison |
| 07 | `07-fhrp-takeover.md` | hsrp, vrrp | redirection |
| 08 | `08-rip-eigrp.md` | rip, eigrp | redirection (routing) |
| 09 | `09-ospf-injection.md` | ospf | redirection + disruption |
| 10 | `10-bgp-hijack.md` | bgp | redirection, inter-AS |
| 11 | `11-ipv6-naming.md` | ra, llmnr | redirection → identity |
| 12 | `12-mpls-vrf-hop.md` | mpls | segmentation bypass |

Each file = Theory → Demo attack → Defense (Cisco + Juniper + detection).
Start with `00-preflight.md`. Full background stays in `TUTORIAL.md`.
