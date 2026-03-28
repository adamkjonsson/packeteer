# RFC References

RFCs implemented or referenced by this library.

| RFC | Title | Where used |
|-----|-------|-----------|
| [RFC 791](https://datatracker.ietf.org/doc/html/rfc791) | Internet Protocol (IPv4) | `IPHeader`, `fragment_ipv4` |
| [RFC 793](https://datatracker.ietf.org/doc/html/rfc793) | Transmission Control Protocol | `TCPHeader` |
| [RFC 768](https://datatracker.ietf.org/doc/html/rfc768) | User Datagram Protocol | `UDPHeader` |
| [RFC 792](https://datatracker.ietf.org/doc/html/rfc792) | Internet Control Message Protocol | `ICMPHeader` |
| [RFC 894](https://datatracker.ietf.org/doc/html/rfc894) | Ethernet (IP over Ethernet) | `EthernetHeader` |
| [RFC 2003](https://datatracker.ietf.org/doc/html/rfc2003) | IP Encapsulation within IP (IP-in-IP, IPv4) | `.ip()` twice, `IPPROTO_IPIP` |
| [RFC 2460](https://datatracker.ietf.org/doc/html/rfc2460) | Internet Protocol Version 6 | `IPv6Header` |
| [RFC 2461](https://datatracker.ietf.org/doc/html/rfc2461) | Neighbor Discovery for IPv6 | Background reference |
| [RFC 2516](https://datatracker.ietf.org/doc/html/rfc2516) | PPP over Ethernet (PPPoE) | `PPPoEHeader`, `PPPoETag` |
| [RFC 2784](https://datatracker.ietf.org/doc/html/rfc2784) | Generic Routing Encapsulation (GRE) | `GREHeader`, `IPPROTO_GRE` |
| [RFC 2890](https://datatracker.ietf.org/doc/html/rfc2890) | Key and Sequence Number Extensions to GRE | `GREHeader.key`, `GREHeader.seq` |
| [RFC 3032](https://datatracker.ietf.org/doc/html/rfc3032) | MPLS Label Stack Encoding | `MPLSLabel` |
| [RFC 3378](https://datatracker.ietf.org/doc/html/rfc3378) | EtherIP: Tunneling Ethernet Frames in IP | `EtherIPHeader`, `IPPROTO_ETHERIP` |
| [RFC 4213](https://datatracker.ietf.org/doc/html/rfc4213) | Basic Transition Mechanisms for IPv6 (IPv6-in-IP) | `.ip()` twice, protocol `41` |
| [RFC 4291](https://datatracker.ietf.org/doc/html/rfc4291) | IPv6 Addressing Architecture | `IPv6Header` address format |
| [RFC 4443](https://datatracker.ietf.org/doc/html/rfc4443) | ICMPv6 | `ICMPv6Header` |
| [RFC 7323](https://datatracker.ietf.org/doc/html/rfc7323) | TCP Extensions for High Performance | `TCPOptions.window_scale`, `TCPOptions.timestamps` |
| [RFC 8200](https://datatracker.ietf.org/doc/html/rfc8200) | Internet Protocol Version 6 (IPv6, obsoletes 2460) | `IPv6Header`, `fragment_ipv6` |
| [RFC 1071](https://datatracker.ietf.org/doc/html/rfc1071) | Computing the Internet Checksum | Checksum computation for IPv4, TCP, UDP, ICMP, GRE |
| [IEEE 802.1Q](https://standards.ieee.org/ieee/802.1Q) | VLAN Tagging | `VLANTag` |
| [IEEE 802.1ad](https://standards.ieee.org/ieee/802.1ad) | Provider Bridges (QinQ) | `.vlan()` called twice |
