# RFC References

RFCs implemented or referenced by this library.

```{list-table}
:header-rows: 1
:widths: 14 44 42

* - RFC
  - Title
  - Where used
* - [RFC 768](https://datatracker.ietf.org/doc/html/rfc768)
  - User Datagram Protocol
  - `UDPHeader`
* - [RFC 2131](https://datatracker.ietf.org/doc/html/rfc2131)
  - Dynamic Host Configuration Protocol (DHCP)
  - `DHCPMessage`, `packeteer.generate.dhcp`, `packeteer.parse.dhcp`; fixed 236-byte header, magic cookie, port 67/68 dispatch
* - [RFC 2132](https://datatracker.ietf.org/doc/html/rfc2132)
  - DHCP Options and BOOTP Vendor Extensions
  - All typed `DHCPOpt*` dataclasses; TLV option encoding/decoding
* - [RFC 1035](https://datatracker.ietf.org/doc/html/rfc1035)
  - Domain Names — Implementation and Specification (DNS)
  - `DNSMessage`, `packeteer.generate.dns`, `packeteer.parse.dns`; name compression (§4.1.4); TCP length prefix (§4.2.2)
* - [RFC 6762](https://datatracker.ietf.org/doc/html/rfc6762)
  - Multicast DNS (mDNS)
  - `DNSQuestion.unicast_response` (QU bit, §5.4); `DNSResourceRecord.cache_flush` (§11.3); `MDNS_PORT`, `MDNS_ADDR_IPV4`, `MDNS_ADDR_IPV6`; port 5353 dispatch in `parse_packet`
* - [RFC 791](https://datatracker.ietf.org/doc/html/rfc791)
  - Internet Protocol (IPv4)
  - `IPHeader`, `fragment_ipv4`
* - [RFC 792](https://datatracker.ietf.org/doc/html/rfc792)
  - Internet Control Message Protocol
  - `ICMPHeader`
* - [RFC 793](https://datatracker.ietf.org/doc/html/rfc793)
  - Transmission Control Protocol
  - `TCPHeader`
* - [RFC 894](https://datatracker.ietf.org/doc/html/rfc894)
  - Ethernet (IP over Ethernet)
  - `EthernetHeader`
* - [RFC 1071](https://datatracker.ietf.org/doc/html/rfc1071)
  - Computing the Internet Checksum
  - Checksum computation for IPv4, TCP, UDP, ICMP, GRE
* - [RFC 2003](https://datatracker.ietf.org/doc/html/rfc2003)
  - IP Encapsulation within IP (IP-in-IP, IPv4)
  - `.ip()` twice, `IPPROTO_IPIP`
* - [RFC 2460](https://datatracker.ietf.org/doc/html/rfc2460)
  - Internet Protocol Version 6
  - `IPv6Header`
* - [RFC 2461](https://datatracker.ietf.org/doc/html/rfc2461)
  - Neighbor Discovery for IPv6
  - Background reference
* - [RFC 2516](https://datatracker.ietf.org/doc/html/rfc2516)
  - PPP over Ethernet (PPPoE)
  - `PPPoEHeader`, `PPPoETag`
* - [RFC 2784](https://datatracker.ietf.org/doc/html/rfc2784)
  - Generic Routing Encapsulation (GRE)
  - `GREHeader`, `IPPROTO_GRE`
* - [RFC 2890](https://datatracker.ietf.org/doc/html/rfc2890)
  - Key and Sequence Number Extensions to GRE
  - `GREHeader.key`, `GREHeader.seq`
* - [RFC 3032](https://datatracker.ietf.org/doc/html/rfc3032)
  - MPLS Label Stack Encoding
  - `MPLSLabel`
* - [RFC 3378](https://datatracker.ietf.org/doc/html/rfc3378)
  - EtherIP: Tunneling Ethernet Frames in IP
  - `EtherIPHeader`, `IPPROTO_ETHERIP`
* - [RFC 3849](https://datatracker.ietf.org/doc/html/rfc3849)
  - IPv6 Address Prefix Reserved for Documentation
  - Synthetic IPv6 addresses used by `packeteer.sanitise.sanitise` (2001:db8::/32)
* - [RFC 4213](https://datatracker.ietf.org/doc/html/rfc4213)
  - Basic Transition Mechanisms for IPv6 (IPv6-in-IP)
  - `.ip()` twice, protocol `41`
* - [RFC 4291](https://datatracker.ietf.org/doc/html/rfc4291)
  - IPv6 Addressing Architecture
  - `IPv6Header` address format
* - [RFC 4443](https://datatracker.ietf.org/doc/html/rfc4443)
  - ICMPv6
  - `ICMPv6Header`
* - [RFC 5737](https://datatracker.ietf.org/doc/html/rfc5737)
  - IPv4 Address Blocks Reserved for Documentation
  - Synthetic IPv4 addresses used by `packeteer.sanitise.sanitise` (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
* - [RFC 7323](https://datatracker.ietf.org/doc/html/rfc7323)
  - TCP Extensions for High Performance
  - `TCPOptions.window_scale`, `TCPOptions.timestamps`
* - [RFC 8200](https://datatracker.ietf.org/doc/html/rfc8200)
  - Internet Protocol Version 6 (IPv6, obsoletes 2460)
  - `IPv6Header`, `fragment_ipv6`
* - [RFC 9260](https://datatracker.ietf.org/doc/html/rfc9260)
  - Stream Control Transmission Protocol (SCTP)
  - `SCTPHeader` and all chunk dataclasses; `IPPROTO_SCTP`; CRC-32c checksum (§6.8)
* - [IEEE 802.1Q](https://standards.ieee.org/ieee/802.1Q)
  - VLAN Tagging
  - `VLANTag`
* - [IEEE 802.1ad](https://standards.ieee.org/ieee/802.1ad)
  - Provider Bridges (QinQ)
  - `.vlan()` called twice
```
