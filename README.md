# HoleNet VPN server feed

Public, machine-readable server feed for the HoleNet application.

The feed is rebuilt every two hours from:

- OpenVPN: [VPN Gate API](https://www.vpngate.net/api/iphone/)
- Xray: [igareck/vpn-configs-for-russia](https://github.com/igareck/vpn-configs-for-russia)

Application endpoint:

`https://raw.githubusercontent.com/TimaFeyka/hole-vpn-servers/main/data/servers.json`

The updater validates both sources and refuses to publish an empty protocol list. Generated data keeps the attribution and licensing terms of its upstream sources. The Xray source is licensed under GPL-3.0.
