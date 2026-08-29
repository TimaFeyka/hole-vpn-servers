# HoleNet VPN server feed

Public, machine-readable server feed for the HoleNet application.

The feed is rebuilt on the owner computer from:

- OpenVPN: [VPN Gate API](https://www.vpngate.net/api/iphone/)
- Xray: [igareck/vpn-configs-for-russia](https://github.com/igareck/vpn-configs-for-russia)

Application endpoint:

`https://raw.githubusercontent.com/TimaFeyka/hole-vpn-servers/main/data/servers.json`

GitHub is only the distribution endpoint for the ready `servers.json`, `ovpn.json`, and `xray.json` files. Collection, health history, logs, and unverified candidates stay on the owner computer and are not published.

The local updater validates both sources, resolves every endpoint, retries TCP connections, and publishes only endpoints reachable during the current run. UDP-only endpoints remain local because a generic UDP probe cannot prove tunnel availability.

Countries and flags are refreshed from the resolved endpoint IP using the public-domain `server-country` datasets from [sapics/ip-location-db](https://github.com/sapics/ip-location-db). Declared upstream country codes remain available as `declaredCountryCode` when GeoIP changes them.

`health-state.json` records the last successful check and consecutive failures. Minimum healthy-server gates prevent a broken network run from replacing the published feed with an unexpectedly small list.

The current local Mac check proves DNS and TCP endpoint reachability, not successful VPN egress or reachability from Russia. A later full-tunnel stage must run each configuration through its native client from the target network.

Generated data keeps the attribution and licensing terms of its upstream sources. The Xray source is licensed under GPL-3.0.
