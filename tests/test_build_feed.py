import base64
import importlib.util
import unittest
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "build_feed.py"
SPEC = importlib.util.spec_from_file_location("build_feed", SCRIPT)
build_feed = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(build_feed)


class BuildFeedTests(unittest.TestCase):
    def test_parses_vpngate_csv(self):
        config = "client\nremote 192.0.2.1 443\n"
        encoded = base64.b64encode(config.encode()).decode()
        raw = (
            "*vpn_servers\n"
            "#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,"
            "Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64\n"
            f"host,192.0.2.1,20,12,30,Japan,JP,1,2,3,4,log,operator,,{encoded}\n"
            "*\n"
        )
        servers = build_feed.parse_ovpn(raw)
        self.assertEqual(len(servers), 1)
        self.assertEqual(servers[0]["protocol"], "openvpn")
        self.assertEqual(servers[0]["countryCode"], "JP")
        self.assertEqual(servers[0]["configContent"], config)

    def test_deduplicates_supported_xray_links(self):
        link = "vless://id@example.com:443?security=tls#%F0%9F%87%A9%F0%9F%87%AA%20Berlin"
        servers = build_feed.parse_xray([("one.txt", f"{link}\n{link}\nwireguard://ignored")])
        self.assertEqual(len(servers), 1)
        self.assertEqual(servers[0]["countryCode"], "DE")
        self.assertEqual(servers[0]["protocol"], "vless")


if __name__ == "__main__":
    unittest.main()
