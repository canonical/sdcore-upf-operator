# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import unittest
from typing import List
from unittest.mock import MagicMock, Mock, call, patch

import iptc
from upf_network import UPFNetwork


class MockIPAddr:
    def __init__(self, ipv4_address: str = "", ipv6_address: str = ""):
        if ipv4_address:
            self.family = 2
            self.address = ipv4_address
        elif ipv6_address:
            self.family = 10
            self.address = ipv6_address


class MockInterface:
    def __init__(self, name: str, ipv4_address: str = "", ipv6_address: str = ""):
        self.name = name
        self.ipaddr = [MockIPAddr(ipv4_address=ipv4_address, ipv6_address=ipv6_address)]


class MockInterfaces:
    def __init__(self, interfaces: List[MockInterface]):
        self.interfaces = interfaces

    def __getitem__(self, item):
        """Return the interface with the given name."""
        for interface in self.interfaces:
            if interface.name == item:
                return interface
        raise KeyError

    def __contains__(self, item):
        """Return whether the given interface exists."""
        for interface in self.interfaces:
            if interface.name == item:
                return True
        return False


class MockRoute:

    def __init__(
        self, destination_network: str = "", gateway: str = "", metric: int = 0, oif: int = 0
    ):
        self.destination_network = destination_network
        self.gateway = gateway
        self.metric = metric
        self.oif = oif

    def get(self, attr: str) -> str:
        if attr == "dst_len":
            if self.destination_network == "default":
                return "0"
            return self.destination_network.split("/")[1]
        return ""

    def get_attr(self, attr: str) -> str:
        if attr == "RTA_GATEWAY":
            return self.gateway
        if attr == "RTA_OIF":
            return self.oif
        if attr == "RTA_PRIORITY":
            return self.metric
        if attr == "RTA_DST":
            return self.destination_network.split("/")[0]
        return ""


class MockIPRoute:

    def __init__(self, routes: List[MockRoute] = [], oif: int = 2):
        self.routes = routes
        self.oif = oif
        self.route = MagicMock()

    def get_routes(self, *args, **kwargs):
        return self.routes

    def link_lookup(self, *args, **kwargs):
        return [self.oif]


class MockNDB:

    def __init__(self):
        self.interfaces = {
            "eth0": None,
            "core": None,
        }

    def __getitem__(self, key):
        """Return the interface with the given name."""
        return self.interfaces[key]


class TestUPFNetwork(unittest.TestCase):

    @patch("iptc.Chain")
    @patch("iptc.Table")
    @patch("pyroute2.IPRoute")
    @patch("pyroute2.NDB")
    def setUp(self, mock_ndb, mock_ip_route, mock_iptc_table, mock_iptc_chain):
        self.access_interface_name = "eth0"
        self.core_interface_name = "eth1"
        self.gnb_subnet = "192.168.1.0/24"
        self.upf_network = UPFNetwork(
            access_interface_name=self.access_interface_name,
            core_interface_name=self.core_interface_name,
            gnb_subnet=self.gnb_subnet,
        )
        self.upf_network.ip_route = MockIPRoute()
        self.upf_network.network_db = MockNDB()
        self.mock_iptc_chain = mock_iptc_chain

    def test_given_interface_has_ipv4_address_when_get_interface_ip_address_ip_is_returned(self):
        self.upf_network.network_db.interfaces = MockInterfaces(
            interfaces=[
                MockInterface(ipv4_address="192.168.1.100", name=self.access_interface_name)
            ]
        )

        ip_address = self.upf_network.get_interface_ip_address(self.access_interface_name)

        self.assertEqual(ip_address, "192.168.1.100")

    def test_given_interface_doesnt_exist_when_get_interface_ip_address_then_empty_string_is_returned(
        self,
    ):
        self.upf_network.network_db.interfaces = MockInterfaces(interfaces=[])

        ip_address = self.upf_network.get_interface_ip_address(self.access_interface_name)

        self.assertEqual(ip_address, "")

    def test_given_interface_doesnt_have_ipv4_address_when_get_interface_ip_address_then_empty_string_is_returned(
        self,
    ):
        self.upf_network.network_db.interfaces = MockInterfaces(
            interfaces=[
                MockInterface(
                    ipv6_address="2001:0db8:85a3:0000:0000:8a2e:0370:7334",
                    name=self.access_interface_name,
                )
            ]
        )

        ip_address = self.upf_network.get_interface_ip_address(self.access_interface_name)

        self.assertEqual(ip_address, "")

    def test_given_no_invalid_network_interface_when_get_invalid_network_interfaces_then_return_empty_list(
        self,
    ):

        self.upf_network.network_db.interfaces = MockInterfaces(
            interfaces=[
                MockInterface(ipv4_address="1.2.3.4", name=self.access_interface_name),
                MockInterface(ipv4_address="2.2.3.1", name=self.core_interface_name),
            ]
        )
        invalid_interfaces = self.upf_network.get_invalid_network_interfaces()

        self.assertEqual(len(invalid_interfaces), 0)

    def test_given_no_access_interface_when_get_invalid_network_interfaces_then_return_access_interface(
        self,
    ):
        self.upf_network.network_db.interfaces = MockInterfaces(
            interfaces=[
                MockInterface(ipv4_address="2.2.3.1", name=self.core_interface_name),
            ]
        )
        invalid_interfaces = self.upf_network.get_invalid_network_interfaces()

        self.assertEqual(invalid_interfaces, [self.access_interface_name])

    def test_given_no_core_interface_when_get_invalid_network_interfaces_then_return_core_interface(
        self,
    ):
        self.upf_network.network_db.interfaces = MockInterfaces(
            interfaces=[
                MockInterface(ipv4_address="2.2.3.1", name=self.access_interface_name),
            ]
        )

        invalid_interfaces = self.upf_network.get_invalid_network_interfaces()

        self.assertEqual(invalid_interfaces, [self.core_interface_name])

    def test_given_core_interface_doesnt_have_ipv4_address_when_get_invalid_network_interfaces_then_return_core_interface(
        self,
    ):
        self.upf_network.network_db.interfaces = MockInterfaces(
            interfaces=[
                MockInterface(ipv4_address="2.2.3.1", name=self.access_interface_name),
                MockInterface(
                    ipv6_address="2001:0db8:85a3:0000:0000:8a2e:0370:7334",
                    name=self.core_interface_name,
                ),
            ]
        )

        invalid_interfaces = self.upf_network.get_invalid_network_interfaces()

        self.assertEqual(invalid_interfaces, [self.core_interface_name])

    def test_given_default_route_not_created_when_configure_then_default_route_is_created(self):
        core_interface_gateway_ip = "1.2.3.1"
        core_interface_oif = 2
        self.upf_network.network_db.interfaces = MockInterfaces(
            interfaces=[
                MockInterface(ipv4_address="1.2.3.4", name=self.access_interface_name),
                MockInterface(ipv4_address="2.2.2.8", name=self.core_interface_name),
            ]
        )
        self.upf_network.ip_route = MockIPRoute(
            oif=core_interface_oif,
            routes=[
                MockRoute(
                    destination_network="1.2.3.0/24",
                    gateway=core_interface_gateway_ip,
                    metric=123,
                    oif=core_interface_oif,
                ),
            ],
        )

        self.upf_network.configure()

        self.upf_network.ip_route.route.assert_any_call(
            "replace",
            dst="default",
            gateway=core_interface_gateway_ip,
            oif=core_interface_oif,
            priority=110,
        )

    def test_given_default_route_already_created_when_configure_then_default_route_not_created(
        self,
    ):
        core_interface_gateway_ip = "1.2.3.1"
        core_interface_oif = 2
        self.upf_network.network_db.interfaces = MockInterfaces(
            interfaces=[
                MockInterface(ipv4_address="1.2.3.4", name=self.access_interface_name),
                MockInterface(ipv4_address="2.2.2.8", name=self.core_interface_name),
            ]
        )
        self.upf_network.ip_route = MockIPRoute(
            oif=core_interface_oif,
            routes=[
                MockRoute(
                    destination_network="default",
                    gateway=core_interface_gateway_ip,
                    metric=110,
                    oif=core_interface_oif,
                ),
            ],
        )

        self.upf_network.configure()

        self.assertNotIn(
            call(
                "replace",
                dst="default",
                gateway=core_interface_gateway_ip,
                oif=core_interface_oif,
                priority=110,
            ),
            self.upf_network.ip_route.route.mock_calls,
            "The specific route call was made but it shouldn't have been.",
        )

    def test_given_ran_route_not_created_when_configure_then_ran_route_is_created(self):
        access_interface_gateway_ip = "2.2.1.1"
        access_interface_oif = 2
        self.upf_network.network_db.interfaces = MockInterfaces(
            interfaces=[
                MockInterface(ipv4_address="1.2.3.4", name=self.access_interface_name),
                MockInterface(ipv4_address="2.2.2.8", name=self.core_interface_name),
            ]
        )
        self.upf_network.ip_route = MockIPRoute(
            oif=access_interface_oif,
            routes=[
                MockRoute(
                    destination_network="1.2.3.0/24",
                    gateway=access_interface_gateway_ip,
                    metric=123,
                    oif=access_interface_oif,
                ),
            ],
        )

        self.upf_network.configure()

        self.upf_network.ip_route.route.assert_any_call(
            "replace",
            dst=self.gnb_subnet,
            gateway=access_interface_gateway_ip,
            oif=2,
        )

    def test_given_ran_route_already_created_when_configure_then_ran_route_not_created(self):
        access_interface_gateway_ip = "2.2.1.1"
        access_interface_oif = 2
        self.upf_network.network_db.interfaces = MockInterfaces(
            interfaces=[
                MockInterface(ipv4_address="1.2.3.4", name=self.access_interface_name),
                MockInterface(ipv4_address="2.2.2.8", name=self.core_interface_name),
            ]
        )
        self.upf_network.ip_route = MockIPRoute(
            oif=access_interface_oif,
            routes=[
                MockRoute(
                    destination_network=self.gnb_subnet,
                    gateway=access_interface_gateway_ip,
                    oif=access_interface_oif,
                ),
            ],
        )

        self.upf_network.configure()

        self.assertNotIn(
            call(
                "replace",
                dst=self.gnb_subnet,
                gateway=access_interface_gateway_ip,
                oif=2,
            ),
            self.upf_network.ip_route.route.mock_calls,
            "The specific route call was made but it shouldn't have been.",
        )

    def test_given_ip_tables_rule_doesnt_exist_when_configure_then_ip_tables_rule_is_created(self):
        self.upf_network.configure()

        expected_rule = iptc.Rule()
        expected_rule.protocol = "icmp"
        match = iptc.Match(expected_rule, "icmp")
        match.icmp_type = "port-unreachable"
        expected_rule.add_match(match)
        expected_rule.target = iptc.Target(expected_rule, "DROP")

        self.upf_network.chain.insert_rule.assert_any_call(expected_rule)

    def test_given_ip_tables_rule_already_exists_when_configure_then_ip_tables_rule_not_created(
        self,
    ):
        mock_match = Mock()
        mock_match.name = "icmp"
        mock_match.parameters = {"icmp_type": "3/3"}
        mock_rule = Mock()
        mock_rule.matches = [mock_match]
        mock_rule.target = Mock()
        mock_rule.target.name = "DROP"
        self.upf_network.chain.rules = [mock_rule]

        self.upf_network.configure()

        self.upf_network.chain.insert_rule.assert_not_called()
