# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import unittest
from socket import AF_INET, AF_INET6
from typing import List
from unittest.mock import MagicMock, Mock, patch

import iptc
from pyroute2 import NetlinkError
from upf_network import IPTablesRule, NetworkInterface, Route, UPFNetwork, UPFNetworkError


class MockIPAddr:
    def __init__(self, ipv4_address: str = "", ipv6_address: str = ""):
        if ipv4_address:
            self.family = AF_INET
            self.address = ipv4_address
        elif ipv6_address:
            self.family = AF_INET6
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

    def __init__(self, routes: List[MockRoute]):
        self.routes = routes
        self.route = MagicMock()

    def get_routes(self, *args, **kwargs):
        return self.routes

    def link_lookup(self, *args, **kwargs):
        return [route.oif for route in self.routes]


class MockNDB:

    def __init__(self):
        self.interfaces = {
            "eth0": None,
            "core": None,
        }

    def __getitem__(self, key):
        """Return the interface with the given name."""
        return self.interfaces[key]


class TestNetworkInterface(unittest.TestCase):

    @patch("pyroute2.IPRoute")
    @patch("pyroute2.NDB")
    def setUp(self, mock_ndb, mock_ip_route):
        self.network_interface_name = "eth0"
        self.network_interface = NetworkInterface(name=self.network_interface_name)
        self.network_interface.network_db = MockNDB()
        self.network_interface.ip_route = MockIPRoute(routes=[])

    def test_given_interface_has_ipv4_address_when_get_interface_ip_address_ip_is_returned(self):
        interface_ipv4_address = "1.2.3.4"
        self.network_interface.network_db.interfaces = MockInterfaces(
            interfaces=[
                MockInterface(
                    ipv4_address=interface_ipv4_address, name=self.network_interface_name
                )
            ]
        )

        address = self.network_interface.get_ip_address()

        self.assertEqual(address, interface_ipv4_address)

    def test_given_interface_doesnt_exist_when_get_interface_ip_address_then_empty_string_is_returned(
        self,
    ):
        self.network_interface.network_db.interfaces = MockInterfaces(interfaces=[])

        address = self.network_interface.get_ip_address()

        self.assertEqual(address, "")

    def test_given_interface_doesnt_have_ipv4_address_when_get_interface_ip_address_then_empty_string_is_returned(
        self,
    ):
        self.network_interface.network_db.interfaces = MockInterfaces(
            interfaces=[
                MockInterface(
                    ipv6_address="2001:0db8:85a3:0000:0000:8a2e:0370:7334",
                    name=self.network_interface_name,
                )
            ]
        )

        address = self.network_interface.get_ip_address()

        self.assertEqual(address, "")

    def test_given_interface_has_gateway_ip_address_when_get_gateway_ip_address_then_gateway_ip_is_returned(
        self,
    ):
        gateway_ip = "1.2.3.1"

        self.network_interface.ip_route = MockIPRoute(
            routes=[
                MockRoute(
                    destination_network="1.2.3.0/24",
                    gateway=gateway_ip,
                    metric=123,
                    oif=2,
                ),
            ],
        )

        address = self.network_interface.get_gateway_ip_address()

        self.assertEqual(address, gateway_ip)

    def test_given_interface_doesnt_exist_when_get_gateway_ip_address_then_empty_string_is_returned(
        self,
    ):
        self.network_interface.ip_route = MockIPRoute(routes=[])

        address = self.network_interface.get_gateway_ip_address()

        self.assertEqual(address, "")

    def test_given_interface_doesnt_have_gateway_ip_address_when_get_gateway_ip_address_then_empty_string_is_returned(
        self,
    ):
        self.network_interface.ip_route = MockIPRoute(
            routes=[
                MockRoute(
                    destination_network="default",
                    gateway="",
                    metric=110,
                    oif=2,
                ),
            ],
        )

        address = self.network_interface.get_gateway_ip_address()

        self.assertEqual(address, "")

    def test_given_interface_exists_when_get_index_then_index_is_returned(self):
        interface_index = 2
        self.network_interface.network_db.interfaces = MockInterfaces(
            interfaces=[MockInterface(ipv4_address="1.2.3.4", name=self.network_interface_name)]
        )
        self.network_interface.ip_route = MockIPRoute(
            routes=[
                MockRoute(
                    destination_network="",
                    gateway="",
                    metric=0,
                    oif=interface_index,
                ),
            ],
        )

        index = self.network_interface.get_index()

        self.assertEqual(index, interface_index)

    def test_given_interface_doesnt_exist_when_get_index_then_negative_one_is_returned(self):
        self.network_interface.network_db.interfaces = MockInterfaces(interfaces=[])

        index = self.network_interface.get_index()

        self.assertEqual(index, -1)

    def test_given_interface_exists_when_exists_then_true_is_returned(self):
        self.network_interface.network_db.interfaces = MockInterfaces(
            interfaces=[MockInterface(ipv4_address="1.2.3.4", name=self.network_interface_name)]
        )

        exists = self.network_interface.exists()

        self.assertTrue(exists)

    def test_given_interface_doesnt_exist_when_exists_then_false_is_returned(self):
        self.network_interface.network_db.interfaces = MockInterfaces(interfaces=[])

        exists = self.network_interface.exists()

        self.assertFalse(exists)

    def test_given_interface_exists_and_has_ipv4_address_when_is_valid_then_true_is_returned(self):
        self.network_interface.network_db.interfaces = MockInterfaces(
            interfaces=[MockInterface(ipv4_address="1.2.3.4", name=self.network_interface_name)]
        )

        is_valid = self.network_interface.is_valid()

        self.assertTrue(is_valid)

    def test_given_interface_doesnt_exist_when_is_valid_then_false_is_returned(self):
        self.network_interface.network_db.interfaces = MockInterfaces(interfaces=[])

        is_valid = self.network_interface.is_valid()

        self.assertFalse(is_valid)

    def test_given_interface_exists_and_doesnt_have_ipv4_address_when_is_valid_then_false_is_returned(
        self,
    ):
        self.network_interface.network_db.interfaces = MockInterfaces(
            interfaces=[
                MockInterface(
                    ipv6_address="2001:0db8:85a3:0000:0000:8a2e:0370:7334",
                    name=self.network_interface_name,
                )
            ]
        )

        is_valid = self.network_interface.is_valid()

        self.assertFalse(is_valid)


class TestRoute(unittest.TestCase):

    @patch("pyroute2.IPRoute")
    def setUp(self, mock_route):
        self.gateway_ip = "1.2.3.1"
        self.oif = 2
        self.metric = 110
        self.route = Route(
            destination="",
            gateway=self.gateway_ip,
            oif=self.oif,
            metric=self.metric,
        )
        self.route.ip_route = MockIPRoute(routes=[])

    def test_given_route_doesnt_exist_when_exists_then_return_false(self):
        exists = self.route.exists()

        self.assertFalse(exists)

    def test_given_route_exists_when_exists_then_return_true(self):
        self.route.ip_route = MockIPRoute(
            routes=[
                MockRoute(
                    destination_network="default",
                    gateway=self.gateway_ip,
                    metric=self.metric,
                    oif=self.oif,
                ),
            ],
        )

        exists = self.route.exists()

        self.assertTrue(exists)

    def test_given_route_doesnt_exist_when_create_then_route_is_created(self):
        self.route.create()

        self.route.ip_route.route.assert_any_call(
            "replace",
            dst="",
            gateway=self.gateway_ip,
            oif=self.oif,
            priority=self.metric,
        )

    def given_netlink_error_when_create_then_exception_is_raised(self):
        self.route.ip_route.route.side_effect = NetlinkError

        with self.assertRaises(UPFNetworkError):
            self.route.create()


class TestIPTablesRule(unittest.TestCase):

    @patch("iptc.Chain")
    @patch("iptc.Table")
    def setUp(self, mock_iptc_table, mock_iptc_chain):
        self.mock_iptc_chain = mock_iptc_chain
        self.ip_tables_rule = IPTablesRule()
        self.ip_tables_rule.chain = self.mock_iptc_chain

    def test_given_rules_does_not_exist_when_exists_then_return_false(self):
        self.mock_iptc_chain.rules = []

        exists = self.ip_tables_rule.exists()

        self.assertFalse(exists)

    def test_given_rules_exist_when_exists_then_return_true(self):
        mock_match = Mock()
        mock_match.name = "icmp"
        mock_match.parameters = {"icmp_type": "3/3"}
        mock_rule = Mock()
        mock_rule.matches = [mock_match]
        mock_rule.target = Mock()
        mock_rule.target.name = "DROP"
        self.mock_iptc_chain.rules = [mock_rule]

        exists = self.ip_tables_rule.exists()

        self.assertTrue(exists)

    def test_given_rules_does_not_exist_when_create_then_rule_is_created(self):
        self.ip_tables_rule.create()

        expected_rule = iptc.Rule()
        expected_rule.protocol = "icmp"
        match = iptc.Match(expected_rule, "icmp")
        match.icmp_type = "port-unreachable"
        expected_rule.add_match(match)
        expected_rule.target = iptc.Target(expected_rule, "DROP")

        self.ip_tables_rule.chain.insert_rule.assert_any_call(expected_rule)


class TestUPFNetwork(unittest.TestCase):

    def setUp(self):
        self.core_interface_name = "eth0"
        self.access_interface_name = "eth1"
        self.gnb_subnet = "1.2.1.0/24"

    @patch("upf_network.IPTablesRule")
    @patch("upf_network.Route")
    @patch("upf_network.NetworkInterface")
    def test_given_invalid_access_interface_when_get_invalid_network_interfaces_then_interface_is_returned(
        self, mock_network_interface, _, __
    ):
        mock_access_interface_instance = MagicMock()
        mock_access_interface_instance.is_valid.return_value = False
        mock_access_interface_instance.name = self.access_interface_name

        mock_core_interface_instance = MagicMock()
        mock_core_interface_instance.is_valid.return_value = True

        mock_network_interface.side_effect = [
            mock_access_interface_instance,
            mock_core_interface_instance,
        ]

        upf_network = UPFNetwork(
            access_interface_name=self.access_interface_name,
            core_interface_name=self.core_interface_name,
            gnb_subnet=self.gnb_subnet,
        )
        invalid_network_interfaces = upf_network.get_invalid_network_interfaces()

        self.assertEqual(invalid_network_interfaces, [self.access_interface_name])

    @patch("upf_network.IPTablesRule")
    @patch("upf_network.Route")
    @patch("upf_network.NetworkInterface")
    def test_given_valid_interfaces_when_get_invalid_network_interfaces_then_empty_list_is_returned(
        self, mock_network_interface, _, __
    ):
        mock_access_interface_instance = MagicMock()
        mock_access_interface_instance.is_valid.return_value = True
        mock_core_interface_instance = MagicMock()
        mock_core_interface_instance.is_valid.return_value = True
        mock_network_interface.side_effect = [
            mock_access_interface_instance,
            mock_core_interface_instance,
        ]
        upf_network = UPFNetwork(
            access_interface_name=self.access_interface_name,
            core_interface_name=self.core_interface_name,
            gnb_subnet=self.gnb_subnet,
        )

        invalid_network_interfaces = upf_network.get_invalid_network_interfaces()

        self.assertEqual(invalid_network_interfaces, [])

    @patch("upf_network.IPTablesRule")
    @patch("upf_network.Route")
    @patch("upf_network.NetworkInterface")
    def test_given_default_route_not_created_when_configure_then_route_is_created(
        self, mock_network_interface, mock_route, _
    ):
        mock_access_interface_instance = MagicMock()
        mock_access_interface_instance.is_valid.return_value = True
        mock_core_interface_instance = MagicMock()
        mock_core_interface_instance.is_valid.return_value = True
        mock_network_interface.side_effect = [
            mock_access_interface_instance,
            mock_core_interface_instance,
        ]
        upf_network = UPFNetwork(
            access_interface_name=self.access_interface_name,
            core_interface_name=self.core_interface_name,
            gnb_subnet=self.gnb_subnet,
        )

        upf_network.configure()

        mock_route.assert_any_call(
            destination="",
            gateway=mock_core_interface_instance.get_gateway_ip_address(),
            oif=mock_core_interface_instance.get_index(),
            metric=110,
        )

    @patch("upf_network.IPTablesRule")
    @patch("upf_network.Route")
    @patch("upf_network.NetworkInterface")
    def test_given_default_route_created_when_configure_then_route_is_not_created(
        self, mock_network_interface, mock_route, _
    ):
        mock_access_interface_instance = MagicMock()
        mock_access_interface_instance.is_valid.return_value = True
        mock_core_interface_instance = MagicMock()
        mock_network_interface.side_effect = [
            mock_access_interface_instance,
            mock_core_interface_instance,
        ]
        mock_route_instance = MagicMock()
        mock_route.return_value = mock_route_instance
        mock_route_instance.exists.return_value = True
        upf_network = UPFNetwork(
            access_interface_name=self.access_interface_name,
            core_interface_name=self.core_interface_name,
            gnb_subnet=self.gnb_subnet,
        )

        upf_network.configure()

        mock_route_instance.create.assert_not_called()

    @patch("upf_network.IPTablesRule")
    @patch("upf_network.Route")
    @patch("upf_network.NetworkInterface")
    def test_given_ran_route_not_created_when_configure_then_route_is_created(
        self, mock_network_interface, mock_route, _
    ):
        mock_access_interface_instance = MagicMock()
        mock_access_interface_instance.is_valid.return_value = True
        mock_core_interface_instance = MagicMock()
        mock_core_interface_instance.is_valid.return_value = True
        mock_network_interface.side_effect = [
            mock_access_interface_instance,
            mock_core_interface_instance,
        ]
        upf_network = UPFNetwork(
            access_interface_name=self.access_interface_name,
            core_interface_name=self.core_interface_name,
            gnb_subnet=self.gnb_subnet,
        )

        upf_network.configure()

        mock_route.assert_any_call(
            destination=self.gnb_subnet,
            gateway=mock_access_interface_instance.get_gateway_ip_address(),
            oif=mock_access_interface_instance.get_index(),
        )

    @patch("upf_network.IPTablesRule")
    @patch("upf_network.Route")
    @patch("upf_network.NetworkInterface")
    def test_given_ran_route_created_when_configure_then_route_is_not_created(
        self, mock_network_interface, mock_route, _
    ):
        mock_access_interface_instance = MagicMock()
        mock_access_interface_instance.is_valid.return_value = True
        mock_core_interface_instance = MagicMock()
        mock_network_interface.side_effect = [
            mock_access_interface_instance,
            mock_core_interface_instance,
        ]
        mock_route_instance = MagicMock()
        mock_route.return_value = mock_route_instance
        mock_route_instance.exists.return_value = True
        upf_network = UPFNetwork(
            access_interface_name=self.access_interface_name,
            core_interface_name=self.core_interface_name,
            gnb_subnet=self.gnb_subnet,
        )

        upf_network.configure()

        mock_route_instance.create.assert_not_called()

    @patch("upf_network.IPTablesRule")
    @patch("upf_network.Route")
    @patch("upf_network.NetworkInterface")
    def test_given_iptables_rule_not_created_when_configure_then_rule_is_created(
        self, mock_network_interface, _, mock_iptables_rule
    ):
        mock_access_interface_instance = MagicMock()
        mock_access_interface_instance.is_valid.return_value = True
        mock_core_interface_instance = MagicMock()
        mock_core_interface_instance.is_valid.return_value = True
        mock_network_interface.side_effect = [
            mock_access_interface_instance,
            mock_core_interface_instance,
        ]
        upf_network = UPFNetwork(
            access_interface_name=self.access_interface_name,
            core_interface_name=self.core_interface_name,
            gnb_subnet=self.gnb_subnet,
        )

        upf_network.configure()

        mock_iptables_rule.assert_called_once()

    @patch("upf_network.IPTablesRule")
    @patch("upf_network.Route")
    @patch("upf_network.NetworkInterface")
    def test_given_iptables_rule_created_when_configure_then_rule_is_not_created(
        self, mock_network_interface, _, mock_iptables_rule
    ):
        mock_access_interface_instance = MagicMock()
        mock_access_interface_instance.is_valid.return_value = True
        mock_core_interface_instance = MagicMock()
        mock_network_interface.side_effect = [
            mock_access_interface_instance,
            mock_core_interface_instance,
        ]
        mock_iptables_rule_instance = MagicMock()
        mock_iptables_rule.return_value = mock_iptables_rule_instance
        mock_iptables_rule_instance.exists.return_value = True
        upf_network = UPFNetwork(
            access_interface_name=self.access_interface_name,
            core_interface_name=self.core_interface_name,
            gnb_subnet=self.gnb_subnet,
        )

        upf_network.configure()

        mock_iptables_rule_instance.create.assert_not_called()
