# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

from socket import AF_INET, AF_INET6
from typing import List
from unittest.mock import MagicMock, Mock, patch

import iptc
import pytest
from charm_config import UpfMode
from upf_network import IPTablesRule, NetworkInterface, Route, UPFNetwork


class MockIPAddr:
    def __init__(self, ipv4_address: str = "", ipv6_address: str = ""):
        if ipv4_address:
            self.family = AF_INET
            self.address = ipv4_address.split("/")[0]
            self.prefixlen = ipv4_address.split("/")[1]
        elif ipv6_address:
            self.family = AF_INET6
            self.address = ipv6_address


class MockInterface:
    def __init__(
        self,
        name: str,
        ipv4_address: str = "",
        ipv6_address: str = "",
        index: int = None,
        mtu_size: int = 1500,
        mac_address: str = "",
        alias: str = "",
        state: str = "down",
    ):
        self.name = name
        self.index = index
        self.ipaddr = [MockIPAddr(ipv4_address=ipv4_address, ipv6_address=ipv6_address)]
        self.mtu = mtu_size
        self.address = mac_address
        self.ifalias = alias
        self.state = state

    def get(self, key):
        return self.__getitem__(key)

    def __getitem__(self, key):
        """Return the given attribute from the interface."""
        return getattr(self, key)


class MockInterfaces:
    def __init__(self, interfaces: List[MockInterface]):
        for interface in interfaces:
            interface.index = interfaces.index(interface)
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

    def get(self, item):
        try:
            return self.__getitem__(item)
        except KeyError:
            return None


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

    def get_attr(self, attr: str) -> [str, int]:
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


class TestNetworkInterface:
    patcher_iproute = patch("pyroute2.IPRoute")
    patcher_ndb = patch("pyroute2.NDB")

    @pytest.fixture(autouse=True)
    def setup(self, request):
        TestNetworkInterface.patcher_iproute.start()
        TestNetworkInterface.patcher_ndb.start()
        self.network_interface_name = "eth0"
        self.interface_ipv4_address = "1.2.3.4/24"
        self.interface_mac_address = "aa:bb:cc:dd"
        self.interface_alias = "0000:01:00.0"
        self.interface_mtu_size = 1400
        self.network_interface = NetworkInterface(
            name=self.network_interface_name,
            ip_address=self.interface_ipv4_address,
            mtu_size=1500,
            alias=self.interface_alias,
            mac_address=self.interface_mac_address,
        )
        self.network_interface.network_db = MockNDB()
        self.network_interface.ip_route = MockIPRoute(routes=[])
        yield
        request.addfinalizer(self.teardown)

    @staticmethod
    def teardown() -> None:
        patch.stopall()

    def test_given_interface_has_ipv4_address_when_get_interface_ip_address_ip_is_returned(self):
        self.network_interface.network_db.interfaces = MockInterfaces(
            interfaces=[
                MockInterface(
                    ipv4_address=self.interface_ipv4_address, name=self.network_interface_name
                )
            ]
        )

        address = self.network_interface.get_ip_address()

        assert address == self.interface_ipv4_address

    def test_given_interface_status_is_up_when_get_interface_status_then_state_is_up(self):
        self.network_interface.network_db.interfaces = MockInterfaces(
            interfaces=[
                MockInterface(
                    ipv4_address=self.interface_ipv4_address,
                    name=self.network_interface_name,
                    state="up",
                )
            ]
        )
        assert self.network_interface.interface_is_up()

    def test_given_interface_doesnt_exist_when_get_interface_ip_address_then_empty_string_is_returned(  # noqa: E501
        self,
    ):
        self.network_interface.network_db.interfaces = MockInterfaces(interfaces=[])

        address = self.network_interface.get_ip_address()

        assert address == ""

    def test_given_interface_doesnt_exist_when_check_interface_states_then_false_is_returned(self):  # noqa: E501
        self.network_interface.network_db.interfaces = MockInterfaces(interfaces=[])

        assert self.network_interface.interface_is_up() is False

    def test_given_interface_doesnt_have_ipv4_address_when_get_interface_ip_address_then_empty_string_is_returned(  # noqa: E501
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

        assert address == ""

    def test_given_interface_exists_when_get_index_then_index_is_returned(self):
        expected_interface_index = 0
        self.network_interface.network_db.interfaces = MockInterfaces(
            interfaces=[
                MockInterface(
                    ipv4_address=self.interface_ipv4_address, name=self.network_interface_name
                )
            ]
        )

        index = self.network_interface.get_index()

        assert index == expected_interface_index

    def test_given_interface_doesnt_exist_when_get_index_then_negative_one_is_returned(self):
        self.network_interface.network_db.interfaces = MockInterfaces(interfaces=[])

        index = self.network_interface.get_index()

        assert index == -1

    def test_given_interface_exists_when_exists_then_true_is_returned(self):
        self.network_interface.network_db.interfaces = MockInterfaces(
            interfaces=[
                MockInterface(
                    ipv4_address=self.interface_ipv4_address, name=self.network_interface_name
                )
            ]
        )

        exists = self.network_interface.exists()

        assert exists is True

    def test_given_interface_doesnt_exist_when_exists_then_false_is_returned(self):
        self.network_interface.network_db.interfaces = MockInterfaces(interfaces=[])

        exists = self.network_interface.exists()

        assert exists is False

    def test_given_interface_doesnt_exist_when_is_valid_then_false_is_returned(self):
        self.network_interface.network_db.interfaces = MockInterfaces(interfaces=[])

        is_valid = self.network_interface.is_valid()

        assert is_valid is False

    def test_given_correct_address_when_addresses_are_set_then_true_is_returned(self):
        self.network_interface.network_db.interfaces = MockInterfaces(
            interfaces=[
                MockInterface(
                    ipv4_address=self.interface_ipv4_address, name=self.network_interface_name
                )
            ]
        )

        addresses_are_set = self.network_interface.addresses_are_set()

        assert addresses_are_set is True

    def test_given_incorrect_address_when_addresses_are_set_then_false_is_returned(self):
        self.network_interface.network_db.interfaces = MockInterfaces(
            interfaces=[MockInterface(ipv4_address="2.3.4.5/30", name=self.network_interface_name)]
        )

        addresses_are_set = self.network_interface.addresses_are_set()

        assert addresses_are_set is False

    def test_given_correct_mtu_size_when_mtu_size_is_set_then_true_is_returned(self):
        self.network_interface.network_db.interfaces = MockInterfaces(
            interfaces=[
                MockInterface(
                    ipv4_address=self.interface_ipv4_address, name=self.network_interface_name
                )
            ]
        )

        mtu_size_is_set = self.network_interface.mtu_size_is_set()

        assert mtu_size_is_set is True

    def test_given_incorrect_mtu_size_when_mtu_size_is_set_then_true_is_returned(self):
        self.network_interface.network_db.interfaces = MockInterfaces(
            interfaces=[
                MockInterface(
                    ipv4_address="2.3.4.5/30",
                    name=self.network_interface_name,
                    mtu_size=self.interface_mtu_size,
                )
            ]
        )

        mtu_size_is_set = self.network_interface.mtu_size_is_set()

        assert mtu_size_is_set is False

    def test_given_interface_has_the_wrong_mac_address_when_mac_address_is_set_then_false_is_returned(  # noqa: E501
        self,
    ):
        self.network_interface.network_db.interfaces = MockInterfaces(
            interfaces=[
                MockInterface(
                    ipv4_address=self.interface_ipv4_address,
                    name=self.network_interface_name,
                    mac_address="wrong mac",
                )
            ]
        )

        mac_address_is_set = self.network_interface.mac_address_is_set()

        assert mac_address_is_set is False

    def test_given_interface_has_the_right_mac_address_when_mac_address_is_set_then_true_is_returned(  # noqa: E501
        self,
    ):
        self.network_interface.network_db.interfaces = MockInterfaces(
            interfaces=[
                MockInterface(
                    ipv4_address=self.interface_ipv4_address,
                    name=self.network_interface_name,
                    mac_address=self.interface_mac_address,
                )
            ]
        )

        mac_address_is_set = self.network_interface.mac_address_is_set()

        assert mac_address_is_set is True

    def test_given_interface_doesnt_have_alias_set_when_alias_is_set_then_false_is_returned(
        self,
    ):
        self.network_interface.network_db.interfaces = MockInterfaces(
            interfaces=[
                MockInterface(
                    ipv4_address=self.interface_ipv4_address,
                    name=self.network_interface_name,
                )
            ]
        )

        alias_is_set = self.network_interface.alias_is_set()

        assert alias_is_set is False

    def test_given_interface_has_the_right_alias_set_when_alias_is_set_then_true_is_returned(
        self,
    ):
        self.network_interface.network_db.interfaces = MockInterfaces(
            interfaces=[
                MockInterface(
                    ipv4_address=self.interface_ipv4_address,
                    name=self.network_interface_name,
                    alias=self.interface_alias,
                )
            ]
        )

        alias_is_set = self.network_interface.alias_is_set()

        assert alias_is_set is True


class TestRoute:
    @pytest.fixture(autouse=True)
    def setup(self):
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

        assert exists is False

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

        assert exists is True

    def test_given_route_doesnt_exist_when_create_then_route_is_created(self):
        self.route.create()

        self.route.ip_route.route.assert_any_call(
            "replace",
            dst="",
            gateway=self.gateway_ip,
            oif=self.oif,
            priority=self.metric,
        )


class TestIPTablesRule:
    patcher_chain = patch("iptc.Chain")
    patcher_table = patch("iptc.Table")

    @pytest.fixture(autouse=True)
    def setup(self, request):
        TestIPTablesRule.patcher_table.start()
        self.mock_iptc_chain = TestIPTablesRule.patcher_chain.start()
        self.ip_tables_rule = IPTablesRule()
        self.ip_tables_rule.chain = self.mock_iptc_chain
        request.addfinalizer(self.teardown)

    @staticmethod
    def teardown() -> None:
        patch.stopall()

    def test_given_rules_does_not_exist_when_exists_then_return_false(self):
        self.mock_iptc_chain.rules = []

        exists = self.ip_tables_rule.exists()

        assert exists is False

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

        assert exists is True

    def test_given_rules_does_not_exist_when_create_then_rule_is_created(self):
        self.ip_tables_rule.create()

        expected_rule = iptc.Rule()
        expected_rule.protocol = "icmp"
        match = iptc.Match(expected_rule, "icmp")
        match.icmp_type = "port-unreachable"
        expected_rule.add_match(match)
        expected_rule.target = iptc.Target(expected_rule, "DROP")

        self.ip_tables_rule.chain.insert_rule.assert_any_call(expected_rule)


class TestUPFNetwork:
    patcher_iptables_rule = patch("upf_network.IPTablesRule")
    patcher_route = patch("upf_network.Route")
    patcher_network_interface = patch("upf_network.NetworkInterface")

    @pytest.fixture(autouse=True)
    def setup(self, request):
        self.core_interface_name = "eth0"
        self.core_ip = "1.2.3.4/24"
        self.core_gateway_ip = "1.2.3.1"
        self.core_interface_mtu_size = 1500
        self.access_interface_name = "eth1"
        self.access_ip = "2.3.4.5/24"
        self.access_gateway_ip = "2.3.4.1"
        self.access_interface_mtu_size = 1500
        self.gnb_subnet = "1.2.1.0/24"
        self.mock_network_interface = TestUPFNetwork.patcher_network_interface.start()
        self.mock_route = TestUPFNetwork.patcher_route.start()
        self.mock_iptables_rule = TestUPFNetwork.patcher_iptables_rule.start()
        yield
        request.addfinalizer(self.teardown)

    @staticmethod
    def teardown() -> None:
        patch.stopall()

    def test_given_invalid_access_interface_when_get_invalid_network_interfaces_then_interface_is_returned(  # noqa: E501
        self,
    ):
        mock_access_interface_instance = MagicMock()
        mock_access_interface_instance.is_valid.return_value = False
        mock_access_interface_instance.name = self.access_interface_name

        mock_core_interface_instance = MagicMock()
        mock_core_interface_instance.is_valid.return_value = True

        self.mock_network_interface.side_effect = [
            mock_access_interface_instance,
            mock_core_interface_instance,
        ]

        upf_network = UPFNetwork(
            upf_mode=UpfMode.af_packet,
            access_interface_name=self.access_interface_name,
            access_ip=self.access_ip,
            access_gateway_ip=self.access_gateway_ip,
            access_mtu_size=self.access_interface_mtu_size,
            core_interface_name=self.core_interface_name,
            core_ip=self.core_ip,
            core_gateway_ip=self.core_gateway_ip,
            core_mtu_size=self.core_interface_mtu_size,
            gnb_subnet=self.gnb_subnet,
        )
        invalid_network_interfaces = upf_network.get_invalid_network_interfaces()

        assert invalid_network_interfaces == [self.access_interface_name]

    def test_given_valid_interfaces_when_get_invalid_network_interfaces_then_empty_list_is_returned(  # noqa: E501
        self,
    ):
        mock_access_interface_instance = MagicMock()
        mock_access_interface_instance.is_valid.return_value = True
        mock_core_interface_instance = MagicMock()
        mock_core_interface_instance.is_valid.return_value = True
        self.mock_network_interface.side_effect = [
            mock_access_interface_instance,
            mock_core_interface_instance,
        ]
        upf_network = UPFNetwork(
            upf_mode=UpfMode.af_packet,
            access_interface_name=self.access_interface_name,
            access_ip=self.access_ip,
            access_gateway_ip=self.access_gateway_ip,
            access_mtu_size=self.access_interface_mtu_size,
            core_interface_name=self.core_interface_name,
            core_ip=self.core_ip,
            core_gateway_ip=self.core_gateway_ip,
            core_mtu_size=self.core_interface_mtu_size,
            gnb_subnet=self.gnb_subnet,
        )

        invalid_network_interfaces = upf_network.get_invalid_network_interfaces()

        assert invalid_network_interfaces == []

    def test_given_default_route_not_created_when_configure_then_route_is_created(self):
        mock_access_interface_instance = MagicMock()
        mock_access_interface_instance.is_valid.return_value = True
        mock_core_interface_instance = MagicMock()
        mock_core_interface_instance.is_valid.return_value = True
        self.mock_network_interface.side_effect = [
            mock_access_interface_instance,
            mock_core_interface_instance,
        ]
        upf_network = UPFNetwork(
            upf_mode=UpfMode.af_packet,
            access_interface_name=self.access_interface_name,
            access_ip=self.access_ip,
            access_gateway_ip=self.access_gateway_ip,
            access_mtu_size=self.access_interface_mtu_size,
            core_interface_name=self.core_interface_name,
            core_ip=self.core_ip,
            core_gateway_ip=self.core_gateway_ip,
            core_mtu_size=self.core_interface_mtu_size,
            gnb_subnet=self.gnb_subnet,
        )

        upf_network.configure()

        self.mock_route.assert_any_call(
            destination="",
            gateway=self.core_gateway_ip,
            oif=mock_core_interface_instance.get_index(),
            metric=110,
        )

    def test_given_default_route_created_when_configure_then_route_is_not_created(self):
        mock_access_interface_instance = MagicMock()
        mock_access_interface_instance.is_valid.return_value = True
        mock_core_interface_instance = MagicMock()
        self.mock_network_interface.side_effect = [
            mock_access_interface_instance,
            mock_core_interface_instance,
        ]
        mock_route_instance = MagicMock()
        self.mock_route.return_value = mock_route_instance
        mock_route_instance.exists.return_value = True
        upf_network = UPFNetwork(
            upf_mode=UpfMode.af_packet,
            access_interface_name=self.access_interface_name,
            access_ip=self.access_ip,
            access_gateway_ip=self.access_gateway_ip,
            access_mtu_size=self.access_interface_mtu_size,
            core_interface_name=self.core_interface_name,
            core_ip=self.core_ip,
            core_gateway_ip=self.core_gateway_ip,
            core_mtu_size=self.core_interface_mtu_size,
            gnb_subnet=self.gnb_subnet,
        )

        upf_network.configure()

        mock_route_instance.create.assert_not_called()

    def test_given_default_route_not_created_when_clean_then_delete_is_not_called(self):
        mock_access_interface_instance = MagicMock()
        mock_access_interface_instance.is_valid.return_value = True
        mock_core_interface_instance = MagicMock()
        mock_core_interface_instance.is_valid.return_value = True
        self.mock_network_interface.side_effect = [
            mock_access_interface_instance,
            mock_core_interface_instance,
        ]
        mock_default_route_instance = MagicMock()
        mock_ran_route_instance = MagicMock()
        self.mock_route.side_effect = [mock_default_route_instance, mock_ran_route_instance]
        mock_default_route_instance.exists.return_value = False
        mock_ran_route_instance.exists.return_value = True
        upf_network = UPFNetwork(
            upf_mode=UpfMode.af_packet,
            access_interface_name=self.access_interface_name,
            access_ip=self.access_ip,
            access_gateway_ip=self.access_gateway_ip,
            access_mtu_size=self.access_interface_mtu_size,
            core_interface_name=self.core_interface_name,
            core_ip=self.core_ip,
            core_gateway_ip=self.core_gateway_ip,
            core_mtu_size=self.core_interface_mtu_size,
            gnb_subnet=self.gnb_subnet,
        )

        upf_network.clean_configuration()

        mock_default_route_instance.delete.assert_not_called()

    def test_given_default_route_created_when_clean_then_delete_is_called(self):
        mock_access_interface_instance = MagicMock()
        mock_access_interface_instance.is_valid.return_value = True
        mock_core_interface_instance = MagicMock()
        mock_core_interface_instance.is_valid.return_value = True
        self.mock_network_interface.side_effect = [
            mock_access_interface_instance,
            mock_core_interface_instance,
        ]
        mock_default_route_instance = MagicMock()
        mock_ran_route_instance = MagicMock()
        self.mock_route.side_effect = [mock_default_route_instance, mock_ran_route_instance]
        mock_default_route_instance.exists.return_value = True
        mock_ran_route_instance.exists.return_value = True
        upf_network = UPFNetwork(
            upf_mode=UpfMode.af_packet,
            access_interface_name=self.access_interface_name,
            access_ip=self.access_ip,
            access_gateway_ip=self.access_gateway_ip,
            access_mtu_size=self.access_interface_mtu_size,
            core_interface_name=self.core_interface_name,
            core_ip=self.core_ip,
            core_gateway_ip=self.core_gateway_ip,
            core_mtu_size=self.core_interface_mtu_size,
            gnb_subnet=self.gnb_subnet,
        )

        upf_network.clean_configuration()

        mock_default_route_instance.delete.assert_called_once()

    def test_given_ran_route_not_created_when_configure_then_route_is_created(self):
        mock_access_interface_instance = MagicMock()
        mock_access_interface_instance.is_valid.return_value = True
        mock_core_interface_instance = MagicMock()
        mock_core_interface_instance.is_valid.return_value = True
        self.mock_network_interface.side_effect = [
            mock_access_interface_instance,
            mock_core_interface_instance,
        ]
        upf_network = UPFNetwork(
            upf_mode=UpfMode.af_packet,
            access_interface_name=self.access_interface_name,
            access_ip=self.access_ip,
            access_gateway_ip=self.access_gateway_ip,
            access_mtu_size=self.access_interface_mtu_size,
            core_interface_name=self.core_interface_name,
            core_ip=self.core_ip,
            core_gateway_ip=self.core_gateway_ip,
            core_mtu_size=self.core_interface_mtu_size,
            gnb_subnet=self.gnb_subnet,
        )

        upf_network.configure()

        self.mock_route.assert_any_call(
            destination=self.gnb_subnet,
            gateway=self.access_gateway_ip,
            oif=mock_access_interface_instance.get_index(),
        )

    def test_given_ran_route_created_when_configure_then_route_is_not_created(self):
        mock_access_interface_instance = MagicMock()
        mock_access_interface_instance.is_valid.return_value = True
        mock_core_interface_instance = MagicMock()
        self.mock_network_interface.side_effect = [
            mock_access_interface_instance,
            mock_core_interface_instance,
        ]
        mock_route_instance = MagicMock()
        self.mock_route.return_value = mock_route_instance
        mock_route_instance.exists.return_value = True
        upf_network = UPFNetwork(
            upf_mode=UpfMode.af_packet,
            access_interface_name=self.access_interface_name,
            access_ip=self.access_ip,
            access_gateway_ip=self.access_gateway_ip,
            access_mtu_size=self.access_interface_mtu_size,
            core_interface_name=self.core_interface_name,
            core_ip=self.core_ip,
            core_gateway_ip=self.core_gateway_ip,
            core_mtu_size=self.core_interface_mtu_size,
            gnb_subnet=self.gnb_subnet,
        )

        upf_network.configure()

        mock_route_instance.create.assert_not_called()

    def test_given_ran_route_not_created_when_clean_then_delete_is_not_called(self):
        mock_access_interface_instance = MagicMock()
        mock_access_interface_instance.is_valid.return_value = True
        mock_core_interface_instance = MagicMock()
        mock_core_interface_instance.is_valid.return_value = True
        self.mock_network_interface.side_effect = [
            mock_access_interface_instance,
            mock_core_interface_instance,
        ]
        mock_default_route_instance = MagicMock()
        mock_ran_route_instance = MagicMock()
        self.mock_route.side_effect = [mock_default_route_instance, mock_ran_route_instance]
        mock_ran_route_instance.exists.return_value = False
        upf_network = UPFNetwork(
            upf_mode=UpfMode.af_packet,
            access_interface_name=self.access_interface_name,
            access_ip=self.access_ip,
            access_gateway_ip=self.access_gateway_ip,
            access_mtu_size=self.access_interface_mtu_size,
            core_interface_name=self.core_interface_name,
            core_ip=self.core_ip,
            core_gateway_ip=self.core_gateway_ip,
            core_mtu_size=self.core_interface_mtu_size,
            gnb_subnet=self.gnb_subnet,
        )

        upf_network.clean_configuration()

        mock_ran_route_instance.delete.assert_not_called()

    def test_given_ran_route_created_when_clean_then_delete_is_called(self):
        mock_access_interface_instance = MagicMock()
        mock_access_interface_instance.is_valid.return_value = True
        mock_core_interface_instance = MagicMock()
        mock_core_interface_instance.is_valid.return_value = True
        self.mock_network_interface.side_effect = [
            mock_access_interface_instance,
            mock_core_interface_instance,
        ]
        mock_default_route_instance = MagicMock()
        mock_ran_route_instance = MagicMock()
        self.mock_route.side_effect = [mock_default_route_instance, mock_ran_route_instance]
        mock_ran_route_instance.exists.return_value = True
        upf_network = UPFNetwork(
            upf_mode=UpfMode.af_packet,
            access_interface_name=self.access_interface_name,
            access_ip=self.access_ip,
            access_gateway_ip=self.access_gateway_ip,
            access_mtu_size=self.access_interface_mtu_size,
            core_interface_name=self.core_interface_name,
            core_ip=self.core_ip,
            core_gateway_ip=self.core_gateway_ip,
            core_mtu_size=self.core_interface_mtu_size,
            gnb_subnet=self.gnb_subnet,
        )

        upf_network.clean_configuration()

        mock_ran_route_instance.delete.assert_called_once()

    def test_given_iptables_rule_not_created_when_configure_then_rule_is_created(self):
        mock_access_interface_instance = MagicMock()
        mock_access_interface_instance.is_valid.return_value = True
        mock_core_interface_instance = MagicMock()
        mock_core_interface_instance.is_valid.return_value = True
        self.mock_network_interface.side_effect = [
            mock_access_interface_instance,
            mock_core_interface_instance,
        ]
        upf_network = UPFNetwork(
            upf_mode=UpfMode.af_packet,
            access_interface_name=self.access_interface_name,
            access_ip=self.access_ip,
            access_gateway_ip=self.access_gateway_ip,
            access_mtu_size=self.access_interface_mtu_size,
            core_interface_name=self.core_interface_name,
            core_ip=self.core_ip,
            core_gateway_ip=self.core_gateway_ip,
            core_mtu_size=self.core_interface_mtu_size,
            gnb_subnet=self.gnb_subnet,
        )

        upf_network.configure()

        self.mock_iptables_rule.assert_called_once()

    def test_given_iptables_rule_created_when_configure_then_rule_is_not_created(self):
        mock_access_interface_instance = MagicMock()
        mock_access_interface_instance.is_valid.return_value = True
        mock_core_interface_instance = MagicMock()
        self.mock_network_interface.side_effect = [
            mock_access_interface_instance,
            mock_core_interface_instance,
        ]
        mock_iptables_rule_instance = MagicMock()
        self.mock_iptables_rule.return_value = mock_iptables_rule_instance
        mock_iptables_rule_instance.exists.return_value = True
        upf_network = UPFNetwork(
            upf_mode=UpfMode.af_packet,
            access_interface_name=self.access_interface_name,
            access_ip=self.access_ip,
            access_gateway_ip=self.access_gateway_ip,
            access_mtu_size=self.access_interface_mtu_size,
            core_interface_name=self.core_interface_name,
            core_ip=self.core_ip,
            core_gateway_ip=self.core_gateway_ip,
            core_mtu_size=self.core_interface_mtu_size,
            gnb_subnet=self.gnb_subnet,
        )

        upf_network.configure()

        mock_iptables_rule_instance.create.assert_not_called()

    def test_given_iptables_rule_not_created_when_clean_then_delete_is_not_called(self):
        mock_access_interface_instance = MagicMock()
        mock_access_interface_instance.is_valid.return_value = True
        mock_core_interface_instance = MagicMock()
        mock_core_interface_instance.is_valid.return_value = True
        self.mock_network_interface.side_effect = [
            mock_access_interface_instance,
            mock_core_interface_instance,
        ]
        mock_iptables_rule_instance = MagicMock()
        self.mock_iptables_rule.return_value = mock_iptables_rule_instance
        mock_iptables_rule_instance.exists.return_value = False
        upf_network = UPFNetwork(
            upf_mode=UpfMode.af_packet,
            access_interface_name=self.access_interface_name,
            access_ip=self.access_ip,
            access_gateway_ip=self.access_gateway_ip,
            access_mtu_size=self.access_interface_mtu_size,
            core_interface_name=self.core_interface_name,
            core_ip=self.core_ip,
            core_gateway_ip=self.core_gateway_ip,
            core_mtu_size=self.core_interface_mtu_size,
            gnb_subnet=self.gnb_subnet,
        )

        upf_network.clean_configuration()

        mock_iptables_rule_instance.delete.assert_not_called()

    def test_given_iptables_rule_created_when_clean_then_delete_is_called(self):
        mock_access_interface_instance = MagicMock()
        mock_access_interface_instance.is_valid.return_value = True
        mock_core_interface_instance = MagicMock()
        mock_core_interface_instance.is_valid.return_value = True
        self.mock_network_interface.side_effect = [
            mock_access_interface_instance,
            mock_core_interface_instance,
        ]
        mock_iptables_rule_instance = MagicMock()
        self.mock_iptables_rule.return_value = mock_iptables_rule_instance
        mock_iptables_rule_instance.exists.return_value = True
        upf_network = UPFNetwork(
            upf_mode=UpfMode.af_packet,
            access_interface_name=self.access_interface_name,
            access_ip=self.access_ip,
            access_gateway_ip=self.access_gateway_ip,
            access_mtu_size=self.access_interface_mtu_size,
            core_interface_name=self.core_interface_name,
            core_ip=self.core_ip,
            core_gateway_ip=self.core_gateway_ip,
            core_mtu_size=self.core_interface_mtu_size,
            gnb_subnet=self.gnb_subnet,
        )

        upf_network.clean_configuration()

        mock_iptables_rule_instance.delete.assert_called_once()

    def test_given_access_address_not_set_when_configure_then_address_is_set(self):
        mock_access_interface_instance = MagicMock()
        mock_access_interface_instance.is_valid.return_value = True
        mock_access_interface_instance.addresses_are_set.return_value = False
        mock_core_interface_instance = MagicMock()
        mock_core_interface_instance.is_valid.return_value = True
        mock_core_interface_instance.addresses_are_set.return_value = True
        self.mock_network_interface.side_effect = [
            mock_access_interface_instance,
            mock_core_interface_instance,
        ]
        upf_network = UPFNetwork(
            upf_mode=UpfMode.af_packet,
            access_interface_name=self.access_interface_name,
            access_ip=self.access_ip,
            access_gateway_ip=self.access_gateway_ip,
            access_mtu_size=self.access_interface_mtu_size,
            core_interface_name=self.core_interface_name,
            core_ip=self.core_ip,
            core_gateway_ip=self.core_gateway_ip,
            core_mtu_size=self.core_interface_mtu_size,
            gnb_subnet=self.gnb_subnet,
        )

        upf_network.configure()

        mock_access_interface_instance.set_ip_address.assert_called_once()

    def test_given_core_address_not_set_when_configure_then_address_is_set(self):
        mock_access_interface_instance = MagicMock()
        mock_access_interface_instance.is_valid.return_value = True
        mock_access_interface_instance.addresses_are_set.return_value = True
        mock_core_interface_instance = MagicMock()
        mock_core_interface_instance.is_valid.return_value = True
        mock_core_interface_instance.addresses_are_set.return_value = False
        self.mock_network_interface.side_effect = [
            mock_access_interface_instance,
            mock_core_interface_instance,
        ]
        upf_network = UPFNetwork(
            upf_mode=UpfMode.af_packet,
            access_interface_name=self.access_interface_name,
            access_ip=self.access_ip,
            access_gateway_ip=self.access_gateway_ip,
            access_mtu_size=self.access_interface_mtu_size,
            core_interface_name=self.core_interface_name,
            core_ip=self.core_ip,
            core_gateway_ip=self.core_gateway_ip,
            core_mtu_size=self.core_interface_mtu_size,
            gnb_subnet=self.gnb_subnet,
        )

        upf_network.configure()

        mock_core_interface_instance.set_ip_address.assert_called_once()

    def test_given_access_address_set_when_configure_then_set_address_is_not_called(self):
        mock_access_interface_instance = MagicMock()
        mock_access_interface_instance.is_valid.return_value = True
        mock_access_interface_instance.addresses_are_set.return_value = True
        mock_core_interface_instance = MagicMock()
        mock_core_interface_instance.is_valid.return_value = True
        mock_core_interface_instance.addresses_are_set.return_value = True
        self.mock_network_interface.side_effect = [
            mock_access_interface_instance,
            mock_core_interface_instance,
        ]
        upf_network = UPFNetwork(
            upf_mode=UpfMode.af_packet,
            access_interface_name=self.access_interface_name,
            access_ip=self.access_ip,
            access_gateway_ip=self.access_gateway_ip,
            access_mtu_size=self.access_interface_mtu_size,
            core_interface_name=self.core_interface_name,
            core_ip=self.core_ip,
            core_gateway_ip=self.core_gateway_ip,
            core_mtu_size=self.core_interface_mtu_size,
            gnb_subnet=self.gnb_subnet,
        )

        upf_network.configure()

        mock_access_interface_instance.set_ip_address.assert_not_called()

    def test_given_core_address_set_when_configure_then_set_address_is_not_called(self):
        mock_access_interface_instance = MagicMock()
        mock_access_interface_instance.is_valid.return_value = True
        mock_access_interface_instance.addresses_are_set.return_value = True
        mock_core_interface_instance = MagicMock()
        mock_core_interface_instance.is_valid.return_value = True
        mock_core_interface_instance.addresses_are_set.return_value = True
        self.mock_network_interface.side_effect = [
            mock_access_interface_instance,
            mock_core_interface_instance,
        ]
        upf_network = UPFNetwork(
            upf_mode=UpfMode.af_packet,
            access_interface_name=self.access_interface_name,
            access_ip=self.access_ip,
            access_gateway_ip=self.access_gateway_ip,
            access_mtu_size=self.access_interface_mtu_size,
            core_interface_name=self.core_interface_name,
            core_ip=self.core_ip,
            core_gateway_ip=self.core_gateway_ip,
            core_mtu_size=self.core_interface_mtu_size,
            gnb_subnet=self.gnb_subnet,
        )

        upf_network.configure()

        mock_core_interface_instance.set_ip_address.assert_not_called()

    def test_given_access_address_set_when_clean_then_unset_address_is_called(self):
        mock_access_interface_instance = MagicMock()
        mock_access_interface_instance.is_valid.return_value = True
        mock_access_interface_instance.get_ip_address.return_value = self.access_ip
        mock_core_interface_instance = MagicMock()
        mock_core_interface_instance.is_valid.return_value = True
        mock_core_interface_instance.get_ip_address.return_value = ""
        self.mock_network_interface.side_effect = [
            mock_access_interface_instance,
            mock_core_interface_instance,
        ]
        upf_network = UPFNetwork(
            upf_mode=UpfMode.af_packet,
            access_interface_name=self.access_interface_name,
            access_ip=self.access_ip,
            access_gateway_ip=self.access_gateway_ip,
            access_mtu_size=self.access_interface_mtu_size,
            core_interface_name=self.core_interface_name,
            core_ip=self.core_ip,
            core_gateway_ip=self.core_gateway_ip,
            core_mtu_size=self.core_interface_mtu_size,
            gnb_subnet=self.gnb_subnet,
        )

        upf_network.clean_configuration()

        mock_access_interface_instance.unset_ip_address.assert_called_once()

    def test_given_core_address_set_when_clean_then_unset_address_is_called(self):
        mock_access_interface_instance = MagicMock()
        mock_access_interface_instance.is_valid.return_value = True
        mock_access_interface_instance.get_ip_address.return_value = ""
        mock_core_interface_instance = MagicMock()
        mock_core_interface_instance.is_valid.return_value = True
        mock_core_interface_instance.get_ip_address.return_value = self.core_ip
        self.mock_network_interface.side_effect = [
            mock_access_interface_instance,
            mock_core_interface_instance,
        ]
        upf_network = UPFNetwork(
            upf_mode=UpfMode.af_packet,
            access_interface_name=self.access_interface_name,
            access_ip=self.access_ip,
            access_gateway_ip=self.access_gateway_ip,
            access_mtu_size=self.access_interface_mtu_size,
            core_interface_name=self.core_interface_name,
            core_ip=self.core_ip,
            core_gateway_ip=self.core_gateway_ip,
            core_mtu_size=self.core_interface_mtu_size,
            gnb_subnet=self.gnb_subnet,
        )

        upf_network.clean_configuration()

        mock_core_interface_instance.unset_ip_address.assert_called_once()

    def test_given_access_address_not_set_when_clean_then_unset_address_is_not_called(self):
        mock_access_interface_instance = MagicMock()
        mock_access_interface_instance.is_valid.return_value = True
        mock_access_interface_instance.get_ip_address.return_value = ""
        mock_core_interface_instance = MagicMock()
        mock_core_interface_instance.is_valid.return_value = True
        mock_core_interface_instance.get_ip_address.return_value = self.core_ip
        self.mock_network_interface.side_effect = [
            mock_access_interface_instance,
            mock_core_interface_instance,
        ]
        upf_network = UPFNetwork(
            upf_mode=UpfMode.af_packet,
            access_interface_name=self.access_interface_name,
            access_ip=self.access_ip,
            access_gateway_ip=self.access_gateway_ip,
            access_mtu_size=self.access_interface_mtu_size,
            core_interface_name=self.core_interface_name,
            core_ip=self.core_ip,
            core_gateway_ip=self.core_gateway_ip,
            core_mtu_size=self.core_interface_mtu_size,
            gnb_subnet=self.gnb_subnet,
        )

        upf_network.clean_configuration()

        mock_access_interface_instance.unset_ip_address.assert_not_called()

    def test_given_core_address_not_set_when_clean_then_unset_address_is_not_called(self):
        mock_access_interface_instance = MagicMock()
        mock_access_interface_instance.is_valid.return_value = True
        mock_access_interface_instance.get_ip_address.return_value = self.access_ip
        mock_core_interface_instance = MagicMock()
        mock_core_interface_instance.is_valid.return_value = True
        mock_core_interface_instance.get_ip_address.return_value = ""
        self.mock_network_interface.side_effect = [
            mock_access_interface_instance,
            mock_core_interface_instance,
        ]
        upf_network = UPFNetwork(
            upf_mode=UpfMode.af_packet,
            access_interface_name=self.access_interface_name,
            access_ip=self.access_ip,
            access_gateway_ip=self.access_gateway_ip,
            access_mtu_size=self.access_interface_mtu_size,
            core_interface_name=self.core_interface_name,
            core_ip=self.core_ip,
            core_gateway_ip=self.core_gateway_ip,
            core_mtu_size=self.core_interface_mtu_size,
            gnb_subnet=self.gnb_subnet,
        )

        upf_network.clean_configuration()

        mock_core_interface_instance.unset_ip_address.assert_not_called()

    def test_given_access_mtu_not_set_when_configure_then_mtu_is_set(self):
        mock_access_interface_instance = MagicMock()
        mock_access_interface_instance.is_valid.return_value = True
        mock_access_interface_instance.addresses_are_set.return_value = True
        mock_access_interface_instance.mtu_size_is_set.return_value = False
        mock_core_interface_instance = MagicMock()
        mock_core_interface_instance.is_valid.return_value = True
        mock_core_interface_instance.addresses_are_set.return_value = True
        mock_core_interface_instance.mtu_size_is_set.return_value = True
        self.mock_network_interface.side_effect = [
            mock_access_interface_instance,
            mock_core_interface_instance,
        ]
        upf_network = UPFNetwork(
            upf_mode=UpfMode.af_packet,
            access_interface_name=self.access_interface_name,
            access_ip=self.access_ip,
            access_gateway_ip=self.access_gateway_ip,
            access_mtu_size=self.access_interface_mtu_size,
            core_interface_name=self.core_interface_name,
            core_ip=self.core_ip,
            core_gateway_ip=self.core_gateway_ip,
            core_mtu_size=self.core_interface_mtu_size,
            gnb_subnet=self.gnb_subnet,
        )

        upf_network.configure()

        mock_access_interface_instance.set_mtu_size.assert_called_once()

    def test_given_core_mtu_not_set_when_configure_then_mtu_is_set(self):
        mock_access_interface_instance = MagicMock()
        mock_access_interface_instance.is_valid.return_value = True
        mock_access_interface_instance.addresses_are_set.return_value = True
        mock_access_interface_instance.mtu_size_is_set.return_value = True
        mock_core_interface_instance = MagicMock()
        mock_core_interface_instance.is_valid.return_value = True
        mock_core_interface_instance.addresses_are_set.return_value = True
        mock_core_interface_instance.mtu_size_is_set.return_value = False
        self.mock_network_interface.side_effect = [
            mock_access_interface_instance,
            mock_core_interface_instance,
        ]
        upf_network = UPFNetwork(
            upf_mode=UpfMode.af_packet,
            access_interface_name=self.access_interface_name,
            access_ip=self.access_ip,
            access_gateway_ip=self.access_gateway_ip,
            access_mtu_size=self.access_interface_mtu_size,
            core_interface_name=self.core_interface_name,
            core_ip=self.core_ip,
            core_gateway_ip=self.core_gateway_ip,
            core_mtu_size=self.core_interface_mtu_size,
            gnb_subnet=self.gnb_subnet,
        )

        upf_network.configure()

        mock_core_interface_instance.set_mtu_size.assert_called_once()

    def test_given_access_mtu_set_when_configure_then_set_mtu_size_is_not_called(self):
        mock_access_interface_instance = MagicMock()
        mock_access_interface_instance.is_valid.return_value = True
        mock_access_interface_instance.addresses_are_set.return_value = True
        mock_access_interface_instance.mtu_size_is_set.return_value = True
        mock_core_interface_instance = MagicMock()
        mock_core_interface_instance.is_valid.return_value = True
        mock_core_interface_instance.addresses_are_set.return_value = True
        mock_core_interface_instance.mtu_size_is_set.return_value = True
        self.mock_network_interface.side_effect = [
            mock_access_interface_instance,
            mock_core_interface_instance,
        ]
        upf_network = UPFNetwork(
            upf_mode=UpfMode.af_packet,
            access_interface_name=self.access_interface_name,
            access_ip=self.access_ip,
            access_gateway_ip=self.access_gateway_ip,
            access_mtu_size=self.access_interface_mtu_size,
            core_interface_name=self.core_interface_name,
            core_ip=self.core_ip,
            core_gateway_ip=self.core_gateway_ip,
            core_mtu_size=self.core_interface_mtu_size,
            gnb_subnet=self.gnb_subnet,
        )

        upf_network.configure()

        mock_access_interface_instance.set_mtu_size.assert_not_called()

    def test_given_core_mtu_set_when_configure_then_set_mtu_size_is_not_called(self):
        mock_access_interface_instance = MagicMock()
        mock_access_interface_instance.is_valid.return_value = True
        mock_access_interface_instance.addresses_are_set.return_value = True
        mock_access_interface_instance.mtu_size_is_set.return_value = True
        mock_core_interface_instance = MagicMock()
        mock_core_interface_instance.is_valid.return_value = True
        mock_core_interface_instance.addresses_are_set.return_value = True
        mock_core_interface_instance.mtu_size_is_set.return_value = True
        self.mock_network_interface.side_effect = [
            mock_access_interface_instance,
            mock_core_interface_instance,
        ]
        upf_network = UPFNetwork(
            upf_mode=UpfMode.af_packet,
            access_interface_name=self.access_interface_name,
            access_ip=self.access_ip,
            access_gateway_ip=self.access_gateway_ip,
            access_mtu_size=self.access_interface_mtu_size,
            core_interface_name=self.core_interface_name,
            core_ip=self.core_ip,
            core_gateway_ip=self.core_gateway_ip,
            core_mtu_size=self.core_interface_mtu_size,
            gnb_subnet=self.gnb_subnet,
        )

        upf_network.configure()
        mock_core_interface_instance.set_mtu_size.assert_not_called()

    def test_given_upf_mode_is_dpdk_and_access_mac_address_is_not_set_when_upfnetwork_instantiated_then_value_error_is_raised(  # noqa: E501
        self,
    ):
        with pytest.raises(ValueError, match="Access network interface MAC address is empty"):
            UPFNetwork(
                upf_mode=UpfMode.dpdk,
                access_interface_name=self.access_interface_name,
                access_ip=self.access_ip,
                access_gateway_ip=self.access_gateway_ip,
                access_mtu_size=self.access_interface_mtu_size,
                core_interface_name=self.core_interface_name,
                core_ip=self.core_ip,
                core_gateway_ip=self.core_gateway_ip,
                core_mtu_size=self.core_interface_mtu_size,
                gnb_subnet=self.gnb_subnet,
            )

    def test_given_upf_mode_is_dpdk_and_access_pci_address_is_not_set_when_upfnetwork_instantiated_then_value_error_is_raised(  # noqa: E501
        self,
    ):
        with pytest.raises(ValueError, match="Access network interface PCI address is empty"):
            UPFNetwork(
                upf_mode=UpfMode.dpdk,
                access_interface_name=self.access_interface_name,
                access_ip=self.access_ip,
                access_gateway_ip=self.access_gateway_ip,
                access_mac_address="a:b:c:d",
                access_mtu_size=self.access_interface_mtu_size,
                core_interface_name=self.core_interface_name,
                core_ip=self.core_ip,
                core_gateway_ip=self.core_gateway_ip,
                core_mtu_size=self.core_interface_mtu_size,
                gnb_subnet=self.gnb_subnet,
            )

    def test_given_upf_mode_is_dpdk_and_core_mac_address_is_not_set_when_upfnetwork_instantiated_then_value_error_is_raised(  # noqa: E501
        self,
    ):
        with pytest.raises(ValueError, match="Core network interface MAC address is empty"):
            UPFNetwork(
                upf_mode=UpfMode.dpdk,
                access_interface_name=self.access_interface_name,
                access_ip=self.access_ip,
                access_gateway_ip=self.access_gateway_ip,
                access_mac_address="a:b:c:d",
                access_pci_address="whatever",
                access_mtu_size=self.access_interface_mtu_size,
                core_interface_name=self.core_interface_name,
                core_ip=self.core_ip,
                core_gateway_ip=self.core_gateway_ip,
                core_mtu_size=self.core_interface_mtu_size,
                gnb_subnet=self.gnb_subnet,
            )

    def test_given_upf_mode_is_dpdk_and_core_pci_address_is_not_set_when_upfnetwork_instantiated_then_value_error_is_raised(  # noqa: E501
        self,
    ):
        with pytest.raises(ValueError, match="Core network interface PCI address is empty"):
            UPFNetwork(
                upf_mode=UpfMode.dpdk,
                access_interface_name=self.access_interface_name,
                access_ip=self.access_ip,
                access_gateway_ip=self.access_gateway_ip,
                access_mac_address="a:b:c:d",
                access_pci_address="whatever",
                access_mtu_size=self.access_interface_mtu_size,
                core_interface_name=self.core_interface_name,
                core_ip=self.core_ip,
                core_gateway_ip=self.core_gateway_ip,
                core_mac_address="a:b:c:d",
                core_mtu_size=self.core_interface_mtu_size,
                gnb_subnet=self.gnb_subnet,
            )

    def test_given_upf_mode_is_dpdk_and_access_interface_exists_when_clean_configuration_then_access_interface_is_deleted(  # noqa: E501
        self,
    ):
        mock_access_interface_instance = MagicMock()
        mock_access_interface_instance.is_valid.return_value = True
        mock_access_interface_instance.name = self.access_interface_name
        mock_access_interface_instance.mac_address = "access mac"
        mock_access_interface_instance.alias = "access pci"
        mock_core_interface_instance = MagicMock()
        mock_core_interface_instance.is_valid.return_value = True
        mock_core_interface_instance.name = self.core_interface_name
        mock_core_interface_instance.mac_address = "core mac"
        mock_core_interface_instance.alias = "core pci"

        self.mock_network_interface.side_effect = [
            mock_access_interface_instance,
            mock_core_interface_instance,
        ]

        upf_network = UPFNetwork(
            upf_mode=UpfMode.dpdk,
            access_interface_name=self.access_interface_name,
            access_ip=self.access_ip,
            access_gateway_ip=self.access_gateway_ip,
            access_mac_address="access mac",
            access_pci_address="access pci",
            access_mtu_size=self.access_interface_mtu_size,
            core_interface_name=self.core_interface_name,
            core_ip=self.core_ip,
            core_gateway_ip=self.core_gateway_ip,
            core_mac_address="core mac",
            core_pci_address="core pci",
            core_mtu_size=self.core_interface_mtu_size,
            gnb_subnet=self.gnb_subnet,
        )

        upf_network.clean_configuration()

        mock_access_interface_instance.delete.assert_called_once()

    def test_given_upf_mode_is_dpdk_and_access_interface_doesnt_exist_when_clean_configuration_then_access_interface_is_deleted(  # noqa: E501
        self,
    ):
        mock_access_interface_instance = MagicMock()
        mock_access_interface_instance.is_valid.return_value = True
        mock_access_interface_instance.name = self.access_interface_name

        upf_network = UPFNetwork(
            upf_mode=UpfMode.dpdk,
            access_interface_name=self.access_interface_name,
            access_ip=self.access_ip,
            access_gateway_ip=self.access_gateway_ip,
            access_mac_address="access mac",
            access_pci_address="access pci",
            access_mtu_size=self.access_interface_mtu_size,
            core_interface_name=self.core_interface_name,
            core_ip=self.core_ip,
            core_gateway_ip=self.core_gateway_ip,
            core_mac_address="core mac",
            core_pci_address="core pci",
            core_mtu_size=self.core_interface_mtu_size,
            gnb_subnet=self.gnb_subnet,
        )

        upf_network.clean_configuration()

        mock_access_interface_instance.delete.assert_not_called()

    def test_given_upf_mode_is_dpdk_and_core_interface_exists_when_clean_configuration_then_core_interface_is_deleted(  # noqa: E501
        self,
    ):
        mock_access_interface_instance = MagicMock()
        mock_access_interface_instance.is_valid.return_value = True
        mock_access_interface_instance.name = self.access_interface_name
        mock_access_interface_instance.mac_address = "access mac"
        mock_access_interface_instance.alias = "access pci"
        mock_core_interface_instance = MagicMock()
        mock_core_interface_instance.is_valid.return_value = True
        mock_core_interface_instance.name = self.core_interface_name
        mock_core_interface_instance.mac_address = "core mac"
        mock_core_interface_instance.alias = "core pci"

        self.mock_network_interface.side_effect = [
            mock_access_interface_instance,
            mock_core_interface_instance,
        ]

        upf_network = UPFNetwork(
            upf_mode=UpfMode.dpdk,
            access_interface_name=self.access_interface_name,
            access_ip=self.access_ip,
            access_gateway_ip=self.access_gateway_ip,
            access_mac_address="access mac",
            access_pci_address="access pci",
            access_mtu_size=self.access_interface_mtu_size,
            core_interface_name=self.core_interface_name,
            core_ip=self.core_ip,
            core_gateway_ip=self.core_gateway_ip,
            core_mac_address="core mac",
            core_pci_address="core pci",
            core_mtu_size=self.core_interface_mtu_size,
            gnb_subnet=self.gnb_subnet,
        )

        upf_network.clean_configuration()

        mock_core_interface_instance.delete.assert_called_once()

    def test_given_upf_mode_is_dpdk_and_core_interface_doesnt_exist_when_clean_configuration_then_core_interface_is_deleted(  # noqa: E501
        self,
    ):
        mock_core_interface_instance = MagicMock()
        mock_core_interface_instance.is_valid.return_value = True
        mock_core_interface_instance.name = self.core_interface_name

        upf_network = UPFNetwork(
            upf_mode=UpfMode.dpdk,
            access_interface_name=self.access_interface_name,
            access_ip=self.access_ip,
            access_gateway_ip=self.access_gateway_ip,
            access_mac_address="access mac",
            access_pci_address="access pci",
            access_mtu_size=self.access_interface_mtu_size,
            core_interface_name=self.core_interface_name,
            core_ip=self.core_ip,
            core_gateway_ip=self.core_gateway_ip,
            core_mac_address="core mac",
            core_pci_address="core pci",
            core_mtu_size=self.core_interface_mtu_size,
            gnb_subnet=self.gnb_subnet,
        )

        upf_network.clean_configuration()

        mock_core_interface_instance.delete.assert_not_called()

    def test_given_upf_mode_is_af_packet_when_clean_configuration_then_access_interface_is_not_deleted(  # noqa: E501
        self,
    ):
        mock_access_interface_instance = MagicMock()
        mock_access_interface_instance.is_valid.return_value = True
        mock_access_interface_instance.name = self.access_interface_name
        mock_core_interface_instance = MagicMock()
        mock_core_interface_instance.is_valid.return_value = True
        mock_core_interface_instance.name = self.core_interface_name

        self.mock_network_interface.side_effect = [
            mock_access_interface_instance,
            mock_core_interface_instance,
        ]

        upf_network = UPFNetwork(
            upf_mode=UpfMode.af_packet,
            access_interface_name=self.access_interface_name,
            access_ip=self.access_ip,
            access_gateway_ip=self.access_gateway_ip,
            access_mtu_size=self.access_interface_mtu_size,
            core_interface_name=self.core_interface_name,
            core_ip=self.core_ip,
            core_gateway_ip=self.core_gateway_ip,
            core_mtu_size=self.core_interface_mtu_size,
            gnb_subnet=self.gnb_subnet,
        )

        upf_network.clean_configuration()

        mock_access_interface_instance.delete.assert_not_called()

    def test_given_upf_mode_is_af_packet_when_clean_configuration_then_core_interface_is_not_deleted(  # noqa: E501
        self,
    ):
        mock_access_interface_instance = MagicMock()
        mock_access_interface_instance.is_valid.return_value = True
        mock_access_interface_instance.name = self.access_interface_name
        mock_core_interface_instance = MagicMock()
        mock_core_interface_instance.is_valid.return_value = True
        mock_core_interface_instance.name = self.core_interface_name

        self.mock_network_interface.side_effect = [
            mock_access_interface_instance,
            mock_core_interface_instance,
        ]

        upf_network = UPFNetwork(
            upf_mode=UpfMode.af_packet,
            access_interface_name=self.access_interface_name,
            access_ip=self.access_ip,
            access_gateway_ip=self.access_gateway_ip,
            access_mtu_size=self.access_interface_mtu_size,
            core_interface_name=self.core_interface_name,
            core_ip=self.core_ip,
            core_gateway_ip=self.core_gateway_ip,
            core_mtu_size=self.core_interface_mtu_size,
            gnb_subnet=self.gnb_subnet,
        )

        upf_network.clean_configuration()

        mock_core_interface_instance.delete.assert_not_called()

    def test_given_upf_in_dpdk_mode_and_access_mac_address_not_set_when_configure_then_access_mac_address_is_set(  # noqa: E501
        self,
    ):
        test_access_mac_address = "aa:bb:cc:dd"
        mock_access_interface_instance = MagicMock()
        mock_access_interface_instance.is_valid.return_value = True
        mock_access_interface_instance.name = self.access_interface_name
        mock_access_interface_instance.mac_address_is_set.return_value = False
        mock_core_interface_instance = MagicMock()
        mock_core_interface_instance.is_valid.return_value = True
        mock_core_interface_instance.name = self.core_interface_name
        self.mock_network_interface.side_effect = [
            mock_access_interface_instance,
            mock_core_interface_instance,
        ]
        upf_network = UPFNetwork(
            upf_mode=UpfMode.dpdk,
            access_interface_name=self.access_interface_name,
            access_ip=self.access_ip,
            access_gateway_ip=self.access_gateway_ip,
            access_mac_address=test_access_mac_address,
            access_pci_address="whatever",
            access_mtu_size=self.access_interface_mtu_size,
            core_interface_name=self.core_interface_name,
            core_ip=self.core_ip,
            core_gateway_ip=self.core_gateway_ip,
            core_mac_address="whatever",
            core_pci_address="whatever",
            core_mtu_size=self.core_interface_mtu_size,
            gnb_subnet=self.gnb_subnet,
        )

        upf_network.configure()

        mock_access_interface_instance.set_mac_address.assert_called_once()

    def test_given_upf_in_dpdk_mode_and_access_mac_address_is_set_when_configure_then_access_mac_address_is_not_set(  # noqa: E501
        self,
    ):
        test_access_mac_address = "aa:bb:cc:dd"
        mock_access_interface_instance = MagicMock()
        mock_access_interface_instance.is_valid.return_value = True
        mock_access_interface_instance.name = self.access_interface_name
        mock_access_interface_instance.mac_address_is_set.return_value = True
        mock_core_interface_instance = MagicMock()
        mock_core_interface_instance.is_valid.return_value = True
        mock_core_interface_instance.name = self.core_interface_name
        self.mock_network_interface.side_effect = [
            mock_access_interface_instance,
            mock_core_interface_instance,
        ]
        upf_network = UPFNetwork(
            upf_mode=UpfMode.dpdk,
            access_interface_name=self.access_interface_name,
            access_ip=self.access_ip,
            access_gateway_ip=self.access_gateway_ip,
            access_mac_address=test_access_mac_address,
            access_pci_address="whatever",
            access_mtu_size=self.access_interface_mtu_size,
            core_interface_name=self.core_interface_name,
            core_ip=self.core_ip,
            core_gateway_ip=self.core_gateway_ip,
            core_mac_address="whatever",
            core_pci_address="whatever",
            core_mtu_size=self.core_interface_mtu_size,
            gnb_subnet=self.gnb_subnet,
        )

        upf_network.configure()

        mock_access_interface_instance.set_mac_address.assert_not_called()

    def test_given_upf_in_dpdk_mode_and_access_alias_not_set_when_configure_then_access_alias_is_set(  # noqa: E501
        self,
    ):
        test_access_alias = "0000:01:00.0"
        mock_access_interface_instance = MagicMock()
        mock_access_interface_instance.is_valid.return_value = True
        mock_access_interface_instance.name = self.access_interface_name
        mock_access_interface_instance.mac_address_is_set.return_value = True
        mock_access_interface_instance.alias_is_set.return_value = False
        mock_core_interface_instance = MagicMock()
        mock_core_interface_instance.is_valid.return_value = True
        mock_core_interface_instance.name = self.core_interface_name
        self.mock_network_interface.side_effect = [
            mock_access_interface_instance,
            mock_core_interface_instance,
        ]
        upf_network = UPFNetwork(
            upf_mode=UpfMode.dpdk,
            access_interface_name=self.access_interface_name,
            access_ip=self.access_ip,
            access_gateway_ip=self.access_gateway_ip,
            access_mac_address="whatever",
            access_pci_address=test_access_alias,
            access_mtu_size=self.access_interface_mtu_size,
            core_interface_name=self.core_interface_name,
            core_ip=self.core_ip,
            core_gateway_ip=self.core_gateway_ip,
            core_mac_address="whatever",
            core_pci_address="whatever",
            core_mtu_size=self.core_interface_mtu_size,
            gnb_subnet=self.gnb_subnet,
        )

        upf_network.configure()

        mock_access_interface_instance.set_alias.assert_called_once()

    def test_given_upf_in_dpdk_mode_and_access_alias_is_set_when_configure_then_access_alias_is_not_set(  # noqa: E501
        self,
    ):
        test_access_alias = "0000:01:00.0"
        mock_access_interface_instance = MagicMock()
        mock_access_interface_instance.is_valid.return_value = True
        mock_access_interface_instance.name = self.access_interface_name
        mock_access_interface_instance.mac_address_is_set.return_value = True
        mock_access_interface_instance.alias_is_set.return_value = True
        mock_core_interface_instance = MagicMock()
        mock_core_interface_instance.is_valid.return_value = True
        mock_core_interface_instance.name = self.core_interface_name
        self.mock_network_interface.side_effect = [
            mock_access_interface_instance,
            mock_core_interface_instance,
        ]
        upf_network = UPFNetwork(
            upf_mode=UpfMode.dpdk,
            access_interface_name=self.access_interface_name,
            access_ip=self.access_ip,
            access_gateway_ip=self.access_gateway_ip,
            access_mac_address="whatever",
            access_pci_address=test_access_alias,
            access_mtu_size=self.access_interface_mtu_size,
            core_interface_name=self.core_interface_name,
            core_ip=self.core_ip,
            core_gateway_ip=self.core_gateway_ip,
            core_mac_address="whatever",
            core_pci_address="whatever",
            core_mtu_size=self.core_interface_mtu_size,
            gnb_subnet=self.gnb_subnet,
        )

        upf_network.configure()

        mock_access_interface_instance.set_alias.assert_not_called()

    def test_given_upf_in_dpdk_mode_and_core_mac_address_not_set_when_configure_then_core_mac_address_is_set(  # noqa: E501
        self,
    ):
        test_core_mac_address = "aa:bb:cc:dd"
        mock_access_interface_instance = MagicMock()
        mock_access_interface_instance.is_valid.return_value = True
        mock_access_interface_instance.name = self.access_interface_name
        mock_access_interface_instance.mac_address_is_set.return_value = False
        mock_access_interface_instance.alias_is_set.return_value = True
        mock_core_interface_instance = MagicMock()
        mock_core_interface_instance.is_valid.return_value = True
        mock_core_interface_instance.name = self.core_interface_name
        mock_core_interface_instance.mac_address_is_set.return_value = False
        self.mock_network_interface.side_effect = [
            mock_access_interface_instance,
            mock_core_interface_instance,
        ]
        upf_network = UPFNetwork(
            upf_mode=UpfMode.dpdk,
            access_interface_name=self.access_interface_name,
            access_ip=self.access_ip,
            access_gateway_ip=self.access_gateway_ip,
            access_mac_address="whatever",
            access_pci_address="whatever",
            access_mtu_size=self.access_interface_mtu_size,
            core_interface_name=self.core_interface_name,
            core_ip=self.core_ip,
            core_gateway_ip=self.core_gateway_ip,
            core_mac_address=test_core_mac_address,
            core_pci_address="whatever",
            core_mtu_size=self.core_interface_mtu_size,
            gnb_subnet=self.gnb_subnet,
        )

        upf_network.configure()

        mock_access_interface_instance.set_mac_address.assert_called_once()

    def test_given_upf_in_dpdk_mode_and_core_mac_address_is_set_when_configure_then_access_mac_core_is_not_set(  # noqa: E501
        self,
    ):
        test_core_mac_address = "aa:bb:cc:dd"
        mock_access_interface_instance = MagicMock()
        mock_access_interface_instance.is_valid.return_value = True
        mock_access_interface_instance.name = self.access_interface_name
        mock_access_interface_instance.mac_address_is_set.return_value = True
        mock_access_interface_instance.alias_is_set.return_value = True
        mock_core_interface_instance = MagicMock()
        mock_core_interface_instance.is_valid.return_value = True
        mock_core_interface_instance.name = self.core_interface_name
        mock_core_interface_instance.mac_address_is_set.return_value = True
        self.mock_network_interface.side_effect = [
            mock_access_interface_instance,
            mock_core_interface_instance,
        ]
        upf_network = UPFNetwork(
            upf_mode=UpfMode.dpdk,
            access_interface_name=self.access_interface_name,
            access_ip=self.access_ip,
            access_gateway_ip=self.access_gateway_ip,
            access_mac_address="whatever",
            access_pci_address="whatever",
            access_mtu_size=self.access_interface_mtu_size,
            core_interface_name=self.core_interface_name,
            core_ip=self.core_ip,
            core_gateway_ip=self.core_gateway_ip,
            core_mac_address=test_core_mac_address,
            core_pci_address="whatever",
            core_mtu_size=self.core_interface_mtu_size,
            gnb_subnet=self.gnb_subnet,
        )

        upf_network.configure()

        mock_core_interface_instance.set_mac_address.assert_not_called()

    def test_given_upf_in_dpdk_mode_and_core_alias_not_set_when_configure_then_core_alias_is_set(
        self,
    ):
        test_core_alias = "0000:01:00.0"
        mock_access_interface_instance = MagicMock()
        mock_access_interface_instance.is_valid.return_value = True
        mock_access_interface_instance.name = self.access_interface_name
        mock_access_interface_instance.mac_address_is_set.return_value = True
        mock_access_interface_instance.alias_is_set.return_value = False
        mock_core_interface_instance = MagicMock()
        mock_core_interface_instance.is_valid.return_value = True
        mock_core_interface_instance.name = self.core_interface_name
        mock_core_interface_instance.mac_address_is_set.return_value = True
        mock_core_interface_instance.alias_is_set.return_value = False
        self.mock_network_interface.side_effect = [
            mock_access_interface_instance,
            mock_core_interface_instance,
        ]
        upf_network = UPFNetwork(
            upf_mode=UpfMode.dpdk,
            access_interface_name=self.access_interface_name,
            access_ip=self.access_ip,
            access_gateway_ip=self.access_gateway_ip,
            access_mac_address="whatever",
            access_pci_address="whatever",
            access_mtu_size=self.access_interface_mtu_size,
            core_interface_name=self.core_interface_name,
            core_ip=self.core_ip,
            core_gateway_ip=self.core_gateway_ip,
            core_mac_address="whatever",
            core_pci_address=test_core_alias,
            core_mtu_size=self.core_interface_mtu_size,
            gnb_subnet=self.gnb_subnet,
        )

        upf_network.configure()

        mock_core_interface_instance.set_alias.assert_called_once()

    def test_given_upf_in_dpdk_mode_and_core_alias_is_set_when_configure_then_core_alias_is_not_set(  # noqa: E501
        self,
    ):
        test_core_alias = "0000:01:00.0"
        mock_access_interface_instance = MagicMock()
        mock_access_interface_instance.is_valid.return_value = True
        mock_access_interface_instance.name = self.access_interface_name
        mock_access_interface_instance.mac_address_is_set.return_value = True
        mock_access_interface_instance.alias_is_set.return_value = True
        mock_core_interface_instance = MagicMock()
        mock_core_interface_instance.is_valid.return_value = True
        mock_core_interface_instance.name = self.core_interface_name
        mock_core_interface_instance.mac_address_is_set.return_value = True
        mock_core_interface_instance.alias_is_set_return_value = True
        self.mock_network_interface.side_effect = [
            mock_access_interface_instance,
            mock_core_interface_instance,
        ]
        upf_network = UPFNetwork(
            upf_mode=UpfMode.dpdk,
            access_interface_name=self.access_interface_name,
            access_ip=self.access_ip,
            access_gateway_ip=self.access_gateway_ip,
            access_mac_address="whatever",
            access_pci_address="whatever",
            access_mtu_size=self.access_interface_mtu_size,
            core_interface_name=self.core_interface_name,
            core_ip=self.core_ip,
            core_gateway_ip=self.core_gateway_ip,
            core_mac_address="whatever",
            core_pci_address=test_core_alias,
            core_mtu_size=self.core_interface_mtu_size,
            gnb_subnet=self.gnb_subnet,
        )

        upf_network.configure()

        mock_core_interface_instance.set_alias.assert_not_called()

    def test_given_interfaces_are_down_when_configure_then_bring_up_interface_is_called_for_both_interfaces(  # noqa: E501
        self,
    ):
        mock_access_interface_instance = MagicMock()
        mock_access_interface_instance.is_valid.return_value = True
        mock_access_interface_instance.addresses_are_set.return_value = True
        mock_access_interface_instance.mtu_size_is_set.return_value = True
        mock_access_interface_instance.interface_is_up.return_value = False
        mock_core_interface_instance = MagicMock()
        mock_core_interface_instance.is_valid.return_value = True
        mock_core_interface_instance.addresses_are_set.return_value = True
        mock_core_interface_instance.mtu_size_is_set.return_value = True
        mock_core_interface_instance.interface_is_up.return_value = False
        self.mock_network_interface.side_effect = [
            mock_access_interface_instance,
            mock_core_interface_instance,
        ]
        upf_network = UPFNetwork(
            upf_mode=UpfMode.af_packet,
            access_interface_name=self.access_interface_name,
            access_ip=self.access_ip,
            access_gateway_ip=self.access_gateway_ip,
            access_mtu_size=self.access_interface_mtu_size,
            core_interface_name=self.core_interface_name,
            core_ip=self.core_ip,
            core_gateway_ip=self.core_gateway_ip,
            core_mtu_size=self.core_interface_mtu_size,
            gnb_subnet=self.gnb_subnet,
        )

        upf_network.configure()

        mock_access_interface_instance.bring_up_interface.assert_called_once()
        mock_core_interface_instance.bring_up_interface.assert_called_once()

    def test_given_interfaces_are_up_when_configure_then_bring_up_interface_is_not_called(self):
        mock_access_interface_instance = MagicMock()
        mock_access_interface_instance.is_valid.return_value = True
        mock_access_interface_instance.addresses_are_set.return_value = True
        mock_access_interface_instance.mtu_size_is_set.return_value = True
        mock_access_interface_instance.interface_is_up.return_value = True
        mock_core_interface_instance = MagicMock()
        mock_core_interface_instance.is_valid.return_value = True
        mock_core_interface_instance.addresses_are_set.return_value = True
        mock_core_interface_instance.mtu_size_is_set.return_value = True
        mock_core_interface_instance.interface_is_up.return_value = True
        self.mock_network_interface.side_effect = [
            mock_access_interface_instance,
            mock_core_interface_instance,
        ]
        upf_network = UPFNetwork(
            upf_mode=UpfMode.af_packet,
            access_interface_name=self.access_interface_name,
            access_ip=self.access_ip,
            access_gateway_ip=self.access_gateway_ip,
            access_mtu_size=self.access_interface_mtu_size,
            core_interface_name=self.core_interface_name,
            core_ip=self.core_ip,
            core_gateway_ip=self.core_gateway_ip,
            core_mtu_size=self.core_interface_mtu_size,
            gnb_subnet=self.gnb_subnet,
        )

        upf_network.configure()

        mock_access_interface_instance.bring_up_interface.assert_not_called()
        mock_core_interface_instance.bring_up_interface.assert_not_called()
