# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import unittest
from dataclasses import dataclass
from typing import AnyStr, List, Optional, Sequence, Tuple

from machine import ExecError
from network import Network, ip_is_valid


@dataclass
class NetworkInterface:
    name: str
    ip: str
    gateway_ip: str


class MockProcessExec:
    def __init__(
        self,
        command: Sequence[str],
        network_interfaces: List[NetworkInterface] = [],
        gnb_subnet: str = "",
        ip_tables_rule_exists: bool = False,
        default_route_created: bool = False,
        ran_route_created: bool = False,
    ):
        self.command = command
        self.network_interfaces = network_interfaces
        self.ip_tables_rule_exists = ip_tables_rule_exists
        self.default_route_created = default_route_created
        self.ran_route_created = ran_route_created
        self.gnb_subnet = gnb_subnet
        self.stdout = "whatever stdout"
        self.stderr = "whatever stderr"

    def wait_output(self) -> Tuple[AnyStr, Optional[AnyStr]]:
        """Return the stdout and stderr of the command."""
        command_str = " ".join(self.command)
        if "ip addr show" in command_str:
            interface_name = self.command[-1]
            return self._ip_addr_show_example_output(interface_name), None
        if "ip route show default 0.0.0.0/0 dev" in command_str:
            interface_name = self.command[-1]
            return self._ip_route_show_example_output(interface_name), None
        if "ip route show default" in command_str:
            return self._default_route_example_output(), None
        if "ip route show" in command_str:
            return self._ran_route_example_output(), None
        if (
            "iptables-legacy --check OUTPUT -p icmp --icmp-type port-unreachable -j DROP"
            in command_str
        ):
            if not self.ip_tables_rule_exists:
                raise ExecError(
                    command=self.command,
                    exit_code=1,
                    stdout="",
                    stderr="iptables: Bad rule (does a matching rule exist in that chain?).\n",
                )
        return self.stdout, self.stderr

    def _get_interface_ip_address(self, interface_name: str) -> str:
        """Return the IP address of the given interface name."""
        if not self.network_interfaces:
            return ""
        return next(
            (
                interface.ip
                for interface in self.network_interfaces
                if interface.name == interface_name
            ),
            "",
        )

    def _get_interface_default_gateway(self, interface_name: str) -> str:
        """Return the default gateway of the given interface name."""
        if not self.network_interfaces:
            return ""
        return next(
            (
                interface.gateway_ip
                for interface in self.network_interfaces
                if interface.name == interface_name
            ),
            "",
        )

    def _ip_addr_show_example_output(self, interface_name: str) -> str:
        """Return an example output of `ip addr show` for the given interface name."""
        if not self.network_interfaces:
            return ""
        interface_ip_address = self._get_interface_ip_address(interface_name)
        return f"""
3: {interface_name}: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 52:54:00:f4:08:c3 brd ff:ff:ff:ff:ff:ff
    inet {interface_ip_address} metric 200 brd 192.168.252.255 scope global dynamic enp6s0
       valid_lft 2057sec preferred_lft 2057sec
    inet6 fd42:5e03:3e68:286a:5054:ff:fef4:8c3/64 scope global mngtmpaddr noprefixroute
       valid_lft forever preferred_lft forever
    inet6 fe80::5054:ff:fef4:8c3/64 scope link
       valid_lft forever preferred_lft forever
    """

    def _ip_route_show_example_output(self, interface_name: str) -> str:
        """Return an example output of `ip route show default`."""
        if not self.network_interfaces:
            return ""
        interface_ip_address = self._get_interface_ip_address(interface_name)
        interface_default_gateway = self._get_interface_default_gateway(interface_name)
        return f"default via {interface_default_gateway} proto dhcp src {interface_ip_address} metric 600"

    def _default_route_example_output(self) -> str:
        """Return an example output of `ip route show default`."""
        if not self.network_interfaces:
            return ""
        interface_default_gateway = "1.1.1.1"
        if self.default_route_created:
            interface_name = self.network_interfaces[1].name
            interface_default_gateway = self._get_interface_default_gateway(interface_name)
        return f"default via {interface_default_gateway}"

    def _ran_route_example_output(self) -> str:
        """Return an example output of `ip route show`."""
        if not self.network_interfaces:
            return ""
        if self.ran_route_created:
            interface_name = self.network_interfaces[0].name
            interface_default_gateway = self._get_interface_default_gateway(interface_name)
            return f"{self.gnb_subnet} via {interface_default_gateway}"
        return ""


class MockMachine:
    def __init__(
        self,
        network_interfaces: List[NetworkInterface] = [],
        gnb_subnet: str = "",
        ip_tables_rule_exists: bool = False,
        default_route_created: bool = False,
        ran_route_created: bool = False,
    ):
        self.network_interfaces = network_interfaces
        self.gnb_subnet = gnb_subnet
        self.ip_tables_rule_exists = ip_tables_rule_exists
        self.default_route_created = default_route_created
        self.ran_route_created = ran_route_created
        self.exec_calls = []
        self.exec_called = False
        self.exec_called_with = None

    def exists(self, path: str) -> bool:
        if "/sys/class/net/" in path:
            return path.split("/")[-1] in [interface.name for interface in self.network_interfaces]
        return True

    def exec(self, command: Sequence[str]) -> MockProcessExec:
        self.exec_called = True
        self.exec_called_with = command
        self.exec_calls.append(command)
        return MockProcessExec(
            command=command,
            network_interfaces=self.network_interfaces,
            gnb_subnet=self.gnb_subnet,
            ip_tables_rule_exists=self.ip_tables_rule_exists,
            default_route_created=self.default_route_created,
            ran_route_created=self.ran_route_created,
        )


class TestNetwork(unittest.TestCase):

    def setUp(self):
        self.access_interface_name = "eth0"
        self.core_interface_name = "eth1"
        self.access_interface_ip = "192.168.252.3/24"
        self.core_interface_ip = "192.168.250.3/24"
        self.access_interface_gateway_ip = "192.168.252.1"
        self.core_interface_gateway_ip = "192.168.250.1"
        self.gnb_subnet = "192.168.1.0/24"
        self.mock_machine = MockMachine(
            network_interfaces=[
                NetworkInterface(
                    name=self.access_interface_name,
                    ip=self.access_interface_ip,
                    gateway_ip=self.access_interface_gateway_ip,
                ),
                NetworkInterface(
                    name=self.core_interface_name,
                    ip=self.core_interface_ip,
                    gateway_ip=self.core_interface_gateway_ip,
                ),
            ],
            gnb_subnet=self.gnb_subnet,
        )
        self.network = Network(
            machine=self.mock_machine,
            access_interface_name=self.access_interface_name,
            core_interface_name=self.core_interface_name,
            gnb_subnet=self.gnb_subnet,
        )

    def test_given_valid_interfaces_when_get_invalid_network_interfaces_then_return_empty_list(
        self,
    ):
        invalid_network_interfaces = self.network.get_invalid_network_interfaces()

        self.assertEqual(invalid_network_interfaces, [])

    def test_given_invalid_interfaces_when_get_invalid_network_interfaces_then_return_invalid_interfaces(
        self,
    ):
        self.mock_machine.network_interfaces = []

        invalid_network_interfaces = self.network.get_invalid_network_interfaces()

        self.assertEqual(invalid_network_interfaces, ["eth0", "eth1"])

    def test_given_iptable_rule_doesnt_exist_when_configure_then_rule_is_created(self):
        self.mock_machine.ip_tables_rule_exists = False

        self.network.configure()

        self.assertIn(
            "iptables-legacy -I OUTPUT -p icmp --icmp-type port-unreachable -j DROP".split(" "),
            self.mock_machine.exec_calls,
        )

    def test_given_iptable_rule_exists_when_configure_then_rule_is_not_created(self):
        self.mock_machine.ip_tables_rule_exists = True

        self.network.configure()

        self.assertNotIn(
            "iptables-legacy -I OUTPUT -p icmp --icmp-type port-unreachable -j DROP".split(" "),
            self.mock_machine.exec_calls,
        )

    def test_given_default_route_not_created_when_configure_then_route_created(self):
        self.mock_machine.default_route_created = False

        self.network.configure()

        self.assertIn(
            f"ip route replace default via {self.core_interface_gateway_ip} metric 110".split(" "),
            self.mock_machine.exec_calls,
        )

    def test_given_default_route_created_when_configure_then_route_not_created(self):
        self.mock_machine.default_route_created = True

        self.network.configure()

        self.assertNotIn(
            f"ip route replace default via {self.core_interface_gateway_ip} metric 110".split(" "),
            self.mock_machine.exec_calls,
        )

    def test_given_ran_route_not_created_when_configure_then_route_created(self):
        self.mock_machine.ran_route_created = False

        self.network.configure()

        self.assertIn(
            f"ip route replace {self.gnb_subnet} via {self.access_interface_gateway_ip}".split(
                " "
            ),
            self.mock_machine.exec_calls,
        )

    def test_given_ran_route_created_when_configure_then_route_not_created(self):
        self.mock_machine.ran_route_created = True

        self.network.configure()

        self.assertNotIn(
            f"ip route replace {self.gnb_subnet} via {self.access_interface_gateway_ip}".split(
                " "
            ),
            self.mock_machine.exec_calls,
        )

    def test_given_ip_address_exists_when_get_interface_ip_address_then_return_ip_address(self):
        ip_address = self.network.get_interface_ip_address(self.access_interface_name)

        self.assertEqual(ip_address, self.access_interface_ip.split("/")[0])

    def test_given_ip_address_doesnt_exist_when_get_interface_ip_address_then_return_empty_string(
        self,
    ):
        self.mock_machine.network_interfaces = []

        ip_address = self.network.get_interface_ip_address(self.access_interface_name)

        self.assertEqual(ip_address, "")

    def test_given_invalid_ip_when_ip_is_valid_then_return_false(self):
        invalid_ip = "192.168.1.256"

        assert not ip_is_valid(invalid_ip)

    def test_given_valid_ip_when_ip_is_valid_then_return_true(self):
        valid_ip = "1.2.3.4"

        assert ip_is_valid(valid_ip)
