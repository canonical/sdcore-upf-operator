# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import unittest
from dataclasses import dataclass
from typing import AnyStr, List, Optional, Sequence, Tuple

from machine import ExecError
from network import Network


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
        ip_tables_rule_exists: bool = False,
    ):
        self.command = command
        self.network_interfaces = network_interfaces
        self.ip_tables_rule_exists = ip_tables_rule_exists
        self.stdout = "whatever stdout"
        self.stderr = "whatever stderr"

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

    def wait_output(self) -> Tuple[AnyStr, Optional[AnyStr]]:
        """Return the stdout and stderr of the command."""
        command_str = " ".join(self.command)
        if "ip addr show" in command_str:
            interface_name = self.command[-1]
            return self._ip_addr_show_example_output(interface_name), None
        if "ip route show default 0.0.0.0/0 dev" in command_str:
            interface_name = self.command[-1]
            return self._ip_route_show_example_output(interface_name), None
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


class MockMachine:
    def __init__(
        self,
        exists_return_value: bool = False,
        pull_return_value: str = "",
        network_interfaces: List[NetworkInterface] = [],
        ip_tables_rule_exists: bool = False,
    ):
        self.exists_return_value = exists_return_value
        self.pull_return_value = pull_return_value
        self.push_called = False
        self.push_called_with = None
        self.network_interfaces = network_interfaces
        self.ip_tables_rule_exists = ip_tables_rule_exists
        self.exec_calls = []
        self.exec_called = False
        self.exec_called_with = None

    def exists(self, path: str) -> bool:
        if "/sys/class/net/" in path:
            return path.split("/")[-1] in [interface.name for interface in self.network_interfaces]
        return self.exists_return_value

    def push(self, path: str, source: str) -> None:
        self.push_called = True
        self.push_called_with = {"path": path, "source": source}

    def pull(self, path: str) -> str:
        return self.pull_return_value

    def make_dir(self, path: str) -> None:
        pass

    def exec(self, command: Sequence[str]) -> MockProcessExec:
        self.exec_called = True
        self.exec_called_with = command
        self.exec_calls.append(command)
        return MockProcessExec(
            command=command,
            network_interfaces=self.network_interfaces,
            ip_tables_rule_exists=self.ip_tables_rule_exists,
        )


class TestNetwork(unittest.TestCase):

    def setUp(self):
        self.mock_machine = MockMachine(
            network_interfaces=[
                NetworkInterface(name="eth0", ip="192.168.252.3/24", gateway_ip="192.168.252.1"),
                NetworkInterface(name="eth1", ip="192.168.250.3/24", gateway_ip="192.168.250.1"),
            ]
        )
        self.access_interface_name = "eth0"
        self.core_interface_name = "eth1"
        self.gnb_subnet = "192.168.1.0/24"
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
        self.network = Network(
            machine=self.mock_machine,
            access_interface_name=self.access_interface_name,
            core_interface_name=self.core_interface_name,
            gnb_subnet=self.gnb_subnet,
        )

        invalid_network_interfaces = self.network.get_invalid_network_interfaces()

        self.assertEqual(invalid_network_interfaces, ["eth0", "eth1"])

    def test_given_rules_dont_exist_when_configure_then_routes_are_created(self):

        self.network.configure()

        core_interface_gateway_ip = next(
            (
                interface.gateway_ip
                for interface in self.mock_machine.network_interfaces
                if interface.name == self.core_interface_name
            ),
            "",
        )
        access_interface_gateway_ip = next(
            (
                interface.gateway_ip
                for interface in self.mock_machine.network_interfaces
                if interface.name == self.access_interface_name
            ),
            "",
        )
        self.assertIn(
            f"ip route replace default via {core_interface_gateway_ip} metric 110".split(" "),
            self.mock_machine.exec_calls,
        )
        self.assertIn(
            f"ip route replace {self.gnb_subnet} via {access_interface_gateway_ip}".split(" "),
            self.mock_machine.exec_calls,
        )
        self.assertIn(
            "iptables-legacy -I OUTPUT -p icmp --icmp-type port-unreachable -j DROP".split(" "),
            self.mock_machine.exec_calls,
        )
