# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import json
import unittest
from dataclasses import dataclass
from typing import AnyStr, List, Optional, Sequence, Tuple
from unittest.mock import patch

import ops
import ops.testing
from charm import SdcoreUpfCharm
from charms.operator_libs_linux.v2.snap import SnapState
from machine import ExecError


@dataclass
class NetworkInterface:
    name: str
    ip: str
    gateway_ip: str


def read_file(path: str) -> str:
    """Read a file and returns as a string.

    Args:
        path (str): path to the file.

    Returns:
        str: content of the file.
    """
    with open(path, "r") as f:
        content = f.read()
    return content


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


class MockSnapObject:
    def __init__(self, name):
        self.name = name
        self.ensure_called = False
        self.ensure_called_with = None
        self.hold_called = False

    def ensure(
        self,
        state,
        classic: Optional[bool] = False,
        devmode: Optional[bool] = False,
        channel: Optional[str] = "",
        cohort: Optional[str] = "",
        revision: Optional[str] = None,
    ):
        self.ensure_called = True
        self.ensure_called_with = (state, classic, devmode, channel, cohort, revision)

    def hold(self):
        self.hold_called = True

    def start(self, services: Optional[List[str]] = None, enable: Optional[bool] = False) -> None:
        self.start_called = True
        self.start_called_with = {"services": services, "enable": enable}


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


class TestCharm(unittest.TestCase):
    @patch("charm.Machine")
    def setUp(self, patch_machine):
        self.mock_machine = MockMachine(
            network_interfaces=[
                NetworkInterface(name="eth0", ip="192.168.252.3/24", gateway_ip="192.168.252.1"),
                NetworkInterface(name="eth1", ip="192.168.250.3/24", gateway_ip="192.168.250.1"),
            ]
        )
        patch_machine.return_value = self.mock_machine
        self.harness = ops.testing.Harness(SdcoreUpfCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

    def test_given_unit_is_not_leader_when_config_changed_then_status_is_blocked(self):
        self.harness.set_leader(False)

        self.harness.update_config()

        self.assertEqual(
            self.harness.model.unit.status,
            ops.BlockedStatus("Scaling is not implemented for this charm"),
        )

    @patch("charms.operator_libs_linux.v2.snap.SnapCache")
    def test_given_upf_snap_uninstalled_when_configure_then_upf_snap_installed(
        self, mock_snap_cache
    ):
        self.harness.set_leader(is_leader=True)
        upf_snap = MockSnapObject("upf")
        snap_cache = {"sdcore-upf": upf_snap}
        mock_snap_cache.return_value = snap_cache

        self.harness.charm.on.install.emit()

        mock_snap_cache.assert_called_with()
        assert upf_snap.ensure_called
        assert upf_snap.ensure_called_with == (
            SnapState.Latest,
            False,
            True,
            "latest/edge",
            "",
            "3",
        )
        assert upf_snap.hold_called

    @patch("charms.operator_libs_linux.v2.snap.SnapCache")
    def test_given_unit_is_leader_when_config_changed_then_status_is_active(self, mock_snap_cache):
        self.harness.set_leader(True)
        upf_snap = MockSnapObject("sdcore-upf")
        snap_cache = {"sdcore-upf": upf_snap}
        mock_snap_cache.return_value = snap_cache

        self.harness.update_config()

        self.assertEqual(self.harness.model.unit.status, ops.ActiveStatus())

    @patch("charms.operator_libs_linux.v2.snap.SnapCache")
    def test_given_config_file_not_written_when_config_changed_then_config_file_is_written(
        self, _
    ):
        self.harness.set_leader(True)
        self.mock_machine.exists_return_value = False

        self.harness.update_config()

        expected_config_file_content = read_file("tests/unit/expected_upf.json").strip()
        assert self.mock_machine.push_called
        assert json.loads(expected_config_file_content) == json.loads(
            self.mock_machine.push_called_with["source"]
        )
        assert self.mock_machine.push_called_with["path"] == "/var/snap/sdcore-upf/common/upf.json"

    @patch("charms.operator_libs_linux.v2.snap.SnapCache")
    def test_given_config_file_written_with_different_content_when_config_changed_then_new_config_file_is_written(
        self, _
    ):
        self.harness.set_leader(True)
        self.mock_machine.exists_return_value = True
        self.mock_machine.pull_return_value = "initial content"

        self.harness.update_config()

        expected_config_file_content = read_file("tests/unit/expected_upf.json").strip()
        assert self.mock_machine.push_called
        assert json.loads(expected_config_file_content) == json.loads(
            self.mock_machine.push_called_with["source"]
        )
        assert self.mock_machine.push_called_with["path"] == "/var/snap/sdcore-upf/common/upf.json"

    @patch("charms.operator_libs_linux.v2.snap.SnapCache")
    def test_given_config_file_written_with_identical_content_when_config_changed_then_new_config_file_not_written(
        self, _
    ):
        self.harness.set_leader(True)
        self.mock_machine.exists_return_value = True
        self.mock_machine.pull_return_value = read_file("tests/unit/expected_upf.json").strip()

        self.harness.update_config()

        assert not self.mock_machine.push_called

    def test_given_invalid_config_when_config_changed_then_status_is_blocked(self):
        self.harness.set_leader(True)
        self.harness.update_config({"gnb-subnet": "not an ip subnet"})

        self.assertEqual(
            self.harness.model.unit.status,
            ops.BlockedStatus("The following configurations are not valid: ['gnb-subnet']"),
        )

    @patch("charms.operator_libs_linux.v2.snap.SnapCache")
    def test_given_network_interfaces_not_valid_when_config_changed_then_status_is_blocked(
        self, _
    ):
        self.mock_machine.network_interfaces = []
        self.harness.set_leader(True)
        self.harness.update_config()

        self.assertEqual(
            self.harness.model.unit.status,
            ops.BlockedStatus("Network interfaces are not valid: ['eth0', 'eth1']"),
        )

    @patch("charms.operator_libs_linux.v2.snap.SnapCache")
    def test_given_network_interfaces_valid_when_config_changed_then_routes_are_created(self, _):
        gnb_subnet = "192.168.251.0/24"
        self.harness.set_leader(True)
        self.harness.update_config(
            {
                "gnb-subnet": gnb_subnet,
                "core-interface-name": "eth0",
                "access-interface-name": "eth1",
            }
        )

        assert self.mock_machine.exec_called
        core_interface_gateway_ip = next(
            (
                interface.gateway_ip
                for interface in self.mock_machine.network_interfaces
                if interface.name == "eth0"
            ),
            "",
        )
        access_interface_gateway_ip = next(
            (
                interface.gateway_ip
                for interface in self.mock_machine.network_interfaces
                if interface.name == "eth1"
            ),
            "",
        )
        assert (
            f"ip route replace default via {core_interface_gateway_ip} metric 110".split(" ")
            in self.mock_machine.exec_calls
        )
        assert (
            f"ip route replace {gnb_subnet} via {access_interface_gateway_ip}".split(" ")
            in self.mock_machine.exec_calls
        )
        assert (
            "iptables-legacy -I OUTPUT -p icmp --icmp-type port-unreachable -j DROP".split(" ")
            in self.mock_machine.exec_calls
        )
