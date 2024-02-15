#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Abstract the network configuration for the UPF service."""
import ipaddress
import logging
import re
from typing import List

from machine import ExecError, Machine

logger = logging.getLogger(__name__)


class Network:
    """Abstract the network configuration for the UPF service."""

    def __init__(
        self,
        machine: Machine,
        access_interface_name: str,
        core_interface_name: str,
        gnb_subnet: str,
    ):
        self.machine = machine
        self.access_interface_name = access_interface_name
        self.core_interface_name = core_interface_name
        self.gnb_subnet = gnb_subnet

    def get_invalid_network_interfaces(self) -> List[str]:
        """Return whether the network interfaces are valid.

        The network interface is valid if it exists and has a valid IP address.
        """
        invalid_network_interfaces = []
        if not self.access_interface_name:
            raise ValueError("Access network interface name is empty")
        if not self.core_interface_name:
            raise ValueError("Core network interface name is empty")
        if not self._interface_is_valid(self.access_interface_name):
            invalid_network_interfaces.append(self.access_interface_name)
            logger.warning("Access network interface %s is not valid", self.access_interface_name)
        if not self._interface_is_valid(self.core_interface_name):
            invalid_network_interfaces.append(self.core_interface_name)
            logger.warning("Core network interface %s is not valid", self.core_interface_name)
        return invalid_network_interfaces

    def configure(self) -> None:
        """Configure the network for the UPF service.

        - Create the default route for the core network
        - Create the route to the gNB subnet
        - Create iptables rule in the OUTPUT chain to block ICMP port-unreachable packets
        """
        if not self._default_route_exists():
            self._create_default_route()
        if not self._ran_route_exists():
            self._create_ran_route()
        if not self._ip_tables_rule_exists():
            self._create_ip_tables_rule()

    def get_interface_ip_address(self, interface_name: str) -> str:
        """Get the IP address of the given network interface."""
        try:
            stdout, _ = self._exec_command_in_workload(command=f"ip addr show {interface_name}")
        except ExecError:
            logger.warning("Failed to get IP address for interface %s", interface_name)
            return ""
        match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/", stdout)
        if match:
            return match.group(1)
        return ""

    def _get_interface_gateway_ip_address(self, interface_name: str) -> str:
        """Get the gateway IP address of the given network interface."""
        try:
            stdout, _ = self._exec_command_in_workload(
                command=f"ip route show default 0.0.0.0/0 dev {interface_name}"
            )
        except ExecError:
            logger.warning("Failed to get gateway IP address for interface %s", interface_name)
            return ""
        match = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", stdout)
        if match:
            return match.group(1)
        return ""

    def _default_route_exists(self) -> bool:
        """Return whether the default route already exists."""
        stdout, stderr = self._exec_command_in_workload(command="ip route show default")
        if stderr:
            logger.warning("Failed to get default route")
            return False
        return f"default via {self._get_core_network_gateway_ip()}" in stdout

    def _ran_route_exists(self) -> bool:
        """Return whether the ran route already exists."""
        stdout, stderr = self._exec_command_in_workload(command="ip route show")
        if stderr:
            logger.warning("Failed to get ran route")
            return False
        return f"{self.gnb_subnet} via {self._get_access_network_gateway_ip()}" in stdout

    def _get_core_network_gateway_ip(self) -> str:
        """Get the gateway IP address of the core network."""
        return self._get_interface_gateway_ip_address(self.core_interface_name)

    def _get_access_network_gateway_ip(self) -> str:
        """Get the gateway IP address of the access network."""
        return self._get_interface_gateway_ip_address(self.access_interface_name)

    def _create_default_route(self) -> None:
        """Create the default route for the core network."""
        self._exec_command_in_workload(
            f"ip route replace default via {self._get_core_network_gateway_ip()} metric 110"
        )
        logger.info("Default core network route created")

    def _create_ran_route(self) -> None:
        """Create ip route towards gnb-subnet."""
        self._exec_command_in_workload(
            command=f"ip route replace {self.gnb_subnet} via {self._get_access_network_gateway_ip()}"
        )
        logger.info("Route to gnb-subnet created")

    def _ip_tables_rule_exists(self) -> bool:
        """Return whether iptables rule already exists using the `--check` parameter."""
        try:
            self._exec_command_in_workload(
                command="iptables-legacy --check OUTPUT -p icmp --icmp-type port-unreachable -j DROP"
            )
            return True
        except ExecError:
            return False

    def _create_ip_tables_rule(self) -> None:
        """Create iptable rule in the OUTPUT chain to block ICMP port-unreachable packets."""
        self._exec_command_in_workload(
            command="iptables-legacy -I OUTPUT -p icmp --icmp-type port-unreachable -j DROP"
        )
        logger.info("Iptables rule for ICMP created")

    def _interface_is_valid(self, interface_name: str) -> bool:
        """Return whether the given network interface is valid.

        The network interface is valid if it exists and has a valid IP address.
        """
        if not self._interface_exists(interface_name):
            logger.warning("Interface %s does not exist", interface_name)
            return False
        ip_address = self.get_interface_ip_address(interface_name)
        if not ip_address:
            logger.warning("IP address for interface %s is empty", interface_name)
            return False
        if not ip_is_valid(ip_address):
            logger.warning(
                "IP address %s for interface %s is not valid", ip_address, interface_name
            )
            return False
        return True

    def _exec_command_in_workload(self, command: str) -> tuple:
        """Execute command in workload."""
        process = self.machine.exec(command=command.split())
        return process.wait_output()

    def _interface_exists(self, interface_name: str) -> bool:
        """Return whether the given network interface exists."""
        return self.machine.exists(path=f"/sys/class/net/{interface_name}")


def ip_is_valid(ip_address: str) -> bool:
    """Check whether given IP config is valid."""
    try:
        ipaddress.ip_network(ip_address, strict=False)
        return True
    except ValueError:
        return False
