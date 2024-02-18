#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Abstract the network configuration for the UPF service."""

import logging
from typing import List, Optional

import iptc
from pyroute2 import NDB, IPRoute, NetlinkError

logger = logging.getLogger(__name__)


class UPFNetworkError(Exception):
    """Custom exception for UPFNetwork."""


class UPFNetwork:
    """Abstract the network configuration for the UPF service."""

    def __init__(
        self,
        access_interface_name: str,
        core_interface_name: str,
        gnb_subnet: str,
    ):
        self.access_interface_name = access_interface_name
        self.core_interface_name = core_interface_name
        self.gnb_subnet = gnb_subnet
        self.ip_route = IPRoute()
        self.network_db = NDB()
        table = iptc.Table(iptc.Table.FILTER)
        self.chain = iptc.Chain(table, "OUTPUT")

    def get_interface_ip_address(self, interface_name: str) -> str:
        """Get the IP address of the given network interface."""
        interfaces = self.network_db.interfaces  # type: ignore[reportAttributeAccessIssue]
        try:
            iface_record = interfaces[interface_name]
            ip_addresses = iface_record.ipaddr
            for ip in ip_addresses:
                if ip.family == 2:
                    return ip.address
            logger.warning("No IPv4 address found for interface %s", interface_name)
        except KeyError:
            logger.warning("Interface %s not found in the network database", interface_name)
        return ""

    def get_invalid_network_interfaces(self) -> List[str]:
        """Return whether the network interfaces are valid."""
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
        """Configure the network for the UPF service."""
        if not self._default_route_exists():
            logger.info("Default route does not exist")
            self._create_default_route()
        if not self._ran_route_exists():
            logger.info("RAN route does not exist")
            self._create_ran_route()
        if not self._ip_tables_rule_exists():
            logger.info("Iptables rule does not exist")
            self._create_ip_tables_rule()

    def _get_interface_gateway_ip_address(self, interface_name: str) -> str:
        """Get the gateway IP address of the given network interface."""
        iface_index = self.ip_route.link_lookup(ifname=interface_name)
        if not iface_index:
            logger.warning("Interface %s not found", interface_name)
            return ""
        routes = self.ip_route.get_routes(family=2)
        for route in routes:
            oif = route.get_attr("RTA_OIF")
            gateway_ip = route.get_attr("RTA_GATEWAY")
            if oif == iface_index[0]:
                if gateway_ip:
                    return gateway_ip
        return ""

    def _default_route_exists(self) -> bool:
        """Check if the default route to the core network already exists."""
        core_interface_index = self.ip_route.link_lookup(ifname=self.core_interface_name)
        if not core_interface_index:
            logger.error("Core network interface not found")
            return False
        core_gateway_ip = self._get_core_network_gateway_ip()
        return self._route_exists(
            destination="",
            gateway=core_gateway_ip,
            oif=core_interface_index[0],
            metric=110,
        )

    def _ran_route_exists(self) -> bool:
        """Check if the route for the gNB subnet via the access network's gateway already exists."""
        access_gateway_ip = self._get_access_network_gateway_ip()
        return self._route_exists(destination=self.gnb_subnet, gateway=access_gateway_ip)

    def _route_exists(
        self,
        destination: str,
        gateway: str,
        oif: Optional[int] = None,
        metric: Optional[int] = None,
    ) -> bool:
        """Return whether the route already exists.

        Args:
            destination: The destination IP address. If it is the default route, it should be an empty string.
            gateway: The gateway IP address
            oif: The output interface index
            metric: The route metric
        """
        routes = self.ip_route.get_routes(family=2)
        for route in routes:
            route_destination = route.get_attr("RTA_DST")
            route_gateway = route.get_attr("RTA_GATEWAY")
            route_dst_len = route.get("dst_len")
            route_oif = route.get_attr("RTA_OIF")
            route_metric = route.get_attr("RTA_PRIORITY")
            route_destination_with_mask = f"{route_destination}/{route_dst_len}"
            if route_gateway != gateway:
                continue
            if oif and route_oif != oif:
                continue
            if metric and route_metric != metric:
                continue
            if destination and route_destination_with_mask != destination:
                continue
            return True
        return False

    def _get_core_network_gateway_ip(self) -> str:
        """Get the gateway IP address of the core network."""
        return self._get_interface_gateway_ip_address(self.core_interface_name)

    def _get_access_network_gateway_ip(self) -> str:
        """Get the gateway IP address of the access network."""
        return self._get_interface_gateway_ip_address(self.access_interface_name)

    def _create_default_route(self) -> None:
        """Create the default route for the core network."""
        core_gateway_ip = self._get_core_network_gateway_ip()
        if core_gateway_ip == "":
            logger.error("Core network gateway IP address is not available.")
            return
        core_interface = self.ip_route.link_lookup(ifname=self.core_interface_name)
        if not core_interface:
            logger.error("Core network interface not found")
            return
        core_interface_index = core_interface[0]
        try:
            self.ip_route.route(
                "replace",
                dst="default",
                gateway=core_gateway_ip,
                oif=core_interface_index,
                priority=110,
            )
        except NetlinkError as e:
            UPFNetworkError(f"Failed to create or replace the default route: {e}")
        logger.info("Route to default via %s created/updated successfully", core_gateway_ip)

    def _create_ran_route(self) -> None:
        """Create the RAN route towards gnb-subnet using pyroute2."""
        access_gateway_ip = self._get_access_network_gateway_ip()
        if not access_gateway_ip:
            logger.error("Access network gateway IP is not available.")
            return
        access_interface = self.ip_route.link_lookup(ifname=self.access_interface_name)
        if not access_interface:
            logger.error("Access network interface not found")
            return
        access_interface_index = access_interface[0]
        try:
            self.ip_route.route(
                "replace",
                dst=self.gnb_subnet,
                gateway=access_gateway_ip,
                oif=access_interface_index,
            )
        except NetlinkError as e:
            raise UPFNetworkError(f"Failed to create or replace the RAN route: {e}")
        logger.info(
            "Route to %s via %s created/updated successfully", self.gnb_subnet, access_gateway_ip
        )

    def _ip_tables_rule_exists(self) -> bool:
        """Return whether iptables rule already exists using the `--check` parameter."""
        for rule in self.chain.rules:
            for match in rule.matches:
                if (
                    match.name == "icmp" and match.parameters["icmp_type"] == "3/3"
                ) and rule.target.name == "DROP":
                    return True
        return False

    def _create_ip_tables_rule(self) -> None:
        """Create iptable rule in the OUTPUT chain to block ICMP port-unreachable packets."""
        rule = iptc.Rule()
        rule.protocol = "icmp"
        match = iptc.Match(rule, "icmp")
        match.icmp_type = "port-unreachable"
        rule.add_match(match)
        rule.target = iptc.Target(rule, "DROP")
        self.chain.insert_rule(rule)
        logger.info("Iptables rule for ICMP port-unreachable packets created.")

    def _interface_is_valid(self, interface_name: str) -> bool:
        """Return whether the given network interface is valid."""
        if not self._interface_exists(interface_name):
            logger.warning("Interface %s does not exist", interface_name)
            return False
        ip_address = self.get_interface_ip_address(interface_name)
        if not ip_address:
            logger.warning("IP address for interface %s is empty", interface_name)
            return False
        return True

    def _interface_exists(self, interface_name: str) -> bool:
        """Return whether the given network interface exists."""
        return interface_name in self.network_db.interfaces  # type: ignore[reportAttributeAccessIssue]
