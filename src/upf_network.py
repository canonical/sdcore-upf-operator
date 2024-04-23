#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Abstract the network configuration for the UPF service."""

import logging
from socket import AF_INET
from typing import List, Optional

import iptc
from pyroute2 import NDB, IPRoute, NetlinkError

logger = logging.getLogger(__name__)


class UPFNetworkError(Exception):
    """Custom exception for UPFNetwork."""


class NetworkInterface:
    """A class to interact with a network interface."""

    def __init__(self, name: str, ip_address: str, mtu_size: int = 1500):
        self.network_db = NDB()
        self.ip_route = IPRoute()
        self.name = name
        self.ip_address = ip_address
        self.mtu_size = mtu_size

    def exists(self) -> bool:
        """Return whether the network interface exists."""
        return self.name in self.network_db.interfaces  # type: ignore[reportAttributeAccessIssue]

    def is_valid(self) -> bool:
        """Return whether the network interface is valid."""
        if not self.exists():
            logger.warning("Interface %s does not exist", self.name)
            return False
        # ip_address = self.get_ip_address()
        # if not ip_address:
        #     logger.warning("IP address for interface %s is empty", self.name)
        #     return False
        return True

    def get_ip_address(self) -> str:
        """Get the IPv4 address of the given network interface."""
        interfaces = self.network_db.interfaces  # type: ignore[reportAttributeAccessIssue]
        try:
            iface_record = interfaces[self.name]
            ip_addresses = iface_record.ipaddr
            for ip in ip_addresses:
                if ip.family == AF_INET:
                    return f"{ip.address}/{ip.prefixlen}"
            logger.warning("No IPv4 address found for interface %s", self.name)
        except KeyError:
            logger.warning("Interface %s not found in the network database", self.name)
        return ""

    def addresses_are_set(self) -> bool:
        """Check if the given network interface is already configured."""
        interfaces = self.network_db.interfaces  # type: ignore[reportAttributeAccessIssue]
        try:
            iface_record = interfaces[self.name]
            ip_addresses = iface_record.ipaddr
            for ip in ip_addresses:
                if ip.family == AF_INET:
                    logger.info("Found IP: %s/%s", ip.address, ip.prefixlen)
                    if f"{ip.address}/{ip.prefixlen}" != self.ip_address:
                        return False
            if not self.get_ip_address():
                return False
        except KeyError:
            logger.warning("Interface %s not found in the network database", self.name)
            return False
        return True

    def set_ip_address(self) -> None:
        """Clean all unrequired IPs and set the IP address for the given network interface."""
        interfaces = self.network_db.interfaces  # type: ignore[reportAttributeAccessIssue]
        try:
            iface_record = interfaces[self.name]
            ip_addresses = iface_record.ipaddr
            # remove all unrequired IPs
            for ip in ip_addresses:
                if ip.family == AF_INET:
                    if ip.address != self.ip_address:
                        logger.info("Removing IP %s/%s from interface %s",
                                    ip.address, ip.prefixlen, self.name)
                        iface_record.del_ip(f"{ip.address}/{ip.prefixlen}").commit()
            # add requested IP if not already there
            if not self.get_ip_address():
                logger.info("Adding IP %s to interface %s", self.ip_address, self.name)
                iface_record.add_ip(self.ip_address).commit()
        except KeyError:
            logger.warning("Interface %s not found in the network database", self.name)

    def mtu_size_is_set(self) -> bool:
        """Check if MTU size of the given network interface is already configured ."""
        interfaces = self.network_db.interfaces  # type: ignore[reportAttributeAccessIssue]
        try:
            iface_record = interfaces[self.name]
            return iface_record.get("mtu") == self.mtu_size
        except KeyError:
            logger.warning("Interface %s not found in the network database", self.name)
            return False

    def set_mtu_size(self) -> None:
        """Set the MTU size for the given network interface."""
        interfaces = self.network_db.interfaces  # type: ignore[reportAttributeAccessIssue]
        try:
            iface_record = interfaces[self.name]
            logger.info("Setting MTU size to %s for interface %s", self.mtu_size, self.name)
            iface_record.set("mtu", self.mtu_size).commit()
        except KeyError:
            logger.warning("Interface %s not found in the network database", self.name)

    def get_gateway_ip_address(self) -> str:
        """Get the gateway IPv4 address of the given network interface."""
        iface_index = self.get_index()
        routes = self.ip_route.get_routes(family=AF_INET)
        for route in routes:
            oif = route.get_attr("RTA_OIF")
            gateway_ip = route.get_attr("RTA_GATEWAY")
            if oif == iface_index:
                if gateway_ip:
                    return gateway_ip
        return ""

    def get_index(self) -> int:
        """Get the index of the network interface."""
        iface_index = self.ip_route.link_lookup(ifname=self.name)
        if not iface_index:
            logger.warning("Interface %s not found", self.name)
            return -1
        return iface_index[0]


class Route:
    """A class to interact with a network route."""

    def __init__(
        self,
        destination: str,
        gateway: str,
        oif: Optional[int] = None,
        metric: Optional[int] = None,
    ):
        self.ip_route = IPRoute()
        self.destination = destination
        self.gateway = gateway
        self.oif = oif
        self.metric = metric

    def exists(self) -> bool:
        """Return whether the IPv4 route already exists."""
        routes = self.ip_route.get_routes(family=AF_INET)
        for route in routes:
            route_destination = route.get_attr("RTA_DST")
            route_gateway = route.get_attr("RTA_GATEWAY")
            route_dst_len = route.get("dst_len")
            route_oif = route.get_attr("RTA_OIF")
            route_metric = route.get_attr("RTA_PRIORITY")
            route_destination_with_mask = f"{route_destination}/{route_dst_len}"
            if route_gateway != self.gateway:
                continue
            if self.oif and route_oif != self.oif:
                continue
            if self.metric and route_metric != self.metric:
                continue
            if self.destination and route_destination_with_mask != self.destination:
                continue
            return True
        return False

    def create(self) -> None:
        """Create the route."""
        try:
            self.ip_route.route(
                "replace",
                dst=self.destination,
                gateway=self.gateway,
                oif=self.oif,
                priority=self.metric,
            )
        except NetlinkError as e:
            UPFNetworkError(f"Failed to create or replace the route: {e}")
        logger.info(
            "Route to %s via %s created/updated successfully", self.destination, self.gateway
        )


class IPTablesRule:
    """A class to interact with an iptables rule."""

    def __init__(self):
        table = iptc.Table(iptc.Table.FILTER)
        self.chain = iptc.Chain(table, "OUTPUT")

    def exists(self) -> bool:
        """Return whether iptables rule already exists using the `--check` parameter."""
        for rule in self.chain.rules:
            for match in rule.matches:
                if (
                    match.name == "icmp" and match.parameters["icmp_type"] == "3/3"
                ) and rule.target.name == "DROP":
                    return True
        return False

    def create(self) -> None:
        """Create iptable rule in the OUTPUT chain to block ICMP port-unreachable packets."""
        rule = iptc.Rule()
        rule.protocol = "icmp"
        match = iptc.Match(rule, "icmp")
        match.icmp_type = "port-unreachable"
        rule.add_match(match)
        rule.target = iptc.Target(rule, "DROP")
        self.chain.insert_rule(rule)
        logger.info("Iptables rule for ICMP port-unreachable packets created.")


class UPFNetwork:
    """Abstract the network configuration for the UPF service."""

    def __init__(
        self,
        access_interface_name: str,
        access_ip: str,
        access_gateway_ip: str,
        access_mtu_size: int,
        core_interface_name: str,
        core_ip: str,
        core_gateway_ip: str,
        core_mtu_size: int,
        gnb_subnet: str,
    ):
        if not access_interface_name:
            raise ValueError("Access network interface name is empty")
        if not core_interface_name:
            raise ValueError("Core network interface name is empty")
        self.access_interface = NetworkInterface(access_interface_name, access_ip, access_mtu_size)
        self.core_interface = NetworkInterface(core_interface_name, core_ip, core_mtu_size)
        self.default_route = Route(
            destination="",
            gateway=core_gateway_ip,
            oif=self.core_interface.get_index(),
            metric=110,
        )
        self.ran_route = Route(
            destination=gnb_subnet,
            gateway=access_gateway_ip,
            oif=self.access_interface.get_index(),
        )
        self.ip_tables_rule = IPTablesRule()

    def get_invalid_network_interfaces(self) -> List[str]:
        """Return whether the network interfaces are valid."""
        invalid_network_interfaces = []
        if not self.access_interface.is_valid():
            invalid_network_interfaces.append(self.access_interface.name)
            logger.warning("Access network interface %s is not valid", self.access_interface.name)
        if not self.core_interface.is_valid():
            invalid_network_interfaces.append(self.core_interface.name)
            logger.warning("Core network interface %s is not valid", self.core_interface.name)
        return invalid_network_interfaces

    def configure(self) -> None:
        """Configure the network for the UPF service."""
        if not self.access_interface.addresses_are_set():
            self.access_interface.set_ip_address()
        if not self.access_interface.mtu_size_is_set():
            self.access_interface.set_mtu_size()
        if not self.core_interface.addresses_are_set():
            self.core_interface.set_ip_address()
        if not self.core_interface.mtu_size_is_set():
            self.core_interface.set_mtu_size()
        if not self.default_route.exists():
            logger.info("Default route does not exist")
            self.default_route.create()
        if not self.ran_route.exists():
            logger.info("RAN route does not exist")
            self.ran_route.create()
        if not self.ip_tables_rule.exists():
            logger.info("Iptables rule does not exist")
            self.ip_tables_rule.create()

    def is_configured(self) -> bool:
        """Return whether the network is configured for the UPF service."""
        ifaces_are_configured = (
                self.access_interface.addresses_are_set()
                and self.core_interface.addresses_are_set()
        )
        routes_are_configured = (
            self.default_route.exists()
            and self.ran_route.exists()
            and self.ip_tables_rule.exists()
        )
        return ifaces_are_configured and routes_are_configured
