#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Abstract the network configuration for the UPF service."""

import logging
from socket import AF_INET
from typing import List, Optional

import iptc
from pyroute2 import NDB, IPRoute, NetlinkError

from charm_config import UpfMode

logger = logging.getLogger(__name__)


class NetworkInterface:
    """A class to interact with a network interface."""

    def __init__(
        self,
        name: str,
        ip_address: str,
        mac_address: Optional[str] = None,
        alias: Optional[str] = None,
        mtu_size: int = 1500,
    ):
        self.network_db = NDB()
        self.ip_route = IPRoute()
        self.name = name
        self.ip_address = ip_address
        self.mac_address = mac_address
        self.mtu_size = mtu_size
        self.alias = alias

    def exists(self) -> bool:
        """Return whether the network interface exists."""
        return self.name in self.network_db.interfaces  # type: ignore[reportAttributeAccessIssue]

    def is_valid(self) -> bool:
        """Return whether the network interface is valid."""
        if not self.exists():
            logger.warning("Interface %s does not exist", self.name)
            return False
        return True

    def get_ip_address(self) -> str:
        """Get the IPv4 address of the given network interface.

        Returns:
            str: first available IP address in CIDR notation
        """
        interfaces = self.network_db.interfaces  # type: ignore[reportAttributeAccessIssue]
        if iface_record := interfaces.get(self.name):
            ip_addresses = iface_record.ipaddr
            for ip in ip_addresses:
                if ip.family == AF_INET:
                    return f"{ip.address}/{ip.prefixlen}"
            logger.warning("No IPv4 address found for interface %s", self.name)
            return ""
        logger.warning("Interface %s not found in the network database", self.name)
        return ""

    def addresses_are_set(self) -> bool:
        """Check if the given network interface is already configured."""
        interfaces = self.network_db.interfaces  # type: ignore[reportAttributeAccessIssue]
        if iface_record := interfaces.get(self.name):
            ip_addresses = iface_record.ipaddr
            for ip in ip_addresses:
                if ip.family == AF_INET:
                    logger.info("Found IP: %s/%s", ip.address, ip.prefixlen)
                    if f"{ip.address}/{ip.prefixlen}" != self.ip_address:
                        return False
            if not self.get_ip_address():
                return False
            return True
        logger.warning("Interface %s not found in the network database", self.name)
        return False

    def mac_address_is_set(self) -> bool:
        """Check if the given network interface has the right MAC address."""
        interfaces = self.network_db.interfaces  # type: ignore[reportAttributeAccessIssue]
        if iface_record := interfaces.get(self.name):
            mac_address = iface_record.get("address")
            return mac_address == self.mac_address
        logger.warning("Interface %s not found in the network database", self.name)
        return False

    def set_mac_address(self) -> None:
        """Set the MAC address for the given network interface."""
        interfaces = self.network_db.interfaces  # type: ignore[reportAttributeAccessIssue]
        if iface_record := interfaces.get(self.name):
            iface_record.set(address=self.mac_address).commit()
            logger.info("MAC address for the %s interface set to %s", self.name, self.mac_address)
            return
        logger.warning(
            "Setting MAC address for interface %s failed: Interface not found in the network database",  # noqa: E501
            self.name,
        )

    def alias_is_set(self) -> bool:
        """Check if the given network interface has the right alias set."""
        interfaces = self.network_db.interfaces  # type: ignore[reportAttributeAccessIssue]
        if iface_record := interfaces.get(self.name):
            alias = iface_record.get("ifalias")
            return alias == self.alias
        logger.warning("Interface %s not found in the network database", self.name)
        return False

    def set_alias(self) -> None:
        """Set an alias for the given network interface."""
        interfaces = self.network_db.interfaces  # type: ignore[reportAttributeAccessIssue]
        if iface_record := interfaces.get(self.name):
            iface_record.set(ifalias=self.alias).commit()
            logger.info("Alias for the %s interface set to %s", self.name, self.mac_address)
            return
        logger.warning(
            "Setting alias for interface %s failed: Interface not found in the network database",
            self.name,
        )

    def interface_is_up(self) -> bool:
        """Check if the given network interface is up."""
        interfaces = self.network_db.interfaces  # type: ignore[reportAttributeAccessIssue]
        if iface_record := interfaces.get(self.name):
            return iface_record["state"] == "up"
        logger.warning(
            "Checking the state of network interface is failed: Interface %s not found in the network database",  # noqa: E501
            self.name,
        )
        return False

    def bring_up_interface(self) -> None:
        """Set the network interface status to up."""
        interfaces = self.network_db.interfaces  # type: ignore[reportAttributeAccessIssue]
        if iface_record := interfaces.get(self.name):
            iface_record.set(state="up").commit()
            return
        logger.warning(
            "Setting the interface state to up is failed: Interface %s not found in the network database",  # noqa: E501
            self.name,
        )

    def set_ip_address(self) -> None:
        """Clean all unrequired IPs and set the IP address for the given network interface."""
        interfaces = self.network_db.interfaces  # type: ignore[reportAttributeAccessIssue]
        if iface_record := interfaces.get(self.name):
            ip_addresses = iface_record.ipaddr
            # remove all unrequired IPs
            for ip in ip_addresses:
                if ip.family == AF_INET:
                    if ip.address != self.ip_address:
                        logger.info(
                            "Removing IP %s/%s from interface %s",
                            ip.address,
                            ip.prefixlen,
                            self.name,
                        )
                        iface_record.del_ip(f"{ip.address}/{ip.prefixlen}").commit()
            # add requested IP if not already there
            if not self.get_ip_address():
                logger.info("Adding IP %s to interface %s", self.ip_address, self.name)
                iface_record.add_ip(self.ip_address).commit()
        else:
            logger.warning(
                "Setting IP for interface %s failed: Interface not found in the network database",
                self.name,
            )

    def unset_ip_address(self) -> None:
        """Remove the configured IP address from the given network interface."""
        interfaces = self.network_db.interfaces  # type: ignore[reportAttributeAccessIssue]
        if iface_record := interfaces.get(self.name):
            logger.info("Removing IP %s from interface %s", self.ip_address, self.name)
            iface_record.del_ip(self.ip_address).commit()
            return
        logger.warning(
            "Unsetting IP for interface %s failed: Interface not found in the network database",
            self.name,
        )

    def create(self) -> None:
        """Create given network interface.

        In DPDK mode the actual network interfaces of the host are removed from the management
        of the kernel. To be able to handle ICMP and ARP requests UPF uses virtual interfaces.
        This method creates a virtual interface with the MAC address matching the corresponding
        physical interface and tags it with the PCI address of the physical interface.
        """
        peer_interface_name = f"{self.name}-vdev"
        (
            self.network_db.interfaces.create(  # type: ignore[reportAttributeAccessIssue]
                ifname=self.name,
                kind="veth",
                peer={"ifname": peer_interface_name},
            )
            .set(
                state="up",
                address=self.mac_address,
                mtu=self.mtu_size,
            )
            .add_ip(address=self.ip_address, prefixlen=24)
            .commit()
        )
        self.network_db.reload()
        self.network_db.interfaces[self.name].set(ifalias=self.alias).commit()  # type: ignore[reportAttributeAccessIssue]  # noqa: E501
        self.network_db.interfaces[peer_interface_name].set(state="up").commit()  # type: ignore[reportAttributeAccessIssue]  # noqa: E501

        logger.info(
            "Network interface %s created with IP %s, MAC %s and alias %s",
            self.name,
            self.ip_address,
            self.mac_address,
            self.alias,
        )

    def delete(self) -> None:
        """Delete given network interface."""
        interface_index = self.get_index()
        self.ip_route.link("del", index=interface_index)
        logger.info("Network interface %s deleted", self.name)
        self.ip_route.close()

    def mtu_size_is_set(self) -> bool:
        """Check if MTU size of the given network interface is already configured ."""
        interfaces = self.network_db.interfaces  # type: ignore[reportAttributeAccessIssue]
        if iface_record := interfaces.get(self.name):
            return iface_record.get("mtu") == self.mtu_size
        logger.warning("Interface %s not found in the network database", self.name)
        return False

    def set_mtu_size(self) -> None:
        """Set the MTU size for the given network interface."""
        interfaces = self.network_db.interfaces  # type: ignore[reportAttributeAccessIssue]
        if iface_record := interfaces.get(self.name):
            logger.info("Setting MTU size to %s for interface %s", self.mtu_size, self.name)
            iface_record.set("mtu", self.mtu_size).commit()
            return
        logger.warning(
            "Setting MTU size for interface %s failed: Interface not found in the network database",  # noqa: E501
            self.name,
        )

    def get_index(self) -> int:
        """Get the index of the network interface."""
        try:
            return self.network_db.interfaces[self.name].get("index")  # type: ignore[reportAttributeAccessIssue]  # noqa: E501
        except KeyError:
            logger.warning("Interface %s not found", self.name)
            return -1


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
            logger.info(
                "Route to %s via %s created/updated successfully",
                self.destination,
                self.gateway,
            )
        except NetlinkError as e:
            logger.error("Failed to create or replace the route: %s", e.args)

    def delete(self) -> None:
        """Delete the route."""
        try:
            self.ip_route.route(
                "delete",
                dst=self.destination,
                gateway=self.gateway,
                oif=self.oif,
                priority=self.metric,
            )
            logger.info("Route to %s via %s deleted successfully", self.destination, self.gateway)
        except NetlinkError as e:
            logger.error("Failed to create or replace the route: %s", e)


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

    def delete(self) -> None:
        """Delete iptable rule in the OUTPUT chain to block ICMP port-unreachable packets."""
        rule = iptc.Rule()
        rule.protocol = "icmp"
        match = iptc.Match(rule, "icmp")
        match.icmp_type = "port-unreachable"
        rule.add_match(match)
        rule.target = iptc.Target(rule, "DROP")
        self.chain.delete_rule(rule)
        logger.info("Iptables rule for ICMP port-unreachable packets deleted.")


class UPFNetwork:
    """Abstract the network configuration for the UPF service."""

    def __init__(
        self,
        upf_mode: str,
        access_interface_name: str,
        access_ip: str,
        access_gateway_ip: str,
        access_mtu_size: int,
        core_interface_name: str,
        core_ip: str,
        core_gateway_ip: str,
        core_mtu_size: int,
        gnb_subnet: str,
        access_mac_address: Optional[str] = None,
        access_pci_address: Optional[str] = None,
        core_mac_address: Optional[str] = None,
        core_pci_address: Optional[str] = None,
    ):
        self.upf_mode = upf_mode
        if not access_interface_name:
            raise ValueError("Access network interface name is empty")
        if not core_interface_name:
            raise ValueError("Core network interface name is empty")
        if upf_mode == UpfMode.dpdk:
            if not access_mac_address:
                raise ValueError("Access network interface MAC address is empty")
            if not access_pci_address:
                raise ValueError("Access network interface PCI address is empty")
            if not core_mac_address:
                raise ValueError("Core network interface MAC address is empty")
            if not core_pci_address:
                raise ValueError("Core network interface PCI address is empty")
        self.access_interface = NetworkInterface(
            name=access_interface_name,
            ip_address=access_ip,
            mtu_size=access_mtu_size,
            mac_address=access_mac_address,
            alias=access_pci_address,
        )
        self.core_interface = NetworkInterface(
            name=core_interface_name,
            ip_address=core_ip,
            mtu_size=core_mtu_size,
            mac_address=core_mac_address,
            alias=core_pci_address,
        )
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
        self._set_ip_addresses()
        self._set_mtu_size()
        if self.upf_mode == UpfMode.dpdk:
            self._configure_interfaces_for_dpdk()
        self._bring_interfaces_up()
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
        if self.upf_mode == UpfMode.dpdk:
            ifaces_are_configured = (
                self.access_interface.addresses_are_set()
                and self.access_interface.mac_address_is_set()
                and self.access_interface.alias_is_set()
                and self.core_interface.addresses_are_set()
                and self.core_interface.mac_address_is_set()
                and self.core_interface.alias_is_set()
            )
        else:
            ifaces_are_configured = (
                self.access_interface.addresses_are_set()
                and self.core_interface.addresses_are_set()
            )
        routes_are_configured = (
            self.default_route.exists()
            and self.ran_route.exists()
            and self.ip_tables_rule.exists()
        )
        interfaces_are_up = (
            self.access_interface.interface_is_up() and self.core_interface.interface_is_up()
        )
        return ifaces_are_configured and routes_are_configured and interfaces_are_up

    def clean_configuration(self) -> None:
        """Remove the configured IPs/routes from the networking."""
        if self.upf_mode == UpfMode.dpdk:
            if self.access_interface.exists():
                self.access_interface.delete()
            if self.core_interface.exists():
                self.core_interface.delete()
        if self.access_interface.get_ip_address():
            self.access_interface.unset_ip_address()
        if self.core_interface.get_ip_address():
            self.core_interface.unset_ip_address()
        if self.default_route.exists():
            self.default_route.delete()
        if self.ran_route.exists():
            self.ran_route.delete()
        if self.ip_tables_rule.exists():
            self.ip_tables_rule.delete()

    def _configure_interfaces_for_dpdk(self) -> None:
        if not self.access_interface.mac_address_is_set():
            self.access_interface.set_mac_address()
        if not self.access_interface.alias_is_set():
            self.access_interface.set_alias()
        if not self.core_interface.mac_address_is_set():
            self.core_interface.set_mac_address()
        if not self.core_interface.alias_is_set():
            self.core_interface.set_alias()

    def _set_ip_addresses(self) -> None:
        if not self.access_interface.addresses_are_set():
            self.access_interface.set_ip_address()
        if not self.core_interface.addresses_are_set():
            self.core_interface.set_ip_address()

    def _set_mtu_size(self) -> None:
        if not self.access_interface.mtu_size_is_set():
            self.access_interface.set_mtu_size()
        if not self.core_interface.mtu_size_is_set():
            self.core_interface.set_mtu_size()

    def _bring_interfaces_up(self) -> None:
        if not self.access_interface.interface_is_up():
            self.access_interface.bring_up_interface()
        if not self.core_interface.interface_is_up():
            self.core_interface.bring_up_interface()
