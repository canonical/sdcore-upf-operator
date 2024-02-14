#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Machine charm for SD-Core User Plane Function."""

import ipaddress
import json
import logging
import re
from typing import List, Optional

import ops
from charms.operator_libs_linux.v2 import snap
from jinja2 import Environment, FileSystemLoader
from machine import ExecError, Machine
from ops.model import ActiveStatus, BlockedStatus

UPF_SNAP_NAME = "sdcore-upf"
UPF_SNAP_CHANNEL = "latest/edge"
UPF_SNAP_REVISION = "3"
UPF_CONFIG_FILE_NAME = "upf.json"
UPF_CONFIG_PATH = "/var/snap/sdcore-upf/common"

logger = logging.getLogger(__name__)


class SdcoreUpfCharm(ops.CharmBase):
    """Machine charm for SD-Core User Plane Function."""

    def __init__(self, *args):
        super().__init__(*args)
        self._machine = Machine()
        self.framework.observe(self.on.install, self._configure)
        self.framework.observe(self.on.update_status, self._configure)
        self.framework.observe(self.on.config_changed, self._configure)

    def _configure(self, _):
        """Handle UPF installation."""
        if not self.unit.is_leader():
            self.unit.status = BlockedStatus("Scaling is not implemented for this charm")
            return
        if invalid_configs := self._get_invalid_configs():
            self.unit.status = BlockedStatus(
                f"The following configurations are not valid: {invalid_configs}"
            )
            return
        if invalid_network_interfaces := self._get_invalid_network_interfaces():
            self.unit.status = BlockedStatus(
                f"Network interfaces are not valid: {invalid_network_interfaces}"
            )
            return
        self._configure_network()
        self._install_upf_snap()
        self._generate_upf_config_file()
        self.unit.status = ActiveStatus()

    def _get_invalid_network_interfaces(self) -> List[str]:
        """Return whether the network interfaces are valid."""
        invalid_network_interfaces = []
        access_interface_name = self._get_access_interface_name()
        core_interface_name = self._get_core_interface_name()
        if not access_interface_name:
            raise ValueError("Access network interface name is empty")
        if not core_interface_name:
            raise ValueError("Core network interface name is empty")
        if not self._interface_is_valid(access_interface_name):
            invalid_network_interfaces.append(access_interface_name)
            logger.warning("Access network interface %s is not valid", access_interface_name)
        if not self._interface_is_valid(core_interface_name):
            invalid_network_interfaces.append(core_interface_name)
            logger.warning("Core network interface %s is not valid", core_interface_name)
        return invalid_network_interfaces

    def _interface_is_valid(self, interface_name: str) -> bool:
        """Return whether the given network interface is valid."""
        if not self._interface_exists(interface_name):
            logger.warning("Interface %s does not exist", interface_name)
            return False
        ip_address = self._get_interface_ip_address(interface_name)
        if not ip_address:
            logger.warning("IP address for interface %s is empty", interface_name)
            return False
        if not ip_is_valid(ip_address):
            logger.warning(
                "IP address %s for interface %s is not valid", ip_address, interface_name
            )
            return False
        return True

    def _install_upf_snap(self) -> None:
        """Install the UPF snap in the workload."""
        try:
            snap_cache = snap.SnapCache()
            upf_snap = snap_cache[UPF_SNAP_NAME]
            upf_snap.ensure(
                snap.SnapState.Latest,
                channel=UPF_SNAP_CHANNEL,
                revision=UPF_SNAP_REVISION,
                devmode=True,
            )
            upf_snap.hold()
            logger.info("UPF snap installed")
        except snap.SnapError as e:
            logger.error("An exception occurred when installing the UPF snap. Reason: %s", str(e))
            raise e

    def _configure_network(self) -> None:
        """Configure the network for the UPF service."""
        if not self._default_route_exists():
            self._create_default_route()
        if not self._ran_route_exists():
            self._create_ran_route()
        if not self._ip_tables_rule_exists():
            self._create_ip_tables_rule()

    def _exec_command_in_workload(self, command: str) -> tuple:
        """Execute command in workload."""
        process = self._machine.exec(command=command.split())
        return process.wait_output()

    def _default_route_exists(self) -> bool:
        """Return whether the default route already exists."""
        stdout, stderr = self._exec_command_in_workload(command="ip route show default")
        if stderr:
            logger.warning("Failed to get default route")
            return False
        return f"default via {self._get_core_network_gateway_ip_config()}" in stdout

    def _ran_route_exists(self) -> bool:
        """Return whether the ran route already exists."""
        stdout, stderr = self._exec_command_in_workload(command="ip route show")
        if stderr:
            logger.warning("Failed to get ran route")
            return False
        return (
            f"{self._get_gnb_subnet_config()} via {self._get_access_network_gateway_ip_config()}"
            in stdout
        )

    def _create_default_route(self) -> None:
        """Create the default route for the core network."""
        self._exec_command_in_workload(
            f"ip route replace default via {self._get_core_network_gateway_ip_config()} metric 110"
        )
        logger.info("Default core network route created")

    def _create_ran_route(self) -> None:
        """Create ip route towards gnb-subnet."""
        self._exec_command_in_workload(
            command=f"ip route replace {self._get_gnb_subnet_config()} via {self._get_access_network_gateway_ip_config()}"
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

    def _interface_exists(self, interface_name: str) -> bool:
        """Return whether the given network interface exists."""
        return self._machine.exists(path=f"/sys/class/net/{interface_name}")

    def _get_interface_ip_address(self, interface_name: str) -> str:
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

    def _generate_upf_config_file(self) -> None:
        """Generate the UPF configuration file."""
        core_interface_name = self._get_core_interface_name()
        if not core_interface_name:
            raise ValueError("Core network interface name is empty")
        core_ip_address = self._get_interface_ip_address(core_interface_name)
        if not core_ip_address:
            raise ValueError("Core network IP address is not valid")
        content = render_upf_config_file(
            upf_hostname=self._get_upf_hostname(),
            upf_mode=self._get_upf_mode(),
            access_interface_name=self._get_access_interface_name(),
            core_interface_name=self._get_core_interface_name(),
            core_ip_address=core_ip_address.split("/")[0] if core_ip_address else "",
            dnn=self._get_dnn_config(),
            pod_share_path=UPF_CONFIG_PATH,
            enable_hw_checksum=self._get_enable_hw_checksum(),
        )
        if not self._upf_config_file_is_written() or not self._upf_config_file_content_matches(
            content=content
        ):
            self._write_upf_config_file(content=content)

    def _upf_config_file_is_written(self) -> bool:
        """Return whether the UPF config file was written to the workload."""
        return self._machine.exists(path=f"{UPF_CONFIG_PATH}/{UPF_CONFIG_FILE_NAME}")

    def _upf_config_file_content_matches(self, content: str) -> bool:
        """Return whether the UPF config file content matches the provided content."""
        existing_content = self._machine.pull(path=f"{UPF_CONFIG_PATH}/{UPF_CONFIG_FILE_NAME}")
        try:
            return json.loads(existing_content) == json.loads(content)
        except json.JSONDecodeError:
            return False

    def _write_upf_config_file(self, content: str) -> None:
        """Write the UPF config file to the workload."""
        self._machine.push(path=f"{UPF_CONFIG_PATH}/{UPF_CONFIG_FILE_NAME}", source=content)
        logger.info("Pushed %s config file", UPF_CONFIG_FILE_NAME)

    def _get_invalid_configs(self) -> list[str]:
        """Return list of invalid configurations."""
        invalid_configs = []
        if not self._get_dnn_config():
            invalid_configs.append("dnn")
        gnb_subnet = self._get_gnb_subnet_config()
        if not gnb_subnet:
            invalid_configs.append("gnb-subnet")
        if not ip_is_valid(gnb_subnet):
            invalid_configs.append("gnb-subnet")
        return invalid_configs

    def _get_core_network_gateway_ip_config(self) -> str:
        core_interface_name = self._get_core_interface_name()
        if not core_interface_name:
            return ""
        return self._get_interface_gateway_ip_address(core_interface_name)

    def _get_gnb_subnet_config(self) -> str:
        return self.model.config.get("gnb-subnet", "")

    def _get_access_network_gateway_ip_config(self) -> str:
        access_interface_name = self._get_access_interface_name()
        if not access_interface_name:
            return ""
        return self._get_interface_gateway_ip_address(access_interface_name)

    def _get_upf_hostname(self) -> str:
        return "0.0.0.0"

    def _get_upf_mode(self) -> str:
        return "af_packet"

    def _get_dnn_config(self) -> str:
        return self.model.config.get("dnn", "")

    def _get_enable_hw_checksum(self) -> bool:
        return bool(self.model.config.get("enable-hw-checksum", False))

    def _get_access_interface_name(self) -> str:
        return self.model.config.get("access-interface-name", "")

    def _get_core_interface_name(self) -> str:
        return self.model.config.get("core-interface-name", "")


def ip_is_valid(ip_address: str) -> bool:
    """Check whether given IP config is valid."""
    try:
        ipaddress.ip_network(ip_address, strict=False)
        return True
    except ValueError:
        return False


def render_upf_config_file(
    upf_hostname: str,
    upf_mode: str,
    access_interface_name: str,
    core_interface_name: str,
    core_ip_address: Optional[str],
    dnn: str,
    pod_share_path: str,
    enable_hw_checksum: bool,
) -> str:
    """Render the configuration file for the 5G UPF service.

    Args:
        upf_hostname: UPF hostname
        upf_mode: UPF mode
        access_interface_name: Access network interface name
        core_interface_name: Core network interface name
        core_ip_address: Core network IP address
        dnn: Data Network Name (DNN)
        pod_share_path: pod_share path
        enable_hw_checksum: Whether to enable hardware checksum or not
    """
    jinja2_environment = Environment(loader=FileSystemLoader("src/templates/"))
    template = jinja2_environment.get_template(f"{UPF_CONFIG_FILE_NAME}.j2")
    content = template.render(
        upf_hostname=upf_hostname,
        mode=upf_mode,
        access_interface_name=access_interface_name,
        core_interface_name=core_interface_name,
        core_ip_address=core_ip_address,
        dnn=dnn,
        pod_share_path=pod_share_path,
        hwcksum=str(enable_hw_checksum).lower(),
    )
    return content


if __name__ == "__main__":  # pragma: nocover
    ops.main(SdcoreUpfCharm)  # type: ignore
