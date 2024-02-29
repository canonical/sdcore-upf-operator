#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Machine charm for SD-Core User Plane Function."""

import ipaddress
import json
import logging
import time
from typing import Optional

import ops
from charms.operator_libs_linux.v2 import snap
from charms.sdcore_upf_k8s.v0.fiveg_n4 import N4Provides  # type: ignore[import]
from jinja2 import Environment, FileSystemLoader
from machine import ExecError, Machine
from ops.model import ActiveStatus, BlockedStatus
from upf_network import UPFNetwork

UPF_SNAP_NAME = "sdcore-upf"
UPF_SNAP_CHANNEL = "latest/edge"
UPF_SNAP_REVISION = "7"
UPF_CONFIG_FILE_NAME = "upf.json"
UPF_CONFIG_PATH = "/var/snap/sdcore-upf/common"
PFCP_PORT = 8805

logger = logging.getLogger(__name__)


class SdcoreUpfCharm(ops.CharmBase):
    """Machine charm for SD-Core User Plane Function."""

    def __init__(self, *args):
        super().__init__(*args)
        self._machine = Machine()
        self._network = UPFNetwork(
            access_interface_name=self._get_access_interface_name(),
            core_interface_name=self._get_core_interface_name(),
            gnb_subnet=self._get_gnb_subnet_config(),
        )
        self.fiveg_n4_provider = N4Provides(charm=self, relation_name="fiveg_n4")
        self.framework.observe(self.on.install, self._configure)
        self.framework.observe(self.on.update_status, self._configure)
        self.framework.observe(self.on.config_changed, self._configure)
        self.framework.observe(
            self.fiveg_n4_provider.on.fiveg_n4_request, self._on_fiveg_n4_request
        )

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
        if invalid_network_interfaces := self._network.get_invalid_network_interfaces():
            self.unit.status = BlockedStatus(
                f"Network interfaces are not valid: {invalid_network_interfaces}"
            )
            return
        self._network.configure()
        self._install_upf_snap()
        self._generate_upf_config_file()
        self._start_upf_service()
        self._update_fiveg_n4_relation_data()
        self.unit.status = ActiveStatus()

    def _on_fiveg_n4_request(self, event) -> None:
        """Handle 5G N4 requests events.

        Args:
            event: Juju event
        """
        if not self.unit.is_leader():
            return
        self._update_fiveg_n4_relation_data()

    def _update_fiveg_n4_relation_data(self) -> None:
        """Publish UPF hostname and the N4 port in the `fiveg_n4` relation data bag."""
        fiveg_n4_relations = self.model.relations.get("fiveg_n4")
        if not fiveg_n4_relations:
            logger.info("No `fiveg_n4` relations found.")
            return
        for fiveg_n4_relation in fiveg_n4_relations:
            self.fiveg_n4_provider.publish_upf_n4_information(
                relation_id=fiveg_n4_relation.id,
                upf_hostname=self._get_n4_upf_hostname(),
                upf_n4_port=PFCP_PORT,
            )

    def _get_n4_upf_hostname(self) -> str:
        """Return the UPF hostname to be exposed over the `fiveg_n4` relation.

        If a configuration is provided, it is returned. If that is
        not available, returns the IP address of the core interface.

        Returns:
            str: Hostname of the UPF
        """
        if configured_hostname := self.model.config.get("external-upf-hostname"):
            return configured_hostname
        else:
            return self._network.core_interface.get_ip_address()

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

    def _start_upf_service(self) -> None:
        """Start the UPF service."""
        snap_cache = snap.SnapCache()
        upf_snap = snap_cache[UPF_SNAP_NAME]
        upf_snap.start(services=["bessd"])
        upf_snap.start(services=["routectl"])
        self._run_bess_configuration()
        upf_snap.start(services=["pfcpiface"])
        logger.info("UPF service started")

    def _run_bess_configuration(self) -> None:
        """Run bessd configuration in workload."""
        initial_time = time.time()
        timeout = 300
        logger.info("Starting configuration of the `bessd` service")
        command = "sdcore-upf.bessctl run /snap/sdcore-upf/current/up4"
        while time.time() - initial_time <= timeout:
            process = self._machine.exec(
                command=command.split(),
                timeout=10,
            )
            try:
                process.wait_output()
                logger.info("Service `bessd` configured")
                return
            except ExecError:
                logger.info("Failed running configuration for bess")
                time.sleep(2)

        raise TimeoutError("Timed out trying to run configuration for bess")

    def _generate_upf_config_file(self) -> None:
        """Generate the UPF configuration file."""
        core_interface_name = self._get_core_interface_name()
        if not core_interface_name:
            raise ValueError("Core network interface name is empty")
        core_ip_address = self._network.core_interface.get_ip_address()
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

    def _get_gnb_subnet_config(self) -> str:
        return self.model.config.get("gnb-subnet", "")

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
