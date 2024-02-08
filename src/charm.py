#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Machine charm for SD-Core User Plane Function."""

import json
import logging
from typing import Optional

import ops
from charms.operator_libs_linux.v2 import snap
from jinja2 import Environment, FileSystemLoader
from machine import Machine
from ops.model import ActiveStatus, BlockedStatus

UPF_SNAP_NAME = "sdcore-upf"
UPF_SNAP_CHANNEL = "latest/edge"
UPF_SNAP_REVISION = "3"
CONFIG_FILE_NAME = "upf.json"
ACCESS_INTERFACE_NAME = "access"
CORE_INTERFACE_NAME = "core"
BESSD_CONFIG_PATH = "/var/snap/sdcore-upf/common"

logger = logging.getLogger(__name__)


def render_bessd_config_file(
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
    template = jinja2_environment.get_template(f"{CONFIG_FILE_NAME}.j2")
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
        self._install_upf_snap()
        self._generate_upf_config_file()
        self.unit.status = ActiveStatus()

    def _install_upf_snap(self) -> None:
        """Install the UPF snap in the machine."""
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

    def _generate_upf_config_file(self) -> None:
        """Generate the UPF configuration file."""
        core_ip_address = self._get_core_network_ip_config()
        content = render_bessd_config_file(
            upf_hostname=self._get_upf_hostname(),
            upf_mode=self._get_upf_mode(),
            access_interface_name=ACCESS_INTERFACE_NAME,
            core_interface_name=CORE_INTERFACE_NAME,
            core_ip_address=core_ip_address.split("/")[0] if core_ip_address else "",
            dnn=self._get_dnn_config(),
            pod_share_path=BESSD_CONFIG_PATH,
            enable_hw_checksum=self._get_enable_hw_checksum(),
        )
        if not self._upf_config_file_is_written() or not self._upf_config_file_content_matches(
            content=content
        ):
            self._write_upf_config_file(content=content)

    def _upf_config_file_is_written(self) -> bool:
        """Return whether the UPF config file was written to the workload.

        Returns:
            bool: Whether the UPF config file was written
        """
        return self._machine.exists(path=f"{BESSD_CONFIG_PATH}/{CONFIG_FILE_NAME}")

    def _upf_config_file_content_matches(self, content: str) -> bool:
        """Return whether the UPF config file content matches the provided content.

        Returns:
            bool: Whether the UPF config file content matches
        """
        existing_content = self._machine.pull(path=f"{BESSD_CONFIG_PATH}/{CONFIG_FILE_NAME}")
        try:
            return json.loads(existing_content) == json.loads(content)
        except json.JSONDecodeError:
            return False

    def _write_upf_config_file(self, content: str) -> None:
        """Write the UPF config file to the workload."""
        self._machine.push(path=f"{BESSD_CONFIG_PATH}/{CONFIG_FILE_NAME}", source=content)
        logger.info("Pushed %s config file", CONFIG_FILE_NAME)

    def _get_core_network_ip_config(self) -> str:
        return "192.168.250.3/24"

    def _get_upf_hostname(self) -> str:
        return "0.0.0.0"

    def _get_upf_mode(self) -> str:
        return "af_packet"

    def _get_dnn_config(self) -> str:
        return "internet"

    def _get_enable_hw_checksum(self) -> bool:
        return True


if __name__ == "__main__":  # pragma: nocover
    ops.main(SdcoreUpfCharm)  # type: ignore
