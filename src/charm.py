#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Machine charm for SD-Core User Plane Function."""

import json
import logging
import time
from typing import Optional

import ops
from charm_config import CharmConfig, CharmConfigInvalidError
from charms.grafana_agent.v0.cos_agent import COSAgentProvider
from charms.operator_libs_linux.v2.snap import SnapCache, SnapError, SnapState
from charms.sdcore_upf_k8s.v0.fiveg_n4 import N4Provides
from jinja2 import Environment, FileSystemLoader
from machine import ExecError, Machine
from ops import (
    ActiveStatus,
    BlockedStatus,
    CollectStatusEvent,
    RemoveEvent,
    WaitingStatus,
)
from upf_network import UPFNetwork

UPF_SNAP_NAME = "sdcore-upf"
UPF_SNAP_CHANNEL = "1.4/edge"
UPF_SNAP_REVISION = "42"
UPF_CONFIG_FILE_NAME = "upf.json"
UPF_CONFIG_PATH = "/var/snap/sdcore-upf/common"
PFCP_PORT = 8805
PROMETHEUS_PORT = 8080
REQUIRED_CPU_EXTENSIONS = ["avx2", "rdrand"]

logger = logging.getLogger(__name__)


class SdcoreUpfCharm(ops.CharmBase):
    """Machine charm for SD-Core User Plane Function."""

    def __init__(self, *args):
        super().__init__(*args)
        self.framework.observe(self.on.collect_unit_status, self._on_collect_status)
        self._machine = Machine()
        self._cos_agent = COSAgentProvider(
            self,
            scrape_configs=[
                {
                    "static_configs": [{"targets": [f"*:{PROMETHEUS_PORT}"]}],
                }
            ],
        )
        try:
            self._charm_config: CharmConfig = CharmConfig.from_charm(charm=self)
        except CharmConfigInvalidError:
            return
        self._network = self._get_network_configuration()
        self.fiveg_n4_provider = N4Provides(charm=self, relation_name="fiveg_n4")
        self.framework.observe(self.on.install, self._configure)
        self.framework.observe(self.on.update_status, self._configure)
        self.framework.observe(self.on.config_changed, self._configure)
        self.framework.observe(
            self.fiveg_n4_provider.on.fiveg_n4_request, self._on_fiveg_n4_request
        )
        self.framework.observe(self.on.remove, self._on_remove)

    def _on_collect_status(self, event: CollectStatusEvent):  # noqa C901
        """Collect unit status."""
        if not self.unit.is_leader():
            event.add_status(BlockedStatus("Scaling is not implemented for this charm"))
            return
        try:
            self._charm_config: CharmConfig = CharmConfig.from_charm(charm=self)
        except CharmConfigInvalidError as exc:
            event.add_status(BlockedStatus(exc.msg))
            return
        if not self._is_cpu_compatible():
            event.add_status(BlockedStatus("CPU is not compatible, see logs for more details"))
            return
        self._network = self._get_network_configuration()
        if invalid_network_interfaces := self._network.get_invalid_network_interfaces():
            event.add_status(
                BlockedStatus(f"Network interfaces are not valid: {invalid_network_interfaces}")
            )
            return
        if not self._network.is_configured():
            event.add_status(WaitingStatus("Waiting for network configuration"))
            return
        if not self._upf_config_file_is_written():
            event.add_status(WaitingStatus("Waiting for UPF configuration file"))
            return
        if not self._bessd_service_started():
            event.add_status(WaitingStatus("Waiting for bessd service to start"))
            return
        if not self._is_bessd_grpc_service_ready():
            event.add_status(WaitingStatus("Waiting for bessd gRPC service to start"))
            return
        if not self._pfcp_service_started():
            event.add_status(WaitingStatus("Waiting for pcfp service to start"))
            return
        if not self._is_bessd_configured():
            event.add_status(WaitingStatus("Waiting for bessd worker to start"))
            return
        if not self._routectl_service_started():
            event.add_status(WaitingStatus("Waiting for routectl service to start"))
            return
        event.add_status(ActiveStatus())

    def _configure(self, _):
        """Handle UPF installation."""
        if not self.unit.is_leader():
            return
        if not self._is_cpu_compatible():
            return
        try:
            self._charm_config: CharmConfig = CharmConfig.from_charm(charm=self)
        except CharmConfigInvalidError:
            return

        self._network = self._get_network_configuration()
        if self._network.get_invalid_network_interfaces():
            return

        self._network.configure()
        if not self._network.is_configured():
            return

        self._install_upf_snap()
        self._generate_upf_config_file()
        self._start_bessd_service()
        self._configure_bessd_service()
        self._start_pfcp_service()
        self._start_routectl_service()
        self._update_fiveg_n4_relation_data()

    def _get_network_configuration(self) -> UPFNetwork:
        """Get the network configuration for the UPF service."""
        return UPFNetwork(
            access_interface_name=self._charm_config.access_interface_name,  # type: ignore
            access_ip=self._charm_config.access_ip,  # type: ignore
            access_gateway_ip=str(self._charm_config.access_gateway_ip),  # type: ignore
            access_mtu_size=self._charm_config.access_interface_mtu_size,  # type: ignore
            core_interface_name=self._charm_config.core_interface_name,  # type: ignore
            core_ip=self._charm_config.core_ip,  # type: ignore
            core_gateway_ip=str(self._charm_config.core_gateway_ip),  # type: ignore
            core_mtu_size=self._charm_config.core_interface_mtu_size,  # type: ignore
            gnb_subnet=str(self._charm_config.gnb_subnet),
        )

    def _on_remove(self, event: RemoveEvent):
        """Stop the upf services and uninstall snap."""
        snap_cache = SnapCache()
        upf_snap = snap_cache[UPF_SNAP_NAME]
        for service in ["bessd", "routectl", "pfcpiface"]:
            if upf_snap.services.get(service):
                upf_snap.stop(services=[service])
        upf_snap.ensure(SnapState.Absent)
        self._network.clean_configuration()

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
        if configured_hostname := self._charm_config.external_upf_hostname:
            return configured_hostname
        else:
            return self._network.core_interface.get_ip_address()

    def _install_upf_snap(self) -> None:
        """Install the UPF snap in the workload."""
        if self._upf_snap_installed():
            return
        try:
            snap_cache = SnapCache()
            upf_snap = snap_cache[UPF_SNAP_NAME]
            upf_snap.ensure(
                SnapState.Latest,
                channel=UPF_SNAP_CHANNEL,
                revision=UPF_SNAP_REVISION,
                devmode=True,
            )
            upf_snap.hold()
            logger.info("UPF snap installed")
        except SnapError as e:
            logger.error("An exception occurred when installing the UPF snap. Reason: %s", str(e))
            raise e

    def _upf_snap_installed(self) -> bool:
        """Check if the UPF snap is installed."""
        snap_cache = SnapCache()
        upf_snap = snap_cache[UPF_SNAP_NAME]
        return upf_snap.state == SnapState.Latest and upf_snap.revision == UPF_SNAP_REVISION

    def _start_bessd_service(self) -> None:
        """Start the bessd service."""
        if self._bessd_service_started():
            return
        snap_cache = SnapCache()
        upf_snap = snap_cache[UPF_SNAP_NAME]
        upf_snap.start(services=["bessd"])
        logger.info("UPF bessd service started")

    def _start_pfcp_service(self) -> None:
        """Start the PFCP service."""
        if self._pfcp_service_started():
            return
        snap_cache = SnapCache()
        upf_snap = snap_cache[UPF_SNAP_NAME]
        upf_snap.start(services=["pfcpiface"])
        logger.info("UPF pfcpiface service started")

    def _start_routectl_service(self) -> None:
        """Start the UPF routectl service."""
        if self._routectl_service_started():
            return
        snap_cache = SnapCache()
        upf_snap = snap_cache[UPF_SNAP_NAME]
        upf_snap.start(services=["routectl"])
        logger.info("UPF routectl service started")

    def _bessd_service_started(self) -> bool:
        """Check if the bessd service is started."""
        snap_cache = SnapCache()
        upf_snap = snap_cache[UPF_SNAP_NAME]
        upf_services = upf_snap.services
        return upf_services["bessd"]["active"]

    def _pfcp_service_started(self) -> bool:
        """Check if the pfcp service is started."""
        snap_cache = SnapCache()
        upf_snap = snap_cache[UPF_SNAP_NAME]
        upf_services = upf_snap.services
        return upf_services["pfcpiface"]["active"]

    def _routectl_service_started(self) -> bool:
        """Check if the routectl service is started."""
        snap_cache = SnapCache()
        upf_snap = snap_cache[UPF_SNAP_NAME]
        upf_services = upf_snap.services
        return upf_services["routectl"]["active"]

    def _configure_bessd_service(self) -> None:
        self._wait_for_bessd_grpc_service_to_be_ready()
        self._run_bess_configuration()

    def _run_bess_configuration(self) -> None:
        """Run bessd configuration in workload."""
        if self._is_bessd_configured():
            return

        logger.info("Starting configuration of the `bessd` service")
        process = self._machine.exec(
            command="sdcore-upf.bessctl run /snap/sdcore-upf/current/opt/bess/bessctl/conf/up4",
            timeout=10,
        )
        try:
            (stdout, stderr) = process.wait_output()
            logger.info("Service `bessd` configuration script complete")
            logger.debug("`up4.bess`: %s", stdout)
            if isinstance(stderr, str) and len(stderr) > 0:
                logger.error("`up4.bess`: %s", stderr)
            return
        except ExecError as e:
            logger.info("Failed running configuration for bess: %s", e)

    def _wait_for_bessd_grpc_service_to_be_ready(self, timeout: float = 60):
        initial_time = time.time()

        while not self._is_bessd_grpc_service_ready():
            if time.time() - initial_time > timeout:
                raise TimeoutError("Timed out waiting for bessd gRPC server to become ready")
            time.sleep(2)

    def _is_bessd_grpc_service_ready(self) -> bool:
        """Check if bessd grpc service is ready.

        Examines the output from bessctl to see if it is able to communicate
        with bessd. This indicates the service is ready to accept configuration
        commands.

        Returns:
            bool:   True/False
        """
        command = "sdcore-upf.bessctl show version"
        process = self._machine.exec(
            command=command,
            timeout=10,
        )
        try:
            process.wait_output()
            return True
        except ExecError as e:
            logger.info("gRPC Check: %s", e)
            return False

    def _is_bessd_configured(self) -> bool:
        """Check if bessd has been configured.

        Examines the output from bessctl to show worker. If there is no
        active worker, bessd is assumed not to be configured.

        Returns:
            bool:   True/False
        """
        command = "sdcore-upf.bessctl show worker"
        process = self._machine.exec(
            command=command,
            timeout=10,
        )
        try:
            (stdout, stderr) = process.wait_output()
            logger.debug("bessd configured workers: %s", stdout)
            return True
        except ExecError as e:
            logger.info(f"Configuration check: {e}")
            return False

    def _generate_upf_config_file(self) -> None:
        """Generate the UPF configuration file."""
        if not self._charm_config.core_interface_name:
            raise ValueError("Core network interface name is empty")
        core_ip_address = self._network.core_interface.get_ip_address()
        if not core_ip_address:
            raise ValueError("Core network IP address is not valid")
        content = render_upf_config_file(
            upf_hostname=self._get_upf_hostname(),
            upf_mode=self._get_upf_mode(),
            access_interface_name=self._charm_config.access_interface_name,  # type: ignore
            core_interface_name=self._charm_config.core_interface_name,
            core_ip_address=core_ip_address.split("/")[0] if core_ip_address else "",
            dnn=self._charm_config.dnn,
            pod_share_path=UPF_CONFIG_PATH,
            enable_hw_checksum=self._charm_config.enable_hw_checksum,
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

    def _get_upf_hostname(self) -> str:
        return "0.0.0.0"

    def _get_upf_mode(self) -> str:
        return "af_packet"

    def _get_cpu_extensions(self) -> list[str]:
        """Return a list of extensions (instructions) supported by the CPU.

        Returns:
            list: List of extensions (instructions) supported by the CPU.
        """
        process = self._machine.exec(command="lscpu", timeout=10)
        try:
            (cpu_info, stderr) = process.wait_output()
        except ExecError as e:
            logger.info("Failed running `lscpu`: %s", e)
            return []
        cpu_flags = []
        for cpu_info_item in cpu_info.split("\n"):
            if "Flags:" in cpu_info_item:
                cpu_flags = cpu_info_item.split()
                del cpu_flags[0]
        return cpu_flags

    def _is_cpu_compatible(self) -> bool:
        """Return whether the CPU meets requirements to run this charm.

        Returns:
            bool: Whether the CPU meets requirements to run this charm
        """
        if not all(
            required_extension in self._get_cpu_extensions()
            for required_extension in REQUIRED_CPU_EXTENSIONS
        ):
            logger.warning(
                "Please use a CPU that has the following capabilities: %s",
                ", ".join(REQUIRED_CPU_EXTENSIONS),
            )
            return False
        return True


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
