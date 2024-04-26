#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import json
import logging
import os
import re
from pathlib import Path

import pytest
import yaml
from charm import PFCP_PORT, UPF_CONFIG_FILE_NAME, UPF_CONFIG_PATH
from juju.application import Application
from juju.machine import Machine
from juju.model import Model
from pytest_operator.plugin import OpsTest

logger = logging.getLogger(__name__)

METADATA = yaml.safe_load(Path("./charmcraft.yaml").read_text())
APP_NAME = METADATA["name"]
MODEL_NAME = "upf-integration"
ACCESS_INTERFACE_NAME = "enp6s0"
CORE_INTERFACE_NAME = "enp7s0"
GRAFANA_AGENT_APPLICATION_NAME = "grafana-agent"


class TestUPFMachineCharm:
    @pytest.fixture(autouse=True)
    @pytest.mark.abort_on_fail
    async def setup(self):
        self.model = Model()
        await self.model.connect(model_name=MODEL_NAME)

    @pytest.fixture(scope="module")
    async def deploy_grafana_agent(self) -> None:
        """Deploys grafana-agent-operator."""
        self.model = Model()
        await self.model.connect(model_name=MODEL_NAME)

        await self.model.deploy(
            GRAFANA_AGENT_APPLICATION_NAME,
            application_name=GRAFANA_AGENT_APPLICATION_NAME,
            trust=True,
        )

    @pytest.fixture(scope="module")
    async def deploy(self, ops_test: OpsTest, request):
        """Deploy the charm-under-test together with related charms.

        Assert on the unit status before any relations/configurations take place.
        """
        assert ops_test.model
        charm = Path(request.config.getoption("--charm_path")).resolve()
        await ops_test.model.deploy(
            charm,
            application_name=APP_NAME,
            config={
                "access-interface-name": ACCESS_INTERFACE_NAME,
                "core-interface-name": CORE_INTERFACE_NAME,
            },
            to=0,
        )

    @pytest.mark.abort_on_fail
    async def test_given_upf_machine_charm_built_when_deploy_than_charm_goes_to_active_status(
        self, ops_test: OpsTest, deploy
    ):
        await ops_test.model.connect(model_name=MODEL_NAME)
        await asyncio.gather(
            deploy,
            ops_test.model.wait_for_idle(apps=[APP_NAME], status="active", timeout=1000),
        )

    @pytest.mark.abort_on_fail
    async def test_given_upf_machine_charm_is_deployed_when_inspect_upf_config_file_then_access_and_core_interfaces_match_charm_config(  # noqa: E501
        self,
    ):
        machine = await self._get_machine("0")
        application = await self._get_application(APP_NAME)

        upf_config = await self._get_upf_config(machine)
        charm_config = await application.get_config()

        assert upf_config["access"]["ifname"] == charm_config["access-interface-name"]["value"]
        assert upf_config["core"]["ifname"] == charm_config["core-interface-name"]["value"]

    @pytest.mark.abort_on_fail
    async def test_given_upf_machine_charm_is_deployed_when_inspect_upf_config_file_then_ip_masquerade_config_matches_core_iface_ip(  # noqa: E501
        self,
    ):
        machine = await self._get_machine("0")
        application = await self._get_application(APP_NAME)

        upf_config = await self._get_upf_config(machine)
        charm_config = await application.get_config()
        core_interface_name = charm_config["core-interface-name"]["value"]

        core_iface_info = await machine.ssh(
            f"ip -f inet addr show {core_interface_name} | grep inet"
        )
        core_iface_ip = core_iface_info.split()[1].split("/")[0]

        assert upf_config["core"]["ip_masquerade"] == core_iface_ip

    @pytest.mark.abort_on_fail
    async def test_given_upf_machine_charm_is_deployed_when_inspect_upf_config_file_then_dnn_matches_charm_config(  # noqa: E501
        self,
    ):
        machine = await self._get_machine("0")
        application = await self._get_application(APP_NAME)

        upf_config = await self._get_upf_config(machine)
        charm_config = await application.get_config()

        assert upf_config["cpiface"]["dnn"] == charm_config["dnn"]["value"]

    @pytest.mark.abort_on_fail
    async def test_given_upf_machine_charm_is_deployed_when_list_processes_then_upf_processes_are_running(  # noqa: E501
        self,
    ):
        machine = await self._get_machine("0")
        application = await self._get_application(APP_NAME)

        charm_config = await application.get_config()
        access_interface_name = charm_config["access-interface-name"]["value"]
        core_interface_name = charm_config["core-interface-name"]["value"]

        processes = await machine.ssh("ps aux | grep /snap/sdcore-upf")

        assert "bessd -f -grpc-url=0.0.0.0:10514 -m 0" in processes
        assert f"route_control.py -i {access_interface_name} {core_interface_name}" in processes
        assert (
            f"pfcpiface -config {os.path.join(UPF_CONFIG_PATH, UPF_CONFIG_FILE_NAME)}" in processes
        )

    @pytest.mark.abort_on_fail
    async def test_given_upf_machine_charm_is_deployed_when_check_open_ports_then_pfcp_port_is_listening(  # noqa: E501
        self,
    ):
        machine = await self._get_machine("0")

        open_ports = await machine.ssh("netstat -ulnp")

        assert str(PFCP_PORT) in open_ports

    @pytest.mark.abort_on_fail
    async def test_given_upf_machine_charm_is_deployed_when_check_bessd_logs_then_no_errors_in_the_logs(  # noqa: E501
        self,
    ):
        machine = await self._get_machine("0")

        bessd_logs = await machine.ssh("journalctl | grep sdcore-upf.bessd | grep -v audit")

        assert not re.search("error", bessd_logs, re.IGNORECASE)
        assert not re.search("traceback", bessd_logs, re.IGNORECASE)

    @pytest.mark.abort_on_fail
    async def test_given_upf_machine_charm_is_deployed_when_check_routes_then_route_to_gnb_subnet_is_set(  # noqa: E501
        self,
    ):
        machine = await self._get_machine("0")
        application = await self._get_application(APP_NAME)

        charm_config = await application.get_config()
        gnb_subnet = charm_config["gnb-subnet"]["value"]
        access_interface_name = charm_config["access-interface-name"]["value"]
        routes = await machine.ssh("ip route")
        gnb_route_pattern = "^%s via \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3} dev %s proto static" % (  # noqa: E501, W605
            gnb_subnet, access_interface_name
        )

        assert any(re.match(gnb_route_pattern, route) for route in routes.splitlines())

    @pytest.mark.abort_on_fail
    async def test_given_upf_machine_charm_is_deployed_when_check_routes_then_default_route_for_core_interface_is_set(  # noqa: E501
        self,
    ):
        machine = await self._get_machine("0")
        application = await self._get_application(APP_NAME)

        charm_config = await application.get_config()
        core_interface_name = charm_config["core-interface-name"]["value"]
        routes = await machine.ssh("ip route")
        core_default_route_pattern = "^default via \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3} dev %s proto static metric 110" % (  # noqa: E501, W605
            core_interface_name,
        )

        assert any(re.match(core_default_route_pattern, route) for route in routes.splitlines())

    @pytest.mark.abort_on_fail
    async def test_given_upf_machine_charm_is_deployed_when_charm_config_changed_then_upf_config_file_is_updated(  # noqa: E501
        self,
    ):
        test_dnn_name = "integration"
        machine = await self._get_machine("0")
        application = await self._get_application(APP_NAME)

        await application.set_config(config={"dnn": test_dnn_name})
        await self.model.wait_for_idle(status="active")
        upf_config = await self._get_upf_config(machine)

        assert upf_config["cpiface"]["dnn"] == test_dnn_name

    @pytest.mark.abort_on_fail
    async def test_given_upf_machine_charm_is_deployed_when_charm_config_changed_to_invalid_then_charm_goes_to_blocked_state(  # noqa: E501
        self,
    ):
        invalid_access_iface_name = "whatever"
        application = await self._get_application(APP_NAME)

        await application.set_config(config={"access-interface-name": invalid_access_iface_name})
        await self.model.wait_for_idle()

        assert application.status == "blocked"

    @pytest.mark.abort_on_fail
    async def test_given_upf_machine_charm_is_deployed_and_in_blocked_status_when_charm_config_changed_back_to_valid_then_charm_goes_to_active_state(  # noqa: E501
        self,
    ):
        application = await self._get_application(APP_NAME)

        await application.set_config(config={"access-interface-name": ACCESS_INTERFACE_NAME})
        await self.model.wait_for_idle()

        assert application.status == "active"

    @pytest.mark.abort_on_fail
    async def test_given_grafana_agent_deployed_when_relate_to_grafana_agent_then_status_is_active(self, deploy_grafana_agent):  # noqa: E501
        application = await self._get_application(APP_NAME)
        await self.model.integrate(
            relation1=f"{APP_NAME}:cos-agent",
            relation2=f"{GRAFANA_AGENT_APPLICATION_NAME}:cos-agent",
        )
        await self.model.wait_for_idle(apps=[APP_NAME])
        assert application.status == "active"

    async def _get_machine(self, machine_id: str):
        return Machine(entity_id=machine_id, model=self.model)

    async def _get_application(self, application_name: str):
        return Application(entity_id=application_name, model=self.model)

    @staticmethod
    async def _get_upf_config(machine):
        await machine.scp_from(os.path.join(UPF_CONFIG_PATH, UPF_CONFIG_FILE_NAME), ".")
        with open(UPF_CONFIG_FILE_NAME, "r") as upf_config_file:
            upf_config = json.loads(upf_config_file.read())
        return upf_config
