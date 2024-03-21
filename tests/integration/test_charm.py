#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import json
import logging
import re
from pathlib import Path

import pytest
import yaml
from charm import PFCP_PORT
from juju.application import Application
from juju.machine import Machine
from juju.model import Model
from pytest_operator.plugin import OpsTest

logger = logging.getLogger(__name__)

METADATA = yaml.safe_load(Path("./charmcraft.yaml").read_text())
APP_NAME = METADATA["name"]
MODEL_NAME = "upf-integration"
UPF_CONFIG_FILE_PATH = "/var/snap/sdcore-upf/common/upf.json"


@pytest.mark.abort_on_fail
async def test_given_upf_machine_charm_built_when_deploy_than_charm_goes_to_active_status(
    ops_test: OpsTest
):
    charm = await ops_test.build_charm(".")
    await ops_test.model.connect(model_name=MODEL_NAME)

    await asyncio.gather(
        ops_test.model.deploy(
            charm,
            application_name=APP_NAME,
            config={
                "access-interface-name": "enp6s0",
                "core-interface-name": "enp7s0",
            },
            to=0,
        ),
        ops_test.model.wait_for_idle(apps=[APP_NAME], status="active", timeout=1000),
    )


@pytest.mark.abort_on_fail
async def test_given_upf_machine_charm_is_deployed_when_inspect_upf_config_file_then_access_and_core_interfaces_match_charm_config():  # noqa: E501
    machine = await _get_machine("0")
    application = await _get_application(APP_NAME)

    upf_config = await _get_upf_config(machine)
    charm_config = await application.get_config()

    assert upf_config["access"]["ifname"] == charm_config["access-interface-name"]["value"]
    assert upf_config["core"]["ifname"] == charm_config["core-interface-name"]["value"]


@pytest.mark.abort_on_fail
async def test_given_upf_machine_charm_is_deployed_when_inspect_upf_config_file_then_ip_masquerade_config_matches_core_iface_ip():  # noqa: E501
    machine = await _get_machine("0")
    application = await _get_application(APP_NAME)

    upf_config = await _get_upf_config(machine)
    charm_config = await application.get_config()
    core_interface_name = charm_config["core-interface-name"]["value"]

    core_iface_info = await machine.ssh(f"ip -f inet addr show {core_interface_name} | grep inet")
    core_iface_ip = core_iface_info.split()[1].split("/")[0]

    assert upf_config["core"]["ip_masquerade"] == core_iface_ip


@pytest.mark.abort_on_fail
async def test_given_upf_machine_charm_is_deployed_when_inspect_upf_config_file_then_dnn_matches_charm_config():  # noqa: E501
    machine = await _get_machine("0")
    application = await _get_application(APP_NAME)

    upf_config = await _get_upf_config(machine)
    charm_config = await application.get_config()

    assert upf_config["cpiface"]["dnn"] == charm_config["dnn"]["value"]


@pytest.mark.abort_on_fail
async def test_given_upf_machine_charm_is_deployed_when_list_processes_then_upf_processes_are_running():  # noqa: E501
    machine = await _get_machine("0")
    application = await _get_application(APP_NAME)

    charm_config = await application.get_config()
    access_interface_name = charm_config["access-interface-name"]["value"]
    core_interface_name = charm_config["core-interface-name"]["value"]

    processes = await machine.ssh("ps aux | grep /snap/sdcore-upf")

    assert "bessd -f -grpc-url=0.0.0.0:10514 -m 0" in processes
    assert f"route_control.py -i {access_interface_name} {core_interface_name}" in processes
    assert f"pfcpiface -config {UPF_CONFIG_FILE_PATH}" in processes


@pytest.mark.abort_on_fail
async def test_given_upf_machine_charm_is_deployed_when_check_open_ports_then_pfcp_port_is_listening():  # noqa: E501
    machine = await _get_machine("0")

    open_ports = await machine.ssh("netstat -ulnp")

    assert str(PFCP_PORT) in open_ports


@pytest.mark.abort_on_fail
async def test_given_upf_machine_charm_is_deployed_when_check_bessd_logs_then_no_errors_in_the_logs():  # noqa: E501
    machine = await _get_machine("0")

    bessd_logs = await machine.ssh("journalctl | grep sdcore-upf.bessd | grep -v audit")
    logger.error(bessd_logs)

    assert not re.search("error", bessd_logs, re.IGNORECASE)
    assert not re.search("traceback", bessd_logs, re.IGNORECASE)


async def _get_machine(machine_id: str):
    model = Model()
    await model.connect(model_name=MODEL_NAME)
    return Machine(entity_id=machine_id, model=model)


async def _get_application(application_name: str):
    model = Model()
    await model.connect(model_name=MODEL_NAME)
    return Application(entity_id=application_name, model=model)


async def _get_upf_config(machine):
    await machine.scp_from(UPF_CONFIG_FILE_PATH, ".")
    with open(UPF_CONFIG_FILE_PATH.split("/")[-1], "r") as upf_config_file:
        upf_config = json.loads(upf_config_file.read())
    return upf_config
