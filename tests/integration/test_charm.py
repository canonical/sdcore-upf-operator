#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import logging
from pathlib import Path

import pytest
import yaml
from pytest_operator.plugin import OpsTest

logger = logging.getLogger(__name__)

METADATA = yaml.safe_load(Path("./charmcraft.yaml").read_text())
APP_NAME = METADATA["name"]
MODEL_NAME = "upf-integration"


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
