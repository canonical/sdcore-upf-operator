# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


import json
from unittest.mock import MagicMock, call

from charms.operator_libs_linux.v2.snap import SnapState
from ops import testing

from tests.unit.fixtures import UPFUnitTestFixtures


class TestCharmConfigure(UPFUnitTestFixtures):
    def test_given_dpdk_mode_when_configure_then_interfaces_are_created(
        self,
    ):
        self.mock_upf_network.access_interface.exists.return_value = False
        self.mock_upf_network.core_interface.exists.return_value = False
        state_in = testing.State(
            leader=True,
            config={
                "upf-mode": "dpdk",
                "access-interface-mac-address": "00:00:00:00:00:00",
                "access-interface-pci-address": "0000:00:00.0",
                "core-interface-mac-address": "00:00:00:00:00:01",
                "core-interface-pci-address": "0000:00:00.1",
            },
        )

        self.ctx.run(self.ctx.on.config_changed(), state_in)

        self.mock_upf_network.access_interface.create.assert_called_once()
        self.mock_upf_network.core_interface.create.assert_called_once()

    def test_given_leader_when_configure_then_network_is_configured(
        self,
    ):
        state_in = testing.State(
            leader=True,
        )

        self.ctx.run(self.ctx.on.config_changed(), state_in)

        self.mock_upf_network.configure.assert_called_once()

    def test_given_snap_not_installed_when_configure_then_upf_snap_is_installed(
        self,
    ):
        upf_snap = MagicMock()
        upf_snap.services = {
            "bessd": {"active": False},
            "pfcpiface": {"active": False},
            "routectl": {"active": False},
        }
        snap_cache = {"sdcore-upf": upf_snap}
        self.mock_snap_cache.return_value = snap_cache
        state_in = testing.State(
            leader=True,
        )

        self.ctx.run(self.ctx.on.config_changed(), state_in)

        upf_snap.ensure.assert_called_once_with(
            SnapState.Latest,
            channel="1.4/edge",
            devmode=True,
        )
        upf_snap.hold.assert_called_once()

    def test_given_upf_snap_installed_when_configure_then_upf_snap_is_not_installed(
        self,
    ):
        upf_snap = MagicMock()
        upf_snap.services = {
            "bessd": {"active": False},
            "pfcpiface": {"active": False},
            "routectl": {"active": False},
        }
        upf_snap.state = SnapState.Latest
        upf_snap.revision = "54"
        snap_cache = {"sdcore-upf": upf_snap}
        self.mock_snap_cache.return_value = snap_cache
        state_in = testing.State(
            leader=True,
        )

        self.ctx.run(self.ctx.on.config_changed(), state_in)

        upf_snap.ensure.assert_not_called()
        upf_snap.hold.assert_not_called()

    def test_given_config_file_not_pushed_when_configure_then_config_file_is_pushed(
        self,
    ):
        state_in = testing.State(
            leader=True,
        )

        self.ctx.run(self.ctx.on.config_changed(), state_in)

        _, kwargs = self.mock_machine.push.call_args
        assert kwargs["path"] == "/var/snap/sdcore-upf/common/upf.json"
        with open("tests/unit/expected_upf.json", "r") as f:
            expected_config = f.read()
        assert json.loads(kwargs["source"]) == json.loads(expected_config)

    def test_config_file_already_pushed_when_configure_then_config_file_not_pushed(
        self,
    ):
        with open("tests/unit/expected_upf.json", "r") as f:
            expected_config = f.read()
        self.mock_machine.pull.return_value = expected_config
        state_in = testing.State(
            leader=True,
        )

        self.ctx.run(self.ctx.on.config_changed(), state_in)

        self.mock_machine.push.assert_not_called()

    def test_services_not_running_when_configure_then_services_started(
        self,
    ):
        upf_snap = MagicMock()
        upf_snap.services = {
            "bessd": {"active": False},
            "pfcpiface": {"active": False},
            "routectl": {"active": False},
        }
        snap_cache = {"sdcore-upf": upf_snap}
        self.mock_snap_cache.return_value = snap_cache
        state_in = testing.State(
            leader=True,
        )

        self.ctx.run(self.ctx.on.config_changed(), state_in)

        upf_snap.start.assert_has_calls(
            calls=[
                call(services=["bessd"]),
                call(services=["pfcpiface"]),
                call(services=["routectl"]),
            ]
        )

    def test_services_running_when_configure_then_services_not_started(
        self,
    ):
        upf_snap = MagicMock()
        upf_snap.services = {
            "bessd": {"active": True},
            "pfcpiface": {"active": True},
            "routectl": {"active": True},
        }
        snap_cache = {"sdcore-upf": upf_snap}
        self.mock_snap_cache.return_value = snap_cache
        state_in = testing.State(
            leader=True,
        )

        self.ctx.run(self.ctx.on.config_changed(), state_in)

        upf_snap.start.assert_not_called()

    def test_given_fiveg_n4_relation_when_configure_then_n4_information_published(
        self,
    ):
        n4_relation = testing.Relation(
            endpoint="fiveg_n4",
            interface="fiveg_n4",
        )
        state_in = testing.State(
            leader=True,
            relations=[n4_relation],
        )

        self.ctx.run(self.ctx.on.config_changed(), state_in)

        self.mock_n4_provides_publish_upf_information.assert_called_once_with(
            relation_id=n4_relation.id,
            upf_hostname="192.168.250.3",
            upf_n4_port=8805,
        )
