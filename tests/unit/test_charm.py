# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import json
import unittest
from itertools import count
from unittest.mock import MagicMock, call, patch

import ops
import ops.testing
from charm import SdcoreUpfCharm
from charms.operator_libs_linux.v2.snap import SnapState
from machine import ExecError


def read_file(path: str) -> str:
    """Read a file and returns as a string.

    Args:
        path (str): path to the file.

    Returns:
        str: content of the file.
    """
    with open(path, "r") as f:
        content = f.read()
    return content


class TestCharm(unittest.TestCase):
    @patch("charm.UPFNetwork")
    @patch("charm.Machine")
    def setUp(self, patch_machine, patch_network):
        self.mock_machine = MagicMock()
        self.mock_machine.pull.return_value = ""
        patch_machine.return_value = self.mock_machine
        self.mock_upf_network = MagicMock()
        self.mock_upf_network.get_invalid_network_interfaces.return_value = []
        self.mock_upf_network.core_interface.get_ip_address.return_value = "192.168.250.3"
        patch_network.return_value = self.mock_upf_network
        self.harness = ops.testing.Harness(SdcoreUpfCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

    def test_given_unit_is_not_leader_when_config_changed_then_status_is_blocked(self):
        self.harness.set_leader(False)

        self.harness.update_config()

        self.assertEqual(
            self.harness.model.unit.status,
            ops.BlockedStatus("Scaling is not implemented for this charm"),
        )

    @patch("charms.operator_libs_linux.v2.snap.SnapCache")
    def test_given_upf_snap_uninstalled_when_configure_then_upf_snap_installed(
        self, mock_snap_cache
    ):
        self.harness.set_leader(is_leader=True)
        upf_snap = MagicMock()
        snap_cache = {"sdcore-upf": upf_snap}
        mock_snap_cache.return_value = snap_cache

        self.harness.charm.on.install.emit()

        upf_snap.ensure.assert_called_with(
            SnapState.Latest,
            channel="latest/edge",
            revision="3",
            devmode=True,
        )
        upf_snap.hold.assert_called()

    @patch("charms.operator_libs_linux.v2.snap.SnapCache")
    def test_given_upf_service_not_started_when_config_changed_then_service_started(
        self, mock_snap_cache
    ):
        self.harness.set_leader(True)
        upf_snap = MagicMock()
        snap_cache = {"sdcore-upf": upf_snap}
        mock_snap_cache.return_value = snap_cache

        self.harness.update_config()

        upf_snap.start.assert_has_calls(
            calls=[
                call(services=["bessd"]),
                call(services=["routectl"]),
                call(services=["pfcpiface"]),
            ]
        )

    @patch("charm.time.sleep")
    @patch("charm.time.time")
    @patch("charms.operator_libs_linux.v2.snap.SnapCache")
    def test_bess_configuration_timeout_error_raised_on_exec_error(
        self, mock_snap_cache, mock_time, mock_sleep
    ):
        mock_time.side_effect = count(start=1)
        mock_sleep.return_value = None
        self.harness.set_leader(True)
        upf_snap = MagicMock()
        mock_process = MagicMock()
        self.mock_machine.exec.return_value = mock_process
        mock_process.wait_output.side_effect = ExecError(
            command="whatever",
            exit_code=1,
            stdout="",
            stderr="",
        )
        snap_cache = {"sdcore-upf": upf_snap}
        mock_snap_cache.return_value = snap_cache

        with self.assertRaises(TimeoutError):
            self.harness.update_config()

    @patch("charms.operator_libs_linux.v2.snap.SnapCache")
    def test_given_unit_is_leader_when_config_changed_then_status_is_active(self, mock_snap_cache):
        self.harness.set_leader(True)
        upf_snap = MagicMock()
        snap_cache = {"sdcore-upf": upf_snap}
        mock_snap_cache.return_value = snap_cache

        self.harness.update_config()

        self.assertEqual(self.harness.model.unit.status, ops.ActiveStatus())

    @patch("charms.operator_libs_linux.v2.snap.SnapCache")
    def test_given_config_file_not_written_when_config_changed_then_config_file_is_written(
        self, _
    ):
        self.harness.set_leader(True)
        self.mock_machine.exists.return_value = False

        self.harness.update_config()

        expected_config_file_content = read_file("tests/unit/expected_upf.json").strip()

        _, kwargs = self.mock_machine.push.call_args
        assert kwargs["path"] == "/var/snap/sdcore-upf/common/upf.json"
        assert json.loads(kwargs["source"]) == json.loads(expected_config_file_content)

    @patch("charms.operator_libs_linux.v2.snap.SnapCache")
    def test_given_config_file_written_with_different_content_when_config_changed_then_new_config_file_is_written(
        self, _
    ):
        self.harness.set_leader(True)
        self.mock_machine.exists_return_value = True
        self.mock_machine.pull_return_value = "initial content"

        self.harness.update_config()

        expected_config_file_content = read_file("tests/unit/expected_upf.json").strip()
        _, kwargs = self.mock_machine.push.call_args
        assert kwargs["path"] == "/var/snap/sdcore-upf/common/upf.json"
        assert json.loads(kwargs["source"]) == json.loads(expected_config_file_content)

    @patch("charms.operator_libs_linux.v2.snap.SnapCache")
    def test_given_config_file_written_with_identical_content_when_config_changed_then_new_config_file_not_written(
        self, _
    ):
        self.harness.set_leader(True)
        self.mock_machine.exists.return_value = True
        self.mock_machine.pull.return_value = read_file("tests/unit/expected_upf.json").strip()

        self.harness.update_config()

        self.mock_machine.push.assert_not_called()

    def test_given_invalid_config_when_config_changed_then_status_is_blocked(self):
        self.harness.set_leader(True)
        self.harness.update_config({"gnb-subnet": "not an ip address"})

        self.assertEqual(
            self.harness.model.unit.status,
            ops.BlockedStatus("The following configurations are not valid: ['gnb-subnet']"),
        )

    @patch("charms.operator_libs_linux.v2.snap.SnapCache")
    def test_given_network_interfaces_not_valid_when_config_changed_then_status_is_blocked(
        self, _
    ):
        self.mock_upf_network.get_invalid_network_interfaces.return_value = [
            "eth0",
            "eth1",
        ]
        self.harness.set_leader(True)
        self.harness.update_config()

        self.assertEqual(
            self.harness.model.unit.status,
            ops.BlockedStatus("Network interfaces are not valid: ['eth0', 'eth1']"),
        )

    @patch("charms.operator_libs_linux.v2.snap.SnapCache")
    def test_given_network_interfaces_valid_when_config_changed_then_routes_are_created(self, _):
        gnb_subnet = "192.168.251.0/24"
        self.harness.set_leader(True)
        self.harness.update_config(
            {
                "gnb-subnet": gnb_subnet,
                "core-interface-name": "eth0",
                "access-interface-name": "eth1",
            }
        )

        self.mock_upf_network.configure.assert_called_once()
