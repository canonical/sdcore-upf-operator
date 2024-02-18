# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import json
import unittest
from unittest.mock import MagicMock, patch

import ops
import ops.testing
from charm import SdcoreUpfCharm
from charms.operator_libs_linux.v2.snap import SnapState


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

    def setUp(self):
        self.patch_machine = MagicMock()
        self.patch_network = MagicMock()

        self.patch_machine.exists.return_value = False
        self.patch_machine.pull.return_value = "file content"
        self.patch_network.get_invalid_network_interfaces.return_value = []
        self.patch_network.get_interface_ip_address.return_value = "192.168.250.3"

        self.machine_patch = patch("charm.Machine", return_value=self.patch_machine)
        self.network_patch = patch("charm.UPFNetwork", return_value=self.patch_network)

        self.machine_patch.start()
        self.network_patch.start()

        self.addCleanup(self.machine_patch.stop)
        self.addCleanup(self.network_patch.stop)

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
    def test_install_upf_snap(self, mock_snap_cache):
        mock_upf_snap = MagicMock()

        mock_snap_cache.return_value = {"sdcore-upf": mock_upf_snap}

        self.harness.charm._install_upf_snap()

        mock_upf_snap.ensure.assert_called_once_with(
            SnapState.Latest,
            channel="latest/edge",
            revision="3",
            devmode=True,
        )
        mock_upf_snap.hold.assert_called_once()

    @patch("charms.operator_libs_linux.v2.snap.SnapCache")
    def test_given_unit_is_leader_when_config_changed_then_status_is_active(self, mock_snap_cache):
        self.harness.set_leader(True)

        self.harness.update_config()

        self.assertEqual(self.harness.model.unit.status, ops.ActiveStatus())

    @patch("charms.operator_libs_linux.v2.snap.SnapCache")
    def test_given_config_file_not_written_when_config_changed_then_config_file_is_written(
        self, _
    ):
        self.harness.set_leader(True)

        self.harness.update_config()

        expected_config_file_content = read_file("tests/unit/expected_upf.json")
        assert (
            "/var/snap/sdcore-upf/common/upf.json" == self.patch_machine.push.call_args[1]["path"]
        )
        assert json.loads(expected_config_file_content) == json.loads(
            self.patch_machine.push.call_args[1]["source"]
        )

    @patch("charms.operator_libs_linux.v2.snap.SnapCache")
    def test_given_config_file_written_with_different_content_when_config_changed_then_new_config_file_is_written(
        self, _
    ):
        self.harness.set_leader(True)
        self.patch_machine.exists.return_value = True

        self.harness.update_config()

        expected_config_file_content = read_file("tests/unit/expected_upf.json").strip()
        assert (
            "/var/snap/sdcore-upf/common/upf.json" == self.patch_machine.push.call_args[1]["path"]
        )
        assert json.loads(expected_config_file_content) == json.loads(
            self.patch_machine.push.call_args[1]["source"]
        )

    @patch("charms.operator_libs_linux.v2.snap.SnapCache")
    def test_given_config_file_written_with_identical_content_when_config_changed_then_new_config_file_not_written(
        self, _
    ):
        self.harness.set_leader(True)
        self.patch_machine.exists.return_value = True
        self.patch_machine.pull.return_value = read_file("tests/unit/expected_upf.json").strip()

        self.harness.update_config()

        self.patch_machine.push.assert_not_called()

    def test_given_invalid_config_when_config_changed_then_status_is_blocked(self):
        self.harness.set_leader(True)
        self.harness.update_config({"gnb-subnet": "not an ip subnet"})

        self.assertEqual(
            self.harness.model.unit.status,
            ops.BlockedStatus("The following configurations are not valid: ['gnb-subnet']"),
        )

    @patch("charms.operator_libs_linux.v2.snap.SnapCache")
    def test_given_network_interfaces_not_valid_when_config_changed_then_status_is_blocked(
        self, _
    ):
        self.patch_network.get_invalid_network_interfaces.return_value = [
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

        self.patch_network.configure.assert_called_once()
