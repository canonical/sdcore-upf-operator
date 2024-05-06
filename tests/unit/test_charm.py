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

TEST_PFCP_PORT = 1234


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
        self.mock_process = MagicMock()
        self.mock_process.wait_output.return_value = (b"Flags: avx2 rdrand", "")
        self.mock_machine.exec.return_value = self.mock_process
        patch_machine.return_value = self.mock_machine
        self.mock_upf_network = MagicMock()
        self.mock_upf_network.get_invalid_network_interfaces.return_value = []
        self.mock_upf_network.core_interface.get_ip_address.return_value = "192.168.250.3"
        patch_network.return_value = self.mock_upf_network
        self.harness = ops.testing.Harness(SdcoreUpfCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

    def test_given_unit_is_not_leader_when_evaluate_status_then_status_is_blocked(self):
        self.harness.set_leader(False)

        self.harness.evaluate_status()

        self.assertEqual(
            self.harness.model.unit.status,
            ops.BlockedStatus("Scaling is not implemented for this charm"),
        )

    @patch("charm.UPFNetwork")
    @patch("charm.SnapCache")
    def test_given_upf_snap_uninstalled_when_configure_then_upf_snap_installed(
        self, mock_snap_cache, patch_network
    ):
        self.harness.set_leader(is_leader=True)
        upf_snap = MagicMock()
        snap_cache = {"sdcore-upf": upf_snap}
        mock_snap_cache.return_value = snap_cache

        self.mock_upf_network = MagicMock()
        self.mock_upf_network.get_invalid_network_interfaces.return_value = []
        self.mock_upf_network.core_interface.get_ip_address.return_value = "192.168.250.3"
        patch_network.return_value = self.mock_upf_network

        self.harness.charm.on.install.emit()

        upf_snap.ensure.assert_called_with(
            SnapState.Latest,
            channel="1.4/edge",
            revision="42",
            devmode=True,
        )
        upf_snap.hold.assert_called()

    @patch("charm.UPFNetwork")
    @patch("charm.SnapCache")
    def test_given_upf_service_not_started_when_config_changed_then_service_started(
        self, mock_snap_cache, patch_network
    ):
        self.harness.set_leader(True)
        upf_snap = MagicMock()
        upf_snap.services = {
            "bessd": {"active": False},
            "pfcpiface": {"active": False},
            "routectl": {"active": False},
        }
        snap_cache = {"sdcore-upf": upf_snap}
        mock_snap_cache.return_value = snap_cache

        self.mock_upf_network = MagicMock()
        self.mock_upf_network.get_invalid_network_interfaces.return_value = []
        self.mock_upf_network.core_interface.get_ip_address.return_value = "192.168.250.3"
        patch_network.return_value = self.mock_upf_network

        self.harness.update_config()

        upf_snap.start.assert_has_calls(
            calls=[
                call(services=["bessd"]),
                call(services=["pfcpiface"]),
                call(services=["routectl"]),
            ]
        )

    @patch("charm.SnapCache")
    def test_given_upf_services_started_when_remove_then_services_stopped(self, mock_snap_cache):
        self.harness.set_leader(True)
        upf_snap = MagicMock()
        upf_snap.services = {
            "bessd": {"active": True},
            "routectl": {"active": True},
            "pfcpiface": {"active": True},
        }
        snap_cache = {"sdcore-upf": upf_snap}
        mock_snap_cache.return_value = snap_cache

        self.harness.charm.on.remove.emit()

        upf_snap.stop.assert_has_calls(
            calls=[
                call(services=["bessd"]),
                call(services=["routectl"]),
                call(services=["pfcpiface"]),
            ]
        )

    @patch("charm.SnapCache")
    def test_given_upf_snap_uninstalled_when_remove_then_services_not_stopped(
        self, mock_snap_cache
    ):
        self.harness.set_leader(True)
        upf_snap = MagicMock()
        upf_snap.services = {}
        snap_cache = {"sdcore-upf": upf_snap}
        mock_snap_cache.return_value = snap_cache

        self.harness.charm.on.remove.emit()

        upf_snap.stop.assert_not_called()

    @patch("charm.UPFNetwork")
    @patch("charm.SnapCache")
    def test_given_bessd_not_configured_when_config_changed_then_bessctl_run_called(
        self, mock_snap_cache, patch_network
    ):
        self.harness.set_leader(True)
        upf_snap = MagicMock()
        snap_cache = {"sdcore-upf": upf_snap}
        mock_snap_cache.return_value = snap_cache

        self.mock_upf_network = MagicMock()
        self.mock_upf_network.get_invalid_network_interfaces.return_value = []
        self.mock_upf_network.core_interface.get_ip_address.return_value = "192.168.250.3"
        patch_network.return_value = self.mock_upf_network

        self.mock_process.wait_output.side_effect = [
            (b"Flags: avx2 rdrand", ""),
            (b"Flags: avx2 rdrand", ""),
            (b"Flags: avx2 rdrand", ""),
            ExecError(
                command="configuration check",
                exit_code=1,
                stdout="mock to represent bessd not configured",
                stderr="",
            ),
            ("stdout", "stderr"),
        ]
        self.harness.update_config()

        self.assertEqual(
            "sdcore-upf.bessctl run /snap/sdcore-upf/current/opt/bess/bessctl/conf/up4",
            self.mock_machine.method_calls[-1].kwargs["command"],
        )

    @patch("charm.UPFNetwork")
    @patch("charm.time.sleep")
    @patch("charm.time.time")
    @patch("charm.SnapCache")
    def test_bess_configuration_timeout_error_raised_on_exec_error(
        self, mock_snap_cache, mock_time, mock_sleep, patch_network
    ):
        mock_time.side_effect = count(start=1, step=60)
        mock_sleep.return_value = None
        self.harness.set_leader(True)
        upf_snap = MagicMock()
        self.mock_process.wait_output.side_effect = [
            (b"Flags: avx2 rdrand", ""),
            (b"Flags: avx2 rdrand", ""),
            ExecError(command="whatever", exit_code=1, stdout="", stderr=""),
        ]
        snap_cache = {"sdcore-upf": upf_snap}
        mock_snap_cache.return_value = snap_cache

        self.mock_upf_network = MagicMock()
        self.mock_upf_network.get_invalid_network_interfaces.return_value = []
        self.mock_upf_network.core_interface.get_ip_address.return_value = "192.168.250.3"
        patch_network.return_value = self.mock_upf_network

        with self.assertRaises(TimeoutError):
            self.harness.update_config()

    @patch("charm.UPFNetwork")
    @patch("charm.SnapCache")
    def test_given_unit_is_leader_when_config_changed_then_status_is_active(self, mock_snap_cache, patch_network):  # noqa: E501
        self.harness.set_leader(True)
        upf_snap = MagicMock()
        snap_cache = {"sdcore-upf": upf_snap}
        mock_snap_cache.return_value = snap_cache

        self.mock_upf_network = MagicMock()
        self.mock_upf_network.get_invalid_network_interfaces.return_value = []
        self.mock_upf_network.core_interface.get_ip_address.return_value = "192.168.250.3"
        patch_network.return_value = self.mock_upf_network

        self.harness.evaluate_status()

        self.assertEqual(self.harness.model.unit.status, ops.ActiveStatus())

    @patch("charm.UPFNetwork")
    @patch("charm.SnapCache")
    def test_given_config_file_not_written_when_config_changed_then_config_file_is_written(
        self, _, patch_network
    ):
        self.harness.set_leader(True)
        self.mock_machine.exists.return_value = False

        self.mock_upf_network = MagicMock()
        self.mock_upf_network.get_invalid_network_interfaces.return_value = []
        self.mock_upf_network.core_interface.get_ip_address.return_value = "192.168.250.3"
        patch_network.return_value = self.mock_upf_network

        self.harness.update_config()

        expected_config_file_content = read_file("tests/unit/expected_upf.json").strip()

        _, kwargs = self.mock_machine.push.call_args
        assert kwargs["path"] == "/var/snap/sdcore-upf/common/upf.json"
        assert json.loads(kwargs["source"]) == json.loads(expected_config_file_content)

    @patch("charm.UPFNetwork")
    @patch("charm.SnapCache")
    def test_given_config_file_written_with_different_content_when_config_changed_then_new_config_file_is_written(  # noqa: E501
        self, _, patch_network
    ):
        self.harness.set_leader(True)
        self.mock_machine.exists_return_value = True
        self.mock_machine.pull_return_value = "initial content"

        self.mock_upf_network = MagicMock()
        self.mock_upf_network.get_invalid_network_interfaces.return_value = []
        self.mock_upf_network.core_interface.get_ip_address.return_value = "192.168.250.3"
        patch_network.return_value = self.mock_upf_network

        self.harness.update_config()

        expected_config_file_content = read_file("tests/unit/expected_upf.json").strip()
        _, kwargs = self.mock_machine.push.call_args
        assert kwargs["path"] == "/var/snap/sdcore-upf/common/upf.json"
        assert json.loads(kwargs["source"]) == json.loads(expected_config_file_content)

    @patch("charm.UPFNetwork")
    @patch("charm.SnapCache")
    def test_given_config_file_written_with_identical_content_when_config_changed_then_new_config_file_not_written(  # noqa: E501
        self, _, __
    ):
        self.harness.set_leader(True)
        self.mock_machine.exists.return_value = True
        self.mock_machine.pull.return_value = read_file("tests/unit/expected_upf.json").strip()

        self.harness.update_config()

        self.mock_machine.push.assert_not_called()

    @patch("charm.SnapCache")
    def test_given_invalid_gnbsubnet_config_when_config_changed_then_status_is_blocked(self, _):
        self.harness.set_leader(True)
        self.harness.update_config({"gnb-subnet": "not an ip address"})

        self.harness.evaluate_status()

        self.assertEqual(
            self.harness.model.unit.status,
            ops.BlockedStatus("The following configurations are not valid: ['gnb-subnet']"),
        )

    @patch("charm.UPFNetwork")
    @patch("charm.SnapCache")
    def test_given_network_interfaces_not_valid_when_config_changed_then_status_is_blocked(
        self, _, patch_network
    ):
        self.mock_upf_network.get_invalid_network_interfaces.return_value = [
            "eth0",
            "eth1",
        ]
        patch_network.return_value = self.mock_upf_network

        self.harness.set_leader(True)

        self.harness.evaluate_status()

        self.assertEqual(
            self.harness.model.unit.status,
            ops.BlockedStatus("Network interfaces are not valid: ['eth0', 'eth1']"),
        )

    @patch("charm.UPFNetwork")
    @patch("charm.SnapCache")
    def test_given_network_interfaces_valid_when_config_changed_then_routes_are_created(self, _, patch_network):  # noqa: E501
        gnb_subnet = "192.168.251.0/24"
        self.harness.set_leader(True)

        self.mock_upf_network = MagicMock()
        self.mock_upf_network.get_invalid_network_interfaces.return_value = []
        self.mock_upf_network.core_interface.get_ip_address.return_value = "192.168.250.3"
        patch_network.return_value = self.mock_upf_network

        self.harness.update_config(
            {
                "gnb-subnet": gnb_subnet,
                "core-interface-name": "eth0",
                "access-interface-name": "eth1",
            }
        )

        self.mock_upf_network.configure.assert_called_once()

    @patch("charm.UPFNetwork")
    @patch("charms.sdcore_upf_k8s.v0.fiveg_n4.N4Provides.publish_upf_n4_information")
    def test_given_unit_is_not_leader_when_fiveg_n4_request_then_upf_hostname_is_not_published(
        self, patched_publish_upf_n4_information, patch_network
    ):
        self.harness.set_leader(is_leader=False)
        test_external_upf_hostname = "test-upf.external.hostname.com"

        self.mock_upf_network = MagicMock()
        self.mock_upf_network.get_invalid_network_interfaces.return_value = []
        self.mock_upf_network.core_interface.get_ip_address.return_value = "192.168.250.3"
        patch_network.return_value = self.mock_upf_network

        self.harness.update_config(
            key_values={"external-upf-hostname": test_external_upf_hostname}
        )

        n4_relation_id = self.harness.add_relation("fiveg_n4", "n4_requirer_app")
        self.harness.add_relation_unit(n4_relation_id, "n4_requirer_app/0")

        patched_publish_upf_n4_information.assert_not_called()

    @patch("charm.UPFNetwork")
    @patch("charms.sdcore_upf_k8s.v0.fiveg_n4.N4Provides.publish_upf_n4_information")
    @patch("charm.PFCP_PORT", TEST_PFCP_PORT)
    @patch("charm.SnapCache")
    def test_given_external_upf_hostname_config_set_and_fiveg_n4_relation_created_when_fiveg_n4_request_then_upf_hostname_and_n4_port_is_published(  # noqa: E501
        self, patched_snap_cache, patched_publish_upf_n4_information, _
    ):
        upf_snap = MagicMock()
        snap_cache = {"sdcore-upf": upf_snap}
        patched_snap_cache.return_value = snap_cache
        self.harness.set_leader(True)
        test_external_upf_hostname = "test-upf.external.hostname.com"
        self.harness.update_config(
            key_values={"external-upf-hostname": test_external_upf_hostname}
        )

        n4_relation_id = self.harness.add_relation("fiveg_n4", "n4_requirer_app")
        self.harness.add_relation_unit(n4_relation_id, "n4_requirer_app/0")

        patched_publish_upf_n4_information.assert_called_once_with(
            relation_id=n4_relation_id,
            upf_hostname=test_external_upf_hostname,
            upf_n4_port=TEST_PFCP_PORT,
        )

    @patch("charms.sdcore_upf_k8s.v0.fiveg_n4.N4Provides.publish_upf_n4_information")
    @patch("charm.PFCP_PORT", TEST_PFCP_PORT)
    @patch("charm.SnapCache")
    def test_given_external_upf_hostname_config_not_set_and_fiveg_n4_relation_created_when_fiveg_n4_request_then_upf_hostname_and_n4_port_is_published(  # noqa: E501
        self, patched_snap_cache, patched_publish_upf_n4_information
    ):
        upf_snap = MagicMock()
        snap_cache = {"sdcore-upf": upf_snap}
        patched_snap_cache.return_value = snap_cache
        self.harness.set_leader(True)
        n4_relation_id = self.harness.add_relation("fiveg_n4", "n4_requirer_app")
        self.harness.add_relation_unit(n4_relation_id, "n4_requirer_app/0")

        patched_publish_upf_n4_information.assert_called_once_with(
            relation_id=n4_relation_id,
            upf_hostname="192.168.250.3",
            upf_n4_port=TEST_PFCP_PORT,
        )

    @patch("charm.UPFNetwork")
    @patch("charms.sdcore_upf_k8s.v0.fiveg_n4.N4Provides.publish_upf_n4_information")
    @patch("charm.PFCP_PORT", TEST_PFCP_PORT)
    @patch("charm.SnapCache")
    def test_given_fiveg_n4_relation_exists_when_external_upf_hostname_config_changed_then_new_upf_hostname_is_published(  # noqa: E501
        self, patched_snap_cache, patched_publish_upf_n4_information, patch_network
    ):
        upf_snap = MagicMock()
        snap_cache = {"sdcore-upf": upf_snap}
        patched_snap_cache.return_value = snap_cache

        self.mock_upf_network = MagicMock()
        self.mock_upf_network.get_invalid_network_interfaces.return_value = []
        self.mock_upf_network.core_interface.get_ip_address.return_value = "192.168.250.3"
        patch_network.return_value = self.mock_upf_network

        self.harness.set_leader(True)
        test_external_upf_hostname = "test-upf.external.hostname.com"
        self.harness.update_config(key_values={"external-upf-hostname": "whatever.com"})
        n4_relation_id = self.harness.add_relation("fiveg_n4", "n4_requirer_app")
        self.harness.add_relation_unit(n4_relation_id, "n4_requirer_app/0")
        expected_calls = [
            call(
                relation_id=n4_relation_id,
                upf_hostname="whatever.com",
                upf_n4_port=TEST_PFCP_PORT,
            ),
            call(
                relation_id=n4_relation_id,
                upf_hostname=test_external_upf_hostname,
                upf_n4_port=TEST_PFCP_PORT,
            ),
        ]

        self.harness.update_config(
            key_values={"external-upf-hostname": test_external_upf_hostname}
        )

        patched_publish_upf_n4_information.assert_has_calls(expected_calls)

    @patch("charm.SnapCache")
    def test_given_upf_installed_when_remove_then_snap_removed(self, patched_snap_cache):
        self.harness.set_leader(True)
        upf_snap = MagicMock()
        snap_cache = {"sdcore-upf": upf_snap}
        patched_snap_cache.return_value = snap_cache

        self.harness.charm.on.remove.emit()

        upf_snap.stop.assert_has_calls(
            calls=[
                call(services=["bessd"]),
                call(services=["routectl"]),
                call(services=["pfcpiface"]),
            ]
        )
        upf_snap.ensure.assert_called_with(SnapState.Absent)

    @patch("charm.SnapCache")
    def test_given_cpu_not_compatible_when_install_then_status_is_blocked(
        self, _
    ):
        self.mock_process.wait_output.return_value = (b"Flags: ssse3 fma cx16 rdrand", "")
        self.harness.set_leader(True)
        self.harness.charm.on.install.emit()

        self.harness.evaluate_status()

        self.assertEqual(
            self.harness.model.unit.status,
            ops.BlockedStatus("CPU is not compatible, see logs for more details"),
        )

    @patch("charm.UPFNetwork")
    @patch("charm.SnapCache")
    def test_given_cpu_compatible_when_install_then_status_is_active(
        self, _, patch_network
    ):
        self.mock_upf_network = MagicMock()
        self.mock_upf_network.get_invalid_network_interfaces.return_value = []
        self.mock_upf_network.core_interface.get_ip_address.return_value = "192.168.250.3"
        patch_network.return_value = self.mock_upf_network
        self.harness.set_leader(True)
        self.harness.charm.on.install.emit()

        self.harness.evaluate_status()

        self.assertEqual(
            self.harness.model.unit.status,
            ops.ActiveStatus(),
        )


class TestCharmInitialisation(unittest.TestCase):
    @patch("charm.UPFNetwork")
    @patch("charm.Machine")
    def setUp(self, patch_machine, patch_network):
        self.mock_machine = MagicMock()
        self.mock_machine.pull.return_value = ""
        self.mock_process = MagicMock()
        self.mock_process.wait_output.return_value = ("", "")
        self.mock_machine.exec.return_value = self.mock_process
        patch_machine.return_value = self.mock_machine
        self.mock_upf_network = MagicMock()
        self.mock_upf_network.get_invalid_network_interfaces.return_value = []
        self.mock_upf_network.core_interface.get_ip_address.return_value = (
            "192.168.250.3"
        )
        patch_network.return_value = self.mock_upf_network
        self.harness = ops.testing.Harness(SdcoreUpfCharm)
        self.addCleanup(self.harness.cleanup)

    @patch("charm.SnapCache")
    def test_given_invalid_iface_ip_config_when_config_changed_then_status_is_blocked(self, _):
        self.harness.set_leader(True)
        self.harness.update_config({"access-ip": "not an ip address"})
        self.harness.begin()

        self.harness.evaluate_status()

        self.assertEqual(
            self.harness.model.unit.status,
            ops.BlockedStatus(
                "The following configurations are not valid: ['access-ip']"
            ),
        )
