# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import json
from itertools import count
from unittest.mock import MagicMock, call, patch

import ops
import ops.testing
import pytest
from charm import SdcoreUpfCharm
from charms.operator_libs_linux.v2.snap import SnapState
from machine import ExecError

TEST_PFCP_PORT = 1234


def read_file(path: str) -> str:
    """Read a file and return as a string."""
    with open(path, "r") as f:
        content = f.read()
    return content


class TestCharm:
    patcher_upf_network = patch("charm.UPFNetwork")
    patcher_machine = patch("charm.Machine")
    patcher_snap_cache = patch("charm.SnapCache")
    patcher_pfcp_port = patch("charm.PFCP_PORT", TEST_PFCP_PORT)

    @pytest.fixture()
    def setup(self):
        self.mock_machine = MagicMock()
        self.mock_machine.pull.return_value = ""
        self.mock_process = MagicMock()
        self.mock_process.wait_output.return_value = ("Flags: avx2 rdrand", "")
        self.mock_machine.exec.return_value = self.mock_process
        mock_machine = TestCharm.patcher_machine.start()
        mock_machine.return_value = self.mock_machine
        self.mock_upf_network = MagicMock()
        self.mock_upf_network.get_invalid_network_interfaces.return_value = []
        self.mock_upf_network.core_interface.get_ip_address.return_value = "192.168.250.3"
        mock_upf_network = TestCharm.patcher_upf_network.start()
        mock_upf_network.return_value = self.mock_upf_network
        self.mock_snap_cache = TestCharm.patcher_snap_cache.start()
        self.mock_pfcp_port = TestCharm.patcher_pfcp_port.start()

    @staticmethod
    def teardown() -> None:
        patch.stopall()

    @pytest.fixture(autouse=True)
    def create_harness(self, setup, request):
        self.harness = ops.testing.Harness(SdcoreUpfCharm)
        self.harness.set_model_name(name="whatever")
        self.harness.set_leader(is_leader=True)
        self.harness.begin()
        yield self.harness
        self.harness.cleanup()
        request.addfinalizer(self.teardown)

    def test_given_unit_is_not_leader_when_evaluate_status_then_status_is_blocked(self):
        self.harness.set_leader(False)

        self.harness.evaluate_status()

        assert self.harness.model.unit.status == ops.BlockedStatus(
            "Scaling is not implemented for this charm"
        )

    def test_given_upf_snap_uninstalled_when_configure_then_upf_snap_installed(self):
        upf_snap = MagicMock()
        snap_cache = {"sdcore-upf": upf_snap}
        self.mock_snap_cache.return_value = snap_cache

        self.harness.charm.on.install.emit()

        upf_snap.ensure.assert_called_with(
            SnapState.Latest,
            channel="1.4/edge",
            revision="42",
            devmode=True,
        )
        upf_snap.hold.assert_called()

    def test_given_upf_service_not_started_when_config_changed_then_service_started(self):
        upf_snap = MagicMock()
        upf_snap.services = {
            "bessd": {"active": False},
            "pfcpiface": {"active": False},
            "routectl": {"active": False},
        }
        snap_cache = {"sdcore-upf": upf_snap}
        self.mock_snap_cache.return_value = snap_cache

        self.harness.update_config()

        upf_snap.start.assert_has_calls(
            calls=[
                call(services=["bessd"]),
                call(services=["pfcpiface"]),
                call(services=["routectl"]),
            ]
        )

    def test_given_upf_snap_uninstalled_when_remove_then_services_not_stopped(self):
        upf_snap = MagicMock()
        upf_snap.services = {}
        snap_cache = {"sdcore-upf": upf_snap}
        self.mock_snap_cache.return_value = snap_cache

        self.harness.charm.on.remove.emit()

        upf_snap.stop.assert_not_called()

    def test_given_upf_services_started_when_remove_then_services_stopped(self):
        upf_snap = MagicMock()
        upf_snap.services = {
            "bessd": {"active": True},
            "routectl": {"active": True},
            "pfcpiface": {"active": True},
        }
        snap_cache = {"sdcore-upf": upf_snap}
        self.mock_snap_cache.return_value = snap_cache

        self.harness.charm.on.remove.emit()

        upf_snap.stop.assert_has_calls(
            calls=[
                call(services=["bessd"]),
                call(services=["routectl"]),
                call(services=["pfcpiface"]),
            ]
        )

    def test_given_bessd_not_configured_when_config_changed_then_bessctl_run_called(self):
        upf_snap = MagicMock()
        snap_cache = {"sdcore-upf": upf_snap}
        self.mock_snap_cache.return_value = snap_cache

        self.mock_process.wait_output.side_effect = [
            ("Flags: avx2 rdrand", ""),
            ("Flags: avx2 rdrand", ""),
            ("Flags: avx2 rdrand", ""),
            ExecError(
                command="configuration check",
                exit_code=1,
                stdout="mock to represent bessd not configured",
                stderr="",
            ),
            ("stdout", "stderr"),
        ]
        self.harness.update_config()

        assert "sdcore-upf.bessctl run /snap/sdcore-upf/current/opt/bess/bessctl/conf/up4" == self.mock_machine.method_calls[-1].kwargs["command"]  # noqa: E501

    def test_bess_configuration_timeout_error_raised_on_exec_error(self):
        mock_sleep = patch("charm.time.sleep").start()
        mock_time = patch("charm.time.time").start()
        mock_time.side_effect = count(start=1, step=60)
        mock_sleep.return_value = None
        upf_snap = MagicMock()
        self.mock_process.wait_output.side_effect = [
            ("Flags: avx2 rdrand", ""),
            ("Flags: avx2 rdrand", ""),
            ExecError(command="whatever", exit_code=1, stdout="", stderr=""),
        ]
        snap_cache = {"sdcore-upf": upf_snap}
        self.mock_snap_cache.return_value = snap_cache

        with pytest.raises(TimeoutError):
            self.harness.update_config()

    def test_given_unit_is_leader_when_config_changed_then_status_is_active(self):
        upf_snap = MagicMock()
        snap_cache = {"sdcore-upf": upf_snap}
        self.mock_snap_cache.return_value = snap_cache

        self.harness.evaluate_status()

        assert self.harness.model.unit.status == ops.ActiveStatus()

    def test_given_config_file_not_written_when_config_changed_then_config_file_is_written(self):
        self.mock_machine.exists.return_value = False

        self.harness.update_config()

        expected_config_file_content = read_file("tests/unit/expected_upf.json").strip()

        _, kwargs = self.mock_machine.push.call_args
        assert kwargs["path"] == "/var/snap/sdcore-upf/common/upf.json"
        assert json.loads(kwargs["source"]) == json.loads(expected_config_file_content)

    def test_given_config_file_written_with_different_content_when_config_changed_then_new_config_file_is_written(self):  # noqa: E501
        self.mock_machine.exists_return_value = True
        self.mock_machine.pull_return_value = "initial content"

        self.harness.update_config()

        expected_config_file_content = read_file("tests/unit/expected_upf.json").strip()
        _, kwargs = self.mock_machine.push.call_args
        assert kwargs["path"] == "/var/snap/sdcore-upf/common/upf.json"
        assert json.loads(kwargs["source"]) == json.loads(expected_config_file_content)

    def test_given_config_file_written_with_identical_content_when_config_changed_then_new_config_file_not_written(self):  # noqa: E501
        self.mock_machine.exists.return_value = True
        self.mock_machine.pull.return_value = read_file("tests/unit/expected_upf.json").strip()

        self.harness.update_config()

        self.mock_machine.push.assert_not_called()

    def test_given_invalid_gnbsubnet_config_when_config_changed_then_status_is_blocked(self):
        self.harness.update_config({"gnb-subnet": "not an ip address"})

        self.harness.evaluate_status()

        assert self.harness.model.unit.status == ops.BlockedStatus(
            "The following configurations are not valid: ['gnb-subnet']"
        )

    def test_given_network_interfaces_not_valid_when_config_changed_then_status_is_blocked(self):
        self.mock_upf_network.get_invalid_network_interfaces.return_value = [
            "eth0",
            "eth1",
        ]
        self.mock_upf_network.return_value = self.mock_upf_network

        self.harness.evaluate_status()

        assert self.harness.model.unit.status == ops.BlockedStatus(
            "Network interfaces are not valid: ['eth0', 'eth1']"
        )

    def test_given_network_not_configured_when_config_changed_then_snap_is_not_installed(self):
        self.mock_upf_network.is_configured.return_value = False
        upf_snap = MagicMock()
        snap_cache = {"sdcore-upf": upf_snap}
        self.mock_snap_cache.return_value = snap_cache

        self.harness.charm.on.install.emit()

        self.harness.evaluate_status()

        upf_snap.ensure.assert_not_called()

    def test_given_network_interfaces_valid_when_config_changed_then_routes_are_created(self):
        gnb_subnet = "192.168.251.0/24"

        self.harness.update_config(
            {
                "gnb-subnet": gnb_subnet,
                "core-interface-name": "eth0",
                "access-interface-name": "eth1",
            }
        )

        self.mock_upf_network.configure.assert_called_once()

    def test_given_unit_is_not_leader_when_fiveg_n4_request_then_upf_hostname_is_not_published(self):  # noqa: E501
        mock_publish_upf_n4_information = patch("charms.sdcore_upf_k8s.v0.fiveg_n4.N4Provides.publish_upf_n4_information").start()  # noqa: E501
        self.harness.set_leader(is_leader=False)
        test_external_upf_hostname = "test-upf.external.hostname.com"

        self.harness.update_config(
            key_values={"external-upf-hostname": test_external_upf_hostname}
        )

        n4_relation_id = self.harness.add_relation(
            "fiveg_n4", "n4_requirer_app"
        )
        self.harness.add_relation_unit(n4_relation_id, "n4_requirer_app/0")

        mock_publish_upf_n4_information.assert_not_called()

    def test_given_external_upf_hostname_config_set_and_fiveg_n4_relation_created_when_fiveg_n4_request_then_upf_hostname_and_n4_port_is_published(self):  # noqa: E501
        mock_publish_upf_n4_information = patch("charms.sdcore_upf_k8s.v0.fiveg_n4.N4Provides.publish_upf_n4_information").start()  # noqa: E501
        upf_snap = MagicMock()
        snap_cache = {"sdcore-upf": upf_snap}
        self.mock_snap_cache.return_value = snap_cache
        test_external_upf_hostname = "test-upf.external.hostname.com"
        self.harness.update_config(
            key_values={"external-upf-hostname": test_external_upf_hostname}
        )

        n4_relation_id = self.harness.add_relation(
            "fiveg_n4", "n4_requirer_app"
        )
        self.harness.add_relation_unit(n4_relation_id, "n4_requirer_app/0")

        mock_publish_upf_n4_information.assert_called_once_with(
            relation_id=n4_relation_id,
            upf_hostname=test_external_upf_hostname,
            upf_n4_port=TEST_PFCP_PORT,
        )

    def test_given_external_upf_hostname_config_not_set_and_fiveg_n4_relation_created_when_fiveg_n4_request_then_upf_hostname_and_n4_port_is_published(self):  # noqa: E501
        mock_publish_upf_n4_information = patch("charms.sdcore_upf_k8s.v0.fiveg_n4.N4Provides.publish_upf_n4_information").start()  # noqa: E501
        upf_snap = MagicMock()
        snap_cache = {"sdcore-upf": upf_snap}
        self.mock_snap_cache.return_value = snap_cache
        n4_relation_id = self.harness.add_relation(
            "fiveg_n4", "n4_requirer_app"
        )
        self.harness.add_relation_unit(n4_relation_id, "n4_requirer_app/0")

        mock_publish_upf_n4_information.assert_called_once_with(
            relation_id=n4_relation_id,
            upf_hostname="192.168.250.3",
            upf_n4_port=TEST_PFCP_PORT,
        )

    def test_given_fiveg_n4_relation_exists_when_external_upf_hostname_config_changed_then_new_upf_hostname_is_published(self):  # noqa: E501
        mock_publish_upf_n4_information = patch("charms.sdcore_upf_k8s.v0.fiveg_n4.N4Provides.publish_upf_n4_information").start()  # noqa: E501
        upf_snap = MagicMock()
        snap_cache = {"sdcore-upf": upf_snap}
        self.mock_snap_cache.return_value = snap_cache

        test_external_upf_hostname = "test-upf.external.hostname.com"
        self.harness.update_config(key_values={"external-upf-hostname": "whatever.com"})
        n4_relation_id = self.harness.add_relation(
            "fiveg_n4", "n4_requirer_app"
        )
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

        mock_publish_upf_n4_information.assert_has_calls(expected_calls)

    def test_given_upf_installed_when_remove_then_snap_removed(self):
        upf_snap = MagicMock()
        snap_cache = {"sdcore-upf": upf_snap}
        self.mock_snap_cache.return_value = snap_cache

        self.harness.charm.on.remove.emit()

        upf_snap.stop.assert_has_calls(
            calls=[
                call(services=["bessd"]),
                call(services=["routectl"]),
                call(services=["pfcpiface"]),
            ]
        )
        upf_snap.ensure.assert_called_with(SnapState.Absent)

    def test_given_cpu_not_compatible_when_install_then_status_is_blocked(self):
        self.mock_process.wait_output.return_value = ("Flags: ssse3 fma cx16 rdrand", "")
        self.harness.charm.on.install.emit()

        self.harness.evaluate_status()

        assert self.harness.model.unit.status == ops.BlockedStatus(
            "CPU is not compatible, see logs for more details"
        )

    def test_given_cpu_compatible_when_install_then_status_is_active(self):
        self.harness.charm.on.install.emit()

        self.harness.evaluate_status()

        assert self.harness.model.unit.status == ops.ActiveStatus()


class TestCharmInitialisation:
    patcher_upf_network = patch("charm.UPFNetwork")
    patcher_machine = patch("charm.Machine")
    patcher_snap_cache = patch("charm.SnapCache")

    @pytest.fixture()
    def setup(self):
        mock_upf_network = MagicMock()
        mock_upf_network.get_invalid_network_interfaces.return_value = []
        mock_upf_network.core_interface.get_ip_address.return_value = "192.168.250.3"
        mock_machine = MagicMock()
        mock_machine.pull.return_value = ""
        mock_process = MagicMock()
        mock_process.wait_output.return_value = ("", "")
        mock_machine.exec.return_value = mock_process
        self.mock_upf_network = TestCharmInitialisation.patcher_upf_network.start()
        self.mock_upf_network.return_value = mock_upf_network
        self.mock_machine = TestCharmInitialisation.patcher_machine.start()
        self.mock_machine.return_value = mock_machine
        self.mock_snap_cache = TestCharmInitialisation.patcher_snap_cache.start()

    @staticmethod
    def teardown() -> None:
        patch.stopall()

    @pytest.fixture(autouse=True)
    def create_harness(self, setup, request):
        self.harness = ops.testing.Harness(SdcoreUpfCharm)
        self.harness.set_model_name(name="whatever")
        self.harness.set_leader(is_leader=True)
        yield self.harness
        self.harness.cleanup()
        request.addfinalizer(self.teardown)

    def test_given_invalid_iface_ip_config_when_config_changed_then_status_is_blocked(self):
        self.harness.update_config({"access-ip": "not an ip address"})
        self.harness.begin()

        self.harness.evaluate_status()

        assert self.harness.model.unit.status == ops.BlockedStatus(
                "The following configurations are not valid: ['access-ip']"
            )
