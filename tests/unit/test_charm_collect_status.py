# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


from unittest.mock import MagicMock

import pytest
import scenario
from machine import ExecError
from ops import ActiveStatus, BlockedStatus, WaitingStatus

from tests.unit.fixtures import UPFUnitTestFixtures


class TestCharmCollectUnitStatus(UPFUnitTestFixtures):
    def test_given_unit_not_leader_when_collect_unit_status_then_status_is_blocked(
        self,
    ):
        state_in = scenario.State(
            leader=False,
        )

        state_out = self.ctx.run("collect_unit_status", state_in)
        assert state_out.unit_status == BlockedStatus("Scaling is not implemented for this charm")

    @pytest.mark.parametrize(
        "config_param,value",
        [
            pytest.param("gnb-subnet", ""),
            pytest.param("gnb-subnet", "1111.11112.11113.22224"),
            pytest.param("access-ip", ""),
            pytest.param("access-gateway-ip", ""),
            pytest.param("access-gateway-ip", "111.111.111.1111"),
            pytest.param("access-interface-mtu-size", 0),
            pytest.param("access-interface-mtu-size", 999999999),
            pytest.param("core-ip", ""),
            pytest.param("core-gateway-ip", ""),
            pytest.param("core-gateway-ip", "111.111.111.1111"),
            pytest.param("core-interface-mtu-size", 0),
            pytest.param("core-interface-mtu-size", 999999999),
        ],
    )
    def test_given_invalid_config_when_collect_unit_status_then_status_is_blocked(
        self, config_param, value
    ):
        state_in = scenario.State(
            leader=True,
            config={
                config_param: value,
            },
        )

        state_out = self.ctx.run("collect_unit_status", state_in)

        assert state_out.unit_status == BlockedStatus(
            f"The following configurations are not valid: ['{config_param}']"
        )

    def test_given_upf_mode_set_to_dpdk_and_hugepages_enabled_but_mac_addresses_of_access_and_core_interfaces_not_set_when_collect_unit_status_then_status_is_blocked(  # noqa: E501
        self,
    ):
        state_in = scenario.State(
            leader=True,
            config={"upf-mode": "dpdk"},
        )

        state_out = self.ctx.run("collect_unit_status", state_in)

        assert state_out.unit_status == BlockedStatus(
            "The following configurations are not valid: ['access-interface-mac-address', 'access-interface-pci-address', 'core-interface-mac-address', 'core-interface-pci-address']"  # noqa: E501
        )

    def test_given_cpu_incompatible_when_collect_unit_status_then_status_is_blocked(
        self,
    ):
        self.mock_process.wait_output.return_value = ("Flags: ssse3 fma cx16 rdrand", "")
        state_in = scenario.State(
            leader=True,
        )

        state_out = self.ctx.run("collect_unit_status", state_in)

        assert state_out.unit_status == BlockedStatus(
            "CPU is not compatible, see logs for more details"
        )

    def test_given_invalid_network_interfaces_when_collect_unit_status_then_status_is_blocked(
        self,
    ):
        self.mock_upf_network.get_invalid_network_interfaces.return_value = [
            "eth0",
            "eth1",
        ]
        state_in = scenario.State(
            leader=True,
        )

        state_out = self.ctx.run("collect_unit_status", state_in)

        assert state_out.unit_status == BlockedStatus(
            "Network interfaces are not valid: ['eth0', 'eth1']"
        )

    def test_given_network_not_configured_when_collect_unit_status_then_status_is_waiting(
        self,
    ):
        self.mock_upf_network.get_invalid_network_interfaces.return_value = []
        state_in = scenario.State(
            leader=True,
        )
        self.mock_upf_network.is_configured.return_value = False

        state_out = self.ctx.run("collect_unit_status", state_in)

        assert state_out.unit_status == WaitingStatus("Waiting for network configuration")

    def test_given_upf_config_file_not_written_collect_unit_status_then_status_is_waiting(
        self,
    ):
        self.mock_upf_network.get_invalid_network_interfaces.return_value = []
        self.mock_machine.exists.return_value = False
        state_in = scenario.State(
            leader=True,
        )
        self.mock_upf_network.is_configured.return_value = True

        state_out = self.ctx.run("collect_unit_status", state_in)

        assert state_out.unit_status == WaitingStatus("Waiting for UPF configuration file")

    def test_given_bessd_service_not_started_when_collect_unit_status_then_status_is_waiting(
        self,
    ):
        self.mock_upf_network.get_invalid_network_interfaces.return_value = []
        self.mock_machine.exists.return_value = True
        upf_snap = MagicMock()
        upf_snap.services = {
            "bessd": {"active": False},
        }
        snap_cache = {"sdcore-upf": upf_snap}
        self.mock_snap_cache.return_value = snap_cache
        state_in = scenario.State(
            leader=True,
        )
        self.mock_upf_network.is_configured.return_value = True

        state_out = self.ctx.run("collect_unit_status", state_in)

        assert state_out.unit_status == WaitingStatus("Waiting for bessd service to start")

    def test_given_grpc_service_not_started_when_collect_unit_status_then_status_is_waiting(
        self,
    ):
        self.mock_upf_network.get_invalid_network_interfaces.return_value = []
        self.mock_machine.exists.return_value = True
        self.mock_upf_network.is_configured.return_value = True
        self.mock_process.wait_output.side_effect = [
            ("Flags: avx2 rdrand", ""),
            ("Flags: avx2 rdrand", ""),
            ExecError("Failed to execute command", 1, "", ""),
            ("Flags: avx2 rdrand", ""),
            ("Flags: avx2 rdrand", ""),
            ExecError("Failed to execute command", 1, "", ""),
        ]
        upf_snap = MagicMock()
        upf_snap.services = {
            "bessd": {"active": True},
        }
        snap_cache = {"sdcore-upf": upf_snap}
        self.mock_snap_cache.return_value = snap_cache
        state_in = scenario.State(
            leader=True,
        )

        state_out = self.ctx.run("collect_unit_status", state_in)

        assert state_out.unit_status == WaitingStatus("Waiting for bessd gRPC service to start")

    def test_given_pfcp_service_not_started_when_collect_unit_status_then_status_is_waiting(
        self,
    ):
        self.mock_upf_network.get_invalid_network_interfaces.return_value = []
        self.mock_machine.exists.return_value = True
        self.mock_upf_network.is_configured.return_value = True
        upf_snap = MagicMock()
        upf_snap.services = {
            "bessd": {"active": True},
            "pfcpiface": {"active": False},
        }
        snap_cache = {"sdcore-upf": upf_snap}
        self.mock_snap_cache.return_value = snap_cache
        state_in = scenario.State(
            leader=True,
        )

        state_out = self.ctx.run("collect_unit_status", state_in)

        assert state_out.unit_status == WaitingStatus("Waiting for pcfp service to start")

    def test_given_routectl_service_not_when_collect_unit_status_then_status_is_waiting(
        self,
    ):
        self.mock_upf_network.get_invalid_network_interfaces.return_value = []
        self.mock_machine.exists.return_value = True
        self.mock_upf_network.is_configured.return_value = True
        upf_snap = MagicMock()
        upf_snap.services = {
            "bessd": {"active": True},
            "pfcpiface": {"active": True},
            "routectl": {"active": False},
        }
        snap_cache = {"sdcore-upf": upf_snap}
        self.mock_snap_cache.return_value = snap_cache
        state_in = scenario.State(
            leader=True,
        )

        state_out = self.ctx.run("collect_unit_status", state_in)

        assert state_out.unit_status == WaitingStatus("Waiting for routectl service to start")

    def test_given_routectl_service_not_when_collect_unit_status_then_status_is_active(
        self,
    ):
        self.mock_upf_network.get_invalid_network_interfaces.return_value = []
        self.mock_machine.exists.return_value = True
        self.mock_upf_network.is_configured.return_value = True
        upf_snap = MagicMock()
        upf_snap.services = {
            "bessd": {"active": True},
            "pfcpiface": {"active": True},
            "routectl": {"active": True},
        }
        snap_cache = {"sdcore-upf": upf_snap}
        self.mock_snap_cache.return_value = snap_cache
        state_in = scenario.State(
            leader=True,
        )

        state_out = self.ctx.run("collect_unit_status", state_in)

        assert state_out.unit_status == ActiveStatus()
