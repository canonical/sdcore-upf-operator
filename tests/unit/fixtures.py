# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

from unittest.mock import MagicMock, patch

import pytest
from ops import testing

from charm import SdcoreUpfCharm


class UPFUnitTestFixtures:
    patcher_n4_provides_publish_upf_information = patch(
        "charm.N4Provides.publish_upf_n4_information"
    )
    patcher_upf_network = patch("charm.UPFNetwork")
    patcher_machine = patch("charm.Machine")
    patcher_snap_cache = patch("charm.SnapCache")

    @pytest.fixture(autouse=True)
    def setup(self, request):
        self.mock_n4_provides_publish_upf_information = (
            UPFUnitTestFixtures.patcher_n4_provides_publish_upf_information.start()
        )
        self.mock_upf_network = MagicMock()
        self.mock_upf_network.get_invalid_network_interfaces.return_value = []
        self.mock_upf_network.core_interface.get_ip_address.return_value = "192.168.250.3"
        mock_upf_network = UPFUnitTestFixtures.patcher_upf_network.start()
        mock_upf_network.return_value = self.mock_upf_network
        self.mock_machine = MagicMock()
        self.mock_machine.pull.return_value = ""
        self.mock_process = MagicMock()
        self.mock_process.wait_output.return_value = ("Flags: avx2 rdrand", "")
        self.mock_machine.exec.return_value = self.mock_process
        mock_machine = UPFUnitTestFixtures.patcher_machine.start()
        mock_machine.return_value = self.mock_machine
        self.mock_snap_cache = UPFUnitTestFixtures.patcher_snap_cache.start()
        yield
        request.addfinalizer(self.teardown)

    @staticmethod
    def teardown() -> None:
        patch.stopall()

    @pytest.fixture(autouse=True)
    def context(self):
        self.ctx = testing.Context(
            charm_type=SdcoreUpfCharm,
        )
