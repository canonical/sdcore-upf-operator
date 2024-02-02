# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import unittest
from typing import List, Optional
from unittest.mock import patch

import ops
import ops.testing
from charm import SdcoreUpfOperatorCharm
from charms.operator_libs_linux.v2.snap import SnapState


class MockSnapObject:
    def __init__(self, name):
        self.name = name
        self.ensure_called = False
        self.ensure_called_with = None
        self.hold_called = False

    def ensure(
        self,
        state,
        classic: Optional[bool] = False,
        devmode: Optional[bool] = False,
        channel: Optional[str] = "",
        cohort: Optional[str] = "",
        revision: Optional[str] = None,
    ):
        self.ensure_called = True
        self.ensure_called_with = (state, classic, devmode, channel, cohort, revision)

    def hold(self):
        self.hold_called = True

    def start(self, services: Optional[List[str]] = None, enable: Optional[bool] = False) -> None:
        self.start_called = True
        self.start_called_with = {"services": services, "enable": enable}


class MockMachine:
    def __init__(self, exists_return_value: bool = False):
        self.exists_return_value = exists_return_value
        self.push_called = False

    def exists(self, path: str) -> bool:
        return self.exists_return_value
        pass

    def push(self, path: str, source: str) -> None:
        self.push_called = True
        self.push_called_with = {"path": path, "source": source}

    def pull(self, path: str) -> str:
        pass

    def make_dir(self, path: str) -> None:
        pass


class TestCharm(unittest.TestCase):
    @patch("charm.Machine")
    def setUp(self, patch_machine):
        self.mock_machine = MockMachine()
        patch_machine.return_value = self.mock_machine
        self.harness = ops.testing.Harness(SdcoreUpfOperatorCharm)
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
        upf_snap = MockSnapObject("upf")
        snap_cache = {"sdcore-upf": upf_snap}
        mock_snap_cache.return_value = snap_cache

        self.harness.charm.on.install.emit()

        mock_snap_cache.assert_called_with()
        assert upf_snap.ensure_called
        assert upf_snap.ensure_called_with == (
            SnapState.Latest,
            False,
            True,
            "latest/edge",
            "",
            "3",
        )
        assert upf_snap.hold_called

    @patch("charms.operator_libs_linux.v2.snap.SnapCache")
    def test_given_unit_is_leader_when_config_changed_then_status_is_active(self, mock_snap_cache):
        self.harness.set_leader(True)
        upf_snap = MockSnapObject("sdcore-upf")
        snap_cache = {"sdcore-upf": upf_snap}
        mock_snap_cache.return_value = snap_cache

        self.harness.update_config()

        self.assertEqual(self.harness.model.unit.status, ops.ActiveStatus())
