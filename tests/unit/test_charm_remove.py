# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


from unittest.mock import MagicMock, call

from charms.operator_libs_linux.v2.snap import Snap
from ops import testing

from tests.unit.fixtures import UPFUnitTestFixtures


class TestCharmRemove(UPFUnitTestFixtures):
    def test_given_services_exist_when_remove_then_services_are_stopped(
        self,
    ):
        upf_snap = MagicMock(spec=Snap)
        snap_cache = {"sdcore-upf": upf_snap}
        self.mock_snap_cache.return_value = snap_cache
        state_in = testing.State(
            leader=False,
        )

        self.ctx.run(self.ctx.on.remove(), state_in)

        upf_snap.stop.assert_has_calls(
            [call(services=["bessd"]), call(services=["routectl"]), call(services=["pfcpiface"])]
        )
