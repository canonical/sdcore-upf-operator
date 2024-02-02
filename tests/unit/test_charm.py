# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import unittest

import ops
import ops.testing
from charm import SdcoreUpfOperatorCharm


class TestCharm(unittest.TestCase):
    def setUp(self):
        self.harness = ops.testing.Harness(SdcoreUpfOperatorCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

    def test_given_when_config_changed_then(self):

        self.harness.update_config()

        self.assertEqual(self.harness.model.unit.status, ops.ActiveStatus())
