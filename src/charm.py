#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Machine charm for SD-Core User Plane Function."""

import logging

import ops
from charms.operator_libs_linux.v2 import snap
from ops.model import ActiveStatus, BlockedStatus

UPF_SNAP_NAME = "sdcore-upf"
UPF_SNAP_CHANNEL = "latest/edge"
UPF_SNAP_REVISION = "3"


logger = logging.getLogger(__name__)


class SdcoreUpfCharm(ops.CharmBase):
    """Machine charm for SD-Core User Plane Function."""

    def __init__(self, *args):
        super().__init__(*args)
        self.framework.observe(self.on.install, self._configure)
        self.framework.observe(self.on.update_status, self._configure)
        self.framework.observe(self.on.config_changed, self._configure)

    def _configure(self, _):
        """Handle UPF installation."""
        if not self.unit.is_leader():
            self.unit.status = BlockedStatus("Scaling is not implemented for this charm")
            return
        self._install_upf_snap()
        self.unit.status = ActiveStatus()

    def _install_upf_snap(self) -> None:
        """Installs the UPF snap in the machine."""
        try:
            snap_cache = snap.SnapCache()
            upf_snap = snap_cache[UPF_SNAP_NAME]
            upf_snap.ensure(
                snap.SnapState.Latest,
                channel=UPF_SNAP_CHANNEL,
                revision=UPF_SNAP_REVISION,
                devmode=True,
            )
            upf_snap.hold()
            logger.info("UPF snap installed")
        except snap.SnapError as e:
            logger.error("An exception occurred when installing the UPF snap. Reason: %s", str(e))
            raise e


if __name__ == "__main__":  # pragma: nocover
    ops.main(SdcoreUpfCharm)  # type: ignore
