# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

resource "juju_application" "upf" {
  name  = var.app_name
  model = var.model_name

  charm {
    name    = "sdcore-upf"
    channel = var.channel
    base = "ubuntu@22.04"
  }
  config = var.config
  placement = var.machine_number
}
