# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

resource "juju_application" "upf" {
  name  = var.app_name
  model = var.model_name

  charm {
    name    = "sdcore-upf"
    channel = var.channel
  }
  config = var.config
  trust  = true
  placement = var.machine_number
}
