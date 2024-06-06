# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

variable "model_name" {
  description = "Name of Juju model to deploy application to."
  type        = string
  default     = "user-machine"
}

variable "app_name" {
  description = "Name of the application in the Juju model."
  type        = string
  default     = "upf"
}

variable "channel" {
  description = "The channel to use when deploying a charm."
  type        = string
  default     = "1.4/edge"
}

variable "config" {
  description = "Application config. Details about available options can be found at https://charmhub.io/sdcore-upf/configure."
  type        = map(string)
  default     = {}
}

variable "machine_number" {
  description = "The machine unit number to use for placement."
  type        = number
  default     = 0
}

