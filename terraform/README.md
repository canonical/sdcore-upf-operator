# SD-Core UPF Terraform Module

This folder contains a base [Terraform][Terraform] module for the sdcore-upf machine charm.

The module uses the [Terraform Juju provider][Terraform Juju provider] to model the charm
deployment onto any machine managed by [Juju][Juju].

The module can be used to deploy the UPF separately as well as a part of a higher level module,
depending on the deployment architecture.

## Module structure

- **main.tf** - Defines the Juju application to be deployed.
- **variables.tf** - Allows customization of the deployment. Except for exposing the deployment
  options (Juju model name, channel or application name) also allows overwriting charm's default
  configuration.
- **output.tf** - Responsible for integrating the module with other Terraform modules, primarily
  by defining potential integration endpoints (charm integrations), but also by exposing
  the application name.
- **terraform.tf** - Defines the Terraform provider.

## Deploying sdcore-upf base module separately

### Pre-requisites

- A host with a CPU supporting AVX2 and RDRAND instructions (Intel Haswell, AMD Excavator or equivalent)
- Juju controller bootstrapped to a LXD cluster
- A Juju machine representing the host that has been added to a model
- Terraform

### Deploying UPF with Terraform

Clone the `sdcore-upf-operator` Git repository.

From inside the `terraform` folder, initialize the provider:

```shell
terraform init
```

Create Terraform plan:

```shell
terraform plan
```

While creating the plan, the default configuration can be overwritten with `-var-file`. To do that,
Terraform `tfvars` file should be prepared prior to the plan creation. You need to know the machine
number and have it set in the variables. The default is machine #0.

Deploy UPF:

```console
terraform apply -auto-approve
```

### Cleaning up

Destroy the deployment:

```shell
terraform destroy -auto-approve
```

## Using sdcore-upf base module in higher level modules

If you want to use `sdcore-upf` base module as part of your Terraform module, import it
like shown below:

```text
module "upf" {
  source = "git::https://github.com/canonical/sdcore-upf-operator//terraform"

  model_name = "juju_model_name"
  config = Optional config map
  machine_number = 0
}
```

Create integrations, for instance:

```text
resource "juju_integration" "upf-prometheus" {
  model = var.model_name
  application {
    name     = module.upf.app_name
    endpoint = module.upf.metrics_endpoint
  }
  application {
    name     = module.prometheus.app_name
    endpoint = module.prometheus.metrics_endpoint
  }
}
```

The complete list of available integrations can be found [here][upf-integrations].

[Terraform]: https://www.terraform.io/
[Terraform Juju provider]: https://registry.terraform.io/providers/juju/juju/latest
[Juju]: https://juju.is
[upf-integrations]: https://charmhub.io/sdcore-upf/integrations
