# SD-Core UPF Operator

[![CharmHub Badge](https://charmhub.io/sdcore-upf/badge.svg)](https://charmhub.io/sdcore-upf)

Charmed Operator for SD-Core's User Plane Function (UPF). For more information, read [here](https://github.com/omec-project/upf).

## Usage

The SD-Core UPF charm should be deployed on a machine with two network interfaces. The `access-interface-name` and `core-interface-name` configuration options should be set to the names of the network interfaces that are connected to the access and core networks, respectively. Those interfaces should have IPv4 addresses assigned to them.

Set Multipass to use LXD as the driver:

```shell
multipass set local.driver=lxd
sudo snap restart multipass.multipassd
```

Create two LXD networks:
```shell
lxc network create access --type=bridge ipv4.address=192.168.252.1/24
lxc network create core --type=bridge ipv4.address=192.168.250.1/24
```

Deploy a VM using Multipass with the `access` and `core` networks:

```shell
multipass launch 22.04 --name upf --network access --network core --memory 8G --cpus 4
```

Add the Machine to the Juju controller:

```shell
sudo cp /var/snap/multipass/common/data/multipassd/ssh-keys/id_rsa .
sudo chown $USER:$USER id_rsa
juju add-machine ssh:ubuntu@<UPF machine IP address> --private-key id_rsa
```

```shell
juju deploy sdcore-upf \
  --config access-interface-name=enp6s0 \
  --config core-interface-name=enp7s0 \
  --to <machine number>
```
