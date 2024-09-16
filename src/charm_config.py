# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Config of the Charm."""

import dataclasses
import logging
from enum import Enum
from typing import Optional

import ops
from pydantic import (  # pylint: disable=no-name-in-module,import-error
    BaseModel,
    Field,
    StrictStr,
    ValidationError,
    validator,
)
from pydantic.networks import IPvAnyAddress

logger = logging.getLogger(__name__)


class CharmConfigInvalidError(Exception):
    """Exception raised when a charm configuration is found to be invalid."""

    def __init__(self, msg: str):
        """Initialize a new instance of the CharmConfigInvalidError exception.

        Args:
            msg (str): Explanation of the error.
        """
        self.msg = msg


def to_kebab(name: str) -> str:
    """Convert a snake_case string to kebab-case."""
    return name.replace("_", "-")


class UpfMode(str, Enum):
    """Class to define available UPF modes for UPF operator."""

    af_packet = "af_packet"
    dpdk = "dpdk"


class UpfConfig(BaseModel):  # pylint: disable=too-few-public-methods
    """Represent UPF operator builtin configuration values."""

    CIDR_REGEX = "^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)([/][0-3][0-2]?|[/][1-2][0-9]|[/][0-9])$"  # noqa: E501, W605

    class Config:
        """Represent config for Pydantic model."""

        alias_generator = to_kebab
        use_enum_values = True

    upf_mode: UpfMode = UpfMode.af_packet
    dnn: StrictStr
    gnb_subnet: str = Field(regex=CIDR_REGEX)
    access_interface_name: StrictStr
    access_ip: str = Field(regex=CIDR_REGEX)
    access_gateway_ip: IPvAnyAddress
    access_interface_mtu_size: int = Field(ge=1200, le=65535)
    access_interface_mac_address: Optional[str]
    access_interface_pci_address: Optional[str]
    core_interface_name: StrictStr
    core_ip: str = Field(regex=CIDR_REGEX)
    core_gateway_ip: IPvAnyAddress
    core_interface_mtu_size: int = Field(ge=1200, le=65535)
    core_interface_mac_address: Optional[str]
    core_interface_pci_address: Optional[str]
    external_upf_hostname: Optional[StrictStr]
    enable_hw_checksum: bool

    @validator("access_interface_mac_address", always=True)
    @classmethod
    def validate_access_interface_mac_address(cls, value: str, values) -> str:
        """Make sure access interface MAC address is given when using DPDK mode."""
        if values["upf_mode"] == UpfMode.dpdk and not value:
            raise ValueError("Access network interface MAC address is empty")
        return value

    @validator("access_interface_pci_address", always=True)
    @classmethod
    def validate_access_interface_pci_address(cls, value: str, values) -> str:
        """Make sure access interface PCI address is given when using DPDK mode."""
        if values["upf_mode"] == UpfMode.dpdk and not value:
            raise ValueError("Access network interface PCI address is empty")
        return value

    @validator("core_interface_mac_address", always=True)
    @classmethod
    def validate_core_interface_mac_address(cls, value: str, values) -> str:
        """Make sure core interface MAC address is given when using DPDK mode."""
        if values["upf_mode"] == UpfMode.dpdk and not value:
            raise ValueError("Core network interface MAC address is empty")
        return value

    @validator("core_interface_pci_address", always=True)
    @classmethod
    def validate_core_interface_pci_address(cls, value: str, values) -> str:
        """Make sure core interface PCI address is given when using DPDK mode."""
        if values["upf_mode"] == UpfMode.dpdk and not value:
            raise ValueError("Core network interface PCI address is empty")
        return value


@dataclasses.dataclass
class CharmConfig:
    """Represents the state of the UPF operator charm.

    Attributes:
        upf_mode: Either `af_packet` (default) or `dpdk`.
        dnn: Data Network Name (DNN).
        gnb_subnet: gNodeB subnet.
        access_interface_name: Name of the UPF's access interface.
        core_interface_name: Name of the UPF's core interface.
        external_upf_hostname: Externally accessible FQDN for the UPF.
        enable_hw_checksum: When enabled, hardware checksum will be used on the network interfaces.
    """

    upf_mode: UpfMode
    dnn: StrictStr
    gnb_subnet: str
    access_interface_name: StrictStr
    access_ip: str
    access_gateway_ip: IPvAnyAddress
    access_interface_mtu_size: int
    access_interface_mac_address: Optional[StrictStr]
    access_interface_pci_address: Optional[StrictStr]
    core_interface_name: StrictStr
    core_ip: str
    core_gateway_ip: IPvAnyAddress
    core_interface_mtu_size: int
    core_interface_mac_address: Optional[StrictStr]
    core_interface_pci_address: Optional[StrictStr]
    external_upf_hostname: Optional[str]
    enable_hw_checksum: bool

    def __init__(self, *, upf_config: UpfConfig):
        """Initialize a new instance of the CharmConfig class.

        Args:
            upf_config: UPF operator configuration.
        """
        self.upf_mode = upf_config.upf_mode
        self.dnn = upf_config.dnn
        self.gnb_subnet = upf_config.gnb_subnet
        self.access_interface_name = upf_config.access_interface_name
        self.access_ip = upf_config.access_ip
        self.access_gateway_ip = upf_config.access_gateway_ip
        self.access_interface_mtu_size = upf_config.access_interface_mtu_size
        self.access_interface_mac_address = upf_config.access_interface_mac_address
        self.access_interface_pci_address = upf_config.access_interface_pci_address
        self.core_interface_name = upf_config.core_interface_name
        self.core_ip = upf_config.core_ip
        self.core_gateway_ip = upf_config.core_gateway_ip
        self.core_interface_mtu_size = upf_config.core_interface_mtu_size
        self.core_interface_mac_address = upf_config.core_interface_mac_address
        self.core_interface_pci_address = upf_config.core_interface_pci_address
        self.external_upf_hostname = upf_config.external_upf_hostname
        self.enable_hw_checksum = upf_config.enable_hw_checksum

    @classmethod
    def from_charm(
        cls,
        charm: ops.CharmBase,
    ) -> "CharmConfig":
        """Initialize a new instance of the CharmState class from the associated charm."""
        try:
            # ignoring because mypy fails with:
            # "has incompatible type "**dict[str, str]"; expected ...""
            return cls(upf_config=UpfConfig(**dict(charm.config.items())))  # type: ignore
        except ValidationError as exc:
            error_fields: list = []
            for error in exc.errors():
                if param := error["loc"]:
                    error_fields.extend(param)
                else:
                    value_error_msg: ValueError = error["ctx"]["error"]  # type: ignore
                    error_fields.extend(str(value_error_msg).split())
            error_fields.sort()
            error_field_str = ", ".join(f"'{f}'" for f in error_fields)
            raise CharmConfigInvalidError(
                f"The following configurations are not valid: [{error_field_str}]"
            ) from exc
