# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Config of the Charm."""

import dataclasses
import logging
from typing import Optional

import ops
from pydantic import (  # pylint: disable=no-name-in-module,import-error
    BaseModel,
    ConfigDict,
    Field,
    StrictStr,
    ValidationError,
)
from pydantic.networks import IPvAnyNetwork
from typing_extensions import TypeAlias

logger = logging.getLogger(__name__)


NetworkType: TypeAlias = "str | bytes | int | tuple[str | bytes | int, str | int]"


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


class UpfConfig(BaseModel):  # pylint: disable=too-few-public-methods
    """Represent UPF operator builtin configuration values."""

    model_config = ConfigDict(alias_generator=to_kebab, use_enum_values=True)

    dnn: StrictStr = Field(default="internet", min_length=1)
    gnb_subnet: IPvAnyNetwork = IPvAnyNetwork("192.168.251.0/24")  # type: ignore
    access_interface_name: StrictStr = Field(default="eth0")
    core_interface_name: StrictStr = Field(default="eth1")
    external_upf_hostname: StrictStr = Field(default="")
    enable_hw_checksum: bool = True


@dataclasses.dataclass
class CharmConfig:
    """Represents the state of the UPF operator charm.

    Attributes:
        dnn: Data Network Name (DNN).
        gnb_subnet: gNodeB subnet.
        access_interface_name: Name of the UPF's access interface.
        core_interface_name: Name of the UPF's core interface.
        external_upf_hostname: Externally accessible FQDN for the UPF.
        enable_hw_checksum: When enabled, hardware checksum will be used on the network interfaces.
    """

    dnn: StrictStr
    gnb_subnet: IPvAnyNetwork
    access_interface_name: Optional[StrictStr]
    core_interface_name: Optional[StrictStr]
    external_upf_hostname: Optional[StrictStr]
    enable_hw_checksum: bool

    def __init__(self, *, upf_config: UpfConfig):
        """Initialize a new instance of the CharmConfig class.

        Args:
            upf_config: UPF operator configuration.
        """
        self.dnn = upf_config.dnn
        self.gnb_subnet = upf_config.gnb_subnet
        self.access_interface_name = upf_config.access_interface_name
        self.core_interface_name = upf_config.core_interface_name
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
