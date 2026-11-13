"""The runtime's config, which the packer writes into the protected app and the runtime reads when it starts.

The config is one JSON object in UTF-8. The packer writes it into a space the runtime's binary keeps for it: the JSON at
the start of the space, and zero bytes over the rest. The runtime reads it up to the first zero byte
(runtime/core/src/embedded_config.cpp). Each platform's module finds the space in its binary, and this one writes and
reads it: android/runtime_library.py for `librasp.so`, and ios/runtime_binary.py for the `RaspRuntime` binary.
"""

import dataclasses
import json

from rasp_packer import errors
from rasp_packer import local_policy as policy_module

# TODO: the config ships in the clear in the runtime's binary, so anyone who reads the binary can read it.
# Encrypt it.


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class RuntimeConfig:
    """The runtime's config.

    Attributes:
        build_id: The id of the protected build.
        checks: The ids of the check groups the protected app runs, sorted.
    """

    build_id: str
    checks: tuple[str, ...]
    local_policy: policy_module.Policy | None = None

    def to_json(self) -> bytes:
        """Writes the config as the runtime reads it.

        Returns:
            A JSON object with one member per attribute, in UTF-8.
        """
        document: dict[str, object] = {"build_id": self.build_id, "checks": self.checks}
        if self.local_policy is not None:
            policy = policy_module.validate_for(
                self.local_policy,
                self.local_policy.platform,
                self.checks,
                self.build_id,
            )
            document["local_policy"] = json.loads(policy.canonical_json)
        return json.dumps(document, ensure_ascii=False, separators=(",", ":")).encode(
            "utf-8"
        )


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class ConfigSpace:
    """Where the config goes in a binary's file.

    Attributes:
        offset: The space's offset in the file, in bytes.
        size: The space's size, in bytes.
    """

    offset: int
    size: int


def write_config(binary: bytes, space: ConfigSpace, config: RuntimeConfig) -> bytes:
    """Writes the config into a binary's space for it.

    Args:
        binary: The binary's content.
        space: Where the config goes in it.
        config: The config.

    Returns:
        The binary with the config's JSON at the start of the space and zero bytes over the rest of it. Its size does
        not change.

    Raises:
        ConfigTooLargeError: The config's JSON and one zero byte do not fit in the space.
    """
    _check_space(binary, space)
    json_config = config.to_json()
    if len(json_config) >= space.size:
        raise errors.ConfigTooLargeError(
            f"the runtime's config is {len(json_config)} bytes, and the runtime keeps room for "
            f"{space.size - 1}"
        )
    written = bytearray(binary)
    written[space.offset : space.offset + space.size] = json_config + bytes(
        space.size - len(json_config)
    )
    return bytes(written)


def read_config(binary: bytes, space: ConfigSpace) -> bytes:
    """Reads the config written into a binary's space for it.

    Args:
        binary: The binary's content.
        space: Where the config is in it.

    Returns:
        The config's JSON: the space's bytes up to the first zero byte.
    """
    _check_space(binary, space)
    data = binary[space.offset : space.offset + space.size]
    if b"\0" not in data:
        raise errors.InvalidRuntimeError("the runtime config is not zero-terminated")
    document, padding = data.split(b"\0", 1)
    if any(padding):
        raise errors.InvalidRuntimeError("the runtime config padding is not zero")
    return document


def _check_space(binary: bytes, space: ConfigSpace) -> None:
    """Bound both config reads and allocations before accessing an embedded section."""
    if (
        space.offset < 0
        or space.size <= 0
        or space.size > 65536
        or space.offset + space.size > len(binary)
    ):
        raise errors.InvalidRuntimeError(
            "the runtime config section has invalid bounds (limit: 64 KiB)"
        )
