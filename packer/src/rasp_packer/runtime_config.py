"""The runtime's config, which the packer writes into the protected app and the runtime reads when it starts.

The config is one JSON object in UTF-8. The packer writes it into a space the runtime's binary keeps for it: the JSON at
the start of the space, and zero bytes over the rest. The runtime reads it up to the first zero byte
(runtime/core/src/embedded_config.cpp). Each platform's module finds the space in its binary, and this one writes and
reads it: android/runtime_library.py for `librasp.so`, and ios/runtime_binary.py for the `RaspRuntime` binary.
"""

import dataclasses
import json

from rasp_packer import errors

# TODO: the config ships in the clear in the runtime's binary, so anyone who reads the binary can read it.
# Encrypt it.


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class RuntimeConfig:
    """The runtime's config.

    Attributes:
        build_id: The id of the protected build.
        checks: The ids of the check groups the protected app runs, sorted.
        checks_mask: The same groups as a mask, one bit per group in the platform's run order, which
            is the form the config carries: the shipped library names no check group.
        stub_class: The name of the app's component factory class, with ``.`` separators: the stub the
            packer points the manifest at, whose native entry points the runtime binds. Empty when the
            platform has no stub (iOS), which leaves the field out of the JSON.
    """

    build_id: str
    checks: tuple[str, ...]
    checks_mask: int
    stub_class: str = ""

    def to_json(self) -> bytes:
        """Writes the config as the runtime reads it.

        The build id stays readable, for support; the check groups go as their mask; the stub's class
        name goes along, so the runtime binds its native entry points on the class the manifest names
        without carrying the class name in its own bytes.

        Returns:
            A JSON object with the build id, the check mask and the stub class, in UTF-8.
        """
        fields: dict[str, object] = {"build_id": self.build_id, "m": self.checks_mask}
        if self.stub_class:
            fields["s"] = self.stub_class
        return json.dumps(
            fields,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")


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
    return binary[space.offset : space.offset + space.size].split(b"\0", 1)[0]
