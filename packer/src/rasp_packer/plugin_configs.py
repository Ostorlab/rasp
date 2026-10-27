"""Plugin configs: what the packer writes into a protected app for the plugins compiled into its runtime.

The runtime gives each of its plugins the config written under the plugin's name, or an empty config when none
is. It reads at most MAX_SIZE bytes of a config.
"""

import collections
import collections.abc
import dataclasses
import pathlib
import re

from rasp_packer import errors

MAX_SIZE = 64 * 1024

_NAME = re.compile(r"[a-z][a-z0-9_]{0,31}")


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class PluginConfig:
    """The config of one plugin.

    Attributes:
        name: The plugin's name. It matches `[a-z][a-z0-9_]{0,31}`.
        data: The config's bytes, at most MAX_SIZE.

    Raises:
        InvalidPluginConfigError: The name doesn't match, or the config is larger than MAX_SIZE.
    """

    name: str
    data: bytes

    def __post_init__(self) -> None:
        """Refuses a name the runtime cannot look up, and a config larger than the runtime reads."""
        if _NAME.fullmatch(self.name) is None:
            raise errors.InvalidPluginConfigError(
                f"the plugin name {self.name!r} doesn't match [a-z][a-z0-9_]{{0,31}}"
            )
        if len(self.data) > MAX_SIZE:
            raise errors.InvalidPluginConfigError(
                f"the config of the plugin {self.name} is larger than {MAX_SIZE} bytes"
            )


def read(arguments: collections.abc.Sequence[str]) -> tuple[PluginConfig, ...]:
    """Reads the plugin configs given as `<name>=<file>` arguments.

    Args:
        arguments: The arguments, each the name of a plugin and the file that holds its config.

    Returns:
        The configs, in the order given.

    Raises:
        InvalidPluginConfigError: An argument is not `<name>=<file>`, a name is invalid or given
            twice, or a file cannot be read or is larger than MAX_SIZE.
    """
    configs = tuple(_read_one(argument) for argument in arguments)
    counts = collections.Counter(config.name for config in configs)
    duplicates = sorted(name for name, count in counts.items() if count > 1)
    if len(duplicates) > 0:
        raise errors.InvalidPluginConfigError(
            f"plugin configs given more than once: {', '.join(duplicates)}"
        )
    return configs


def _read_one(argument: str) -> PluginConfig:
    """Reads the config of one `<name>=<file>` argument, at most one byte more than MAX_SIZE."""
    name, separator, file = argument.partition("=")
    if len(separator) == 0 or len(file) == 0:
        raise errors.InvalidPluginConfigError(
            f"the plugin config {argument!r} is not <name>=<file>"
        )
    try:
        with pathlib.Path(file).open("rb") as stream:
            data = stream.read(MAX_SIZE + 1)
    except OSError as error:
        raise errors.InvalidPluginConfigError(
            f"cannot read the config of the plugin {name}: {error}"
        ) from error
    return PluginConfig(name=name, data=data)
