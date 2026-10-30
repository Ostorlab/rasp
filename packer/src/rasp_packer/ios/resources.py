"""Locates the `RaspRuntime.framework` bundled in the packer.

The framework comes from the runtime build. `framework` looks for it at
`resources/RaspRuntime.framework` in this package, and raises InvalidRuntimeError when it is absent.
"""

import collections.abc
import contextlib
import importlib.resources
import pathlib

from rasp_packer import errors
from rasp_packer.ios import macho

_RESOURCES_DIR = "resources"


@contextlib.contextmanager
def framework(
    override: pathlib.Path | None = None,
) -> collections.abc.Iterator[pathlib.Path]:
    """Gives the `RaspRuntime.framework` to embed in an app.

    Args:
        override: A framework to embed instead of the bundled one.

    Yields:
        Path to the framework directory. It is valid until the context exits.

    Raises:
        InvalidRuntimeError: The framework, its binary or its `Info.plist` is missing.
    """
    if override is not None:
        _check(override)
        yield override
        return
    shipped = (
        importlib.resources.files("rasp_packer.ios")
        / _RESOURCES_DIR
        / macho.RUNTIME_FRAMEWORK
    )
    with importlib.resources.as_file(shipped) as path:
        _check(path)
        yield path


def _check(path: pathlib.Path) -> None:
    if path.is_dir() is False:
        raise errors.InvalidRuntimeError(
            f"{path} not found; build the runtime and place it under {_RESOURCES_DIR}/"
        )
    for name in (macho.RUNTIME_BINARY, "Info.plist"):
        if (path / name).is_file() is False:
            raise errors.InvalidRuntimeError(f"{path} has no {name}")
