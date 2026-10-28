"""The runtime's config, which the packer writes into the protected app and the runtime reads when it starts.

The config is one JSON object, written in UTF-8 to a file named `config.json`: under `assets/rasp/` in an APK, and in
the embedded `RaspRuntime.framework` in an IPA.
"""

import dataclasses
import json

# TODO: the config ships in the clear in the protected app, so anyone who unzips the app can read it.
# Encrypt it.
FILE_NAME = "config.json"


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class RuntimeConfig:
    """The runtime's config.

    Attributes:
        build_id: The id of the protected build.
    """

    build_id: str

    def to_json(self) -> bytes:
        """Writes the config as the runtime reads it.

        Returns:
            A JSON object with one member per attribute, in UTF-8.
        """
        return json.dumps(
            dataclasses.asdict(self), ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
