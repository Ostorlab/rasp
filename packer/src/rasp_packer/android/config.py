"""The runtime configuration the packer writes into the protected APK.

The packer writes this as an asset, next to the encrypted payload. The stub
reads the payload key from it and passes it to the native runtime, which uses the
key to decrypt the payload.
"""

import dataclasses
import json
from typing import Any
from typing import Self

ASSET_DIRECTORY = "assets/rasp"
CONFIG_ENTRY = f"{ASSET_DIRECTORY}/config.json"
PAYLOAD_ENTRY = f"{ASSET_DIRECTORY}/payload.bin"


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class RuntimeConfig:
    """What the runtime needs to start a protected app.

    Attributes:
        build_id: Id of this protected build.
        key_hex: The payload's master key, hex-encoded (first version only).
        dex_names: The names of the original dex entries, in load order.
    """

    build_id: str
    key_hex: str
    dex_names: tuple[str, ...]

    def to_json(self) -> str:
        """Returns the config as the JSON text written into the APK."""
        document: dict[str, Any] = {
            "build_id": self.build_id,
            "key_hex": self.key_hex,
            "dex_names": list(self.dex_names),
        }
        return json.dumps(document, indent=2, sort_keys=True) + "\n"

    @classmethod
    def from_json(cls, text: str) -> Self:
        """Parses the config from its JSON form."""
        document = json.loads(text)
        return cls(
            build_id=document["build_id"],
            key_hex=document["key_hex"],
            dex_names=tuple(document["dex_names"]),
        )
