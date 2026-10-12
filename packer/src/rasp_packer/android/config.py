"""The runtime configuration the packer writes into the protected APK.

The packer writes this as an asset, next to the encrypted payload. The native
runtime reads it to decrypt the payload, and the stub reads it to find the
original application class it must hand control back to.

TODO(hardening): the key is written here as a hex string, in the clear, for the
first version. It must not stay in a readable asset. The hardening work moves it
into the native library (patched in at pack time), behind the white-box tables,
and splits it so no single place holds the whole key. See the repo TODO.
"""

import dataclasses
import json
from typing import Any
from typing import Self

CONFIG_VERSION = "rasp-android-config-1"

ASSET_DIRECTORY = "assets/rasp"
CONFIG_ENTRY = f"{ASSET_DIRECTORY}/config.json"
PAYLOAD_ENTRY = f"{ASSET_DIRECTORY}/payload.bin"


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class RuntimeConfig:
    """What the runtime needs to start a protected app.

    Attributes:
        build_id: Id of this protected build.
        key_hex: The payload's master key, hex-encoded (first version only).
        application_class: The original application class to hand control to.
        dex_names: The names of the original dex entries, in load order.
        version: The config format version.
    """

    build_id: str
    key_hex: str
    application_class: str
    dex_names: tuple[str, ...]
    version: str = CONFIG_VERSION

    def to_json(self) -> str:
        """Returns the config as the JSON text written into the APK."""
        document: dict[str, Any] = {
            "version": self.version,
            "build_id": self.build_id,
            "key_hex": self.key_hex,
            "application_class": self.application_class,
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
            application_class=document["application_class"],
            dex_names=tuple(document["dex_names"]),
            version=document["version"],
        )
