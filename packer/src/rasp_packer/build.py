"""The identity of a protected build: what the packer writes into the app."""

import dataclasses
import uuid
from typing import Self


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class Build:
    """A protected build of an app.

    The runtime sends both ids with every batch it reports to the ADR server.

    Attributes:
        rasp_app_id: Id of the protected app in the RASP registry. The same for every build of the app.
        build_id: Id of this build, new each time the packer protects a release of the app.
    """

    rasp_app_id: uuid.UUID
    build_id: str

    @classmethod
    def new(cls, rasp_app_id: uuid.UUID) -> Self:
        """Creates a new build of an app, with a fresh build id.

        The build id is a UUIDv7, so build ids sort in the order the builds were made.

        Args:
            rasp_app_id: Id of the protected app in the RASP registry.

        Returns:
            The new build.
        """
        return cls(rasp_app_id=rasp_app_id, build_id=str(uuid.uuid7()))
