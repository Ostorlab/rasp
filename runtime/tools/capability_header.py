"""Generate host test expectations from the production catalogue."""

import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "packer" / "src"))
from rasp_packer import capabilities


def main() -> None:
    """Write constexpr records consumed by the compiled production dispatch tests."""
    records = []
    for group in capabilities.catalogue()["platforms"][sys.argv[2]]["groups"]:
        for observation in group["observations"]:
            fields = [
                json.dumps(value)
                for value in (
                    group["name"],
                    observation["signal"],
                    observation["source"],
                )
            ]
            kind = ("none", "boolean", "integer", "string", "string_list").index(
                observation["value_kind"]
            )
            mask = sum(
                1 << ("ok", "unsupported", "error").index(status)
                for status in observation["statuses"]
            )
            values = [*fields, str(kind), str(mask)]
            members = ("group", "signal", "source", "kind", "statuses")
            records.append(
                "  Expected{"
                + ", ".join(
                    f".{name} = {value}"
                    for name, value in zip(members, values, strict=True)
                )
                + "}"
            )
    pathlib.Path(sys.argv[1]).write_text(
        "/// Generated catalogue expectations for compiled dispatch.\nconstexpr auto kExpected = std::to_array<Expected>({\n"
        + ",\n".join(records)
        + "\n});\n"
    )


if __name__ == "__main__":
    main()
