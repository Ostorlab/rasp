"""Generate native cycle definitions from the validated production release catalogue."""

import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "packer" / "src"))
from rasp_packer import capabilities


def main() -> None:
    """Write constexpr identities and canonical ID at configure time, including tidy-only builds."""
    catalogue = capabilities.catalogue()
    lines = [
        "/// Generated exact native catalogue; regenerate through CMake, never edit.",
        "namespace rasp { namespace {",
        f"constexpr std::string_view kCycleCatalogueId = {json.dumps(capabilities.catalogue_id())};",
    ]
    for platform in ("android", "ios"):
        records = []
        for group in catalogue["platforms"][platform]["groups"]:
            for output in group["observations"]:
                records.append(
                    "  CycleOutput{"
                    + ", ".join(
                        f".{key} = {json.dumps(value)}"
                        for key, value in (
                            ("group", group["name"]),
                            ("signal", output["signal"]),
                            ("source", output["source"]),
                        )
                    )
                    + "}"
                )
        name = "Android" if platform == "android" else "Ios"
        lines.append(
            f"constexpr auto k{name}CycleOutputs = std::to_array<CycleOutput>({{\n"
            + ",\n".join(records)
            + "\n});"
        )
    lines.append("} }  // namespace rasp")
    pathlib.Path(sys.argv[1]).write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
