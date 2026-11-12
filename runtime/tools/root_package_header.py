"""Generate the fixed JNI query list from the same versioned data shipped in the packer."""

import json
import pathlib
import sys


def main() -> None:
    """Write bounded constexpr names at configure time, including configure-only tidy."""
    source = (
        pathlib.Path(__file__).resolve().parents[2]
        / "packer/src/rasp_packer/android/root_manager_packages_v1.json"
    )
    data = json.loads(source.read_text())
    names = [entry["name"] for entry in data["packages"]]
    if data["version"] != 1 or len(names) != 3 or len(set(names)) != 3:
        raise ValueError("invalid fixed version1 package list")
    pathlib.Path(sys.argv[1]).write_text(
        "/// Generated list-v1 exact package identifiers; no installed-package enumeration.\n"
        "constexpr auto kRootManagerPackages = std::to_array({"
        + ", ".join(json.dumps(name) for name in names)
        + "});\n"
    )


if __name__ == "__main__":
    main()
