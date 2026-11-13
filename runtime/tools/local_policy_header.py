"""Generate the closed native selector table from the installed packer's reviewed inventory."""

import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "packer" / "src"))

from rasp_packer import capabilities
from rasp_packer import local_policy


def main() -> None:
    """Produce exact catalogue/semantic pins at configure time, including tidy builds."""
    inventory = local_policy.selector_inventory()
    lines = [
        "/// Generated closed operation selector table; edit the reviewed JSON inventory.",
        "namespace rasp::policy_internal {",
        "struct Selector { std::string_view platform; std::string_view group; std::string_view rule_id; std::uint32_t rule_version; };",
        f"inline constexpr std::string_view kCatalogue = {json.dumps(inventory['catalogue_id'])};",
        "inline constexpr auto kSelectors = std::to_array<Selector>({",
    ]
    for rule in inventory["rules"]:
        lines.append(
            "  {"
            + ", ".join(
                json.dumps(rule[key]) for key in ("platform", "group", "rule_id")
            )
            + f", {rule['rule_version']}"
            + "},"
        )
    lines.append("});")
    for platform in ("android", "ios"):
        groups = [
            group["name"]
            for group in capabilities.catalogue()["platforms"][platform]["groups"]
        ]
        lines.append(
            f"inline constexpr auto k{platform.title()}Groups = std::to_array<std::string_view>({{"
            + ",".join(json.dumps(group) for group in groups)
            + "});"
        )
        lines.append(
            f"inline constexpr std::string_view k{platform.title()}SelectorHash = {json.dumps(local_policy.selector_digest(platform))};"
        )
    lines.append("}")
    pathlib.Path(sys.argv[1]).write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
