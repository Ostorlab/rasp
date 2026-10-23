"""The class map the on-demand loader reads: which encrypted dex defines each business class.

The runtime, when it first needs one of the app's own classes, looks the class up in this map to
find the dex to decrypt. The map is plain text, one line per class:

    binary.class.Name,business/0.dex

The name before the comma is the class's binary name; the path after it is the dex's path under
``assets/``. The packer encrypts this text like any other asset. The runtime skips a line with no
comma or an empty side, and when a class is named twice the first line wins, so this module writes
each class once, in the order the splitter gave.
"""

from rasp_packer.android import split


def build(business: tuple[split.BusinessDex, ...]) -> str:
    """Builds the class map text for the business dexes.

    Args:
        business: The business dexes, in the order they are numbered.

    Returns:
        The map text, one ``binary.class.Name,<path>`` line per class, each ending in a newline. It
        is empty when there are no business classes.
    """
    lines = [
        f"{class_name},{dex.path}" for dex in business for class_name in dex.classes
    ]
    return "".join(f"{line}\n" for line in lines)
