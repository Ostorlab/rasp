"""Reads the slots of a runtime library the way the runtime sees them once its code is decrypted."""

from rasp_packer.android import self_encrypt
from rasp_packer.android import slots


def read(library: bytes, raw: bytes, slot: slots.Slot) -> bytes:
    """The plaintext of one slot of `library`, found through the layout of `raw`, the same build unwritten.

    The share comes back unmasked.
    """
    layout = slots.locate(raw)
    if slot == slots.SHARE:
        return slots.mask_share(
            slots.read(library, layout, slots.SHARE), read(library, raw, slots.PAD)
        )
    if self_encrypt.packed_text_digest(library) is None:
        return slots.read(library, layout, slot)
    return self_encrypt.decrypt_range(library, *layout.span(slot))


def region(library: bytes, raw: bytes) -> bytes:
    """The plaintext bytes the key schedule's region record digests."""
    return b"".join(read(library, raw, slot) for slot in slots.REGION_SLOTS)
