"""Finite manifest permission selection for the two opt-in capture sources."""

PERMISSIONS: tuple[tuple[str, str], ...] = (
    ("screenshot", "android.permission.DETECT_SCREEN_CAPTURE"),
    ("screen_recording", "android.permission.DETECT_SCREEN_RECORDING"),
)
MAX_MANIFEST_BYTES = 4 * 1024 * 1024


def selected(checks: tuple[str, ...]) -> tuple[str, ...]:
    """Return only the declarations explicitly selected by the effective runtime config."""
    return tuple(permission for group, permission in PERMISSIONS if group in checks)
