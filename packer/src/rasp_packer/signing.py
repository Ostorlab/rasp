"""The hint that tells the user how to sign a packed app."""

import pathlib
import shlex


def next_step(output: pathlib.Path) -> str | None:
    """Returns the line that tells how to sign the packed app at `output`, or None for an unknown suffix.

    The suffix picks the variant, whatever its case: `apksigner` for an APK, `jarsigner` for an AAB, and
    an instruction to re-sign with the distribution certificate and provisioning profile for an IPA.
    """
    path = shlex.quote(str(output))
    match output.suffix.lower():
        case ".apk":
            return (
                "next: sign it with apksigner sign --ks <your-keystore.jks> "
                f"--ks-key-alias <key-alias> {path}"
            )
        case ".aab":
            return (
                "next: sign it with jarsigner -keystore <your-keystore.jks> "
                f"{path} <key-alias>"
            )
        case ".ipa":
            return (
                f"next: re-sign {path} with the app's distribution certificate and "
                "provisioning profile before uploading it"
            )
        case _:
            return None
