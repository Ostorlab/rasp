"""The protection version of each platform.

A protection version is a whole number that names what protected apps do on a platform. Bump a
platform's number when a change alters what its protected apps do: the runtime's behaviour, or how
the packer transforms the app. Do not bump it for changes that leave protected apps the same, such as
comments, refactors, tests or docs.

The number is part of every build id, so a bump gives each app a new build on that platform.
"""

import collections.abc

from rasp_packer import platforms

PROTECTION_VERSIONS: collections.abc.Mapping[platforms.Platform, int] = {
    platforms.Platform.ANDROID: 1,
    platforms.Platform.IOS: 1,
}
