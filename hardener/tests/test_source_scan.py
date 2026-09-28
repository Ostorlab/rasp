"""Gate: every string literal in the native core is either in the registry or explicitly allowlisted.

Strips comments and preprocessor directives (except #define, whose strings land in the binary), extracts
C string literals, decodes them with the registry's own unescape, and asserts each one of >= 4 decoded
bytes is registered. Short literals are out of scope by design: they match by chance in any binary scan.
"""

import pathlib
import re
import unittest

from rasp_hardener import literals

CPP = pathlib.Path(__file__).resolve().parents[2] / "flutter_rasp" / "android" / "src" / "main" / "cpp"

# Deliberately cleartext: cross-language protocol constants byte-matched by the Python side, format
# escapes, the hex alphabet, and the public (non-secret) build id.
ALLOWLIST = {
    b"rasp-report-1",           # report MAC domain, mirrored in rasp_verifier.report
    b"raxp/guard-mesh/v1",      # guard-mesh seed, mirrored in guardmesh.py / integrity.c
    b"0123456789abcdef",        # hex alphabet (sha256.c)
    b"test-build",              # dev RASP_BUILD_ID (public identity)
    b"%lld",                    # integer format
    rb"\u%04x",                 # JSON control-char escape format (signals.c)
}

_TOKEN_RE = re.compile(r"\'(?:[^\'\\]|\\.)*\'|\"((?:[^\"\\]|\\.)*)\"")
_INCLUDE_RE = re.compile(r"^\s*#\s*include[^\n]*", re.M)


def scan_source(text: str) -> list[str]:
    text = text.replace("\\\n", "")
    text = _INCLUDE_RE.sub("", literals.strip_comments(text))
    text = re.sub(r'__has_include\(\s*"[^"\n]+"\s*\)', "1", text)
    entries: list[str] = []
    previous_end = -1
    for match in _TOKEN_RE.finditer(text):
        raw = match.group(1)
        if raw is None:
            previous_end = -1
            continue
        if previous_end >= 0 and text[previous_end:match.start()].strip() == "":
            entries[-1] += raw
        else:
            entries.append(raw)
        previous_end = match.end()
    return entries


class SourceScanTest(unittest.TestCase):
    def testCoreSources_everyLiteralIsRegisteredOrAllowlisted(self) -> None:
        offenders = []
        for path in sorted(list(CPP.glob("*.c")) + list(CPP.glob("*.h"))):
            if path.name in {"build_generated.h", "build_seed.h", "build_names.h", "wbaes_tables.h", "integrity_regions.h"}:  # generated / config headers are covered by the hygiene gate
                continue
            for raw in scan_source(path.read_text()):
                try:
                    decoded = literals.unescape_c(raw)
                except ValueError as error:
                    offenders.append(f"{path.name}: unsupported literal {raw!r}: {error}")
                    continue
                if len(decoded) >= 4 and decoded not in ALLOWLIST:
                    offenders.append(f"{path.name}: {decoded!r}")
        self.assertEqual(offenders, [])

    def testScanner_findsKnownStrings(self) -> None:
        text = 'int x; /* "commented" */\n#include "not_a_literal.h"\nconst char *p = "native.x";\n'
        self.assertEqual(scan_source(text), ["native.x"])

    def testScanner_commentTokensAndAdjacentLiterals_preserved(self) -> None:
        text = 'const char *p = "https://host/*path*/"; const char *q = "nat" /* gap */ "ive.id";'
        self.assertEqual(scan_source(text), ["https://host/*path*/", "native.id"])

    def testScanner_definesAndCharacterQuotes_checked(self) -> None:
        text = "char c = '\"';\n#define LEAK \"secret\"\n"
        self.assertEqual(scan_source(text), ["secret"])
