"""A virtual patch is selected only for an exact SCA component and version."""

from __future__ import annotations

import unittest

from rasp_agent import patches


class PatchTest(unittest.TestCase):
    def testSelect_whenExactVulnerableComponent_presentEnablesSinkBlock(self) -> None:
        rule = {
            "vulnerabilityId": "CVE-2099-0001",
            "purl": "pkg:pypi/example@1.0",
            "sink": "deserialization",
        }
        selected = patches.select(
            {"components": [{"purl": "pkg:pypi/example@1.0"}]}, [rule]
        )
        self.assertEqual(selected.denied_sinks, frozenset({"deserialization"}))
        self.assertEqual(selected.vulnerability_ids, ("CVE-2099-0001",))

    def testSelect_whenFixedVersion_doesNotEnablePatch(self) -> None:
        rule = {
            "vulnerabilityId": "CVE-2099-0001",
            "purl": "pkg:pypi/example@1.0",
            "sink": "deserialization",
        }
        selected = patches.select(
            {"components": [{"purl": "pkg:pypi/example@2.0"}]}, [rule]
        )
        self.assertEqual(selected.denied_sinks, frozenset())

    def testSelect_whenUnversionedOrUnknownSink_rejectsConfiguration(self) -> None:
        for purl, sink in [
            ("pkg:pypi/example", "sql"),
            ("pkg:npm/@scope/example", "sql"),
            ("pkg:npm/example@#subpath", "sql"),
            ("pkg:pypi/example@1.0", "unknown"),
        ]:
            with self.subTest(purl=purl, sink=sink), self.assertRaises(ValueError):
                patches.select(
                    {"components": []},
                    [{"vulnerabilityId": "CVE-2099-0001", "purl": purl, "sink": sink}],
                )
