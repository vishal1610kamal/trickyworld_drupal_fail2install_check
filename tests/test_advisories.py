import unittest

from f2icheck.advisories import SA017, SA019, assess, parse


class Parse(unittest.TestCase):
    def test_forms(self):
        self.assertEqual(str(parse("11.4.14")), "11.4.14")
        self.assertEqual(str(parse("v10.6.22")), "10.6.22")
        self.assertEqual(str(parse("7.103")), "7.103")
        v = parse("11.4.x-dev")
        self.assertIsNone(v.patch)
        self.assertEqual(v.pre, "x-dev")
        self.assertEqual(parse("12.0.0-beta3").pre, "beta3")
        self.assertEqual(parse("11.5.0-rc1").pre, "rc1")

    def test_rejects(self):
        for bad in ("", "eleven", "11", "11.4.14 extra"):
            with self.assertRaises(ValueError, msg=bad):
                parse(bad)


class Assess(unittest.TestCase):
    CASES = [
        # version, status, level, advisories still open
        ("11.4.14", "fixed", "ok", ()),
        ("11.4.15", "fixed", "ok", ()),
        ("11.4.13", "update", "high", ("SA-CORE-2026-019",)),
        ("11.4.12", "update", "critical", ("SA-CORE-2026-017", "SA-CORE-2026-019")),
        ("11.4.0", "update", "critical", ("SA-CORE-2026-017", "SA-CORE-2026-019")),
        ("11.3.23", "fixed", "ok", ()),
        ("11.3.22", "update", "high", ("SA-CORE-2026-019",)),
        ("11.3.21", "update", "critical", ("SA-CORE-2026-017", "SA-CORE-2026-019")),
        ("10.6.23", "fixed", "ok", ()),
        ("10.6.22", "update", "high", ("SA-CORE-2026-019",)),
        ("10.6.9", "update", "critical", ("SA-CORE-2026-017", "SA-CORE-2026-019")),
        ("11.2.12", "end-of-life", "critical", ("SA-CORE-2026-017", "SA-CORE-2026-019")),
        ("11.0.0", "end-of-life", "critical", ("SA-CORE-2026-017", "SA-CORE-2026-019")),
        ("10.5.10", "end-of-life", "critical", ("SA-CORE-2026-017", "SA-CORE-2026-019")),
        ("10.0.0", "end-of-life", "critical", ("SA-CORE-2026-017", "SA-CORE-2026-019")),
        ("9.5.11", "end-of-life", "critical", ("SA-CORE-2026-017", "SA-CORE-2026-019")),
        ("8.9.20", "end-of-life", "critical", ("SA-CORE-2026-017", "SA-CORE-2026-019")),
        ("8.8.12", "not-affected", "medium", ()),
        ("8.0.0", "not-affected", "medium", ()),
        ("7.103", "not-affected", "medium", ()),
        ("11.5.0-beta1", "pre-release", "high", ("SA-CORE-2026-017", "SA-CORE-2026-019")),
        ("12.0.0-beta3", "pre-release", "high", ("SA-CORE-2026-017", "SA-CORE-2026-019")),
        ("11.4.x-dev", "pre-release", "high", ("SA-CORE-2026-017", "SA-CORE-2026-019")),
        ("11.5.0", "newer", "info", ()),
        ("12.0.0", "newer", "info", ()),
    ]

    def test_table(self):
        for version, status, level, open_ in self.CASES:
            with self.subTest(version=version):
                a = assess(version)
                self.assertEqual((a.status, a.level, a.advisories), (status, level, open_))

    def test_targets_name_the_newest_fix(self):
        self.assertIn("Update to 11.4.14", assess("11.4.12").action)
        self.assertIn("Update to 11.3.23", assess("11.3.22").action)
        self.assertIn("Update to 10.6.23", assess("10.6.1").action)
        for v in ("11.4.13", "11.4.10", "10.6.22"):
            self.assertIn("drush updatedb", assess(v).action, v)

    def test_every_action_says_to_block_the_installer(self):
        for version, *_ in self.CASES:
            a = assess(version)
            self.assertIn("install.php", a.action, version)

    def test_second_fix_is_later_than_first(self):
        self.assertEqual(SA017["fixed"].keys(), SA019["fixed"].keys())
        for branch, patch in SA017["fixed"].items():
            self.assertEqual(SA019["fixed"][branch], patch + 1, branch)

    def test_support_windows_in_fixed_message(self):
        self.assertIn("April 2027", assess("11.4.14").action)
        self.assertIn("December 2026", assess("10.6.23").action)


if __name__ == "__main__":
    unittest.main()
