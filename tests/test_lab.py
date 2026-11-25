"""Checks against a real Drupal site and web server. Skipped unless you point them at one you run:

  F2I_LAB_ROOT=/path/to/project        a Drupal project (Drush in vendor/bin for the state check)
  F2I_LAB_URL=http://127.0.0.1:18081   the same site served by a web server
"""
import os
import unittest

from f2icheck import drupal, files, state, web

ROOT = os.environ.get("F2I_LAB_ROOT")
URL = os.environ.get("F2I_LAB_URL")


@unittest.skipUnless(ROOT, "set F2I_LAB_ROOT to a Drupal project")
class LabSite(unittest.TestCase):
    def test_version_is_read_from_real_core(self):
        site = drupal.find(ROOT)
        self.assertRegex(site.core_version or "", r"^\d+\.\d+")
        self.assertEqual(site.core_version, site.lock_version)

    def test_files_scan_reads_the_whole_tree(self):
        found = files.check(drupal.find(ROOT))
        scanned = next(f for f in found if f.title.startswith("Scanned"))
        self.assertGreater(int(scanned.title.split()[1]), 1000)

    def test_state_through_real_drush(self):
        found = state.check(drupal.find(ROOT))
        self.assertIn("install_task is 'done'", [f.title for f in found])


@unittest.skipUnless(URL, "set F2I_LAB_URL to the site's address")
class LabServer(unittest.TestCase):
    def test_every_path_gets_an_answer(self):
        found = web.check(URL)
        self.assertEqual(len(found[0].evidence), 5)
        self.assertNotIn("no answer", " ".join(found[0].evidence))


if __name__ == "__main__":
    unittest.main()
