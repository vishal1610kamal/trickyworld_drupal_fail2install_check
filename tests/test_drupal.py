import tempfile
import unittest
from pathlib import Path

from f2icheck import drupal
from tests.helpers import make_site


class Find(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_composer_layout_from_project_or_webroot(self):
        project, web = make_site(self.root, "11.4.13")
        for start in (project, web):
            site = drupal.find(start)
            self.assertEqual(site.webroot, web.resolve())
            self.assertEqual(site.core_version, "11.4.13")
        self.assertEqual(drupal.find(project).lock_version, "11.4.13")
        self.assertEqual(drupal.find(project).project, project.resolve())

    def test_flat_and_docroot_layouts(self):
        project, web = make_site(self.root / "a", "10.6.22", layout="flat")
        self.assertEqual(drupal.find(project).webroot, web.resolve())
        project, web = make_site(self.root / "b", "11.3.23", layout="docroot")
        self.assertEqual(drupal.find(project).webroot, (project / "docroot").resolve())

    def test_drupal7(self):
        project, _ = make_site(self.root, "7.103", layout="flat", lock=None, d7=True)
        site = drupal.find(project)
        self.assertEqual(site.core_version, "7.103")
        self.assertEqual(drupal.check(site)[0].level, "medium")

    def test_not_drupal(self):
        with self.assertRaises(FileNotFoundError):
            drupal.find(self.root)

    def test_lock_version_strips_v_and_ignores_bad_json(self):
        project, _ = make_site(self.root, "11.4.14", lock="v11.4.14")
        self.assertEqual(drupal.lock_version(project), "11.4.14")
        (project / "composer.lock").write_text("{not json")
        self.assertIsNone(drupal.lock_version(project))

    def test_mismatch_between_disk_and_lock(self):
        project, _ = make_site(self.root, "11.4.12", lock="11.4.14")
        f = drupal.check(drupal.find(project))
        self.assertEqual(f[0].level, "critical")              # the code on disk decides
        self.assertEqual(f[1].title, "The code on disk and composer.lock disagree")

    def test_lock_only(self):
        project, web = make_site(self.root, "11.4.13")
        (web / "core" / "lib" / "Drupal.php").write_text("<?php // no version here\n")
        f = drupal.check(drupal.find(project))
        self.assertEqual(f[0].level, "high")
        self.assertIn("11.4.13", f[0].title)

    def test_no_version_anywhere(self):
        project, web = make_site(self.root, "11.4.13", lock=None)
        (web / "core" / "lib" / "Drupal.php").write_text("<?php\n")
        self.assertEqual(drupal.check(drupal.find(project))[0].title, "Could not read the Drupal core version")


if __name__ == "__main__":
    unittest.main()
