import json
import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from f2icheck import drupal, files
from tests.helpers import MYSQL_SETTINGS, SQLITE_HEADER, chmod, current_user, make_site

OLD = datetime(2026, 1, 1, tzinfo=timezone.utc).timestamp()


def titles(found):
    return [f.title for f in found]


def by_level(found, level):
    return [f for f in found if f.level == level]


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.project, self.web = make_site(Path(self.tmp.name))
        self.settings = self.web / "sites" / "default" / "settings.php"
        os.utime(self.settings, (OLD, OLD))

    def tearDown(self):
        for root, dirs, names in os.walk(self.tmp.name):
            for n in dirs + names:
                try:
                    os.chmod(os.path.join(root, n), 0o700)
                except OSError:
                    pass
        self.tmp.cleanup()

    def site(self):
        return drupal.find(self.project)


class Settings(Base):
    def test_php_user_owning_settings_can_chmod_it(self):
        chmod(self.settings, 0o444)
        f = files.settings_findings(self.web, current_user(), files.DISCLOSED)
        high = by_level(f, "high")
        self.assertEqual(len(high), 1)
        self.assertIn("change the permissions of", high[0].detail)

    def test_other_user_and_read_only_is_ok(self):
        chmod(self.settings, 0o444)
        f = files.settings_findings(self.web, "nobody", files.DISCLOSED)
        self.assertEqual(f[0].level, "ok")

    def test_world_writable_is_high_for_anyone(self):
        chmod(self.settings, 0o666)
        f = files.settings_findings(self.web, "nobody", files.DISCLOSED)
        self.assertIn("write to", by_level(f, "high")[0].detail)
        f = files.settings_findings(self.web, None, files.DISCLOSED)
        self.assertEqual(by_level(f, "high")[0].level, "high")

    def test_php_user_is_guessed_from_compiled_templates(self):
        chmod(self.settings, 0o444)
        twig = self.web / "sites" / "default" / "files" / "php" / "twig" / "abc"
        twig.mkdir(parents=True)
        (twig / "x.php").write_text("<?php // compiled")
        f = files.settings_findings(self.web, None, files.DISCLOSED)
        self.assertIn(f"PHP runs as {current_user()}", by_level(f, "high")[0].detail)

    def test_without_any_user_hint(self):
        chmod(self.settings, 0o444)
        f = files.settings_findings(self.web, None, files.DISCLOSED)
        self.assertEqual(f[0].level, "info")
        self.assertIn("--web-user", f[0].detail)

    def test_unknown_user_does_not_crash(self):
        chmod(self.settings, 0o444)
        f = files.settings_findings(self.web, "no-such-user-f2i", files.DISCLOSED)
        self.assertIn("doesn't exist here", f[0].detail)

    def test_site_folder_php_can_write_or_chmod(self):
        chmod(self.settings, 0o444)
        f = files.settings_findings(self.web, current_user(), files.DISCLOSED)
        self.assertIn("PHP can write to the sites/default folder", titles(f))
        chmod(self.settings.parent, 0o555)
        f = files.settings_findings(self.web, current_user(), files.DISCLOSED)
        self.assertIn("PHP can change the permissions of the sites/default folder", titles(f))
        f = files.settings_findings(self.web, "nobody", files.DISCLOSED)
        self.assertFalse(any("folder" in t for t in titles(f)))

    def test_clean_settings_text_has_no_findings(self):
        self.assertEqual(files._settings_text(self.settings, Path("s.php"), files.DISCLOSED), [])

    def test_appended_database_block(self):
        self.settings.write_text(MYSQL_SETTINGS + "$databases['default']['default'] = array (\n 'driver' => 'mysql',"
                                 " 'database' => 'other',\n);\n$settings['hash_salt'] = 'new';\n")
        os.utime(self.settings, (OLD, OLD))
        f = files._settings_text(self.settings, Path("s.php"), files.DISCLOSED)
        self.assertEqual(f[0].level, "medium")
        self.assertIn("assigned 2 times, hash_salt 2 times", f[0].detail)

    def test_sqlite_with_php_name_is_critical(self):
        self.settings.write_text("<?php\n$databases['default']['default'] = [\n  'driver' => 'sqlite',\n"
                                 "  'database' => 'core/misc/x.php',\n];\n")
        f = files._settings_text(self.settings, Path("s.php"), datetime(2030, 1, 1, tzinfo=timezone.utc))
        self.assertEqual(f[0].level, "critical")

    def test_sqlite_next_to_mysql_is_high(self):
        self.settings.write_text(MYSQL_SETTINGS + "$databases['default']['default'] = [\n 'driver' => 'sqlite',"
                                 " 'database' => 'sites/default/files/.ht.sqlite',\n];\n")
        f = files._settings_text(self.settings, Path("s.php"), datetime(2030, 1, 1, tzinfo=timezone.utc))
        self.assertTrue(any("names an SQLite database next to mysql" in t for t in titles(f)), titles(f))

    def test_risky_code_but_not_in_comments(self):
        self.settings.write_text(MYSQL_SETTINGS + "if (isset($_GET['k'])) { eval(base64_decode($_GET['k'])); }\n")
        f = files._settings_text(self.settings, Path("s.php"), datetime(2030, 1, 1, tzinfo=timezone.utc))
        self.assertEqual(f[0].level, "high")
        self.assertIn("eval(", f[0].detail)
        self.assertIn("$_GET", f[0].detail)

    def test_recent_change_is_reported(self):
        os.utime(self.settings, None)
        f = files._settings_text(self.settings, Path("s.php"), files.DISCLOSED)
        self.assertEqual(f[0].level, "info")
        self.assertIn("changed on", f[0].title)

    def test_no_settings_at_all(self):
        self.settings.unlink()
        self.assertEqual(files.settings_findings(self.web, None, files.DISCLOSED)[0].level, "medium")


class Webroot(Base):
    def scan(self):
        return files.scan_webroot(self.web, files.configured_sqlite(self.web))

    def test_clean_tree(self):
        f = self.scan()
        self.assertEqual([x.level for x in f], ["ok"])

    def test_php_named_sqlite_database_is_critical(self):
        (self.web / "core" / "misc").mkdir()
        (self.web / "core" / "misc" / "cache.php").write_bytes(SQLITE_HEADER + b"<?php phpinfo(); ?>")
        f = self.scan()
        self.assertEqual(f[0].level, "critical")
        self.assertEqual(f[0].evidence, ["core/misc/cache.php"])

    def test_sites_own_sqlite_database_is_info(self):
        self.settings.write_text("<?php\n$databases['default']['default'] = ['driver' => 'sqlite', "
                                 "'database' => 'sites/default/files/.ht.sqlite'];\n")
        (self.web / "sites" / "default" / "files" / ".ht.sqlite").write_bytes(SQLITE_HEADER)
        f = self.scan()
        self.assertEqual([x.level for x in f], ["info", "ok"])

    def test_stray_database_is_medium(self):
        (self.web / "sites" / "default" / "files" / "backup.db").write_bytes(SQLITE_HEADER)
        self.assertEqual(self.scan()[0].level, "medium")

    def test_php_in_files_but_not_compiled_templates(self):
        files_dir = self.web / "sites" / "default" / "files"
        (files_dir / "php" / "twig" / "h").mkdir(parents=True)
        (files_dir / "php" / "twig" / "h" / "t.php").write_text("<?php // compiled twig")
        (files_dir / "2026-11").mkdir()
        (files_dir / "2026-11" / "avatar.phtml").write_text("<?php // not an avatar")
        f = self.scan()
        self.assertEqual(f[0].level, "high")
        self.assertEqual(f[0].evidence, ["sites/default/files/2026-11/avatar.phtml"])
        self.assertIn("1 compiled Twig templates", f[-1].detail)

    def test_custom_public_files_path(self):
        self.settings.write_text(MYSQL_SETTINGS + "$settings['file_public_path'] = 'uploads';\n")
        (self.web / "uploads").mkdir()
        (self.web / "uploads" / "x.php").write_text("<?php")
        self.assertEqual(self.scan()[0].evidence, ["uploads/x.php"])

    def test_skips_git_and_symlinks(self):
        (self.web / ".git").mkdir()
        (self.web / ".git" / "x.php").write_bytes(SQLITE_HEADER)
        target = Path(self.tmp.name) / "outside.php"
        target.write_bytes(SQLITE_HEADER)
        (self.web / "link.php").symlink_to(target)
        self.assertEqual(self.scan()[0].level, "ok")


class Blocks(Base):
    def test_nothing_visible(self):
        f = files.block_findings(self.site())
        self.assertEqual(f[0].level, "info")

    def test_removed_installer_without_composer_script(self):
        (self.web / "core" / "install.php").unlink()
        f = files.block_findings(self.site())
        self.assertEqual(f[0].level, "medium")
        self.assertIn("restart PHP-FPM", f[0].action)

    def test_removed_installer_with_composer_script(self):
        (self.web / "core" / "install.php").unlink()
        cj = json.loads((self.project / "composer.json").read_text())
        cj["scripts"] = {"post-install-cmd": ["rm -f web/core/install.php"], "post-update-cmd": ["rm -f web/core/install.php"]}
        (self.project / "composer.json").write_text(json.dumps(cj))
        self.assertEqual(files.block_findings(self.site())[0].level, "ok")

    def test_htaccess_block_without_scaffold_append(self):
        with (self.web / ".htaccess").open("a") as fh:
            fh.write('\n<Files "install.php">\n  Require all denied\n</Files>\n')
        f = files.block_findings(self.site())
        self.assertEqual(f[0].level, "medium")
        self.assertIn("ProxyPassMatch", f[0].action)

    def test_htaccess_block_with_scaffold_append(self):
        with (self.web / ".htaccess").open("a") as fh:
            fh.write('\n<Files "install.php">\n  Require all denied\n</Files>\n')
        cj = json.loads((self.project / "composer.json").read_text())
        cj["extra"] = {"drupal-scaffold": {"file-mapping": {"[web-root]/.htaccess": {"append": "assets/x.txt"}}}}
        (self.project / "composer.json").write_text(json.dumps(cj))
        self.assertEqual(files.block_findings(self.site())[0].level, "ok")


if __name__ == "__main__":
    unittest.main()
