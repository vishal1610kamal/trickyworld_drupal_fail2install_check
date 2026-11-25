import contextlib
import io
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from f2icheck.__main__ import main
from tests.helpers import FakeSite, fake_drush, make_site
from tests.test_web import ALREADY, install_routes

OLD = int(datetime(2024, 3, 1, tzinfo=timezone.utc).timestamp())
ANSWERS = {"install_task": "done", "install_time": OLD, "pending": None,
           "user": {"uid": "1", "name": "admin", "mail": "web@example.com", "user_created": str(OLD),
                    "user_login": "0", "user_status": "1", "roles": ["administrator"]}}


def run(args):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = main(args)
    return code, buf.getvalue()


class Cli(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_version_exit_codes(self):
        for version, expected in (("11.4.14", 0), ("11.4.13", 1), ("11.4.12", 2)):
            project, _ = make_site(self.root / version, version)
            code, out = run(["version", str(project)])
            self.assertEqual(code, expected, out)

    def test_json(self):
        project, _ = make_site(self.root, "10.6.22")
        code, out = run(["version", str(project), "--json"])
        data = json.loads(out)
        self.assertEqual(data["worst"], "high")
        self.assertEqual(data["findings"][0]["check"], "version")

    def test_missing_site(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(["version", str(self.root)]), 3)

    def test_all_combines_version_and_reachable_installer(self):
        project, _ = make_site(self.root, "11.4.12")
        drush = fake_drush(self.root, ANSWERS)
        with FakeSite(install_routes(200, ALREADY)) as s:
            code, out = run(["all", str(project), "--url", s.url, "--drush", str(drush), "--web-user", "nobody"])
        self.assertEqual(code, 2)
        self.assertIn("[CRITICAL] all: An affected version with a reachable installer", out)
        self.assertIn("[OK] state: install_task is 'done'", out)

    def test_all_skips_drush_when_settings_look_tampered(self):
        project, web = make_site(self.root, "11.4.14")
        settings = web / "sites" / "default" / "settings.php"
        settings.write_text(settings.read_text() + "eval($_POST['x']);\n")
        drush = fake_drush(self.root, ANSWERS)
        code, out = run(["all", str(project), "--drush", str(drush)])
        self.assertIn("Drush was not run: settings.php looks tampered with", out)
        self.assertFalse((self.root / "calls.log").exists())

    def test_since_option(self):
        project, _ = make_site(self.root, "11.4.14")
        code, out = run(["files", str(project), "--since", "2030-01-01T00:00:00Z", "--web-user", "nobody"])
        self.assertNotIn("changed on", out)

    def test_logs_command(self):
        log = self.root / "access.log"
        log.write_text('198.51.100.4 - - [19/Nov/2026:19:00:05 +0000] "POST /core/install.php HTTP/1.1" 303 0 "-" "x"\n')
        code, out = run(["logs", str(log)])
        self.assertEqual(code, 2)
        self.assertIn("installer form submissions were accepted", out)


if __name__ == "__main__":
    unittest.main()
