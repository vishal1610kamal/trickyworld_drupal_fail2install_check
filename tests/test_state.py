import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from f2icheck import drupal, state
from tests.helpers import fake_drush, make_site

OLD = int(datetime(2024, 3, 1, tzinfo=timezone.utc).timestamp())
NEW = int(datetime(2026, 11, 20, 4, 0, tzinfo=timezone.utc).timestamp())
USER = {"uid": "1", "name": "admin", "mail": "web@example.com", "user_created": str(OLD), "user_login": str(NEW),
        "user_status": "1", "roles": ["authenticated", "administrator"]}


class State(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        project, _ = make_site(self.root)
        self.site = drupal.find(project)
        self.bin = self.root / "bin"
        self.bin.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def run_with(self, **answers):
        a = {"install_task": "done", "install_time": OLD, "pending": None, "user": USER}
        a.update(answers)
        return state.check(self.site, str(fake_drush(self.bin, a)))

    def test_healthy_site(self):
        f = self.run_with()
        self.assertEqual([x.level for x in f], ["ok", "info", "info"])
        self.assertIn("mail: web@example.com", f[-1].evidence)
        self.assertIn("make sure this email address is yours", f[-1].detail)

    def test_incomplete_install_state(self):
        f = self.run_with(install_task="install_configure_form")
        self.assertEqual(f[0].level, "high")
        self.assertIn("'install_configure_form'", f[0].title)

    def test_empty_install_task(self):
        self.assertEqual(self.run_with(install_task=None)[0].title, "install_task is '', not 'done'")

    def test_pending_hook(self):
        # The row shape Drush 13.8 prints (UpdateDBCommands::getUpdatedbStatus).
        pending = {"system-post-mark_installation_finished": {
            "module": "system", "update_id": "mark_installation_finished", "type": "post-update",
            "description": "Mark the installation as finished on sites with incomplete install state."}}
        f = self.run_with(pending=pending)
        self.assertIn("The SA-CORE-2026-019 update hook has not run yet", [x.title for x in f])
        other = {"node-post-x": {"module": "node", "update_id": "x", "type": "post-update", "description": "y"}}
        self.assertNotIn("The SA-CORE-2026-019 update hook has not run yet", [x.title for x in self.run_with(pending=other)])

    def test_hook_pending_parser(self):
        self.assertFalse(state.hook_pending(""))
        self.assertFalse(state.hook_pending("[]"))
        self.assertTrue(state.hook_pending('[{"module": "system", "update_id": "mark_installation_finished"}]'))
        self.assertTrue(state.hook_pending("garbled mark_installation_finished"))

    def test_missing_and_recent_install_time(self):
        self.assertIn("install_time is not set", [x.title for x in self.run_with(install_time=None)])
        f = self.run_with(install_time=NEW)
        self.assertEqual(f[1].level, "medium")
        self.assertIn("2026-11-20 04:00 UTC", f[1].title)

    def test_user1_created_after_disclosure(self):
        f = self.run_with(user=dict(USER, user_created=str(NEW)))
        self.assertEqual(f[-1].level, "high")

    def test_user1_missing(self):
        self.assertEqual(self.run_with(user=None)[-1].title, "User 1 not found")

    def test_never_asks_for_the_password_hash(self):
        self.run_with()
        calls = [json.loads(l) for l in (self.bin / "calls.log").read_text().splitlines()]
        fields = [a for c in calls for a in c if a.startswith("--fields=")]
        self.assertEqual(fields, [f"--fields={state.USER_FIELDS}"])
        self.assertTrue(all(c[0] == f"--root={self.site.webroot}" for c in calls))

    def test_drush_failure(self):
        f = state.check(self.site, str(fake_drush(self.bin, {}, fail=True)))
        self.assertEqual(f[0].level, "medium")
        self.assertIn("unable to query", f[0].detail)

    def test_no_drush_anywhere(self):
        f = state.check(self.site, str(self.root / "missing-drush"))
        self.assertEqual(f[0].title, "Could not read the install state with Drush")


if __name__ == "__main__":
    unittest.main()
