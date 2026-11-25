"""Builders for fake Drupal sites, a local web server and a fake Drush."""
from __future__ import annotations

import json
import os
import stat
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

SQLITE_HEADER = b"SQLite format 3\x00" + b"\x10\x00\x01\x01" + b"\x00" * 76

MYSQL_SETTINGS = """<?php
/**
 * Example from default.settings.php, which must be ignored:
 *   $databases['default']['default'] = ['driver' => 'sqlite', 'database' => 'x.php'];
 *   eval($_GET['x']);
 */
# $databases['default']['default'] = ['driver' => 'pgsql'];
$settings['hash_salt'] = 'abc';
$databases['default']['default'] = array (
  'database' => 'drupal',
  'username' => 'drupal',
  'password' => 'secret',
  'host' => '127.0.0.1',
  'port' => 3306,
  'driver' => 'mysql',
  'namespace' => 'Drupal\\\\mysql\\\\Driver\\\\Database\\\\mysql',
  'init_commands' => ['isolation_level' => 'SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED'],
);
$settings['config_sync_directory'] = 'sites/default/files/config_x/sync';
"""


def make_site(root: Path, version: str = "11.4.14", layout: str = "composer", lock: str | None = "same",
              settings: str = MYSQL_SETTINGS, d7: bool = False) -> tuple[Path, Path]:
    """Return (project, webroot) of a fake site under root."""
    project = root / "project"
    web = project / {"composer": "web", "flat": "", "docroot": "docroot"}[layout] if layout != "flat" else project
    if d7:
        (web / "includes").mkdir(parents=True)
        (web / "includes" / "bootstrap.inc").write_text(f"<?php\ndefine('VERSION', '{version}');\n")
    else:
        (web / "core" / "lib").mkdir(parents=True)
        (web / "core" / "lib" / "Drupal.php").write_text(
            "<?php\nnamespace Drupal;\nclass Drupal {\n  const VERSION = '" + version + "';\n}\n")
        (web / "core" / "install.php").write_text("<?php // the installer\n")
    (web / "sites" / "default" / "files").mkdir(parents=True)
    (web / "sites" / "default" / "settings.php").write_text(settings)
    (web / "index.php").write_text("<?php // front controller\n")
    (web / ".htaccess").write_text("# stock Drupal rules\nRewriteEngine on\n")
    if layout in ("composer", "docroot"):
        (project / "composer.json").write_text(json.dumps({"name": "x/y", "require": {"drupal/core-recommended": "^11.4"}}))
    if lock:
        v = version if lock == "same" else lock
        (project / "composer.lock").write_text(json.dumps({"packages": [{"name": "drupal/core", "version": v},
                                                                        {"name": "twig/twig", "version": "v3.31.1"}]}))
    return project, web


def chmod(path: Path, mode: int) -> None:
    os.chmod(path, mode)


def current_user() -> str:
    import pwd
    return pwd.getpwuid(os.getuid()).pw_name


class FakeSite:
    """A tiny web server: routes maps a raw request path to (status, body, headers). Records raw paths."""

    def __init__(self, routes: dict[str, tuple[int, str, dict]] | None = None, default=(404, "Not Found", {})):
        self.routes = routes or {}
        self.default = default
        self.seen: list[str] = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                outer.seen.append(self.path)
                status, body, headers = outer.routes.get(self.path, outer.default)
                data = body.encode()
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *a):
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *a):
        self.httpd.shutdown()
        self.httpd.server_close()


def fake_drush(folder: Path, answers: dict, fail: bool = False) -> Path:
    """An executable that answers like Drush 13 for the four commands state.py runs, and logs its arguments."""
    script = folder / "drush"
    (folder / "answers.json").write_text(json.dumps(answers))
    script.write_text(f"""#!{sys.executable}
import json, sys, pathlib
here = pathlib.Path(__file__).parent
args = [a for a in sys.argv[1:] if not a.startswith(("--root=", "--uri="))]
with open(here / "calls.log", "a") as f:
    f.write(json.dumps(sys.argv[1:]) + "\\n")
if {fail!r}:
    print("Drush was unable to query the database.", file=sys.stderr); sys.exit(1)
a = json.load(open(here / "answers.json"))
cmd = args[0]
if cmd == "state:get":
    v = a.get(args[1])
    print("" if v is None else v)
elif cmd == "updatedb:status":
    print(json.dumps(a["pending"]) if a.get("pending") else "")
elif cmd == "user:information":
    assert any(x.startswith("--fields=") and "pass" not in x for x in args), "fields must exclude the hash"
    print(json.dumps({{"1": a["user"]}}) if a.get("user") else "")
""")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return script
