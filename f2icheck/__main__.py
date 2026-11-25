"""Command line: python3 -m f2icheck <command> ...  (run `python3 -m f2icheck -h`)."""
from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import __version__, drupal, files, logs, state, web
from .report import Finding, exit_code, render_json, render_text

DEFAULT_SINCE = "2026-11-18"


def _since(text: str) -> datetime:
    t = datetime.fromisoformat(text.replace("Z", "+00:00"))
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="f2icheck", description="Read-only checks for Drupal's installer flaws "
                                "(SA-CORE-2026-017 / CVE-2026-132165 'Fail2Install', SA-CORE-2026-019 / "
                                "CVE-2026-136716) on a site you run.")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--json", action="store_true", help="print JSON instead of text")
    common.add_argument("--evidence", type=int, default=8, metavar="N", help="evidence lines per finding (0 = all)")
    common.add_argument("--since", default=DEFAULT_SINCE, help=f"report changes after this date/time, UTC "
                        f"(default {DEFAULT_SINCE}, the day SA-CORE-2026-017 came out)")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("version", parents=[common], help="is this Drupal core fixed?")
    s.add_argument("path", help="the project folder (with composer.json) or the web root")
    s = sub.add_parser("http", parents=[common], help="can anyone reach the installer? (5 GET requests)")
    s.add_argument("url", help="your site's address, e.g. https://www.example.com or https://example.com/drupal")
    s.add_argument("--timeout", type=float, default=15)
    s.add_argument("--cafile", help="CA bundle for a site with a private certificate")
    s = sub.add_parser("files", parents=[common], help="settings.php, stray databases, PHP in files/, installer blocks")
    s.add_argument("path")
    s.add_argument("--web-user", help="the user PHP runs as (default: the owner of Drupal's compiled templates)")
    s = sub.add_parser("logs", parents=[common], help="installer requests and failure bursts in access/error logs")
    s.add_argument("access", nargs="+", type=Path, help="access logs (combined/common format, .gz is fine)")
    s.add_argument("--errors", nargs="*", type=Path, default=[], help="error logs (PHP, PHP-FPM, Apache, Nginx)")
    s.add_argument("--base-path", default="", help="the site's path if it lives in a subdirectory, e.g. /drupal")
    s.add_argument("--burst", type=int, default=30, help="5xx answers per minute that count as a burst (default 30)")
    s = sub.add_parser("state", parents=[common], help="install_task, install_time and user 1, through Drush")
    s.add_argument("path")
    s.add_argument("--drush", help="path to drush (default: vendor/bin/drush, then PATH)")
    s.add_argument("--uri", help="the site's URI for multisite installs")
    s = sub.add_parser("all", parents=[common], help="everything that applies")
    s.add_argument("path")
    s.add_argument("--url", help="also run the http check against this address")
    s.add_argument("--log", nargs="*", type=Path, default=[], help="also hunt these access logs")
    s.add_argument("--errors", nargs="*", type=Path, default=[])
    s.add_argument("--base-path", default="")
    s.add_argument("--web-user")
    s.add_argument("--drush")
    s.add_argument("--uri")
    s.add_argument("--no-state", action="store_true", help="don't run Drush")
    return p


def run(argv: list[str] | None = None) -> tuple[list[Finding], argparse.Namespace]:
    a = _parser().parse_args(argv)
    since = _since(a.since)
    if a.cmd == "http":
        return web.check(a.url, a.timeout, a.cafile), a
    if a.cmd == "logs":
        return logs.check(a.access, a.errors, since, a.burst, base=a.base_path), a
    site = drupal.find(a.path)
    if a.cmd == "version":
        return drupal.check(site), a
    if a.cmd == "files":
        return files.check(site, a.web_user, since), a
    if a.cmd == "state":
        return state.check(site, a.drush, a.uri, since), a

    found = drupal.check(site)
    file_findings = files.check(site, a.web_user, since)
    found += file_findings
    reach: list[Finding] = []
    if a.url:
        reach = web.check(a.url)
        found += reach
    if a.log:
        found += logs.check(a.log, a.errors, since, base=a.base_path)
    tampered = [f for f in file_findings if f.title.endswith("never needs") or "PHP name" in f.title]
    if a.no_state:
        pass
    elif tampered:
        found.append(Finding("state", "high", "Drush was not run: settings.php looks tampered with",
                             "Drush runs settings.php, so any code added to it would run under your account.",
                             "Read settings.php and restore it from a known-good copy first."))
    else:
        found += state.check(site, a.drush, a.uri, since)
    exposed = any(f.check == "version" and f.level in ("critical", "high") for f in found)
    if exposed and any(f.level in ("critical", "high") for f in reach):
        found.append(Finding("all", "critical", "An affected version with a reachable installer",
                             "This is the combination the attacks since 19 November 2026 need.",
                             "Block /core/install.php in the web server now, then update and run `drush updatedb`."))
    return found, a


def main(argv: list[str] | None = None) -> int:
    try:
        found, a = run(argv)
    except (FileNotFoundError, ValueError) as e:
        print(f"f2icheck: {e}", file=sys.stderr)
        return 3
    print(render_json(found) if a.json else render_text(found, a.evidence))
    return exit_code(found)


if __name__ == "__main__":
    sys.exit(main())
