"""Find a Drupal site on disk and read its core version, without running any of its code."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from .advisories import assess
from .report import Finding

WEB_DIRS = ("", "web", "docroot", "html", "public", "public_html")
_D8 = re.compile(r"""const\s+VERSION\s*=\s*['"]([^'"]+)['"]""")
_D7 = re.compile(r"""define\(\s*['"]VERSION['"]\s*,\s*['"]([^'"]+)['"]""")


@dataclass
class Site:
    project: Path          # where composer.json / composer.lock live (may equal webroot)
    webroot: Path          # the folder that holds index.php
    core_version: str | None
    lock_version: str | None


def find(path: str | Path) -> Site:
    """Accept a project folder (with web/, docroot/ ...) or the web root itself."""
    base = Path(path).resolve()
    for sub in WEB_DIRS:
        web = base / sub if sub else base
        d8 = web / "core" / "lib" / "Drupal.php"
        d7 = web / "includes" / "bootstrap.inc"
        if d8.is_file() or d7.is_file():
            text = (d8 if d8.is_file() else d7).read_text(errors="replace")
            m = (_D8 if d8.is_file() else _D7).search(text)
            project = base if (base / "composer.json").is_file() else (web if (web / "composer.json").is_file() else base)
            return Site(project, web, m.group(1) if m else None, lock_version(project))
    raise FileNotFoundError(f"no Drupal core under {base} (looked in {', '.join(s or '.' for s in WEB_DIRS)})")


def lock_version(project: Path) -> str | None:
    lock = project / "composer.lock"
    if not lock.is_file():
        return None
    try:
        data = json.loads(lock.read_text())
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    for pkg in data.get("packages", []):
        if pkg.get("name") == "drupal/core":
            return str(pkg.get("version", "")).lstrip("v") or None
    return None


def check(site: Site) -> list[Finding]:
    out: list[Finding] = []
    version = site.core_version or site.lock_version
    if not version:
        return [Finding("version", "high", "Could not read the Drupal core version",
                        f"Neither core/lib/Drupal.php nor composer.lock under {site.project} gave a version.",
                        "Run `drush status --field=drupal-version` and compare it with SA-CORE-2026-019.")]
    a = assess(version)
    evidence = [f"core/lib/Drupal.php: {site.core_version or 'not found'}",
                f"composer.lock drupal/core: {site.lock_version or 'not found'}"]
    out.append(Finding("version", a.level, a.title, f"Still exposed to: {', '.join(a.advisories)}" if a.advisories
                       else "", a.action, evidence))
    if site.core_version and site.lock_version and site.core_version != site.lock_version:
        out.append(Finding("version", "high", "The code on disk and composer.lock disagree",
                           f"Drupal.php says {site.core_version}, composer.lock says {site.lock_version}.",
                           "A deploy did not finish, or files were copied over by hand. The files on disk are what "
                           "runs: run `composer install` and check the version again."))
    return out
