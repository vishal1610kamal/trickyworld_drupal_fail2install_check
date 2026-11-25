"""The install state SA-CORE-2026-019 is about, and user 1, read through Drush.

SA-CORE-2026-019 says sites "in unusual or incomplete install states" stayed open to takeover after the first fix,
and that the UI doesn't show it. Its fix adds system_post_update_mark_installation_finished(), which sets the state
value install_task to "done" and fills in install_time when it is missing. Drupal's installer sets install_time
when an installation finishes, and creates user 1, so both dates also tell you when the site was (re)installed.

Drush bootstraps the site, which runs settings.php: read settings.php first if you suspect it was changed (the
files check does that, and `all` skips this check when settings.php looks tampered with).
"""
from __future__ import annotations

import json
import shutil
import subprocess
from datetime import datetime, timezone

from .drupal import Site
from .report import Finding

HOOK = "system_post_update_mark_installation_finished"
HOOK_ROW = ("system", "mark_installation_finished")     # how `drush updatedb:status` lists it (module, update_id)
USER_FIELDS = "uid,name,mail,user_created,user_login,user_status,roles"     # never the password hash


class DrushError(RuntimeError):
    pass


def find_drush(site: Site, explicit: str | None = None) -> str:
    if explicit:
        return explicit
    local = site.project / "vendor" / "bin" / "drush"
    if local.exists():
        return str(local)
    found = shutil.which("drush")
    if not found:
        raise DrushError("Drush not found: pass --drush /path/to/drush")
    return found


def drush(cmd: list[str], site: Site, binary: str, uri: str | None = None, timeout: int = 120) -> str:
    args = [binary, f"--root={site.webroot}"] + ([f"--uri={uri}"] if uri else []) + cmd
    r = subprocess.run(args, cwd=site.project, capture_output=True, text=True, timeout=timeout)
    if r.returncode != 0:
        raise DrushError(f"`{' '.join(['drush'] + cmd)}` failed: {(r.stderr or r.stdout).strip()[:300]}")
    return r.stdout.strip()


def hook_pending(raw: str) -> bool:
    """Is the SA-CORE-2026-019 post-update in `drush updatedb:status --format=json` output? Empty = nothing pending."""
    try:
        rows = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        return HOOK_ROW[1] in raw
    rows = rows.values() if isinstance(rows, dict) else rows
    return any(isinstance(r, dict) and (r.get("module"), r.get("update_id")) == HOOK_ROW for r in rows)


def _when(ts: int) -> datetime:
    return datetime.fromtimestamp(ts, timezone.utc)


def check(site: Site, binary: str | None = None, uri: str | None = None, since: datetime | None = None) -> list[Finding]:
    since = since or datetime(2026, 11, 18, tzinfo=timezone.utc)
    try:
        bin_ = find_drush(site, binary)
        task = drush(["state:get", "install_task"], site, bin_, uri)
        raw_time = drush(["state:get", "install_time"], site, bin_, uri)
        pending = drush(["updatedb:status", "--format=json"], site, bin_, uri)
        users = drush(["user:information", "--uid=1", "--format=json", f"--fields={USER_FIELDS}"], site, bin_, uri)
    except (DrushError, OSError, subprocess.TimeoutExpired) as e:
        return [Finding("state", "medium", "Could not read the install state with Drush", str(e),
                        "Run the queries in the README against the database instead (read-only SQL).")]
    out: list[Finding] = []
    if task == "done":
        out.append(Finding("state", "ok", "install_task is 'done'", "", ""))
    else:
        out.append(Finding("state", "high", f"install_task is {task!r}, not 'done'",
                           "The installer treats the site as not fully installed: the state SA-CORE-2026-019 warns "
                           "about.", "Update to 11.4.14 / 11.3.23 / 10.6.23, run `drush updatedb`, block "
                           "install.php, and check user 1. Note the value first: the update overwrites it."))
    if hook_pending(pending):
        out.append(Finding("state", "high", "The SA-CORE-2026-019 update hook has not run yet",
                           f"`drush updatedb:status` lists {HOOK}.",
                           "Record install_task and install_time, back up the database, then run `drush updatedb`."))
    try:
        installed = _when(int(raw_time))
    except ValueError:
        installed = None
    if installed is None:
        out.append(Finding("state", "medium", "install_time is not set",
                           "Drupal sets it when an installation finishes; the SA-CORE-2026-019 update fills it in.",
                           "Update and run `drush updatedb`."))
    elif installed >= since:
        out.append(Finding("state", "medium", f"install_time is {installed:%Y-%m-%d %H:%M} UTC",
                           "Drupal records it when an installation finishes. A date after the flaw went public means "
                           "the site was installed or reinstalled then, or that the SA-CORE-2026-019 update filled in "
                           "a missing value when you ran it.", "If neither explains it, treat the site as possibly "
                           "reinstalled by someone else."))
    else:
        out.append(Finding("state", "info", f"install_time is {installed:%Y-%m-%d %H:%M} UTC", "", ""))
    try:
        u = next(iter(json.loads(users or "{}").values()))
    except (StopIteration, json.JSONDecodeError, AttributeError):
        u = None
    if not u:
        out.append(Finding("state", "high", "User 1 not found", "Drupal's first account is missing.",
                           "Find out when and how it was removed."))
        return out
    created = _when(int(u.get("user_created") or 0))
    login = int(u.get("user_login") or 0)
    lines = [f"name: {u.get('name')}", f"mail: {u.get('mail')}", f"created: {created:%Y-%m-%d %H:%M} UTC",
             f"last login: {_when(login):%Y-%m-%d %H:%M} UTC" if login else "last login: never",
             f"roles: {', '.join(u.get('roles') or [])}"]
    if created >= since:
        out.append(Finding("state", "high", "User 1 was created after the flaw went public",
                           "A reinstall creates a new user 1 with the attacker's name, email and password.",
                           "Unless you installed this site then, treat it as compromised.", lines))
    else:
        out.append(Finding("state", "info", "User 1",
                           "SA-CORE-2026-019 asks you to make sure this email address is yours, and to consider "
                           "resetting the password.", "Compare with what you expect; reset the password if unsure.",
                           lines))
    return out
