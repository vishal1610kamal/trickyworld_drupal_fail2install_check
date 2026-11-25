"""What a Drupal site's files say: is settings.php protected, are there traces of a reinstall, and is the
installer blocked in a way that survives the next `composer install`. Files are read as text or bytes; nothing from
the site is executed.
"""
from __future__ import annotations

import collections
import grp
import json
import os
import pwd
import re
import stat
from datetime import datetime, timezone
from pathlib import Path

from .advisories import INSTALLER_DOC
from .drupal import Site
from .report import Finding

SQLITE_MAGIC = b"SQLite format 3\x00"
EXEC_EXT = {".php", ".php3", ".php4", ".php5", ".php7", ".php8", ".phtml", ".pht", ".phar", ".phps"}
SKIP_DIRS = {".git", "node_modules"}
DISCLOSED = datetime(2026, 11, 18, tzinfo=timezone.utc)      # SA-CORE-2026-017 day

_DB_ASSIGN = re.compile(r"""\$databases\s*\[\s*['"]default['"]\s*\]\s*\[\s*['"]default['"]\s*\]\s*=""")
_DB_BLOCK = re.compile(r"""\$databases\s*\[\s*['"]default['"]\s*\]\s*\[\s*['"]default['"]\s*\]\s*=\s*(?:array\s*\(|\[)
                       (.*?)(?:\)|\])\s*;""", re.S | re.X)
_DRIVER = re.compile(r"""['"]driver['"]\s*=>\s*['"]([a-z0-9_]+)['"]""", re.I)
_DATABASE = re.compile(r"""['"]database['"]\s*=>\s*['"]([^'"]+)['"]""")
_SALT = re.compile(r"""\$settings\s*\[\s*['"]hash_salt['"]\s*\]\s*=""")
_PUBLIC = re.compile(r"""\$settings\s*\[\s*['"]file_public_path['"]\s*\]\s*=\s*['"]([^'"]+)['"]""")
_RISKY = re.compile(r"""\b(eval|assert|base64_decode|gzinflate|gzuncompress|str_rot13|system|shell_exec|passthru|
                        popen|proc_open|pcntl_exec|create_function)\s*\(|`[^`\n]+`|\$_(GET|POST|REQUEST|COOKIE|FILES)\b""",
                    re.X)
_HTACCESS_BLOCK = re.compile(r"""<Files\s+"?install\.php"?\s*>\s*(?:#.*\n\s*)*Require\s+all\s+denied""", re.I)


def _strip_comments(php: str) -> str:
    php = re.sub(r"/\*.*?\*/", " ", php, flags=re.S)
    return re.sub(r"(?m)^\s*(#|//).*$", " ", php)


def _owner(uid: int) -> str:
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def _group(gid: int) -> str:
    try:
        return grp.getgrgid(gid).gr_name
    except KeyError:
        return str(gid)


def _user_groups(user: str) -> tuple[int, set[int]]:
    pw = pwd.getpwnam(user)
    gids = {pw.pw_gid} | {g.gr_gid for g in grp.getgrall() if user in g.gr_mem}
    return pw.pw_uid, gids


def _can(user: str | None, st: os.stat_result) -> tuple[bool, bool]:
    """(can write, can change permissions) for `user` on a file with stat `st`."""
    if user is None:
        return bool(st.st_mode & stat.S_IWOTH), False
    uid, gids = _user_groups(user)
    if uid == 0:
        return True, True
    owner = st.st_uid == uid
    write = (owner and st.st_mode & stat.S_IWUSR) or (st.st_gid in gids and st.st_mode & stat.S_IWGRP) \
        or st.st_mode & stat.S_IWOTH
    return bool(write), owner


def php_user(site_dirs: list[Path]) -> str | None:
    """Who PHP runs as, judged by who owns the Twig templates Drupal compiles at run time."""
    owners: collections.Counter[int] = collections.Counter()
    for d in site_dirs:
        storage = d / "files" / "php"
        if storage.is_dir():
            for p in storage.rglob("*.php"):
                owners[p.stat().st_uid] += 1
    return _owner(owners.most_common(1)[0][0]) if owners else None


def _site_dirs(web: Path) -> list[Path]:
    sites = web / "sites"
    return sorted(p for p in sites.iterdir() if p.is_dir() and (p / "settings.php").is_file()) if sites.is_dir() else []


def settings_findings(web: Path, web_user: str | None, since: datetime) -> list[Finding]:
    out: list[Finding] = []
    dirs = _site_dirs(web)
    if not dirs:
        return [Finding("files", "medium", "No sites/*/settings.php found", f"Looked under {web / 'sites'}.")]
    guessed = php_user(dirs)
    user = web_user or guessed
    for d in dirs:
        sp = d / "settings.php"
        rel = sp.relative_to(web)
        st = sp.stat()
        mode = stat.filemode(st.st_mode)
        who = f"{rel}: {mode} {_owner(st.st_uid)}:{_group(st.st_gid)}"
        how = f"--web-user {web_user}" if web_user else (f"PHP runs as {guessed} (it owns the Twig templates "
                                                         "Drupal compiled)" if guessed else "no web user given")
        if user is not None:
            try:
                write, chmod = _can(user, st)
            except KeyError:
                write, chmod = _can(None, st)
                how += f"; user {user} doesn't exist here"
        else:
            write, chmod = _can(None, st)
        if write or chmod:
            out.append(Finding("files", "high", f"PHP can make {rel} writable or rewrite it",
                               f"{who}. {how}: it can {'write to' if write else 'change the permissions of'} the file.",
                               "SA-CORE-2026-017: some exploit paths are blocked only when the web server can't write "
                               "to settings.php or change its permissions. A read-only mode doesn't stop the file's "
                               "owner: make another user own it (for example your deploy user), mode 444 or 440, "
                               "with PHP able only to read it.", [who]))
        else:
            out.append(Finding("files", "ok" if user else "info",
                               f"{rel} is not writable by {'PHP' if user else 'everyone'}", f"{who}. {how}."
                               + ("" if user else " Pass --web-user to check the PHP user."), ""))
        dst = d.stat()
        if user is not None:
            try:
                dwrite, dchmod = _can(user, dst)
            except KeyError:
                dwrite = dchmod = False
            if dwrite or dchmod:
                verb = "write to" if dwrite else "change the permissions of"
                out.append(Finding("files", "medium", f"PHP can {verb} the {d.relative_to(web)} folder",
                                   f"{d.relative_to(web)}: {stat.filemode(dst.st_mode)} {_owner(dst.st_uid)}",
                                   "Drupal's status report asks for this folder to be read-only too: a folder PHP can "
                                   "write to, or make writable, lets it replace settings.php with a new file."))
        out += _settings_text(sp, rel, since)
    return out


def db_blocks(code: str) -> list[tuple[str | None, str | None]]:
    """(driver, database) for each $databases['default']['default'] block, in file order."""
    out = []
    for block in _DB_BLOCK.findall(code):
        d, db = _DRIVER.search(block), _DATABASE.search(block)
        out.append((d.group(1).lower() if d else None, db.group(1) if db else None))
    return out


def _settings_text(sp: Path, rel: Path, since: datetime) -> list[Finding]:
    out: list[Finding] = []
    code = _strip_comments(sp.read_text(errors="replace"))
    assigns = len(_DB_ASSIGN.findall(code))
    blocks = db_blocks(code)
    drivers = sorted({d for d, _ in blocks if d})
    salts = len(_SALT.findall(code))
    if assigns > 1 or salts > 1:
        out.append(Finding("files", "medium", f"{rel} sets the database or hash salt more than once",
                           f"$databases['default']['default'] assigned {assigns} times, hash_salt {salts} times.",
                           "The installer appends a new block when it runs. If you didn't write both blocks, compare "
                           "the file with a backup: the last one wins."))
    sqlite = [db or "?" for d, db in blocks if d == "sqlite"]
    bad = [db for db in sqlite if Path(db).suffix.lower() in EXEC_EXT]
    if bad:
        out.append(Finding("files", "critical", f"{rel} points Drupal at an SQLite database with a PHP name",
                           ", ".join(bad), "This is the shape of the published Fail2Install chain. Treat the site "
                           "as compromised: see 'Your Drupal site got hacked. Now what?' on drupal.org."))
    elif sqlite and len(drivers) > 1:
        others = ", ".join(d for d in drivers if d != "sqlite")
        out.append(Finding("files", "high", f"{rel} names an SQLite database next to {others}",
                           f"SQLite database: {', '.join(sqlite)}.",
                           "A reinstall writes new database settings into settings.php. If your site never used "
                           "SQLite, find out who added it."))
    risky = sorted({m.group(0).strip()[:40] for m in _RISKY.finditer(code)})
    if risky:
        out.append(Finding("files", "high", f"{rel} contains code settings.php never needs",
                           ", ".join(risky), "Read the file (don't run drush or any PHP on the site until you have): "
                           "attackers who reach settings.php often add code there, and every Drupal request and "
                           "drush command runs it."))
    mtime = datetime.fromtimestamp(sp.stat().st_mtime, timezone.utc)
    if mtime >= since:
        out.append(Finding("files", "info", f"{rel} changed on {mtime:%Y-%m-%d %H:%M} UTC",
                           f"That is after {since:%Y-%m-%d}.", "If nobody on your team changed it then, compare it "
                           "with your backup or your repository."))
    return out


def scan_webroot(web: Path, configured_dbs: set[str]) -> list[Finding]:
    """SQLite databases anywhere in the web root, and PHP files where only uploads belong."""
    disguised, stray, own, php_in_files, compiled = [], [], [], [], 0
    files_dirs = [d / "files" for d in _site_dirs(web) if (d / "files").is_dir()]
    for d in _site_dirs(web):
        m = _PUBLIC.search(_strip_comments((d / "settings.php").read_text(errors="replace")))
        if m and (web / m.group(1)).is_dir():
            files_dirs.append((web / m.group(1)).resolve())
    in_files = tuple(str(fd.resolve()) + os.sep for fd in files_dirs)
    in_storage = tuple(str((fd / "php").resolve()) + os.sep for fd in files_dirs)
    scanned = 0
    for root, dirs, names in os.walk(web):
        dirs[:] = [x for x in dirs if x not in SKIP_DIRS]
        for n in names:
            p = Path(root) / n
            try:
                if not p.is_file() or p.is_symlink():
                    continue
                with p.open("rb") as fh:
                    head = fh.read(16)
            except OSError:
                continue
            scanned += 1
            rel = str(p.relative_to(web))
            ext = p.suffix.lower()
            if head == SQLITE_MAGIC:
                if ext in EXEC_EXT:
                    disguised.append(rel)
                elif str(p.resolve()) in configured_dbs:
                    own.append(rel)
                else:
                    stray.append(rel)
            if ext in EXEC_EXT and str(p).startswith(in_files):
                if str(p).startswith(in_storage):
                    compiled += 1
                else:
                    php_in_files.append(rel)
    out: list[Finding] = []
    if disguised:
        out.append(Finding("files", "critical", "A file with a PHP name is really an SQLite database",
                           "The published Fail2Install chain ends with exactly this: the installer creates an SQLite "
                           "database under a .php name, with attacker text inside, so the web server runs it.",
                           "Don't delete it yet (it's evidence): copy it off the server, block the installer, then "
                           "follow 'Your Drupal site got hacked. Now what?' on drupal.org.", disguised))
    if php_in_files:
        out.append(Finding("files", "high", "PHP files in the public files folder",
                           "Uploads never need to be PHP, and Drupal's own compiled templates (files/php/) are "
                           "left out of this list.", "Open each one as text. Unknown PHP here is the most common "
                           "web shell location.", php_in_files))
    if stray:
        out.append(Finding("files", "medium", "SQLite database files inside the web root",
                           "Your settings.php doesn't name these.", "Move databases out of the web root, and find out "
                           "where these came from.", stray))
    if own:
        out.append(Finding("files", "info", "The site's own SQLite database is inside the web root",
                           "Drupal's .htaccess hides it on Apache; on Nginx, deny it in the server block.", "", own))
    out.append(Finding("files", "ok" if not (disguised or php_in_files or stray) else "info",
                       f"Scanned {scanned} files in the web root", f"{compiled} compiled Twig templates (expected).", ""))
    return out


def configured_sqlite(web: Path) -> set[str]:
    out = set()
    for d in _site_dirs(web):
        code = _strip_comments((d / "settings.php").read_text(errors="replace"))
        for driver, db in db_blocks(code):
            if driver == "sqlite" and db:
                q = Path(db) if Path(db).is_absolute() else web / db
                out.add(str(q.resolve()))
    return out


def block_findings(site: Site) -> list[Finding]:
    """Is the installer blocked in a way this folder can show, and will the block survive Composer?"""
    out: list[Finding] = []
    web, project = site.webroot, site.project
    composer = {}
    if (project / "composer.json").is_file():
        try:
            composer = json.loads((project / "composer.json").read_text())
        except json.JSONDecodeError:
            composer = {}
    scripts = json.dumps(composer.get("scripts", {}))
    mapping = composer.get("extra", {}).get("drupal-scaffold", {}).get("file-mapping", {})
    appended = any("htaccess" in k and isinstance(v, dict) and ("append" in v or "prepend" in v)
                   for k, v in mapping.items())
    installer = web / "core" / "install.php"
    htaccess = web / ".htaccess"
    blocked_in_htaccess = htaccess.is_file() and bool(_HTACCESS_BLOCK.search(htaccess.read_text(errors="replace")))
    if not installer.exists():
        persistent = "install.php" in scripts
        out.append(Finding("files", "ok" if persistent else "medium", "core/install.php has been removed",
                           "Composer restores it on every install or update" + (", and composer.json removes it again."
                                                                              if persistent else "."),
                           "" if persistent else "Add the removal to composer.json's post-install-cmd and "
                           "post-update-cmd scripts. After removing it on PHP-FPM, restart PHP-FPM: with "
                           "opcache.validate_timestamps=0 the deleted file kept answering in our tests."))
    if blocked_in_htaccess:
        out.append(Finding("files", "ok" if appended else "medium", ".htaccess blocks install.php",
                           "" if appended else "But .htaccess is a scaffold file: `composer install` rewrites it and "
                           "the block disappears.",
                           "Works only where Apache reads .htaccess for PHP requests: not on Nginx, and not when "
                           "Apache passes PHP to PHP-FPM with ProxyPassMatch (it answered 200 in our tests). "
                           + ("" if appended else "Keep the lines in a file appended by the drupal-scaffold "
                              "file-mapping in composer.json.")))
    if installer.exists() and not blocked_in_htaccess:
        out.append(Finding("files", "info", "No installer block in .htaccess or the file system",
                           "A block in the web server configuration (Drupal's recommended option) can't be seen from "
                           "here.", f"Run the http check against the live site to test it ({INSTALLER_DOC})."))
    return out


def check(site: Site, web_user: str | None = None, since: datetime = DISCLOSED) -> list[Finding]:
    return (settings_findings(site.webroot, web_user, since) + scan_webroot(site.webroot, configured_sqlite(site.webroot))
            + block_findings(site))
