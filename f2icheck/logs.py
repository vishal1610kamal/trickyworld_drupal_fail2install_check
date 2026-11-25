"""Hunt web server logs for the traces Drupal's advisories and Searchlight Cyber's write-up point to.

Access logs (Apache/Nginx "combined" or "common", optionally with a leading vhost:port, plain or .gz):
  - every request for install.php, in any spelling, with who sent it and what the server answered;
  - PHP files outside Drupal's entry points that answered 200 (where a dropped file would show up);
  - minutes with many 5xx answers close to installer requests.
Error logs (PHP, PHP-FPM, Apache, Nginx, MySQL client errors): database and resource failures per minute. The
published attack needs the installer's database checks to fail on purpose, so a burst of these errors right before
installer requests is worth a look. Times are compared as each log's local time.
"""
from __future__ import annotations

import collections
import gzip
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import unquote, urlsplit

from .report import Finding

ACCESS = re.compile(r'^(?:\S+:\d+\s+)?(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<time>[^\]]+)\] "(?P<req>[^"]*)" '
                    r'(?P<status>\d{3}) (?P<size>\S+)(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?')
INSTALL = re.compile(r"(?:^|/)install\.php(?:$|/)", re.I)
PHP = re.compile(r"\.(?:php\d?|phtml|pht|phar)(?:$|/)", re.I)
# Drupal 8+ PHP entry points that may answer 200 to anyone or to logged-in users.
ENTRY_POINTS = {"/index.php", "/update.php", "/core/install.php", "/core/rebuild.php", "/core/authorize.php",
                "/core/modules/statistics/statistics.php", "/core/modules/system/tests/https.php",
                "/core/modules/system/tests/http.php"}
FAILURES = re.compile(r"too many connections|\[1040\]|cannot assign requested address|\[2002\]|too many open files|"
                      r"emfile|too many clients already|remaining connection slots are reserved|"
                      r"could not connect to server|server has gone away", re.I)
ERROR_TIMES = [
    (re.compile(r"\[(\w{3} \w{3} \d{2} \d{2}:\d{2}:\d{2})(?:\.\d+)? (\d{4})\]"), lambda m: datetime.strptime(
        f"{m.group(1)} {m.group(2)}", "%a %b %d %H:%M:%S %Y")),                                  # Apache error log
    (re.compile(r"\[(\d{2}-\w{3}-\d{4} \d{2}:\d{2}:\d{2})"), lambda m: datetime.strptime(m.group(1), "%d-%b-%Y %H:%M:%S")),
    (re.compile(r"^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})"), lambda m: datetime.strptime(m.group(1), "%Y/%m/%d %H:%M:%S")),
    (re.compile(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})"), lambda m: datetime.strptime(m.group(1).replace("T", " "),
                                                                                           "%Y-%m-%d %H:%M:%S")),
]


@dataclass
class Hit:
    time: datetime          # local time as logged, no time zone (compared with error logs)
    utc: datetime           # the same moment in UTC (compared with --since)
    ip: str
    method: str
    path: str               # as logged
    status: int
    ua: str


def _open(path: Path):
    return gzip.open(path, "rt", errors="replace") if path.suffix == ".gz" else path.open(errors="replace")


def norm(path: str) -> str:
    """Decode and normalise a request path the way a web server would before matching files."""
    p = unquote(urlsplit(path).path if "://" not in path else urlsplit(path).path)
    p = re.sub(r"/{2,}", "/", p)
    parts: list[str] = []
    for seg in p.split("/"):
        if seg == ".":
            continue
        if seg == "..":
            if parts:
                parts.pop()
            continue
        parts.append(seg)
    return "/".join(parts) or "/"


def read_access(paths: list[Path]) -> tuple[list[Hit], int]:
    hits, skipped = [], 0
    for path in paths:
        with _open(path) as fh:
            for line in fh:
                m = ACCESS.match(line)
                if not m:
                    skipped += 1
                    continue
                req = m.group("req").split()
                if len(req) < 2:
                    skipped += 1
                    continue
                try:
                    t = datetime.strptime(m.group("time"), "%d/%b/%Y:%H:%M:%S %z")
                except ValueError:
                    skipped += 1
                    continue
                hits.append(Hit(t.replace(tzinfo=None), t.astimezone(timezone.utc), m.group("ip"), req[0].upper(),
                                req[1], int(m.group("status")), m.group("ua") or ""))
    return hits, skipped


def read_errors(paths: list[Path]) -> collections.Counter:
    per_minute: collections.Counter[datetime | None] = collections.Counter()
    for path in paths:
        with _open(path) as fh:
            for line in fh:
                if not FAILURES.search(line):
                    continue
                when = None
                for rx, conv in ERROR_TIMES:
                    m = rx.search(line)
                    if m:
                        try:
                            when = conv(m).replace(second=0, microsecond=0)
                        except ValueError:
                            when = None
                        break
                per_minute[when] += 1
    return per_minute


def _fmt(h: Hit) -> str:
    return f"{h.time:%Y-%m-%d %H:%M:%S} {h.ip} {h.method} {h.path} -> {h.status}" + (f' "{h.ua[:60]}"' if h.ua else "")


def site_path(path: str, base: str) -> str:
    """The request path relative to the site's base path ("/drupal" for a site in a subdirectory)."""
    p = norm(path)
    base = "/" + base.strip("/") if base.strip("/") else ""
    return (p[len(base):] or "/") if base and (p == base or p.startswith(base + "/")) else p


def check(access: list[Path], errors: list[Path] | None = None, since: datetime | None = None,
          burst: int = 30, window: int = 5, base: str = "") -> list[Finding]:
    hits, skipped = read_access(access)
    recent = [h for h in hits if since is None or h.utc >= since]
    out: list[Finding] = []

    inst = [h for h in recent if INSTALL.search(site_path(h.path, base))]
    posts = [h for h in inst if h.method == "POST"]
    answered = [h for h in inst if h.method != "POST" and 200 <= h.status < 300]
    accepted_posts = [h for h in posts if h.status < 400]
    if accepted_posts:
        out.append(Finding("logs", "critical", f"{len(accepted_posts)} installer form submissions were accepted",
                           "POST requests to install.php got a 2xx/3xx answer. The installer's forms are how a "
                           "reinstall happens.", "Treat the site as possibly compromised: check user 1, settings.php "
                           "and the files listed by the files check, and keep these log lines.",
                           [_fmt(h) for h in accepted_posts]))
    if posts and not accepted_posts:
        out.append(Finding("logs", "high", f"{len(posts)} installer form submissions, all refused",
                           "Someone tried to submit the installer's forms; the server answered 4xx/5xx.",
                           "Keep blocking install.php, and check the IPs below against your other logs.",
                           [_fmt(h) for h in posts]))
    if answered:
        ips = collections.Counter(h.ip for h in answered)
        out.append(Finding("logs", "high", f"The installer answered {len(answered)} requests from {len(ips)} addresses",
                           "install.php was reachable: it answered with 2xx.", "Block it in the web server "
                           "configuration, then look at what these addresses did next.",
                           [_fmt(h) for h in answered]))
    blocked = [h for h in inst if h.method != "POST" and h.status >= 400]
    if blocked:
        out.append(Finding("logs", "info", f"{len(blocked)} installer requests were refused",
                           f"From {len(set(h.ip for h in blocked))} addresses.", "",
                           [_fmt(h) for h in blocked]))

    def entry(path: str) -> bool:
        m = re.match(r"(.*?\.php)(?:/|$)", path, re.I)
        return bool(m) and m.group(1).lower() in ENTRY_POINTS

    odd = [h for h in recent if 200 <= h.status < 300 and PHP.search(site_path(h.path, base))
           and not entry(site_path(h.path, base))]
    if odd:
        in_files = [h for h in odd if "/files/" in site_path(h.path, base)]
        out.append(Finding("logs", "critical" if in_files else "high",
                           f"{len(odd)} requests ran PHP files that are not Drupal entry points",
                           "Drupal only needs index.php, update.php and a few files in /core. Others answering 200 "
                           "are where a dropped file shows up" + (", and some are in a files folder." if in_files
                                                                   else "."),
                           "Look at each file on disk (as text) and at who requested it.", [_fmt(h) for h in odd]))

    per_minute = collections.Counter(h.time.replace(second=0) for h in recent if h.status >= 500)
    bursts = sorted(m for m, n in per_minute.items() if n >= burst)
    err_minutes = read_errors(errors) if errors else collections.Counter()
    err_bursts = sorted(m for m, n in err_minutes.items() if m is not None and n >= max(1, burst // 3))
    near = []
    for b in sorted(set(bursts) | set(err_bursts)):
        close = [h for h in inst if abs(h.time.replace(second=0) - b) <= timedelta(minutes=window)]
        if close:
            near.append(f"{b:%Y-%m-%d %H:%M}: {per_minute.get(b, 0)} 5xx answers, {err_minutes.get(b, 0)} database/"
                        f"resource errors, {len(close)} installer requests within {window} min")
    if near:
        out.append(Finding("logs", "high", "Failure bursts next to installer requests",
                           "The published attack makes the installer's database checks fail on purpose, then retries. "
                           "Floods of 5xx answers or connection errors around installer requests fit that pattern.",
                           "Compare with your monitoring for those minutes, and check the site for compromise.", near))
    elif bursts or err_bursts:
        out.append(Finding("logs", "info", f"{len(set(bursts) | set(err_bursts))} minutes with failure bursts, "
                           "none near installer requests", "", "",
                           [f"{b:%Y-%m-%d %H:%M}: {per_minute.get(b, 0)} 5xx, {err_minutes.get(b, 0)} errors"
                            for b in sorted(set(bursts) | set(err_bursts))]))

    span = f"{min(h.time for h in hits):%Y-%m-%d %H:%M} to {max(h.time for h in hits):%Y-%m-%d %H:%M}" if hits else "none"
    level = "ok" if not any(f.level in ("critical", "high") for f in out) else "info"
    out.append(Finding("logs", level, f"Read {len(hits)} requests ({span}), {len(recent)} since "
                       f"{since:%Y-%m-%d %H:%M} UTC" if since else f"Read {len(hits)} requests ({span})",
                       f"{skipped} lines were not in a format this tool reads." if skipped else "",
                       "" if hits else "Point --log at an access log in Apache/Nginx combined or common format."))
    return out
