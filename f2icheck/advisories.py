"""What Drupal's November 2026 installer advisories say about a given core version.

Sources (read 25-26 November 2026):
  SA-CORE-2026-017, CVE-2026-132165, published 18 Nov 2026: https://www.drupal.org/sa-core-2026-017
      affected: <10.6.22 || >=11.0.0 <11.3.22 || >=11.4.0 <11.4.13
  SA-CORE-2026-019, CVE-2026-136716, published 25 Nov 2026: https://www.drupal.org/sa-core-2026-019
      affected: <10.6.23 || >= 11.0.0 <11.3.23 || >=11.4.0 <11.4.14  (needs update.php / drush updatedb too)
  Drupal 7 and Drupal 8 before 8.9 keep trusting settings.php when the database check fails, so Searchlight Cyber
  found them not affected by CVE-2026-132165:
      https://www.slcyber.io/research/fail2install-system-limits-pre-auth-rce-drupal
  Support windows: PSA-2026-11-02 (10.6 and 11.3 until December 2026, 11.4 until April 2027).
"""
from __future__ import annotations

import re
from dataclasses import dataclass

SA017 = {"id": "SA-CORE-2026-017", "cve": "CVE-2026-132165", "url": "https://www.drupal.org/sa-core-2026-017",
         "fixed": {(10, 6): 22, (11, 3): 22, (11, 4): 13}}
SA019 = {"id": "SA-CORE-2026-019", "cve": "CVE-2026-136716", "url": "https://www.drupal.org/sa-core-2026-019",
         "fixed": {(10, 6): 23, (11, 3): 23, (11, 4): 14}}
SUPPORTED_UNTIL = {(10, 6): "December 2026", (11, 3): "December 2026", (11, 4): "April 2027"}
INSTALLER_DOC = ("https://www.drupal.org/docs/administering-a-drupal-site/security-in-drupal/"
                 "securing-the-installer-installphp")

_VERSION = re.compile(r"^v?(\d+)\.(\d+)(?:\.(\d+|x))?(?:-?([0-9A-Za-z.+-]+))?$")


@dataclass(frozen=True)
class Version:
    major: int
    minor: int
    patch: int | None      # None for "11.4.x-dev" and for two-part Drupal 7 versions
    pre: str | None        # "beta1", "rc2", "dev", "x-dev", ...

    @property
    def branch(self) -> tuple[int, int]:
        return self.major, self.minor

    def __str__(self) -> str:
        s = f"{self.major}.{self.minor}"
        if self.patch is not None:
            s += f".{self.patch}"
        return s + (f"-{self.pre}" if self.pre else "")


def parse(text: str) -> Version:
    m = _VERSION.match(text.strip())
    if not m:
        raise ValueError(f"not a Drupal version: {text!r}")
    major, minor, patch, pre = m.groups()
    if patch == "x":
        patch, pre = None, ("x-" + pre if pre else "x-dev")
    return Version(int(major), int(minor), int(patch) if patch is not None else None, pre or None)


@dataclass(frozen=True)
class Assessment:
    version: str
    status: str            # fixed | update | end-of-life | not-affected | pre-release | newer
    level: str             # report level
    title: str
    action: str
    advisories: tuple[str, ...] = ()   # advisory IDs the version is still exposed to


def _fixed(sa: dict, v: Version) -> bool:
    return v.patch is not None and v.patch >= sa["fixed"][v.branch]


def assess(text: str) -> Assessment:
    v = parse(text)
    s = str(v)
    block = f"block /core/install.php in the web server ({INSTALLER_DOC})"

    if v.pre:
        return Assessment(s, "pre-release", "high",
                          f"Drupal {s} is a development or pre-release version: no security advisory covers it",
                          "Move to a stable release that includes the 18 and 25 November 2026 fixes; until then "
                          + block + ". PSA-2026-11-16 named 12.0.0-beta3 and 11.5.0-beta1 as affected.",
                          (SA017["id"], SA019["id"]))
    if v.major < 8 or (v.major == 8 and v.minor < 9):
        name = "Drupal 7" if v.major == 7 else f"Drupal {s}"
        return Assessment(s, "not-affected", "medium",
                          f"{name} is not affected by CVE-2026-132165 (Searchlight Cyber) but is end of life",
                          "Its installer keeps trusting settings.php when the database check fails. It still gets no "
                          "security fixes at all: plan the upgrade, and " + block + ".")
    if v.branch in SA017["fixed"]:
        if v.patch is None:
            return Assessment(s, "pre-release", "high", f"Drupal {s} is a development snapshot",
                              "Check that it includes the 18 and 25 November 2026 fixes, or " + block + ".",
                              (SA017["id"], SA019["id"]))
        open_ = tuple(sa["id"] for sa in (SA017, SA019) if not _fixed(sa, v))
        target = f"{v.major}.{v.minor}.{SA019['fixed'][v.branch]}"
        until = SUPPORTED_UNTIL[v.branch]
        if not open_:
            return Assessment(s, "fixed", "ok", f"Drupal {s} includes the fixes for both advisories",
                              f"Run `drush updatedb` (or /update.php) if you haven't since updating, and still "
                              f"{block}. This branch gets security fixes until {until}.")
        if open_ == (SA019["id"],):
            return Assessment(s, "update", "high",
                              f"Drupal {s} fixes CVE-2026-132165 but not CVE-2026-136716 (SA-CORE-2026-019)",
                              f"Update to {target}, then run `drush updatedb` (or /update.php): an update hook repairs "
                              f"sites in an incomplete install state. Then {block}.", open_)
        return Assessment(s, "update", "critical",
                          f"Drupal {s} is affected by CVE-2026-132165 (exploited since 19 Nov 2026) and CVE-2026-136716",
                          f"Update to {target} and run `drush updatedb` now; until then {block}. Then check the "
                          "site for signs of compromise.", open_)
    if (v.major, v.minor) < (10, 6) or (v.major == 11 and v.minor < 3):
        return Assessment(s, "end-of-life", "critical",
                          f"Drupal {s} is affected and end of life: no fix will be released for it",
                          f"Now: {block} (the advisories' interim step for unsupported sites). Then upgrade to "
                          "11.4.14 or later, and check the site for signs of compromise.",
                          (SA017["id"], SA019["id"]))
    return Assessment(s, "newer", "info",
                      f"Drupal {s} is newer than the November 2026 advisories",
                      "It should include both fixes; confirm on https://www.drupal.org/security and " + block + ".")
