import gzip
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from f2icheck import logs

SINCE = datetime(2026, 11, 18, tzinfo=timezone.utc)


def line(t: datetime, path: str, status: int = 200, method: str = "GET", ip: str = "203.0.113.7",
         ua: str = "curl/8.5", vhost: str = "") -> str:
    stamp = t.strftime("%d/%b/%Y:%H:%M:%S %z")
    return f'{vhost}{ip} - - [{stamp}] "{method} {path} HTTP/1.1" {status} 512 "-" "{ua}"\n'


T0 = datetime(2026, 11, 19, 19, 0, 5, tzinfo=timezone.utc)


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name: str, lines: list[str]) -> Path:
        p = self.dir / name
        if name.endswith(".gz"):
            with gzip.open(p, "wt") as fh:
                fh.writelines(lines)
        else:
            p.write_text("".join(lines))
        return p

    def find(self, found, title_part):
        return next(f for f in found if title_part in f.title)


class Normalise(unittest.TestCase):
    def test_norm(self):
        self.assertEqual(logs.norm("/core//install.php"), "/core/install.php")
        self.assertEqual(logs.norm("/core/./install.php?x=1"), "/core/install.php")
        self.assertEqual(logs.norm("/core/%69nstall.php"), "/core/install.php")
        self.assertEqual(logs.norm("/a/../core/install.php"), "/core/install.php")

    def test_site_path(self):
        self.assertEqual(logs.site_path("/drupal/core/install.php", "/drupal"), "/core/install.php")
        self.assertEqual(logs.site_path("/drupalx/index.php", "/drupal"), "/drupalx/index.php")
        self.assertEqual(logs.site_path("/index.php", ""), "/index.php")


class Installer(Base):
    def test_accepted_post_is_critical(self):
        p = self.write("access.log", [line(T0, "/core/install.php?langcode=en", 200, "POST"),
                                      line(T0, "/core/install.php", 200)])
        f = logs.check([p], since=SINCE)
        self.assertEqual(f[0].level, "critical")
        self.assertIn("POST /core/install.php?langcode=en -> 200", f[0].evidence[0])
        self.assertEqual(self.find(f, "The installer answered").level, "high")

    def test_all_spellings_are_counted(self):
        spellings = ["/core/install.php", "/install.php", "/core/install.php/foo", "/core//install.php",
                     "/core/./install.php", "/CORE/INSTALL.PHP", "/core/%69nstall.php"]
        p = self.write("access.log", [line(T0, s, 403) for s in spellings])
        f = logs.check([p], since=SINCE)
        self.assertEqual(self.find(f, "installer requests were refused").title, "7 installer requests were refused")

    def test_refused_posts_are_high(self):
        p = self.write("access.log", [line(T0, "/core/install.php", 403, "POST")])
        self.assertEqual(logs.check([p], since=SINCE)[0].title, "1 installer form submissions, all refused")

    def test_since_uses_the_logged_time_zone(self):
        ist = timezone(timedelta(hours=5, minutes=30))
        # 03:00 on 18 Nov in India is 21:30 on 17 Nov in UTC: before SA-CORE-2026-017 day.
        p = self.write("access.log", [line(datetime(2026, 11, 18, 3, 0, tzinfo=ist), "/core/install.php", 200),
                                      line(datetime(2026, 11, 18, 6, 0, tzinfo=ist), "/core/install.php", 200)])
        f = logs.check([p], since=SINCE)
        self.assertEqual(self.find(f, "The installer answered").title,
                         "The installer answered 1 requests from 1 addresses")

    def test_vhost_prefix_and_gzip(self):
        p = self.write("access.log.1.gz", [line(T0, "/core/install.php", 200, vhost="www.example.com:443 ")])
        f = logs.check([p], since=SINCE)
        self.assertEqual(self.find(f, "The installer answered").level, "high")

    def test_unreadable_lines_are_counted(self):
        p = self.write("access.log", ["garbage\n", line(T0, "/", 200)])
        f = logs.check([p], since=SINCE)
        self.assertIn("1 lines were not in a format", f[-1].detail)
        self.assertEqual(f[-1].level, "ok")


class StrayPhp(Base):
    def test_php_in_files_folder_is_critical(self):
        p = self.write("access.log", [line(T0, "/sites/default/files/cache.php", 200),
                                      line(T0, "/index.php", 200), line(T0, "/update.php", 403)])
        f = logs.check([p], since=SINCE)
        self.assertEqual(f[0].level, "critical")
        self.assertEqual(len(f[0].evidence), 1)

    def test_other_unknown_php_is_high_and_404s_are_ignored(self):
        p = self.write("access.log", [line(T0, "/modules/x/y.php", 200), line(T0, "/wp-login.php", 404)])
        f = logs.check([p], since=SINCE)
        self.assertEqual(f[0].level, "high")
        self.assertEqual(len(f[0].evidence), 1)

    def test_entry_points_with_path_info_and_base_path(self):
        p = self.write("access.log", [line(T0, "/drupal/index.php/node/1", 200),
                                      line(T0, "/drupal/core/authorize.php", 200)])
        f = logs.check([p], since=SINCE, base="/drupal")
        self.assertEqual([x.level for x in f], ["ok"])


class Bursts(Base):
    def test_burst_next_to_installer_requests(self):
        lines = [line(T0 + timedelta(seconds=i % 50), "/", 503) for i in range(40)]
        lines.append(line(T0 + timedelta(minutes=2), "/core/install.php", 200))
        p = self.write("access.log", lines)
        f = logs.check([p], since=SINCE)
        b = self.find(f, "Failure bursts next to installer requests")
        self.assertEqual(b.level, "high")
        self.assertIn("40 5xx answers", b.evidence[0])

    def test_burst_without_installer_requests(self):
        p = self.write("access.log", [line(T0, "/", 503) for _ in range(40)])
        f = logs.check([p], since=SINCE)
        self.assertEqual(self.find(f, "minutes with failure bursts").level, "info")

    def test_error_log_formats(self):
        err = self.write("error.log", [
            "[Thu Nov 19 19:01:02.123456 2026] [php:error] [pid 1] PHP Fatal error: SQLSTATE[HY000] [1040] Too many connections\n",
            "[19-Nov-2026 19:01:05] WARNING: [pool www] child 12 said into stderr: \"Too many open files\"\n",
            "[19-Nov-2026 19:01:30 UTC] PHP Warning: SQLSTATE[HY000] [2002] Cannot assign requested address\n",
            "2026/11/19 19:01:07 [error] 1#1: *9 connect() failed (99: Cannot assign requested address)\n",
            "2026-11-19T19:01:09.5Z 0 [Warning] FATAL: sorry, too many clients already\n",
            "[19-Nov-2026 19:01:10] NOTICE: ready to handle connections\n",
        ] * 3)
        minutes = logs.read_errors([err])
        self.assertEqual(minutes[datetime(2026, 11, 19, 19, 1)], 15)
        acc = self.write("access.log", [line(T0 + timedelta(minutes=1, seconds=20), "/core/install.php", 200)])
        f = logs.check([acc], [err], since=SINCE)
        self.assertIn("15 database/resource errors", self.find(f, "Failure bursts").evidence[0])


if __name__ == "__main__":
    unittest.main()
