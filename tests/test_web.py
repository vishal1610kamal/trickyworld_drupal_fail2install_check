import socket
import unittest

from f2icheck import web
from tests.helpers import FakeSite

ALREADY = "<html><head><title>Drupal already installed | Drupal</title></head><body>To start over...</body></html>"
FORM = "<html><head><title>Choose language | Drupal</title></head><body><form id='install-select-language-form'>"


def install_routes(status, body, prefix=""):
    paths = ["/core/install.php", "/core/install.php/foo", "/core//install.php", "/core/./install.php"]
    routes = {prefix + p: (status, body, {}) for p in paths}
    routes[prefix + "/install.php"] = (301, "", {"Location": prefix + "/core/install.php"})
    return routes


class Http(unittest.TestCase):
    def test_all_blocked_is_ok(self):
        with FakeSite(default=(403, "Forbidden", {})) as s:
            f = web.check(s.url)
        self.assertEqual(f[0].level, "ok")
        self.assertEqual(len(f[0].evidence), 5)

    def test_patched_site_still_answers(self):
        with FakeSite(install_routes(200, ALREADY)) as s:
            f = web.check(s.url)
        self.assertEqual(f[0].level, "high")
        self.assertIn("Drupal already installed", f[0].title)
        self.assertIn("/install.php -> 200 (already-installed), ended at /core/install.php", f[0].evidence)

    def test_paths_are_sent_exactly_as_written(self):
        with FakeSite(default=(404, "", {})) as s:
            web.check(s.url)
        self.assertEqual(s.seen, list(web.PATHS))

    def test_open_installer_form_is_critical(self):
        with FakeSite(install_routes(200, FORM)) as s:
            f = web.check(s.url)
        self.assertEqual(f[0].level, "critical")

    def test_one_variant_open_is_enough(self):
        routes = {p: (403, "", {}) for p in web.PATHS}
        routes["/core/install.php/foo"] = (200, ALREADY, {})
        with FakeSite(routes) as s:
            f = web.check(s.url)
        self.assertEqual(f[0].level, "high")

    def test_soft_404_is_medium(self):
        with FakeSite(default=(200, "<html>Page not found</html>", {})) as s:
            f = web.check(s.url)
        self.assertEqual(f[0].level, "medium")

    def test_redirect_to_other_host_not_followed(self):
        routes = {p: (302, "", {"Location": "https://elsewhere.example/x"}) for p in web.PATHS}
        with FakeSite(routes) as s:
            f = web.check(s.url)
        self.assertEqual(f[0].level, "medium")
        self.assertIn("redirects to another host", f[0].evidence[0])
        self.assertEqual(len(s.seen), 5)

    def test_redirect_loop_stops(self):
        routes = {p: (302, "", {"Location": p}) for p in web.PATHS}
        with FakeSite(routes) as s:
            p = web.probe(s.url, "/core/install.php", max_redirects=2)
        self.assertEqual(p.note, "too many redirects")
        self.assertEqual(len(s.seen), 3)

    def test_subdirectory_site(self):
        with FakeSite(install_routes(200, ALREADY, prefix="/drupal")) as s:
            f = web.check(s.url + "/drupal/")
        self.assertEqual(f[0].level, "high")
        self.assertTrue(all(p.startswith("/drupal/") for p in s.seen))

    def test_closed_port(self):
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        f = web.check(f"http://127.0.0.1:{port}", timeout=2)
        self.assertEqual(f[0].level, "info")
        self.assertIn("no answer", f[0].evidence[0])

    def test_bad_address(self):
        for bad in ("example.com", "ftp://example.com", "http://"):
            with self.assertRaises(ValueError, msg=bad):
                web.check(bad)

    def test_classify(self):
        self.assertEqual(web.classify(403, b""), "blocked")
        self.assertEqual(web.classify(500, b""), "other")
        self.assertEqual(web.classify(200, ALREADY.encode()), "already-installed")
        self.assertEqual(web.classify(200, FORM.encode()), "installer-form")


if __name__ == "__main__":
    unittest.main()
