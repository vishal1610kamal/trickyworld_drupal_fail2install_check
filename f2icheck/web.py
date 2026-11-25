"""Can anyone on the internet reach your Drupal installer? GET requests only, to a site you run.

The first three paths are the ones Drupal's "Securing the installer" page tells you to test; the last two are the
same file written the way a misconfigured rule may miss. Paths are sent exactly as written (no normalising), and
redirects are followed only on the same host, like `curl -L` in Drupal's instructions.
"""
from __future__ import annotations

import http.client
import ssl
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

from . import __version__
from .advisories import INSTALLER_DOC
from .report import Finding

PATHS = ("/core/install.php", "/install.php", "/core/install.php/foo", "/core//install.php", "/core/./install.php")
BLOCKED = {401, 403, 404, 405, 410, 451}
FORM_MARKERS = ("choose language", "install-select-language-form", "select an installation profile",
                "install-select-profile-form", "database configuration", "install-settings-form")
INSTALLED_MARKER = "drupal already installed"
MAX_BODY = 256 * 1024


@dataclass
class Probe:
    path: str
    status: int | None
    page: str          # installer-form | already-installed | other | blocked | error
    final: str
    note: str = ""


def _request(url: str, timeout: float, context: ssl.SSLContext | None) -> tuple[int, dict, bytes]:
    parts = urlsplit(url)
    target = parts.path + (f"?{parts.query}" if parts.query else "")
    if parts.scheme == "https":
        conn = http.client.HTTPSConnection(parts.hostname, parts.port or 443, timeout=timeout,
                                           context=context or ssl.create_default_context())
    else:
        conn = http.client.HTTPConnection(parts.hostname, parts.port or 80, timeout=timeout)
    try:
        conn.putrequest("GET", target, skip_accept_encoding=True)
        conn.putheader("User-Agent", f"fail2install-check/{__version__}")
        conn.putheader("Accept", "text/html")
        conn.endheaders()
        resp = conn.getresponse()
        return resp.status, {k.lower(): v for k, v in resp.getheaders()}, resp.read(MAX_BODY)
    finally:
        conn.close()


def classify(status: int, body: bytes) -> str:
    if status in BLOCKED:
        return "blocked"
    if status != 200:
        return "other"
    text = body.decode("utf-8", "replace").lower()
    if INSTALLED_MARKER in text:
        return "already-installed"
    if any(m in text for m in FORM_MARKERS):
        return "installer-form"
    return "other"


def probe(base: str, path: str, timeout: float = 15, context: ssl.SSLContext | None = None,
          max_redirects: int = 3) -> Probe:
    root = urlsplit(base)
    url = f"{root.scheme}://{root.netloc}{root.path.rstrip('/')}{path}"
    note = ""
    try:
        for _ in range(max_redirects + 1):
            status, headers, body = _request(url, timeout, context)
            if status in (301, 302, 303, 307, 308) and "location" in headers:
                nxt = urljoin(url, headers["location"])
                if urlsplit(nxt).netloc != root.netloc:
                    note = f"redirects to another host: {nxt}"
                    return Probe(path, status, "other", url, note)
                url = nxt
                continue
            return Probe(path, status, classify(status, body), url, note)
        return Probe(path, status, "other", url, "too many redirects")
    except (OSError, http.client.HTTPException, ssl.SSLError) as e:
        return Probe(path, None, "error", url, f"{type(e).__name__}: {e}")


def check(base: str, timeout: float = 15, cafile: str | None = None) -> list[Finding]:
    if urlsplit(base).scheme not in ("http", "https") or not urlsplit(base).hostname:
        raise ValueError(f"give the site's address with http:// or https://, not {base!r}")
    context = ssl.create_default_context(cafile=cafile) if cafile else None
    probes = [probe(base, p, timeout, context) for p in PATHS]
    lines = [f"{p.path} -> {p.status if p.status is not None else 'no answer'} ({p.page})"
             + (f", ended at {urlsplit(p.final).path}" if urlsplit(p.final).path != urlsplit(base).path.rstrip('/') + p.path else "")
             + (f"; {p.note}" if p.note else "") for p in probes]
    pages = {p.page for p in probes}
    block = f"Block it in the web server configuration ({INSTALLER_DOC})."
    if "installer-form" in pages:
        return [Finding("http", "critical", "The installer's setup forms are open to anyone",
                        "A request reached Drupal's installation forms. On a live site that means an unfinished or "
                        "broken install state: the situation SA-CORE-2026-019 warns about.",
                        "Block /core/install.php now, update to 11.4.14 / 11.3.23 / 10.6.23, run `drush updatedb`, "
                        "then check user 1 and settings.php. " + block, lines)]
    if "already-installed" in pages:
        return [Finding("http", "high", "The installer answers requests (it shows 'Drupal already installed')",
                        "A fixed Drupal refuses to reinstall, but the advisories recommend that nobody can reach "
                        "install.php at all: SA-CORE-2026-019 says sites that secured the installer are not vulnerable.",
                        block, lines)]
    if "error" in pages and pages <= {"error", "blocked"}:
        return [Finding("http", "info", "Some requests got no answer", "Check the address and try again.", "",
                        lines)]
    if "other" in pages:
        return [Finding("http", "medium", "Some installer URLs answered with something other than 403/404",
                        "Open them in a browser to see what they are (a custom error page that answers 200 is "
                        "harmless; anything from Drupal is not).", block, lines)]
    return [Finding("http", "ok", "All five installer URLs are blocked (403/404)", "", "", lines)]
