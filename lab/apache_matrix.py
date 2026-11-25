"""Test Drupal's three ways of blocking install.php on a real Apache 2.4 + Drupal 11.4.14 lab.

Part 1 (matrix): three PHP handler setups (mod_php; PHP-FPM via SetHandler; PHP-FPM via ProxyPassMatch) x four
configurations (stock; Option 1 <Location> in the server config; Option 2 <Files> appended to .htaccess; Option 3
file removed) x five URLs (the three from Drupal's "Check that it works" section plus two path-normalisation
variants), plus "/" and "/update.php" to show the site still works. PHP and Apache restart for every cell.

Part 2 (OPcache): Option 3 on a running server. The installer is requested once (so OPcache holds it), deleted,
and requested again 0 s, 3 s and 10 s later, then after a PHP reload. Run with OPcache's default timestamp checks
and with opcache.validate_timestamps=0 (a common production setting).

Only GET requests to 127.0.0.1. Writes results.json / results.md / opcache.md into --out.
"""
import argparse, json, os, shutil, signal, subprocess, sys, time

ap = argparse.ArgumentParser()
ap.add_argument("--lab", required=True)
ap.add_argument("--out", required=True)
a = ap.parse_args()
LAB = a.lab
WEB = f"{LAB}/d11/web"
APA = f"{LAB}/apache"
FPM_PORT = 19083
for d in ("run", "logs", "conf"):
    os.makedirs(f"{APA}/{d}", exist_ok=True)
os.makedirs(f"{LAB}/fpm", exist_ok=True)

MODS = "/usr/lib/apache2/modules"
BUILTIN = set(subprocess.run(["/usr/sbin/apache2", "-l"], capture_output=True, text=True).stdout.split())
COMMON_MODS = [m for m in ["authz_core", "authz_host", "authn_core", "dir", "mime", "rewrite", "log_config",
                           "headers", "expires", "env", "setenvif", "alias", "filter"] if f"mod_{m}.c" not in BUILTIN]

URLS = ["/core/install.php", "/install.php", "/core/install.php/foo", "/core//install.php", "/core/./install.php"]
PROXY_MODS = f"LoadModule proxy_module {MODS}/mod_proxy.so\nLoadModule proxy_fcgi_module {MODS}/mod_proxy_fcgi.so\n"
HANDLERS = {
    "mod_php": {"port": 18081, "mpm": "prefork", "fpm": False,
                "extra": f"LoadModule php_module {MODS}/libphp8.3.so\n"
                         "<FilesMatch \".+\\.ph(ar|p|tml)$\">\n  SetHandler application/x-httpd-php\n</FilesMatch>\n"},
    "fpm_sethandler": {"port": 18082, "mpm": "event", "fpm": True,
                       "extra": PROXY_MODS + "<FilesMatch \".+\\.ph(ar|p|tml)$\">\n"
                                f"  SetHandler \"proxy:fcgi://127.0.0.1:{FPM_PORT}\"\n</FilesMatch>\n"},
    "fpm_proxypassmatch": {"port": 18083, "mpm": "event", "fpm": True,
                           "extra": PROXY_MODS + f"ProxyPassMatch \"^/(.*\\.php(/.*)?)$\" \"fcgi://127.0.0.1:{FPM_PORT}{WEB}/$1\"\n"},
}
OPTION1 = '<Location "/core/install.php">\n  Require all denied\n</Location>\n'
OPTION2 = '\n<Files "install.php">\n  Require all denied\n</Files>\n'


def conf(name, h, option, validate=True):
    p = h["port"]
    mods = "".join(f"LoadModule {m}_module {MODS}/mod_{m}.so\n" for m in COMMON_MODS)
    php_flag = "" if validate or h["fpm"] else "php_admin_value opcache.validate_timestamps 0\n"
    return f"""ServerName lab.localhost
ServerRoot "{APA}"
Listen 127.0.0.1:{p}
PidFile "{APA}/run/{p}.pid"
DefaultRuntimeDir "{APA}/run"
Mutex file:{APA}/run default
LoadModule mpm_{h['mpm']}_module {MODS}/mod_mpm_{h['mpm']}.so
{mods}TypesConfig /etc/mime.types
ErrorLog "{APA}/logs/{name}-error.log"
LogFormat "%h %l %u %t \\"%r\\" %>s %b \\"%{{Referer}}i\\" \\"%{{User-Agent}}i\\"" combined
CustomLog "{APA}/logs/{name}-access.log" combined
<Directory />
  AllowOverride None
  Require all denied
</Directory>
DocumentRoot "{WEB}"
<Directory "{WEB}">
  AllowOverride All
  Require all granted
  Options FollowSymLinks
</Directory>
DirectoryIndex index.php index.html
{h['extra']}{php_flag}{OPTION1 if option == 'option1' else ''}"""


def wait_port(port, up=True):
    for _ in range(150):
        busy = f"127.0.0.1:{port} " in subprocess.run(["ss", "-ltn"], capture_output=True, text=True).stdout
        if busy == up:
            return
        time.sleep(0.1)
    sys.exit(f"port {port} never {'opened' if up else 'closed'}")


def apache(cmd, path, port):
    r = subprocess.run(["/usr/sbin/apache2", "-f", path, "-k", cmd], capture_output=True, text=True)
    if r.returncode:
        sys.exit(f"apache2 {cmd} failed: {r.stderr or r.stdout}")
    wait_port(port, up=(cmd == "start"))


def fpm(cmd, validate=True):
    pid_file = f"{LAB}/fpm/fpm.pid"
    if cmd == "start":
        path = f"{LAB}/fpm/php-fpm.conf"
        open(path, "w").write(f"""[global]
pid = {pid_file}
error_log = {LAB}/fpm/error.log
daemonize = yes
[lab]
listen = 127.0.0.1:{FPM_PORT}
listen.allowed_clients = 127.0.0.1
pm = static
pm.max_children = 5
catch_workers_output = yes
{'' if validate else 'php_admin_value[opcache.validate_timestamps] = 0'}
""")
        subprocess.run(["/usr/sbin/php-fpm8.3", "--fpm-config", path], check=True)
        wait_port(FPM_PORT)
    elif os.path.exists(pid_file):
        os.kill(int(open(pid_file).read()), signal.SIGTERM)
        wait_port(FPM_PORT, up=False)


def fetch(port, url):
    # --path-as-is keeps "//" and "/./" as sent; -L follows redirects like the docs' second check.
    r = subprocess.run(["curl", "-s", "--path-as-is", "-L", "--max-redirs", "3", "-o", "-", "-w", "\n%{http_code} %{url_effective}",
                        "-m", "30", f"http://127.0.0.1:{port}{url}"], capture_output=True, text=True)
    body, _, tail = r.stdout.rpartition("\n")
    code, _, final = tail.partition(" ")
    low = body.lower()
    marker = ("already-installed page" if "already installed" in low else
              "installer form" if "choose language" in low else
              "front page" if "fail2install lab" in low else
              "access denied" if "access denied" in low or "forbidden" in low else
              "not found" if "not found" in low else "")
    return {"url": url, "status": int(code or 0), "final": final.replace(f"http://127.0.0.1:{port}", ""), "body": marker}


htaccess, installer = f"{WEB}/.htaccess", f"{WEB}/core/install.php"
shutil.copy2(htaccess, f"{APA}/htaccess.orig")
shutil.copy2(installer, f"{APA}/install.php.orig")


def reset():
    shutil.copy2(f"{APA}/htaccess.orig", htaccess)
    if not os.path.exists(installer):
        shutil.copy2(f"{APA}/install.php.orig", installer)


results, opc = [], []
try:
    for name, h in HANDLERS.items():
        for option in ("stock", "option1", "option2", "option3"):
            path = f"{APA}/conf/{name}-{option}.conf"
            open(path, "w").write(conf(name, h, option))
            reset()
            if option == "option2":
                with open(htaccess, "a") as f:
                    f.write(OPTION2)
            if option == "option3":
                os.remove(installer)
            if h["fpm"]:
                fpm("start")
            apache("start", path, h["port"])
            for u in URLS + ["/", "/update.php"]:
                results.append({"handler": name, "option": option, **fetch(h["port"], u)})
            apache("stop", path, h["port"])
            if h["fpm"]:
                fpm("stop")

    for name in ("mod_php", "fpm_sethandler"):
        h = HANDLERS[name]
        for validate in (True, False):
            reset()
            path = f"{APA}/conf/{name}-opcache-{'on' if validate else 'off'}.conf"
            open(path, "w").write(conf(name, h, "stock", validate))
            if h["fpm"]:
                fpm("start", validate)
            apache("start", path, h["port"])
            row = {"handler": name, "validate_timestamps": "1 (default)" if validate else "0",
                   "before delete": fetch(h["port"], URLS[0])["status"]}
            os.remove(installer)
            row["0 s after"] = fetch(h["port"], URLS[0])["status"]
            time.sleep(3)
            row["3 s after"] = fetch(h["port"], URLS[0])["status"]
            time.sleep(7)
            row["10 s after"] = fetch(h["port"], URLS[0])["status"]
            if h["fpm"]:
                fpm("stop"); fpm("start", validate)
            else:
                apache("stop", path, h["port"]); apache("start", path, h["port"])
            row["after PHP reload"] = fetch(h["port"], URLS[0])["status"]
            apache("stop", path, h["port"])
            if h["fpm"]:
                fpm("stop")
            opc.append(row)
finally:
    reset()
    for h in HANDLERS.values():
        if f"127.0.0.1:{h['port']} " in subprocess.run(["ss", "-ltn"], capture_output=True, text=True).stdout:
            pidf = f"{APA}/run/{h['port']}.pid"
            if os.path.exists(pidf):
                os.kill(int(open(pidf).read()), signal.SIGTERM)
    fpm("stop")

os.makedirs(a.out, exist_ok=True)
json.dump({"matrix": results, "opcache": opc}, open(f"{a.out}/results.json", "w"), indent=1)
with open(f"{a.out}/results.md", "w") as f:
    f.write("| Handler | Option | URL | Status | Final URL | Body |\n|---|---|---|---|---|---|\n")
    for r in results:
        f.write(f"| {r['handler']} | {r['option']} | `{r['url']}` | {r['status']} | `{r['final']}` | {r['body']} |\n")
with open(f"{a.out}/opcache.md", "w") as f:
    cols = list(opc[0].keys()) if opc else []
    f.write("| " + " | ".join(cols) + " |\n|" + "---|" * len(cols) + "\n")
    for r in opc:
        f.write("| " + " | ".join(str(r[c]) for c in cols) + " |\n")
print(open(f"{a.out}/results.md").read())
print(open(f"{a.out}/opcache.md").read())
