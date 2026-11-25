"""Option 3 (delete core/install.php) on servers that are already running.

Six servers run side by side on the same Drupal 11.4.14 web root: mod_php, PHP-FPM via SetHandler and PHP-FPM via
ProxyPassMatch, each with OPcache's default timestamp checks and with opcache.validate_timestamps=0. Each FPM
setup has its own pool (its own OPcache). Every URL form is requested twice (so PHP has cached it), the file is
deleted once, and every server is asked again 0, 3, 10 and 125 seconds later (PHP's realpath cache lives 120 s),
then after PHP is restarted. GET requests to 127.0.0.1 only. Writes opcache.json / opcache.md into --out.
"""
import argparse, json, os, shutil, signal, subprocess, sys, time

ap = argparse.ArgumentParser()
ap.add_argument("--lab", required=True)
ap.add_argument("--out", required=True)
a = ap.parse_args()
LAB, WEB = a.lab, f"{a.lab}/d11/web"
APA = f"{LAB}/apache2"
os.makedirs(f"{APA}/run", exist_ok=True); os.makedirs(f"{APA}/logs", exist_ok=True); os.makedirs(f"{LAB}/fpm2", exist_ok=True)
MODS = "/usr/lib/apache2/modules"
BUILTIN = set(subprocess.run(["/usr/sbin/apache2", "-l"], capture_output=True, text=True).stdout.split())
COMMON = [m for m in ["authz_core", "authz_host", "authn_core", "dir", "mime", "rewrite", "log_config", "headers",
                      "expires", "env", "setenvif", "alias", "filter"] if f"mod_{m}.c" not in BUILTIN]
PROXY = f"LoadModule proxy_module {MODS}/mod_proxy.so\nLoadModule proxy_fcgi_module {MODS}/mod_proxy_fcgi.so\n"
URLS = ["/core/install.php", "/core//install.php", "/core/./install.php", "/core/install.php/foo"]

SERVERS = []
for i, (handler, validate) in enumerate([(h, v) for h in ("mod_php", "fpm_sethandler", "fpm_proxypassmatch")
                                         for v in (True, False)]):
    SERVERS.append({"name": f"{handler}/{'ts=1' if validate else 'ts=0'}", "handler": handler, "validate": validate,
                    "port": 18091 + i, "fpm_port": 19091 + i if handler != "mod_php" else None})


def wait_port(port, up=True):
    for _ in range(150):
        if (f"127.0.0.1:{port} " in subprocess.run(["ss", "-ltn"], capture_output=True, text=True).stdout) == up:
            return
        time.sleep(0.1)
    sys.exit(f"port {port} never {'opened' if up else 'closed'}")


def conf(s):
    p = s["port"]
    if s["handler"] == "mod_php":
        extra = (f"LoadModule php_module {MODS}/libphp8.3.so\n<FilesMatch \".+\\.ph(ar|p|tml)$\">\n"
                 "  SetHandler application/x-httpd-php\n</FilesMatch>\n"
                 + ("" if s["validate"] else "php_admin_value opcache.validate_timestamps 0\n"))
        mpm = "prefork"
    elif s["handler"] == "fpm_sethandler":
        extra = PROXY + f"<FilesMatch \".+\\.ph(ar|p|tml)$\">\n  SetHandler \"proxy:fcgi://127.0.0.1:{s['fpm_port']}\"\n</FilesMatch>\n"
        mpm = "event"
    else:
        extra = PROXY + f"ProxyPassMatch \"^/(.*\\.php(/.*)?)$\" \"fcgi://127.0.0.1:{s['fpm_port']}{WEB}/$1\"\n"
        mpm = "event"
    mods = "".join(f"LoadModule {m}_module {MODS}/mod_{m}.so\n" for m in COMMON)
    path = f"{APA}/{p}.conf"
    open(path, "w").write(f"""ServerName lab.localhost
ServerRoot "{APA}"
Listen 127.0.0.1:{p}
PidFile "{APA}/run/{p}.pid"
DefaultRuntimeDir "{APA}/run"
Mutex file:{APA}/run default
LoadModule mpm_{mpm}_module {MODS}/mod_mpm_{mpm}.so
{mods}TypesConfig /etc/mime.types
ErrorLog "{APA}/logs/{p}-error.log"
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
DirectoryIndex index.php
{extra}""")
    return path


def fpm_start(s):
    d = f"{LAB}/fpm2/{s['fpm_port']}"
    os.makedirs(d, exist_ok=True)
    open(f"{d}/php-fpm.conf", "w").write(f"""[global]
pid = {d}/fpm.pid
error_log = {d}/error.log
daemonize = yes
[lab]
listen = 127.0.0.1:{s['fpm_port']}
listen.allowed_clients = 127.0.0.1
pm = static
pm.max_children = 2
{'' if s['validate'] else 'php_admin_value[opcache.validate_timestamps] = 0'}
""")
    subprocess.run(["/usr/sbin/php-fpm8.3", "--fpm-config", f"{d}/php-fpm.conf"], check=True)
    wait_port(s["fpm_port"])


def fpm_stop(s):
    pid = f"{LAB}/fpm2/{s['fpm_port']}/fpm.pid"
    if os.path.exists(pid):
        os.kill(int(open(pid).read()), signal.SIGTERM)
        wait_port(s["fpm_port"], up=False)


def apache(cmd, s):
    subprocess.run(["/usr/sbin/apache2", "-f", f"{APA}/{s['port']}.conf", "-k", cmd], check=True, capture_output=True)
    wait_port(s["port"], up=(cmd == "start"))


def status(s, url):
    r = subprocess.run(["curl", "-s", "--path-as-is", "-o", "/dev/null", "-w", "%{http_code}", "-m", "20",
                        f"http://127.0.0.1:{s['port']}{url}"], capture_output=True, text=True)
    return int(r.stdout or 0)


installer = f"{WEB}/core/install.php"
backup = f"{APA}/install.php.orig"
shutil.copy2(installer, backup)
rows = {(s["name"], u): {} for s in SERVERS for u in URLS}
try:
    for s in SERVERS:
        conf(s)
        if s["fpm_port"]:
            fpm_start(s)
        apache("start", s)
    for _ in range(2):
        for s in SERVERS:
            for u in URLS:
                rows[(s["name"], u)]["before"] = status(s, u)
    os.remove(installer)
    t0 = time.time()
    for label, at in (("0 s", 0), ("3 s", 3), ("10 s", 10), ("125 s", 125)):
        time.sleep(max(0, t0 + at - time.time()))
        for s in SERVERS:
            for u in URLS:
                rows[(s["name"], u)][label] = status(s, u)
    for s in SERVERS:
        if s["fpm_port"]:
            fpm_stop(s); fpm_start(s)
        else:
            apache("stop", s); apache("start", s)
    for s in SERVERS:
        for u in URLS:
            rows[(s["name"], u)]["after PHP restart"] = status(s, u)
finally:
    if not os.path.exists(installer):
        shutil.copy2(backup, installer)
    for s in SERVERS:
        try:
            apache("stop", s)
        except Exception:
            pass
        if s["fpm_port"]:
            fpm_stop(s)

os.makedirs(a.out, exist_ok=True)
json.dump([{"server": k[0], "url": k[1], **v} for k, v in rows.items()], open(f"{a.out}/opcache.json", "w"), indent=1)
cols = ["before", "0 s", "3 s", "10 s", "125 s", "after PHP restart"]
with open(f"{a.out}/opcache.md", "w") as f:
    f.write("| Server | URL | " + " | ".join(cols) + " |\n|---|---|" + "---|" * len(cols) + "\n")
    for (name, u), v in rows.items():
        f.write(f"| {name} | `{u}` | " + " | ".join(str(v.get(c, "")) for c in cols) + " |\n")
print(open(f"{a.out}/opcache.md").read())
