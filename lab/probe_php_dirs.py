"""Do Drupal's .htaccess protections stop a PHP file placed outside Drupal's entry points from running?

A harmless probe (it prints a marker and nothing else) is placed in sites/default/files/ (protected by that
directory's .htaccess) and in modules/ (protected by the root .htaccess RewriteRule), requested once under each of
the three Apache + PHP setups with stock Drupal 11.4.14 rules, then deleted. GET requests to 127.0.0.1 only.
"""
import argparse, os, subprocess, sys, time

ap = argparse.ArgumentParser()
ap.add_argument("--lab", required=True)
ap.add_argument("--out", required=True)
a = ap.parse_args()
WEB = f"{a.lab}/d11/web"
APA = f"{a.lab}/apache"
MARK = "F2I-PROBE-RAN"
probes = {"/sites/default/files/f2i-probe.php": f"{WEB}/sites/default/files/f2i-probe.php",
          "/modules/f2i-probe.php": f"{WEB}/modules/f2i-probe.php"}


def wait_port(port, up=True):
    for _ in range(150):
        if (f"127.0.0.1:{port} " in subprocess.run(["ss", "-ltn"], capture_output=True, text=True).stdout) == up:
            return
        time.sleep(0.1)
    sys.exit(f"port {port} never {'opened' if up else 'closed'}")


rows = []
try:
    for path in probes.values():
        open(path, "w").write(f"<?php echo '{MARK}';\n")
    for name, port, fpm in (("mod_php", 18081, False), ("fpm_sethandler", 18082, True), ("fpm_proxypassmatch", 18083, True)):
        conf = f"{APA}/conf/{name}-stock.conf"          # written by apache_matrix.py
        if fpm:
            subprocess.run(["/usr/sbin/php-fpm8.3", "--fpm-config", f"{a.lab}/fpm/php-fpm.conf"], check=True)
            wait_port(19083)
        subprocess.run(["/usr/sbin/apache2", "-f", conf, "-k", "start"], check=True)
        wait_port(port)
        for url in probes:
            r = subprocess.run(["curl", "-s", "-o", "-", "-w", "\n%{http_code}", "-m", "20", f"http://127.0.0.1:{port}{url}"],
                               capture_output=True, text=True)
            body, _, code = r.stdout.rpartition("\n")
            rows.append((name, url, code, "PHP ran" if MARK in body else "did not run"))
        subprocess.run(["/usr/sbin/apache2", "-f", conf, "-k", "stop"], check=True)
        wait_port(port, up=False)
        if fpm:
            os.kill(int(open(f"{a.lab}/fpm/fpm.pid").read()), 15)
            wait_port(19083, up=False)
finally:
    for path in probes.values():
        if os.path.exists(path):
            os.remove(path)

with open(f"{a.out}/php-dirs.md", "w") as f:
    f.write("| Handler | Probe URL | Status | Result |\n|---|---|---|---|\n")
    for r in rows:
        f.write("| " + " | ".join(r) + " |\n")
print(open(f"{a.out}/php-dirs.md").read())
