# fail2install-check: is your Drupal site safe from the installer flaws?

On 18 November 2026 Drupal fixed a flaw in its installer, `core/install.php`, that lets someone without an account
re-run the installation on a live site and take it over
([SA-CORE-2026-017](https://www.drupal.org/sa-core-2026-017), CVE-2026-132165, which Searchlight Cyber
[calls Fail2Install](https://www.slcyber.io/research/fail2install-system-limits-pre-auth-rce-drupal)). Drupal says
it has been exploited on live sites since 19 November 2026 at 19:00 UTC, and CISA added it to its Known Exploited
Vulnerabilities catalog on 24 November. On 25 November a second advisory followed
([SA-CORE-2026-019](https://www.drupal.org/sa-core-2026-019), CVE-2026-136716): sites in "unusual or incomplete
install states" stayed open to takeover after the first fix, and they need 11.4.14, 11.3.23 or 10.6.23 **plus**
`update.php` / `drush updatedb`.

`f2icheck` answers the questions those advisories leave you with, for a site you run:

| Command | What it checks |
|---|---|
| `version` | The core version on disk (and in `composer.lock`) against both advisories, end-of-life branches, Drupal 7. |
| `http` | Whether anyone can reach the installer: five GET requests, the three from Drupal's [Securing the installer](https://www.drupal.org/docs/administering-a-drupal-site/security-in-drupal/securing-the-installer-installphp) page plus two path spellings a rule may miss. |
| `files` | Whether PHP can write to `settings.php` or change its permissions (SA-CORE-2026-017 names this), traces of a reinstall in `settings.php`, SQLite databases with a PHP name anywhere in the web root, PHP files in the public files folder, and whether your installer block survives the next `composer install`. |
| `logs` | Installer requests in your access logs (any spelling, form submissions, what answered 200), PHP files outside Drupal's entry points that answered 200, and bursts of 5xx answers or database/resource errors next to installer requests. |
| `state` | Through Drush: `install_task` and `install_time` (the state SA-CORE-2026-019 repairs), whether its update hook has run, and user 1's name, email and creation date. |
| `all` | All of the above that apply, and a combined warning when an affected version has a reachable installer. |

It changes nothing on the site and sends nothing anywhere except the five requests of `http`, to the address you
give. Python 3.10 or newer, standard library only.

This is the code behind the TrickyWorld article
[Drupal Fail2Install: why 11.4.13 isn't enough](https://www.trickyworld.in/computer-tricks/cyber-security/drupal-fail2install-cve-2026-132165/).

## Try it

```
python3 -m f2icheck version /var/www/mysite                  # a project folder or the web root
python3 -m f2icheck http https://www.example.com             # your own site; /drupal subfolders work too
python3 -m f2icheck files /var/www/mysite --web-user www-data
python3 -m f2icheck logs /var/log/apache2/access.log* --errors /var/log/php8.3-fpm.log
python3 -m f2icheck state /var/www/mysite                    # uses vendor/bin/drush, or --drush PATH
python3 -m f2icheck all /var/www/mysite --url https://www.example.com --log /var/log/nginx/access.log*
```

Add `--json` for machine-readable output and `--evidence 0` to list every log line. `--since` (default
2026-11-18, the day of the first advisory) sets the date after which changes count as suspicious. Exit codes: 0
nothing to do, 1 something to fix, 2 something critical, 3 the tool couldn't run.

Run `files` before `state` if you think the site may be compromised: Drush loads `settings.php`, so code an
attacker added there would run under your account. `all` skips Drush on its own when `settings.php` looks
tampered with.

## What the lab showed

We installed Drupal 11.4.14 (drupal/recommended-project, PHP 8.3.36, MySQL 8.0.46, Drush 13.8.1) and served it with
Apache 2.4.52 in three common ways: mod_php, PHP-FPM through `SetHandler`, and PHP-FPM through `ProxyPassMatch`.
Then we tried Drupal's three ways of blocking the installer. Full tables are in [results/](results/).

| Setup | No block | Option 1: `<Location>` in server config | Option 2: `<Files>` in .htaccess | Option 3: delete the file |
|---|---|---|---|---|
| mod_php | 200 on all 5 URLs | 403 on all 5 | 403 on all 5 | 404 on all 5 |
| PHP-FPM, `SetHandler` | 200 on all 5 | 403 on all 5 | 403 on all 5 | 404 on all 5 |
| PHP-FPM, `ProxyPassMatch` | 200 on 4 (404 on `/install.php`) | 403 on 4 | **200 on 4: no effect** | 404 on all 5 |

- **A patched site still answers.** With no block, `/core/install.php` returned 200 with Drupal's "Drupal already
  installed" page on every setup. The fix makes the installer refuse; only a block stops it answering.
- **`ProxyPassMatch` ignores .htaccess for PHP.** Apache hands those requests to PHP-FPM before it reads any
  .htaccess, so Option 2 did nothing, and a harmless test PHP file placed in `sites/default/files/` and in
  `modules/` ran there (403 on the other two setups): Drupal's .htaccess rules that stop uploaded PHP from running
  don't apply either ([results/php-outside-entry-points.md](results/php-outside-entry-points.md)).
- **Deleting the file needs a PHP-FPM restart if OPcache doesn't check files.** With
  `opcache.validate_timestamps=0`, a common production setting, the deleted installer kept answering 200 for at
  least 10 seconds after deletion and was gone by the 125-second check; restarting PHP-FPM ended it at once. With
  the default setting, and on mod_php, it was 404 straight away
  ([results/opcache-after-delete.md](results/opcache-after-delete.md)).
- **The second fix needs `drush updatedb`.** Updating an 11.4.13 site's code to 11.4.14 left
  `system_post_update_mark_installation_finished` pending until `drush updatedb` ran; `state` reported it before and
  not after ([results/state-before-updatedb.txt](results/state-before-updatedb.txt),
  [results/upgrade-11.4.13-to-11.4.14.txt](results/upgrade-11.4.13-to-11.4.14.txt)). The hook writes the update's
  own time into `install_time` when the value is missing, so note it first if you need it as evidence.
- **`composer audit` already knows.** On 11.4.13 it listed SA-CORE-2026-019 and ten Twig advisories that 11.4.14's
  Twig 3.31.1 fixes; on 11.4.14 it found nothing ([results/composer-audit-11.4.13.txt](results/composer-audit-11.4.13.txt)).

The lab sites were installed on 25 November 2026, so `state` and `files` rightly flag their install date, user 1's
creation date and the settings.php change as "after the flaw went public". On a site installed earlier, those
lines only appear if something changed. The lab's first Apache run was misconfigured and answered 500 to
everything for a minute; `logs` found that burst next to installer requests in the real access logs
([results/logs-lab.txt](results/logs-lab.txt)), which is the pattern the check is for.

The scripts that produced these tables are in [lab/](lab/). They need Apache 2.4 with mod_php 8.3, mod_proxy_fcgi
and php-fpm8.3, a Drupal project, and only send GET requests to 127.0.0.1.

## Limits

- Nginx was not tested (not installed on the lab machine). Drupal's page warns that an exact-match
  `location = /core/install.php` misses `/core/install.php/foo` on servers that pass `.php/` paths to PHP; use
  `location ^~ /core/install.php`, and run `http` to confirm.
- `http` sees what the internet sees only if you run it from outside your network, against the public address.
- Log hunting depends on what your logs keep; access logs don't show POST bodies, and minute buckets compare each
  log's local time.
- The SQLite, settings.php and user 1 checks look for the traces the advisories and Searchlight Cyber's write-up
  describe. Finding nothing doesn't prove a site is clean. If anything looks wrong, follow Drupal's
  [Your Drupal site got hacked. Now what?](https://www.drupal.org/docs/develop/security/your-drupal-site-got-hacked-now-what).
- Version data is from the advisories as of 26 November 2026. Branches 10.6 and 11.3 stop getting security fixes in
  December 2026; 11.4 in April 2027
  ([PSA-2026-11-02](https://www.drupal.org/psa-2026-11-02)).

## Tests

```
python3 -m unittest discover -s tests -t .
```

89 tests; 85 run anywhere and pass on Python 3.10.12, 3.11.0rc1, 3.12.12 and 3.13.11. They use fake Drupal trees,
a local web server that records the exact paths it receives, synthetic Apache/Nginx/PHP-FPM/MySQL log lines and a
fake Drush that prints Drush 13.8's real row format. Four more run against a real site when you point them at one:

```
F2I_LAB_ROOT=/path/to/drupal-project F2I_LAB_URL=http://127.0.0.1:18081 \
python3 -m unittest discover -s tests -t .
```

They passed against the lab site described above.

## Sources

- [SA-CORE-2026-017](https://www.drupal.org/sa-core-2026-017) and [SA-CORE-2026-019](https://www.drupal.org/sa-core-2026-019) (Drupal Security Team)
- [Securing the installer (install.php)](https://www.drupal.org/docs/administering-a-drupal-site/security-in-drupal/securing-the-installer-installphp) (Drupal documentation)
- [Fail2Install: Turning System Limits into Pre-Auth RCE in Drupal](https://www.slcyber.io/research/fail2install-system-limits-pre-auth-rce-drupal) (Searchlight Cyber)
- [Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (CISA)
- Drupal core 11.4.14's `system_post_update_mark_installation_finished()` and `install_finished()`, read in the
  release's source
