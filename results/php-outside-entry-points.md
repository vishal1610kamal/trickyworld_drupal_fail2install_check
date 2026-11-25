| Handler | Probe URL | Status | Result |
|---|---|---|---|
| mod_php | /sites/default/files/f2i-probe.php | 403 | did not run |
| mod_php | /modules/f2i-probe.php | 403 | did not run |
| fpm_sethandler | /sites/default/files/f2i-probe.php | 403 | did not run |
| fpm_sethandler | /modules/f2i-probe.php | 403 | did not run |
| fpm_proxypassmatch | /sites/default/files/f2i-probe.php | 200 | PHP ran |
| fpm_proxypassmatch | /modules/f2i-probe.php | 200 | PHP ran |
