| Server | URL | before | 0 s | 3 s | 10 s | 125 s | after PHP restart |
|---|---|---|---|---|---|---|---|
| mod_php/ts=1 | `/core/install.php` | 200 | 404 | 404 | 404 | 404 | 404 |
| mod_php/ts=1 | `/core//install.php` | 200 | 404 | 404 | 404 | 404 | 404 |
| mod_php/ts=1 | `/core/./install.php` | 200 | 404 | 404 | 404 | 404 | 404 |
| mod_php/ts=1 | `/core/install.php/foo` | 200 | 404 | 404 | 404 | 404 | 404 |
| mod_php/ts=0 | `/core/install.php` | 200 | 404 | 404 | 404 | 404 | 404 |
| mod_php/ts=0 | `/core//install.php` | 200 | 404 | 404 | 404 | 404 | 404 |
| mod_php/ts=0 | `/core/./install.php` | 200 | 404 | 404 | 404 | 404 | 404 |
| mod_php/ts=0 | `/core/install.php/foo` | 200 | 404 | 404 | 404 | 404 | 404 |
| fpm_sethandler/ts=1 | `/core/install.php` | 200 | 500 | 404 | 404 | 404 | 404 |
| fpm_sethandler/ts=1 | `/core//install.php` | 200 | 404 | 404 | 404 | 404 | 404 |
| fpm_sethandler/ts=1 | `/core/./install.php` | 200 | 404 | 404 | 404 | 404 | 404 |
| fpm_sethandler/ts=1 | `/core/install.php/foo` | 200 | 404 | 404 | 404 | 404 | 404 |
| fpm_sethandler/ts=0 | `/core/install.php` | 200 | 200 | 200 | 200 | 404 | 404 |
| fpm_sethandler/ts=0 | `/core//install.php` | 200 | 200 | 200 | 200 | 404 | 404 |
| fpm_sethandler/ts=0 | `/core/./install.php` | 200 | 200 | 200 | 200 | 404 | 404 |
| fpm_sethandler/ts=0 | `/core/install.php/foo` | 200 | 200 | 200 | 200 | 404 | 404 |
| fpm_proxypassmatch/ts=1 | `/core/install.php` | 200 | 500 | 404 | 404 | 404 | 404 |
| fpm_proxypassmatch/ts=1 | `/core//install.php` | 200 | 404 | 404 | 404 | 404 | 404 |
| fpm_proxypassmatch/ts=1 | `/core/./install.php` | 200 | 404 | 404 | 404 | 404 | 404 |
| fpm_proxypassmatch/ts=1 | `/core/install.php/foo` | 200 | 404 | 404 | 404 | 404 | 404 |
| fpm_proxypassmatch/ts=0 | `/core/install.php` | 200 | 200 | 200 | 200 | 404 | 404 |
| fpm_proxypassmatch/ts=0 | `/core//install.php` | 200 | 200 | 200 | 200 | 404 | 404 |
| fpm_proxypassmatch/ts=0 | `/core/./install.php` | 200 | 200 | 200 | 200 | 404 | 404 |
| fpm_proxypassmatch/ts=0 | `/core/install.php/foo` | 200 | 404 | 404 | 404 | 404 | 404 |
