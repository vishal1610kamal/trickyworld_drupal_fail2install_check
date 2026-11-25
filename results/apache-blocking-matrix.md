| Handler | Option | URL | Status | Final URL | Body |
|---|---|---|---|---|---|
| mod_php | stock | `/core/install.php` | 200 | `/core/install.php` | already-installed page |
| mod_php | stock | `/install.php` | 200 | `/core/install.php` | already-installed page |
| mod_php | stock | `/core/install.php/foo` | 200 | `/core/install.php/foo` | already-installed page |
| mod_php | stock | `/core//install.php` | 200 | `/core//install.php` | already-installed page |
| mod_php | stock | `/core/./install.php` | 200 | `/core/./install.php` | already-installed page |
| mod_php | stock | `/` | 200 | `/` | front page |
| mod_php | stock | `/update.php` | 403 | `/update.php` |  |
| mod_php | option1 | `/core/install.php` | 403 | `/core/install.php` | access denied |
| mod_php | option1 | `/install.php` | 403 | `/core/install.php` | access denied |
| mod_php | option1 | `/core/install.php/foo` | 403 | `/core/install.php/foo` | access denied |
| mod_php | option1 | `/core//install.php` | 403 | `/core//install.php` | access denied |
| mod_php | option1 | `/core/./install.php` | 403 | `/core/./install.php` | access denied |
| mod_php | option1 | `/` | 200 | `/` | front page |
| mod_php | option1 | `/update.php` | 403 | `/update.php` |  |
| mod_php | option2 | `/core/install.php` | 403 | `/core/install.php` | access denied |
| mod_php | option2 | `/install.php` | 403 | `/install.php` | access denied |
| mod_php | option2 | `/core/install.php/foo` | 403 | `/core/install.php/foo` | access denied |
| mod_php | option2 | `/core//install.php` | 403 | `/core//install.php` | access denied |
| mod_php | option2 | `/core/./install.php` | 403 | `/core/./install.php` | access denied |
| mod_php | option2 | `/` | 200 | `/` | front page |
| mod_php | option2 | `/update.php` | 403 | `/update.php` |  |
| mod_php | option3 | `/core/install.php` | 404 | `/core/install.php` | not found |
| mod_php | option3 | `/install.php` | 404 | `/core/install.php` | not found |
| mod_php | option3 | `/core/install.php/foo` | 404 | `/core/install.php/foo` | not found |
| mod_php | option3 | `/core//install.php` | 404 | `/core//install.php` | not found |
| mod_php | option3 | `/core/./install.php` | 404 | `/core/./install.php` | not found |
| mod_php | option3 | `/` | 200 | `/` | front page |
| mod_php | option3 | `/update.php` | 403 | `/update.php` |  |
| fpm_sethandler | stock | `/core/install.php` | 200 | `/core/install.php` | already-installed page |
| fpm_sethandler | stock | `/install.php` | 200 | `/core/install.php` | already-installed page |
| fpm_sethandler | stock | `/core/install.php/foo` | 200 | `/core/install.php/foo` | already-installed page |
| fpm_sethandler | stock | `/core//install.php` | 200 | `/core//install.php` | already-installed page |
| fpm_sethandler | stock | `/core/./install.php` | 200 | `/core/./install.php` | already-installed page |
| fpm_sethandler | stock | `/` | 200 | `/` | front page |
| fpm_sethandler | stock | `/update.php` | 403 | `/update.php` |  |
| fpm_sethandler | option1 | `/core/install.php` | 403 | `/core/install.php` | access denied |
| fpm_sethandler | option1 | `/install.php` | 403 | `/core/install.php` | access denied |
| fpm_sethandler | option1 | `/core/install.php/foo` | 403 | `/core/install.php/foo` | access denied |
| fpm_sethandler | option1 | `/core//install.php` | 403 | `/core//install.php` | access denied |
| fpm_sethandler | option1 | `/core/./install.php` | 403 | `/core/./install.php` | access denied |
| fpm_sethandler | option1 | `/` | 200 | `/` | front page |
| fpm_sethandler | option1 | `/update.php` | 403 | `/update.php` |  |
| fpm_sethandler | option2 | `/core/install.php` | 403 | `/core/install.php` | access denied |
| fpm_sethandler | option2 | `/install.php` | 403 | `/install.php` | access denied |
| fpm_sethandler | option2 | `/core/install.php/foo` | 403 | `/core/install.php/foo` | access denied |
| fpm_sethandler | option2 | `/core//install.php` | 403 | `/core//install.php` | access denied |
| fpm_sethandler | option2 | `/core/./install.php` | 403 | `/core/./install.php` | access denied |
| fpm_sethandler | option2 | `/` | 200 | `/` | front page |
| fpm_sethandler | option2 | `/update.php` | 403 | `/update.php` |  |
| fpm_sethandler | option3 | `/core/install.php` | 404 | `/core/install.php` | not found |
| fpm_sethandler | option3 | `/install.php` | 404 | `/core/install.php` | not found |
| fpm_sethandler | option3 | `/core/install.php/foo` | 404 | `/core/install.php/foo` | not found |
| fpm_sethandler | option3 | `/core//install.php` | 404 | `/core//install.php` | not found |
| fpm_sethandler | option3 | `/core/./install.php` | 404 | `/core/./install.php` | not found |
| fpm_sethandler | option3 | `/` | 200 | `/` | front page |
| fpm_sethandler | option3 | `/update.php` | 403 | `/update.php` |  |
| fpm_proxypassmatch | stock | `/core/install.php` | 200 | `/core/install.php` | already-installed page |
| fpm_proxypassmatch | stock | `/install.php` | 404 | `/install.php` | not found |
| fpm_proxypassmatch | stock | `/core/install.php/foo` | 200 | `/core/install.php/foo` | already-installed page |
| fpm_proxypassmatch | stock | `/core//install.php` | 200 | `/core//install.php` | already-installed page |
| fpm_proxypassmatch | stock | `/core/./install.php` | 200 | `/core/./install.php` | already-installed page |
| fpm_proxypassmatch | stock | `/` | 200 | `/` | front page |
| fpm_proxypassmatch | stock | `/update.php` | 403 | `/update.php` |  |
| fpm_proxypassmatch | option1 | `/core/install.php` | 403 | `/core/install.php` | access denied |
| fpm_proxypassmatch | option1 | `/install.php` | 404 | `/install.php` | not found |
| fpm_proxypassmatch | option1 | `/core/install.php/foo` | 403 | `/core/install.php/foo` | access denied |
| fpm_proxypassmatch | option1 | `/core//install.php` | 403 | `/core//install.php` | access denied |
| fpm_proxypassmatch | option1 | `/core/./install.php` | 403 | `/core/./install.php` | access denied |
| fpm_proxypassmatch | option1 | `/` | 200 | `/` | front page |
| fpm_proxypassmatch | option1 | `/update.php` | 403 | `/update.php` |  |
| fpm_proxypassmatch | option2 | `/core/install.php` | 200 | `/core/install.php` | already-installed page |
| fpm_proxypassmatch | option2 | `/install.php` | 404 | `/install.php` | not found |
| fpm_proxypassmatch | option2 | `/core/install.php/foo` | 200 | `/core/install.php/foo` | already-installed page |
| fpm_proxypassmatch | option2 | `/core//install.php` | 200 | `/core//install.php` | already-installed page |
| fpm_proxypassmatch | option2 | `/core/./install.php` | 200 | `/core/./install.php` | already-installed page |
| fpm_proxypassmatch | option2 | `/` | 200 | `/` | front page |
| fpm_proxypassmatch | option2 | `/update.php` | 403 | `/update.php` |  |
| fpm_proxypassmatch | option3 | `/core/install.php` | 404 | `/core/install.php` | not found |
| fpm_proxypassmatch | option3 | `/install.php` | 404 | `/install.php` | not found |
| fpm_proxypassmatch | option3 | `/core/install.php/foo` | 404 | `/core/install.php/foo` | not found |
| fpm_proxypassmatch | option3 | `/core//install.php` | 404 | `/core//install.php` | not found |
| fpm_proxypassmatch | option3 | `/core/./install.php` | 404 | `/core/./install.php` | not found |
| fpm_proxypassmatch | option3 | `/` | 200 | `/` | front page |
| fpm_proxypassmatch | option3 | `/update.php` | 403 | `/update.php` |  |
