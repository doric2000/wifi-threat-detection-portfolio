#!/bin/sh
set -eu
: "${KISMET_USER:?Set KISMET_USER in .env}"
: "${KISMET_PASSWORD:?Set KISMET_PASSWORD in .env}"
umask 077
printf 'httpd_bind_address=127.0.0.1
httpd_username=%s
httpd_password=%s
' "$KISMET_USER" "$KISMET_PASSWORD" > /etc/kismet/kismet_site.conf
exec kismet "$@"
