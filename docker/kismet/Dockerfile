# Kismet capture container.
# Runs with --network host + privileged (see docker-compose.yml) so it can put
# the USB Wi-Fi adapter (phy2) into monitor mode and serve its API on :2501.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# Install the Kismet apt repo key + source, then Kismet and wireless tools.
# Mirrors scripts/bootstrap.sh (release repo for the 'noble' codename).
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates wget gnupg iw rfkill \
    && wget -O - https://www.kismetwireless.net/repos/kismet-release.gpg.key --quiet \
        | gpg --dearmor \
        | tee /usr/share/keyrings/kismet-archive-keyring.gpg >/dev/null \
    && echo "deb [signed-by=/usr/share/keyrings/kismet-archive-keyring.gpg] https://www.kismetwireless.net/repos/apt/release/noble noble main" \
        > /etc/apt/sources.list.d/kismet.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends kismet \
    && rm -rf /var/lib/apt/lists/*

# Runtime credentials come from an ignored local .env file.
COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh

# The data source (-c <adapter>) is supplied via the compose `command:` so the
# adapter name is easy to change without rebuilding the image.
ENTRYPOINT ["/entrypoint.sh"]
