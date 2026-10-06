#!/usr/bin/env bash
set -euo pipefail

# Installs Kismet from the official repository and then Python deps.
# Supported: Ubuntu (bionic/focal/jammy/noble/plucky), Debian (bookworm/trixie), Kali.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
REQUIREMENTS_FILE="${PROJECT_ROOT}/requirements.txt"

if [[ "${EUID}" -eq 0 ]]; then
  echo "Do not run as root. Run as your normal user; sudo will be used as needed."
  exit 1
fi

if ! command -v sudo >/dev/null 2>&1; then
  echo "sudo is required but was not found."
  exit 1
fi

if [[ ! -f /etc/os-release ]]; then
  echo "Cannot detect Linux distribution (/etc/os-release not found)."
  exit 1
fi

source /etc/os-release
DISTRO_ID="${ID:-}"
CODENAME="${VERSION_CODENAME:-}"

# Kali often reports kali-rolling; Kismet repo uses 'kali'.
if [[ "${DISTRO_ID}" == "kali" ]]; then
  CODENAME="kali"
fi

case "${DISTRO_ID}:${CODENAME}" in
  ubuntu:bionic|ubuntu:focal|ubuntu:jammy|ubuntu:noble|ubuntu:plucky|debian:bookworm|debian:trixie|kali:kali)
    ;;
  *)
    echo "Unsupported distro/codename for this script: ${DISTRO_ID}:${CODENAME}"
    echo "See https://www.kismetwireless.net/packages/ and pick the matching repo manually."
    exit 1
    ;;
esac

REPO="https://www.kismetwireless.net/repos/apt/release/${CODENAME} ${CODENAME} main"
KEYRING="/usr/share/keyrings/kismet-archive-keyring.gpg"
LIST_FILE="/etc/apt/sources.list.d/kismet.list"

if [[ ! -f "${REQUIREMENTS_FILE}" ]]; then
  echo "requirements.txt not found at: ${REQUIREMENTS_FILE}"
  exit 1
fi

echo "Installing Kismet apt key..."
wget -O - https://www.kismetwireless.net/repos/kismet-release.gpg.key --quiet \
  | gpg --dearmor \
  | sudo tee "${KEYRING}" >/dev/null

echo "Configuring Kismet apt repo for ${CODENAME}..."
echo "deb [signed-by=${KEYRING}] https://www.kismetwireless.net/repos/apt/release/${CODENAME} ${CODENAME} main" \
  | sudo tee "${LIST_FILE}" >/dev/null

echo "Installing Kismet package..."
sudo apt update
sudo apt install -y kismet

echo "Installing Python dependencies..."
python3 -m pip install -r "${REQUIREMENTS_FILE}"

echo

echo "Done."
echo "If this is your first Kismet install, add your user to kismet group:"
echo "  sudo usermod -aG kismet ${USER}"
echo "Then log out and back in (or reboot) for group membership to apply."
