#!/usr/bin/env bash
set -euo pipefail

TAG="${1:-0.14.0}"
OUT_ROOT="${2:-./Release}"
REPO_URL="https://github.com/maxDcb/C2LinuxImplant/releases/download/${TAG}"
ASSET="Release.tar.gz"

TMP_DIR="$(mktemp -d)"

cleanup() {
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

mkdir -p "${OUT_ROOT}"

echo "[*] Preparing ${OUT_ROOT}/LinuxBeacons and ${OUT_ROOT}/LinuxModules"
rm -rf "${OUT_ROOT}/LinuxBeacons" "${OUT_ROOT}/LinuxModules"
mkdir -p "${OUT_ROOT}/LinuxBeacons" "${OUT_ROOT}/LinuxModules"

TAR_PATH="${TMP_DIR}/${ASSET}"
EXTRACT_DIR="${TMP_DIR}/extract-linux"

echo "[*] Downloading ${ASSET}"
curl -fL "${REPO_URL}/${ASSET}" -o "${TAR_PATH}"

echo "[*] Extracting ${ASSET}"
mkdir -p "${EXTRACT_DIR}"
tar -xzf "${TAR_PATH}" -C "${EXTRACT_DIR}"

RELEASE_ROOT="${EXTRACT_DIR}"
if [[ -d "${EXTRACT_DIR}/Release" ]]; then
  RELEASE_ROOT="${EXTRACT_DIR}/Release"
fi

if [[ ! -d "${RELEASE_ROOT}/LinuxBeacons" ]]; then
  echo "[-] Missing LinuxBeacons in ${ASSET}" >&2
  exit 1
fi

if [[ ! -d "${RELEASE_ROOT}/LinuxModules" ]]; then
  echo "[-] Missing LinuxModules in ${ASSET}" >&2
  exit 1
fi

cp -a "${RELEASE_ROOT}/LinuxBeacons/." "${OUT_ROOT}/LinuxBeacons/"
cp -a "${RELEASE_ROOT}/LinuxModules/." "${OUT_ROOT}/LinuxModules/"

echo
echo "[+] Done. Layout:"
find "${OUT_ROOT}/LinuxBeacons" "${OUT_ROOT}/LinuxModules" -maxdepth 1 -type f | sort

