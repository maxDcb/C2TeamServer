#!/usr/bin/env bash
set -euo pipefail

TAG="${1:-0.15.0}"
OUT_ROOT="${2:-./Release}"
REPO_URL="https://github.com/maxDcb/C2Implant/releases/download/${TAG}"

ARCHS=("x86" "x64" "arm64")
TMP_DIR="$(mktemp -d)"

cleanup() {
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

mkdir -p "${OUT_ROOT}"

echo "[*] Preparing ${OUT_ROOT}/WindowsBeacons and ${OUT_ROOT}/WindowsModules"
rm -rf "${OUT_ROOT}/WindowsBeacons" "${OUT_ROOT}/WindowsModules"
mkdir -p "${OUT_ROOT}/WindowsBeacons" "${OUT_ROOT}/WindowsModules"

for ARCH in "${ARCHS[@]}"; do
  ASSET="C2Implant-windows-${ARCH}.zip"
  URL="${REPO_URL}/${ASSET}"
  ZIP_PATH="${TMP_DIR}/${ASSET}"
  EXTRACT_DIR="${TMP_DIR}/extract-${ARCH}"

  echo "[*] Downloading ${ASSET}"
  curl -fL "${URL}" -o "${ZIP_PATH}"

  echo "[*] Extracting ${ASSET}"
  mkdir -p "${EXTRACT_DIR}"
  unzip -q "${ZIP_PATH}" -d "${EXTRACT_DIR}"

  RELEASE_ROOT="${EXTRACT_DIR}"
  if [[ -d "${EXTRACT_DIR}/Release" ]]; then
    RELEASE_ROOT="${EXTRACT_DIR}/Release"
  fi

  if [[ ! -d "${RELEASE_ROOT}/WindowsBeacons" ]]; then
    echo "[-] Missing WindowsBeacons in ${ASSET}" >&2
    exit 1
  fi

  if [[ ! -d "${RELEASE_ROOT}/WindowsModules" ]]; then
    echo "[-] Missing WindowsModules in ${ASSET}" >&2
    exit 1
  fi

  mkdir -p "${OUT_ROOT}/WindowsBeacons/${ARCH}"
  mkdir -p "${OUT_ROOT}/WindowsModules/${ARCH}"

  cp -a "${RELEASE_ROOT}/WindowsBeacons/." "${OUT_ROOT}/WindowsBeacons/${ARCH}/"
  cp -a "${RELEASE_ROOT}/WindowsModules/." "${OUT_ROOT}/WindowsModules/${ARCH}/"

  echo "[+] Imported ${ARCH}"
done

echo
echo "[+] Done. Layout:"
find "${OUT_ROOT}/WindowsBeacons" "${OUT_ROOT}/WindowsModules" -maxdepth 2 -type d | sort

