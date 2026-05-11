#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: ./download-c2linuximplant-artifacts.sh [tag] [out_root] [arch]

Download Linux C2LinuxImplant release artifacts and stage them into:
  <out_root>/LinuxBeacons/<arch>/
  <out_root>/LinuxModules/<arch>/

Arguments:
  tag       GitHub release tag to download. Default: 0.14.0
  out_root  Release staging root. Default: ./Release
  arch      Target Linux architecture. Default: x64

Examples:
  ./download-c2linuximplant-artifacts.sh
  ./download-c2linuximplant-artifacts.sh 0.14.0 ./Release x64
USAGE
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if (( $# > 3 )); then
  echo "Error: too many arguments." >&2
  usage >&2
  exit 2
fi

TAG="${1:-0.14.0}"
OUT_ROOT="${2:-./Release}"
ARCH="${3:-x64}"
REPO_URL="https://github.com/maxDcb/C2LinuxImplant/releases/download/${TAG}"
ASSET="Release.tar.gz"

if [[ "${ARCH}" != "x64" ]]; then
  echo "Error: unsupported Linux architecture: ${ARCH}" >&2
  usage >&2
  exit 2
fi

TMP_DIR="$(mktemp -d)"

cleanup() {
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

mkdir -p "${OUT_ROOT}"

echo "[*] Preparing ${OUT_ROOT}/LinuxBeacons/${ARCH} and ${OUT_ROOT}/LinuxModules/${ARCH}"
rm -rf "${OUT_ROOT}/LinuxBeacons" "${OUT_ROOT}/LinuxModules"
mkdir -p "${OUT_ROOT}/LinuxBeacons/${ARCH}" "${OUT_ROOT}/LinuxModules/${ARCH}"

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

cp -a "${RELEASE_ROOT}/LinuxBeacons/." "${OUT_ROOT}/LinuxBeacons/${ARCH}/"
cp -a "${RELEASE_ROOT}/LinuxModules/." "${OUT_ROOT}/LinuxModules/${ARCH}/"

echo
echo "[+] Done. Layout:"
find "${OUT_ROOT}/LinuxBeacons" "${OUT_ROOT}/LinuxModules" -maxdepth 2 -type f | sort
