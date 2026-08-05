#!/usr/bin/env bash
# Install gossan from GitHub Releases into a durable PATH location.
#
# Copy-paste:
#   curl -sSfL https://raw.githubusercontent.com/santhreal/gossan/main/scripts/install.sh | bash
#
# Env overrides:
#   GOSSAN_INSTALL_DIR  install prefix (default: ~/.local/bin)
#   GOSSAN_VERSION      release tag without leading v (default: latest)
#   GOSSAN_REPO         owner/name (default: santhreal/gossan)
set -euo pipefail

REPO="${GOSSAN_REPO:-santhreal/gossan}"
PREFIX="${GOSSAN_INSTALL_DIR:-${HOME}/.local/bin}"
VERSION="${GOSSAN_VERSION:-}"

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "error: need \`$1\` on PATH" >&2
    exit 1
  }
}

need curl
need uname
need mktemp

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
arch="$(uname -m)"

case "${os}" in
  linux)  os_triple="unknown-linux-gnu" ;;
  darwin) os_triple="apple-darwin" ;;
  mingw*|msys*|cygwin*)
    echo "error: use scripts/install.ps1 on Windows" >&2
    exit 1
    ;;
  *)
    echo "error: unsupported OS: ${os}" >&2
    exit 1
    ;;
esac

case "${arch}" in
  x86_64|amd64) arch_triple="x86_64" ;;
  aarch64|arm64) arch_triple="aarch64" ;;
  *)
    echo "error: unsupported architecture: ${arch}" >&2
    exit 1
    ;;
esac

target="${arch_triple}-${os_triple}"
asset="gossan-${target}.tar.gz"

if [[ -n "${VERSION}" ]]; then
  base="https://github.com/${REPO}/releases/download/v${VERSION}"
else
  base="https://github.com/${REPO}/releases/latest/download"
fi

tmpdir="$(mktemp -d)"
cleanup() { rm -rf "${tmpdir}"; }
trap cleanup EXIT

echo "gossan install → ${PREFIX}"
echo "  downloading ${base}/${asset}"
curl -fsSL "${base}/${asset}" -o "${tmpdir}/${asset}"
# Best-effort checksum verification when the sidecar is published.
if curl -fsSL "${base}/${asset}.sha256" -o "${tmpdir}/${asset}.sha256" 2>/dev/null; then
  need_sha=true
  if command -v sha256sum >/dev/null 2>&1; then
    (cd "${tmpdir}" && sha256sum -c "${asset}.sha256")
  elif command -v shasum >/dev/null 2>&1; then
    expected="$(awk '{print $1}' "${tmpdir}/${asset}.sha256")"
    actual="$(shasum -a 256 "${tmpdir}/${asset}" | awk '{print $1}')"
    [[ "${expected}" == "${actual}" ]] || {
      echo "error: checksum mismatch" >&2
      exit 1
    }
  else
    need_sha=false
  fi
  if [[ "${need_sha}" == "true" ]]; then
    echo "  checksum ok"
  fi
else
  echo "  note: no ${asset}.sha256 sidecar; skipping checksum verify"
fi

tar -xzf "${tmpdir}/${asset}" -C "${tmpdir}"
bin_src="$(find "${tmpdir}" -type f -name gossan | head -n1 || true)"
if [[ -z "${bin_src}" ]]; then
  echo "error: archive did not contain gossan binary" >&2
  exit 1
fi
chmod 0755 "${bin_src}"

mkdir -p "${PREFIX}"
# Copy, never symlink into a temp extract. A real file survives reboots.
install -m 0755 "${bin_src}" "${PREFIX}/gossan"

if ! "${PREFIX}/gossan" --version >/dev/null 2>&1; then
  echo "error: installed binary does not execute (${PREFIX}/gossan)" >&2
  exit 1
fi

echo "  ✓ gossan → ${PREFIX}/gossan ($("${PREFIX}/gossan" --version 2>/dev/null | head -1))"

case ":${PATH}:" in
  *":${PREFIX}:"*) ;;
  *)
    echo
    echo "PATH note: ${PREFIX} is not on \$PATH."
    echo "Copy-paste one of these and restart your shell:"
    echo
    echo "  # bash"
    echo "  echo 'export PATH=\"${PREFIX}:\$PATH\"' >> ~/.bashrc && source ~/.bashrc"
    echo
    echo "  # zsh"
    echo "  echo 'export PATH=\"${PREFIX}:\$PATH\"' >> ~/.zshrc && source ~/.zshrc"
    echo
    echo "  # fish"
    echo "  fish -c \"fish_add_path ${PREFIX}\""
    echo
    echo "  # this session only"
    echo "  export PATH=\"${PREFIX}:\$PATH\""
    ;;
esac

echo "done. Try: gossan --version && gossan probe-engine"
