#!/usr/bin/env bash
# s0-cli installer — POSIX-friendly, downloads the right pre-built
# binary from the latest GitHub release and installs it onto $PATH.
#
# Usage (default — install latest into /usr/local):
#     curl -fsSL https://raw.githubusercontent.com/antonellof/s0-cli/main/install.sh | bash
#
# Pin a version, install into ~/.local without sudo:
#     curl -fsSL https://raw.githubusercontent.com/antonellof/s0-cli/main/install.sh \
#       | bash -s -- --version v0.3.2 --prefix "$HOME/.local"
#
# Flags:
#     --version VERSION    Install a specific tag (default: latest GitHub release).
#     --prefix DIR         Install root. Binary lands in DIR/bin, support files in
#                          DIR/lib/s0-<platform>-<arch>. Defaults to /usr/local
#                          (uses sudo when needed).
#     --bin-dir DIR        Override just the bin dir (default: $PREFIX/bin).
#     --lib-dir DIR        Override just the lib dir (default: $PREFIX/lib).
#     --skip-verify        Skip SHA-256 verification (not recommended).
#     --init               After install, run `s0 init` to write a config
#                          file (interactive). Skipped automatically when
#                          stdin is not a TTY (e.g. piped from curl).
#     --no-init            Never prompt to run `s0 init`.
#     --uninstall          Remove a previously installed s0.
#     --help               Show this help and exit.
#
# Environment overrides (alternative to flags):
#     S0_VERSION  S0_PREFIX  S0_BIN_DIR  S0_LIB_DIR
#     S0_INIT=1            Same as --init.
#     S0_INIT=0            Same as --no-init.

set -euo pipefail

REPO="antonellof/s0-cli"
GITHUB="https://github.com"
GITHUB_API="https://api.github.com"

# ----- defaults from env --------------------------------------------------
VERSION="${S0_VERSION:-}"
PREFIX="${S0_PREFIX:-/usr/local}"
BIN_DIR="${S0_BIN_DIR:-}"
LIB_DIR="${S0_LIB_DIR:-}"
SKIP_VERIFY=0
UNINSTALL=0
# 1 = always run, 0 = never run, "" = auto (prompt only on a TTY)
RUN_INIT="${S0_INIT:-}"

# ----- helpers ------------------------------------------------------------
err()  { printf '\033[31merror\033[0m: %s\n' "$*" >&2; }
log()  { printf '\033[32m=>\033[0m %s\n'        "$*" >&2; }
warn() { printf '\033[33mwarn\033[0m: %s\n'    "$*" >&2; }
die()  { err "$*"; exit 1; }

usage() { sed -n '2,/^set -/p' "$0" | sed 's/^# \{0,1\}//;/^set -/d'; }

need() { command -v "$1" >/dev/null 2>&1 || die "missing required tool: $1"; }

sha256() {
  if   command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  elif command -v shasum    >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}'
  else die "need sha256sum or shasum to verify the download"
  fi
}

# Run a command as root only if the target path can't be written by us.
# "Writable" walks up the path until we hit the first existing ancestor
# (since the leaf often doesn't exist yet at install time) and checks
# whether *that* is writable. Avoids unconditional sudo for user-owned
# prefixes like ~/.local or /tmp/foo.
_first_existing() {
  p="$1"
  while [ -n "$p" ] && [ ! -e "$p" ]; do
    p="$(dirname "$p")"
    [ "$p" = "/" ] && break
  done
  printf '%s' "$p"
}

maybe_sudo() {
  target="$1"; shift
  anchor="$(_first_existing "$target")"
  if [ -w "$anchor" ]; then
    "$@"
  else
    if ! command -v sudo >/dev/null 2>&1; then
      die "need write access to $target (and sudo is not available)"
    fi
    log "elevating with sudo for $target"
    sudo "$@"
  fi
}

# ----- arg parse ----------------------------------------------------------
while [ "$#" -gt 0 ]; do
  case "$1" in
    --version)     VERSION="$2";   shift 2;;
    --prefix)      PREFIX="$2";    shift 2;;
    --bin-dir)     BIN_DIR="$2";   shift 2;;
    --lib-dir)     LIB_DIR="$2";   shift 2;;
    --skip-verify) SKIP_VERIFY=1;  shift;;
    --init)        RUN_INIT=1;     shift;;
    --no-init)     RUN_INIT=0;     shift;;
    --uninstall)   UNINSTALL=1;    shift;;
    -h|--help)     usage; exit 0;;
    *) die "unknown flag: $1 (try --help)";;
  esac
done

BIN_DIR="${BIN_DIR:-${PREFIX}/bin}"
LIB_DIR="${LIB_DIR:-${PREFIX}/lib}"

# ----- detect platform ----------------------------------------------------
detect_os() {
  case "$(uname -s)" in
    Linux*)             echo linux ;;
    Darwin*)            echo macos ;;
    MINGW*|MSYS*|CYGWIN*) echo windows ;;
    *) die "unsupported OS: $(uname -s) (use the .tar.gz from the release page manually)";;
  esac
}

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64)  echo x86_64 ;;
    arm64|aarch64) echo arm64  ;;
    *) die "unsupported architecture: $(uname -m)";;
  esac
}

OS="$(detect_os)"
ARCH="$(detect_arch)"

if [ "$OS" = "windows" ] && [ "$ARCH" != "x86_64" ]; then
  die "Windows on $ARCH is not built. Use WSL2 with the linux-arm64 binary."
fi

ASSET_NAME="s0-${OS}-${ARCH}"
EXT="tar.gz"
[ "$OS" = "windows" ] && EXT="zip"
ARCHIVE="${ASSET_NAME}.${EXT}"

# ----- uninstall path ----------------------------------------------------
if [ "$UNINSTALL" = "1" ]; then
  bin="${BIN_DIR}/s0"
  [ "$OS" = "windows" ] && bin="${BIN_DIR}/s0.exe"
  lib="${LIB_DIR}/${ASSET_NAME}"
  if [ -e "$bin" ] || [ -L "$bin" ]; then
    log "removing $bin"
    maybe_sudo "$(dirname "$bin")" rm -f "$bin"
  fi
  if [ -d "$lib" ]; then
    log "removing $lib"
    maybe_sudo "$lib" rm -rf "$lib"
  fi
  log "uninstalled."
  exit 0
fi

# ----- resolve version ----------------------------------------------------
need curl
need uname

if [ -z "$VERSION" ]; then
  log "resolving latest release from $REPO"
  # GitHub's redirecting "latest" URL avoids needing jq.
  VERSION="$(
    curl -fsSLI -o /dev/null -w '%{url_effective}' \
      "${GITHUB}/${REPO}/releases/latest" \
      | sed -E 's#.*/tag/##'
  )"
fi
[ -z "$VERSION" ] && die "could not determine release version"
case "$VERSION" in v*) ;; *) VERSION="v${VERSION}" ;; esac

URL="${GITHUB}/${REPO}/releases/download/${VERSION}/${ARCHIVE}"
SHA_URL="${URL}.sha256"

log "platform   : ${OS}/${ARCH}"
log "version    : ${VERSION}"
log "download   : ${URL}"
log "install to : ${LIB_DIR}/${ASSET_NAME}  (symlink: ${BIN_DIR}/s0)"

# ----- fetch + verify -----------------------------------------------------
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

if ! curl -fL --retry 3 --progress-bar -o "${TMP}/${ARCHIVE}" "$URL"; then
  die "download failed. Asset may not exist for this platform yet — check ${GITHUB}/${REPO}/releases/${VERSION}"
fi

if [ "$SKIP_VERIFY" = "0" ]; then
  log "verifying SHA-256"
  if curl -fsSL -o "${TMP}/${ARCHIVE}.sha256" "$SHA_URL"; then
    expected="$(awk '{print $1}' "${TMP}/${ARCHIVE}.sha256")"
    actual="$(sha256 "${TMP}/${ARCHIVE}")"
    [ "$expected" = "$actual" ] || die "SHA-256 mismatch (expected $expected, got $actual)"
  else
    warn "no .sha256 file found at ${SHA_URL}, skipping verification"
  fi
fi

# ----- extract + install --------------------------------------------------
log "extracting"
maybe_sudo "$LIB_DIR" mkdir -p "$LIB_DIR"

if [ "$OS" = "windows" ]; then
  need unzip
  maybe_sudo "$LIB_DIR" unzip -oq "${TMP}/${ARCHIVE}" -d "$LIB_DIR"
  bin_src="${LIB_DIR}/${ASSET_NAME}/s0.exe"
  bin_dst="${BIN_DIR}/s0.exe"
else
  need tar
  maybe_sudo "$LIB_DIR" tar -xzf "${TMP}/${ARCHIVE}" -C "$LIB_DIR"
  bin_src="${LIB_DIR}/${ASSET_NAME}/s0"
  bin_dst="${BIN_DIR}/s0"
fi

[ -e "$bin_src" ] || die "expected binary not found at $bin_src"

maybe_sudo "$BIN_DIR" mkdir -p "$BIN_DIR"
maybe_sudo "$bin_dst" ln -sf "$bin_src" "$bin_dst"

# macOS Gatekeeper: strip quarantine xattrs from the unsigned bundle so
# the first launch isn't blocked. Best-effort only — fails silently on Linux.
if [ "$OS" = "macos" ] && command -v xattr >/dev/null 2>&1; then
  maybe_sudo "${LIB_DIR}/${ASSET_NAME}" xattr -dr com.apple.quarantine "${LIB_DIR}/${ASSET_NAME}" 2>/dev/null || true
fi

# ----- post-install -------------------------------------------------------
log "installed s0 → $bin_dst"

# Confirm it works AND warn the user if BIN_DIR isn't on PATH.
case ":$PATH:" in
  *":${BIN_DIR}:"*) on_path=1 ;;
  *)                on_path=0 ;;
esac

if [ "$on_path" = "1" ]; then
  "$bin_dst" version || warn "binary installed but failed to run — see error above"
else
  warn "${BIN_DIR} is not on your PATH. Add it with one of:"
  warn "    bash:  echo 'export PATH=\"${BIN_DIR}:\$PATH\"' >> ~/.bashrc"
  warn "    zsh :  echo 'export PATH=\"${BIN_DIR}:\$PATH\"' >> ~/.zshrc"
  warn "    fish:  fish_add_path '${BIN_DIR}'"
  log "or invoke directly: ${bin_dst} version"
fi

# Decide whether to launch the config wizard.
#   RUN_INIT=1  → always
#   RUN_INIT=0  → never
#   RUN_INIT="" → ask if we have a TTY, otherwise skip silently
should_init=0
case "$RUN_INIT" in
  1) should_init=1 ;;
  0) should_init=0 ;;
  "")
    # `curl … | bash` doesn't have a TTY on stdin. Don't trap users
    # there with an unanswerable y/n prompt — print the manual steps
    # instead. They can re-run with `--init` if they want the wizard.
    if [ -t 0 ] && [ -t 1 ]; then
      printf '\n\033[1m? Run `s0 init` now to set up your LLM provider + API key?\033[0m [Y/n] '
      read -r ans </dev/tty || ans="n"
      case "$ans" in
        n|N|no|NO) should_init=0 ;;
        *)         should_init=1 ;;
      esac
    fi
    ;;
esac

if [ "$should_init" = "1" ]; then
  if [ "$on_path" = "1" ]; then
    "$bin_dst" init || warn "s0 init exited non-zero — re-run it manually with: $bin_dst init"
  else
    "$bin_dst" init || warn "s0 init exited non-zero — re-run it manually with: $bin_dst init"
  fi
  cat <<EOF

ready: scan something with  s0 scan ./your/repo
docs:  https://github.com/${REPO}#readme
EOF
else
  cat <<EOF

next steps:
  1) install scanners you want (semgrep, bandit, trivy, ...)  — see 's0 doctor'
  2) configure a provider key, either with the wizard or by hand:
       - ${bin_dst} init                     ← interactive setup (recommended)
       - export OPENAI_API_KEY=sk-...
       - mkdir -p ~/.config/s0 && cp .env.example ~/.config/s0/.env
  3) scan something:  s0 scan ./your/repo

docs: https://github.com/${REPO}#readme
EOF
fi
