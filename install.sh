#!/bin/sh
# Installs devflow and registers it with the agent CLIs and IDEs found here.
#
#     curl -fsSL https://raw.githubusercontent.com/jholhewres/devflow/main/install.sh | sh
#
# What it does, in order, and nothing else:
#
#   1. asks GitHub which release is the latest, or takes --version;
#   2. downloads the archive that fits this machine, and checksums.txt;
#   3. refuses to go on unless the archive matches its checksum;
#   4. puts `devflow` in ~/.local/bin (or --bin-dir);
#   5. runs `devflow register`, which adds devflow to each tool found:
#      Claude Code (its plugin marketplace), Codex and Gemini CLI (their own
#      commands), Cursor, OpenCode and VS Code (their JSON config, copied to
#      <file>.devflow-backup first). Run again, it changes only what differs.
#
# Options:
#
#   --tools=claude,codex   only these: claude, codex, gemini, cursor,
#                          opencode, vscode (default: every one found)
#   --version=0.1.0        that release instead of the latest
#   --bin-dir=DIR          install there instead of ~/.local/bin
#   --from=FILE            install a local archive or binary, no download
#   --no-register          install the binary only
#   --dry-run              download and verify, then say what would change
#   --uninstall            take devflow out of the tools, then the binary
#
# Everything is inside `main`, called on the last line: a download cut off
# half way through defines a function and runs nothing.

set -eu

REPO="jholhewres/devflow"

say() { printf 'devflow: %s\n' "$*"; }
fail() {
  printf 'devflow: %s\n' "$*" >&2
  exit 1
}

fetch() {
  # HTTPS only, never older than TLS 1.2.
  curl --proto '=https' --tlsv1.2 -fsSL "$@"
}

latest_version() {
  # The `latest` page redirects to the tag: no API, no rate limit.
  where=$(curl --proto '=https' --tlsv1.2 -fsSLI -o /dev/null -w '%{url_effective}' \
    "https://github.com/$REPO/releases/latest") || return 1
  tag=${where##*/}
  case "$tag" in
    v[0-9]*) printf '%s\n' "${tag#v}" ;;
    *) return 1 ;;
  esac
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{ print $1 }'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{ print $1 }'
  else
    fail "neither sha256sum nor shasum is installed, so the download cannot be checked"
  fi
}

platform() {
  case "$(uname -s)" in
    Linux) os=linux ;;
    Darwin) os=darwin ;;
    *) fail "no build for $(uname -s): install from source with cargo install --git https://github.com/$REPO devflow-mcp" ;;
  esac
  case "$(uname -m)" in
    x86_64 | amd64) arch=amd64 ;;
    aarch64 | arm64) arch=arm64 ;;
    *) fail "no build for $(uname -m)" ;;
  esac
  printf '%s_%s\n' "$os" "$arch"
}

# Puts the verified binary at $1/devflow: from --from, or downloaded.
obtain() {
  into=$1
  if [ -n "$from" ]; then
    [ -f "$from" ] || fail "$from is not a file"
    case "$from" in
      *.tar.gz) tar xzf "$from" -C "$into" devflow || fail "$from holds no devflow" ;;
      *) cp "$from" "$into/devflow" ;;
    esac
    say "using $from"
    return
  fi
  if [ -z "$version" ]; then
    version=$(latest_version) || fail "could not tell the latest release; pass --version"
  fi
  archive="devflow_${version}_$(platform).tar.gz"
  base="https://github.com/$REPO/releases/download/v$version"
  say "downloading $archive"
  fetch "$base/$archive" -o "$into/$archive" || fail "no $archive in release v$version"
  fetch "$base/checksums.txt" -o "$into/checksums.txt" || fail "release v$version has no checksums.txt"
  want=$(awk -v name="$archive" '$2 == name || $2 == "*" name { print $1 }' "$into/checksums.txt")
  [ -n "$want" ] || fail "checksums.txt does not list $archive"
  got=$(sha256_of "$into/$archive")
  [ "$want" = "$got" ] || fail "$archive does not match its checksum: refusing to install it"
  say "checksum verified"
  tar xzf "$into/$archive" -C "$into" devflow || fail "$archive holds no devflow"
}

main() {
  tools=""
  version="${DEVFLOW_VERSION:-}"
  bin_dir="${DEVFLOW_BIN_DIR:-$HOME/.local/bin}"
  from=""
  register=1
  dry=0
  uninstall=0
  for arg in "$@"; do
    case "$arg" in
      --tools=*) tools=${arg#--tools=} ;;
      --version=*) version=${arg#--version=} ; version=${version#v} ;;
      --bin-dir=*) bin_dir=${arg#--bin-dir=} ;;
      --from=*) from=${arg#--from=} ;;
      --no-register) register=0 ;;
      --dry-run) dry=1 ;;
      --uninstall) uninstall=1 ;;
      -h | --help)
        sed -n '2,27p' "$0" 2>/dev/null | sed 's/^# \{0,1\}//'
        return 0
        ;;
      *) fail "unknown option $arg (see --help)" ;;
    esac
  done

  set --
  [ -n "$tools" ] && set -- "--tools=$tools"
  [ "$dry" = 1 ] && set -- "$@" --dry-run

  if [ "$uninstall" = 1 ]; then
    installed="$bin_dir/devflow"
    [ -x "$installed" ] || installed=$(command -v devflow 2>/dev/null || true)
    [ -n "$installed" ] || fail "devflow is not installed"
    "$installed" unregister "$@" </dev/null || say "some tools kept devflow; see above"
    if [ "$dry" = 1 ]; then
      say "would remove $installed"
    else
      rm -f "$installed"
      say "removed $installed"
    fi
    return 0
  fi

  command -v curl >/dev/null 2>&1 || [ -n "$from" ] || fail "curl is needed"
  work=$(mktemp -d "${TMPDIR:-/tmp}/devflow.XXXXXX")
  trap 'rm -rf "$work"' EXIT INT TERM
  obtain "$work"
  chmod 0755 "$work/devflow"
  "$work/devflow" --version >/dev/null 2>&1 || fail "the binary does not run on this machine"

  target="$bin_dir/devflow"
  if [ "$dry" = 1 ]; then
    say "would install $("$work/devflow" --version) to $target"
    run="$work/devflow"
  else
    mkdir -p "$bin_dir"
    # Into place by rename, so a running devflow is never half overwritten.
    cp "$work/devflow" "$target.new"
    mv -f "$target.new" "$target"
    say "installed $("$target" --version) to $target"
    run="$target"
  fi

  if [ "$register" = 1 ]; then
    "$run" register --bin="$target" "$@" </dev/null || say "some tools were not registered; see above"
  fi

  case ":$PATH:" in
    *":$bin_dir:"*) ;;
    *) say "$bin_dir is not on PATH: add it to your shell's profile so agent CLIs find devflow" ;;
  esac
}

main "$@"
