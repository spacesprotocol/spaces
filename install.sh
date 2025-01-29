#!/usr/bin/env sh
set -eu
(set -o pipefail 2>/dev/null) && set -o pipefail

help() {
  cat <<'EOF'
Install spaces binaries (spaced and space-cli) from GitHub releases.

USAGE:
    install.sh [options]

FLAGS:
    -h, --help      Display this message
    -f, --force     Force overwriting existing binaries
    -v, --verbose   Show detailed output

OPTIONS:
    --tag VERSION   Specific version to install (e.g., 0.0.6a), defaults to latest release
    --to LOCATION   Where to install the binaries [default: /usr/local/bin]

NOTES:
    Installing to /usr/local/bin requires root privileges.
    Either run with sudo or specify a different location with --to.
EOF
}

say() {
  echo "install: $*" >&2
}

err() {
  if [ -n "${td-}" ]; then
    rm -rf "$td"
  fi
  say "error: $*"
  say "run './install.sh --help' to see available options"
  exit 1
}

need() {
  if ! command -v "$1" > /dev/null 2>&1; then
    err "need $1 (command not found)"
  fi
}

check_write_permission() {
  if [ ! -w "$1" ]; then
    err "no write permission for $1
    Either:
    1. Run this script with sudo
    2. Use --to to specify a different location for executables (e.g., --to ~/.local/bin)
    3. Grant write permission to $1"
  fi
}

download() {
  url="$1"
  output="$2"
  if command -v curl > /dev/null; then
    if [ "$output" = "-" ]; then
      curl --proto =https --tlsv1.2 -sSfL "$url"
    else
      curl --proto =https --tlsv1.2 -sSfL "$url" -o "$output"
    fi
  else
    wget --https-only --secure-protocol=TLSv1_2 --quiet "$url" -O "$output"
  fi
}

# Initialize default values
force=false
verbose=false
dest="/usr/local/bin"
tag=""
td=""

# Process command line arguments
while test $# -gt 0; do
  case $1 in
    --force | -f)
      force=true
      ;;
    --help | -h)
      help
      exit 0
      ;;
    --verbose | -v)
      verbose=true
      ;;
    --tag)
      tag="$2"
      shift
      ;;
    --to)
      dest="$2"
      shift
      ;;
    *)
      say "error: unrecognized argument '$1'"
      help
      exit 1
      ;;
  esac
  shift
done

# Check for required commands
command -v curl > /dev/null 2>&1 || command -v wget > /dev/null 2>&1 || err "need wget or curl"
need mktemp
need tar

# Detect OS and architecture
os=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m)

# Map architecture to match release files
case "$arch" in
  x86_64) arch="x86_64" ;;
  aarch64|arm64) arch="arm64" ;;
  *) err "unsupported architecture: $arch" ;;
esac

# Verify OS support
case "$os" in
  darwin|linux) ;; # supported
  *) err "unsupported operating system: $os" ;;
esac

# Get latest version if not specified
if [ -z "$tag" ]; then
  [ "$verbose" = true ] && say "fetching latest release version..."
  api_response=$(download "https://api.github.com/repos/spacesprotocol/spaces/releases/latest" - || echo "failed")
  if [ "$api_response" = "failed" ]; then
    err "could not fetch release information from GitHub"
  fi
  
  tag=$(echo "$api_response" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
  if [ -z "$tag" ]; then
    err "no releases found in the repository"
  fi
fi

# Standardize tag format
tag_without_v="${tag#v}"  # Remove 'v' prefix if present
check_tag="v$tag_without_v"  # Add 'v' prefix for consistency

# Verify the tag exists
[ "$verbose" = true ] && say "verifying tag $check_tag exists..."
api_response=$(download "https://api.github.com/repos/spacesprotocol/spaces/releases/tags/$check_tag" - || echo "failed")
if [ "$api_response" = "failed" ] || echo "$api_response" | grep -q "Not Found"; then
  err "release tag '$check_tag' not found, visit https://github.com/spacesprotocol/spaces/releases to see available versions"
fi

[ -z "$tag_without_v" ] && err "could not determine version to install"

[ "$verbose" = true ] && say "installing spaces version $check_tag"

# Create temporary directory
td=$(mktemp -d || mktemp -d -t tmp)
trap 'rm -rf "$td"' EXIT

# Verify destination directory
if [ ! -d "$dest" ]; then
  if [ "$force" = true ]; then
    if ! mkdir -p "$dest" 2>/dev/null; then
      err "failed to create $dest
    Either:
    1. Run this script with sudo
    2. Use --to to specify a different location (e.g., --to ~/.local/bin)"
    fi
  else
    err "destination directory does not exist: $dest (use --force to create it)"
  fi
fi

# Check write permissions before proceeding
check_write_permission "$dest"

# Construct download URL
download_url="https://github.com/spacesprotocol/spaces/releases/download/$check_tag/spaces-$check_tag-${os}-${arch}.tar.gz"

[ "$verbose" = true ] && say "downloading from: $download_url"

# Download and extract
download "$download_url" "$td/spaces.tar.gz" || err "download failed"
tar xzf "$td/spaces.tar.gz" -C "$td" || err "failed to extract archive"

# Install binaries
for binary in spaced space-cli; do
  if [ -f "$dest/$binary" ] && [ "$force" = false ]; then
    err "$dest/$binary already exists (use --force to overwrite)"
  fi
  
  binary_path="$dest/$binary"
  if ! find "$td" -type f -name "$binary" -exec cp {} "$binary_path" \; ; then
    err "failed to copy $binary to $dest (permission denied)"
  fi
  
  if ! chmod 755 "$binary_path"; then
    err "failed to set permissions on $binary (permission denied)"
  fi
  
  [ "$verbose" = true ] && say "installed $binary to $binary_path"
done

# Verify installation
for binary in spaced space-cli; do
  if ! [ -x "$dest/$binary" ]; then
    err "installation verification failed for $binary"
  fi
done

# Final instructions
say "Successfully intalled spaces $check_tag"
if ! echo "$PATH" | grep -q "$dest"; then
  say "note: add $dest to your PATH if not already done"
fi

# Show versions if verbose
if [ "$verbose" = true ]; then
  say "installed versions:"
  "$dest/spaced" --version
fi
