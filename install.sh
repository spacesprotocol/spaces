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
    --to LOCATION   Where to install the binaries (default: auto-detected based on OS)
                   For macOS: ~/.local/bin if exists, else ~/bin
                   For Linux: ~/.local/bin

NOTES:
    The script will automatically choose an appropriate user-writable location.
    The chosen directory will be added to your PATH if needed.
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

add_to_path() {
  local install_dir="$1"
  local shell_rc
  local reload_needed=false

  # Detect shell configuration file based on $SHELL environment variable
  if echo "$SHELL" | grep -q "zsh"; then
    shell_rc="$HOME/.zshrc"
    shell_type="zsh"
  else
    shell_type="bash"
    shell_rc="$HOME/.bashrc"
    [ "$(uname -s)" = "Darwin" ] && shell_rc="$HOME/.bash_profile"
  fi

  if ! echo "$PATH" | tr ':' '\n' | grep -Fq "$install_dir"; then
    say "Adding $install_dir to PATH in $shell_rc"
    echo "export PATH=\"$install_dir:\$PATH\"" >> "$shell_rc"
    reload_needed=true
  fi

  # Return whether reload is needed
  [ "$reload_needed" = true ] && echo "reload" || echo "noreload"
}

determine_install_dir() {
  local os="$1"
  local specified_dir="$2"
  local install_dir

  if [ -n "$specified_dir" ]; then
    install_dir="$specified_dir"
  else
    case "$os" in
      darwin)
        if [ -d "$HOME/.local/bin" ]; then
          install_dir="$HOME/.local/bin"
        else
          install_dir="$HOME/bin"
        fi
        ;;
      linux)
        install_dir="$HOME/.local/bin"
        ;;
      *)
        err "unsupported operating system: $os"
        ;;
    esac
  fi

  # Create directory if it doesn't exist
  if [ ! -d "$install_dir" ]; then
    mkdir -p "$install_dir" || err "failed to create $install_dir"
  fi

  echo "$install_dir"
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
dest=""
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

# Determine installation directory
dest=$(determine_install_dir "$os" "$dest")
[ "$verbose" = true ] && say "installing to: $dest"

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
  err "release tag '$check_tag' not found"
fi

[ -z "$tag_without_v" ] && err "could not determine version to install"

[ "$verbose" = true ] && say "installing spaces version $check_tag"

# Create temporary directory
td=$(mktemp -d || mktemp -d -t tmp)
trap 'rm -rf "$td"' EXIT

# Construct download URL
download_url="https://github.com/spacesprotocol/spaces/releases/download/$check_tag/spaces-$check_tag-${os}-${arch}.tar.gz"

[ "$verbose" = true ] && say "downloading from: $download_url"

# Download and extract
download "$download_url" "$td/spaces.tar.gz" || err "download failed"
tar xzf "$td/spaces.tar.gz" -C "$td" || err "failed to extract archive"

# Install binaries
for binary in spaced space-cli; do
  if [ -f "$dest/$binary" ] && [ "$force" = false ]; then
    err "Found existing spaces executables at $dest. Use --force flag to overwrite"
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

# Add to PATH if needed and get reload status
reload_status=$(add_to_path "$dest")

# Final instructions
say "Successfully installed spaces $check_tag to $dest"

# Reload shell if needed
if [ "$reload_status" = "reload" ]; then
  if echo "$SHELL" | grep -q "zsh"; then
    say "Please run 'source $HOME/.zshrc' to update your PATH"
  else
    if [ "$(uname -s)" = "Darwin" ]; then
      say "Please run 'source $HOME/.bash_profile' to update your PATH"
    else
      say "Please run 'source $HOME/.bashrc' to update your PATH"
    fi
  fi
  say "Or start a new terminal session to apply changes"
fi

# Show versions if verbose
if [ "$verbose" = true ]; then
  say "installed version:"
  "$dest/spaced" --version
fi
