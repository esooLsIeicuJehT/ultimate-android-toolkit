#!/usr/bin/env bash
set -euo pipefail

if [[ "${PREFIX:-}" != *com.termux* ]]; then
    echo "Run this installer inside Termux on Android. On Linux: python3 -m pip install ." >&2
    exit 1
fi

uat_repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
uat_install_extras=false
uat_install_frida=false
for uat_option in "$@"; do
    case "$uat_option" in
        --extras) uat_install_extras=true; uat_install_frida=true ;;
        --frida) uat_install_frida=true ;;
        *) echo "Usage: bash install-termux.sh [--extras] [--frida]" >&2; exit 1 ;;
    esac
done
pkg update -y
# aapt supplies zipalign; aapt2 is its own subpackage. Use native ARM/ARM64 builds.
pkg install -y python openjdk-21 apktool jadx apksigner aapt aapt2 binutils ripgrep unzip termux-tools
if $uat_install_extras; then
    pkg install -y android-tools llvm radare2 openssh
fi
if $uat_install_frida; then
    # Termux's frida package includes Android-native Python bindings, CLI tools and server.
    # Installing root-repo does not grant root, and no Frida server is started here.
    pkg install -y root-repo
    pkg install -y frida
fi
python -m pip install "$uat_repo_dir"
echo
echo "Installed. Run: uat doctor"
echo "Menu: uat menu"
echo "Optional shared storage access: termux-setup-storage"
echo "Keep workspaces and keystores in Termux's private home directory."
