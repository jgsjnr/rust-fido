#!/bin/bash
# OpenSSH SSH_ASKPASS wrapper on Linux and macOS
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "${SCRIPT_DIR}/aegis_ssh_askpass.py" "$@"
