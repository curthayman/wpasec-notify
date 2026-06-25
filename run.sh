#!/usr/bin/env bash
# Run the notifier with config loaded from config.env
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
set -a; source "$DIR/config.env"; set +a
exec python3 "$DIR/wpasec_notify.py" "$@" >> "$DIR/wpasec.log" 2>&1
