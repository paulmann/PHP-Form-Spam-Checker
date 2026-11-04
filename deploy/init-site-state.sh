#!/usr/bin/env bash
#
# Initialise per-site runtime state for the shared spam checker.
#
# Each site runs PHP under its own Unix user (ISPmanager pool user), while the
# module lives in /var/www/lib and is owned by root:www-data. State and verdict
# logs therefore have to be owned by the *site* user, otherwise the guard fails
# open (correctly, but without protection).
#
# Usage: init-site-state.sh <site-slug> <unix-user> [module-dir]

set -euo pipefail

SITE="${1:?usage: init-site-state.sh <site-slug> <unix-user> [module-dir]}"
USER_NAME="${2:?usage: init-site-state.sh <site-slug> <unix-user> [module-dir]}"
MODULE_DIR="${3:-/var/www/lib/PHP-Form-Spam-Checker}"

if [[ ! -d "$MODULE_DIR" ]]; then
    echo "ERROR: module directory not found: $MODULE_DIR" >&2
    exit 1
fi

if ! id "$USER_NAME" >/dev/null 2>&1; then
    echo "ERROR: unknown unix user: $USER_NAME" >&2
    exit 1
fi

STATE_DIR="$MODULE_DIR/var/sites/$SITE"
LOG_DIR="$MODULE_DIR/var/log/sites"
LOG_FILE="$LOG_DIR/$SITE.jsonl"

install -d -m 775 -o "$USER_NAME" -g "$USER_NAME" "$STATE_DIR"
install -d -m 775 -o root -g www-data "$LOG_DIR"

if [[ ! -e "$LOG_FILE" ]]; then
    install -m 644 -o "$USER_NAME" -g "$USER_NAME" /dev/null "$LOG_FILE"
fi

echo "OK: $SITE -> user $USER_NAME"
echo "    state: $STATE_DIR"
echo "    log:   $LOG_FILE"
