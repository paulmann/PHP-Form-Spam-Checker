#!/usr/bin/env bash
#
# Install / update the shared PHP Form Spam Checker on a server.
#
# Usage:
#   deploy/install-shared.sh [SOURCE_DIR] [DEST_DIR]
#
#   SOURCE_DIR  repository checkout (default: parent of this script)
#   DEST_DIR    shared module path (default: /var/www/lib/PHP-Form-Spam-Checker)
#
# IMPORTANT — multi-user hosts:
#   The module is shared by sites that run under different PHP-FPM users.
#   `var/` holds per-site counters and verdict logs owned by those users; this
#   script therefore updates CODE ONLY and never chowns/chmods anything under
#   var/. Rewriting var/ ownership would make every guard fail open.
#   Per-site runtime state is created with deploy/init-site-state.sh.

set -euo pipefail

SOURCE_DIR="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
DEST_DIR="${2:-/var/www/lib/PHP-Form-Spam-Checker}"
OWNER="root:www-data"
PHP_BIN="${PHP_BIN:-/opt/php85/bin/php}"

if [[ ! -f "$SOURCE_DIR/autoload.php" ]]; then
    echo "ERROR: $SOURCE_DIR does not look like the checker checkout (no autoload.php)." >&2
    exit 1
fi

if [[ "$(id -u)" -ne 0 ]]; then
    echo "ERROR: run as root (ownership and permissions are set)." >&2
    exit 1
fi

install -d -m 755 -o root -g www-data "$DEST_DIR"
install -d -m 755 -o root -g www-data "$DEST_DIR/config"
install -d -m 755 -o root -g www-data "$DEST_DIR/config/sites"

# Runtime directories: keep existing ownership; create them only when absent.
for dir in "$DEST_DIR/var" "$DEST_DIR/var/sites" "$DEST_DIR/var/log"; do
    if [[ ! -d "$dir" ]]; then
        install -d -m 775 -o root -g www-data "$dir"
    fi
done

# Code and documentation. config/sites and var are excluded on purpose: rsync
# leaves existing directories alone and `--delete` will not touch them.
rsync -a --delete \
    --exclude '.git' \
    --exclude 'vendor' \
    --exclude 'tests' \
    --exclude 'var' \
    --exclude 'config/sites' \
    --exclude 'composer.lock' \
    --exclude '.phpunit.cache' \
    "$SOURCE_DIR/" "$DEST_DIR/"

if [[ ! -f "$DEST_DIR/config/sites/default.php" ]]; then
    install -m 644 -o root -g www-data "$SOURCE_DIR/config/sites/default.php" "$DEST_DIR/config/sites/default.php"
fi

# Ownership and permissions: code only, never var/.
CODE_DIRS=(src bin integrations public config deploy docs examples)
for dir in "${CODE_DIRS[@]}"; do
    [[ -d "$DEST_DIR/$dir" ]] || continue
    chown -R "$OWNER" "$DEST_DIR/$dir"
    find "$DEST_DIR/$dir" -type d -exec chmod 755 {} +
    find "$DEST_DIR/$dir" -type f -exec chmod 644 {} +
done

for file in autoload.php composer.json README.md README.ru.md CHANGELOG.md LICENSE SECURITY.md CONTRIBUTING.md .editorconfig .gitattributes; do
    if [[ -f "$DEST_DIR/$file" ]]; then
        chown "$OWNER" "$DEST_DIR/$file"
        chmod 644 "$DEST_DIR/$file"
    fi
done
chmod 755 "$DEST_DIR/deploy" 2>/dev/null || true

# Syntax gate for every deployed PHP file.
mapfile -t FILES < <(find "$DEST_DIR/src" "$DEST_DIR/integrations" "$DEST_DIR/config" -type f -name '*.php' -print)
FILES+=("$DEST_DIR/bin/spam-check" "$DEST_DIR/public/check.php" "$DEST_DIR/autoload.php")

for file in "${FILES[@]}"; do
    if ! "$PHP_BIN" -l "$file" >/dev/null 2>&1; then
        echo "ERROR: syntax check failed: $file" >&2
        exit 1
    fi
done

echo "OK: module deployed to $DEST_DIR"
echo "    php:      $("$PHP_BIN" -r 'echo PHP_VERSION;')"
echo "    runtime:  var/ ownership preserved (code-only update)"
echo "    next:     1) config/sites/<host>.php (start with mode=shadow)"
echo "              2) deploy/init-site-state.sh <host> <unix-user>"
echo "    include:  require '$DEST_DIR/integrations/guard.php';"
