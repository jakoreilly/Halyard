#!/usr/bin/env sh
# Halyard quick install for Linux and macOS.
#
#   curl -fsSL https://raw.githubusercontent.com/jakoreilly/Halyard/main/scripts/install.sh | sh
#
# It does four things and stops: check node, clone (or update) the repo, run
# `halyard setup`, print the link. It does NOT register a service, open a
# firewall port, or touch your agent's configuration - each of those is a
# decision with consequences, and each has its own explicit command.
set -eu

REPO="${HALYARD_REPO:-https://github.com/jakoreilly/Halyard.git}"
DIR="${HALYARD_DIR:-$HOME/.halyard-src}"

if ! command -v node >/dev/null 2>&1; then
  echo "Halyard needs Node 18.17 or newer. Install it from https://nodejs.org and re-run." >&2
  exit 1
fi
major=$(node -p 'process.versions.node.split(".")[0]')
if [ "$major" -lt 18 ]; then
  echo "Halyard needs Node 18.17+; found $(node -v)." >&2
  exit 1
fi

if [ -d "$DIR/.git" ]; then
  echo "  updating $DIR"
  git -C "$DIR" pull --ff-only
else
  echo "  cloning into $DIR"
  git clone --depth 1 "$REPO" "$DIR"
fi

cd "$DIR"
node bin/halyard.js setup

cat <<EOF

  Next:
    node $DIR/bin/halyard.js start        run it
    node $DIR/bin/halyard.js doctor       check it
    node $DIR/bin/halyard.js hook-config  wire up the approve/deny relay

  Optional, to put it on your PATH:
    ln -s "$DIR/bin/halyard.js" /usr/local/bin/halyard

EOF
