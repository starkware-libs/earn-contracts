#!/usr/bin/env bash
# Serve the bundled demo on http://localhost:8088
#
# Usage:
#   npm run demo:bundle && npm run demo:serve
# or
#   npm run demo
#
# MetaMask requires a real HTTP origin — `file://` URLs do NOT work.

set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
PORT="${PORT:-8088}"

if [[ ! -f "$DIR/dist/demo.js" ]]; then
  echo "demo bundle missing — run \`npm run demo:bundle\` first" >&2
  exit 1
fi

echo "Serving $DIR on http://localhost:$PORT/  (Ctrl-C to stop)"
cd "$DIR"
python3 -m http.server "$PORT"
