#!/bin/sh
# ReconPipe container entry: `gui` (compose default) or reconpipe.py args.
set -e
WORKDIR="${RECONPIPE_WORKDIR:-/work}"
mkdir -p "$WORKDIR" "${RECONPIPE_HOME:-/root/.reconpipe}"
cd "$WORKDIR"

if [ "${1:-}" = "gui" ]; then
  shift
  exec python3 /opt/reconpipe/reconpipegui.py \
    --browser \
    --host "${RECONPIPE_GUI_HOST:-0.0.0.0}" \
    --port "${RECONPIPE_GUI_PORT:-8088}" \
    "$@"
fi

if [ "${1:-}" = "sh" ] || [ "${1:-}" = "bash" ]; then
  exec "$@"
fi

exec python3 /opt/reconpipe/reconpipe.py "$@"
