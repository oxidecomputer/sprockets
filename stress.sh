#!/usr/bin/env bash
# Repeatedly run the sprockets handshake stress test with a range of
# connection counts, appending "<connections> pass|fail" lines to a log.
#
# Usage: ./stress.sh [log file]   (default: log.txt; Ctrl-C to stop)

LOG=${1:-log.txt}
cd "$(dirname "$0")" || exit 1

# Build once up front so the loop only measures test runs.
cargo test -q -p sprockets-tls --no-run || exit 1

while true; do
    for n in 24 25 26 27; do
        if SPROCKETS_STRESS_CONNECTIONS=$n \
            cargo test -q -p sprockets-tls stress_handshake >/dev/null 2>&1; then
            result=pass
        else
            result=fail
        fi
        echo "$n $result" | tee -a "$LOG"
    done
done
