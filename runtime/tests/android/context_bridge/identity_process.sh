#!/usr/bin/env bash
# Give the JVM fixture a real global argv[0] alias, distinct from its Application package.
set -euo pipefail
exec -a fixture.global.worker "$@"
