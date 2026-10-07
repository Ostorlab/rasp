#!/usr/bin/env bash
# Destructive only to this script's unique disposable container/database.
set -euo pipefail
python_bin="${RASP_TEST_PYTHON:-python3}"
repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
container="rasp-trust-test-$$"
cleanup() { docker rm --force "$container" >/dev/null 2>&1 || true; }
trap cleanup EXIT
port=""
docker run --detach --rm --name "$container" --publish 127.0.0.1::5432 \
  --env POSTGRES_PASSWORD=local_test --env POSTGRES_DB=rasp_test postgres:16-alpine >/dev/null
for attempt in $(seq 1 60); do
  if docker exec "$container" pg_isready -U postgres >/dev/null 2>&1; then break; fi
  sleep 0.5
done
port="$(docker port "$container" 5432/tcp | cut -d: -f2)"
export RASP_TEST_ADMIN_DSN="postgresql://postgres:local_test@127.0.0.1:$port/rasp_test"
export RASP_TEST_POSTGRES_DSN="postgresql://rasp_runtime:local_runtime@127.0.0.1:$port/rasp_test"
export PYTHONPATH="$repo_root/verifier${PYTHONPATH:+:$PYTHONPATH}"
"$python_bin" - <<'PY'
import os
import psycopg
from rasp_verifier import postgres
postgres.migrate(os.environ["RASP_TEST_ADMIN_DSN"])
with psycopg.connect(os.environ["RASP_TEST_ADMIN_DSN"]) as connection:
    connection.execute("CREATE ROLE rasp_runtime LOGIN PASSWORD 'local_runtime'")
    connection.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON rasp_records, rasp_challenges, rasp_counters TO rasp_runtime")
PY
"$python_bin" -m unittest discover -s "$repo_root/verifier/tests" -t "$repo_root/verifier" -q
