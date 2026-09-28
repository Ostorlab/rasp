#!/usr/bin/env bash
# Run real browser integration only against a dedicated local test database.
set -euo pipefail
repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
python_bin="${RASP_TEST_PYTHON:-python3}"
fixture_dir="$(mktemp -d /tmp/rasp-console-fixture.XXXXXX)"
backend_pid=""
cleanup() {
  if [[ -n "$backend_pid" ]]; then
    kill "$backend_pid" 2>/dev/null || true
    wait "$backend_pid" 2>/dev/null || true
  fi
  rm -rf "$fixture_dir"
}
trap cleanup EXIT
export RASP_CONSOLE_FIXTURE_DIR="$fixture_dir"
export RASP_CONSOLE_LIVE_APP="com.example"
export RASP_CONSOLE_LIVE_TOKEN="console-local-fixture-admin"
export RASP_CONSOLE_LIVE_URL="http://127.0.0.1:${RASP_CONSOLE_TEST_PORT:-49188}"
export PYTHONPATH="$repo_root/verifier${PYTHONPATH:+:$PYTHONPATH}"
"$python_bin" - <<'PY' &
import hashlib
import json
import os
import pathlib
import sys
import urllib.parse
from cryptography import fernet
from rasp_verifier import console_server

dsn = os.environ['RASP_TEST_POSTGRES_DSN']
if urllib.parse.urlsplit(dsn).hostname not in ('127.0.0.1', 'localhost', '::1'):
    raise ValueError('live tests require an isolated loopback database')
root = pathlib.Path(os.environ['RASP_CONSOLE_FIXTURE_DIR'])
config = root / 'principals.json'
config.write_text(json.dumps({'principals': [{'id': 'browser-fixture', 'tenantId': root.name,
    'tokenSha256': hashlib.sha256(os.environ['RASP_CONSOLE_LIVE_TOKEN'].encode()).hexdigest(),
    'applications': {os.environ['RASP_CONSOLE_LIVE_APP']: 'admin'}}]}))
os.environ['RASP_POSTGRES_DSN'] = dsn
os.environ['RASP_CONTROL_ENCRYPTION_KEY'] = fernet.Fernet.generate_key().decode()
sys.argv = ['console-server', '--config', str(config), '--port', str(urllib.parse.urlsplit(os.environ['RASP_CONSOLE_LIVE_URL']).port)]
console_server.main()
PY
backend_pid="$!"
"$python_bin" - <<'PY'
import os
import json
import pathlib
import time
import urllib.error
import urllib.request
url = os.environ['RASP_CONSOLE_LIVE_URL'] + '/v1/console/apps/' + os.environ['RASP_CONSOLE_LIVE_APP'] + '/summary'
request = urllib.request.Request(url, headers={'Authorization': 'Bearer ' + os.environ['RASP_CONSOLE_LIVE_TOKEN']})
for attempt in range(100):
    try:
        with urllib.request.urlopen(request, timeout=1) as response:
            summary = json.loads(response.read())
            if response.status == 200 and summary['tenantId'] == pathlib.Path(os.environ['RASP_CONSOLE_FIXTURE_DIR']).name:
                break
    except (OSError, urllib.error.URLError):
        time.sleep(0.1)
else:
    raise RuntimeError('console fixture did not start')
PY
cd "$repo_root/console"
npx playwright test tests/live.spec.js
