"""Private console HTTP adapter. Deployment configuration owns every tenant/app grant."""
from __future__ import annotations

import argparse
import contextlib
import json
import os
import pathlib
import re
import typing
from http import server
from urllib import parse

import psycopg
from cryptography import fernet

from rasp_verifier import console_auth
from rasp_verifier import control_plane
from rasp_verifier import postgres
from rasp_verifier import storage

MAX_BODY_BYTES = 65536


def _pairs(items: list[tuple[str, typing.Any]]) -> dict[str, typing.Any]:
    value = {}
    for key, item in items:
        if key in value:
            raise ValueError('duplicate key')
        value[key] = item
    return value


def _constant(value: str) -> typing.NoReturn:
    raise ValueError('non-finite JSON number')


def make_handler(authorizer: console_auth.Authorizer,
                 services: dict[storage.Scope, control_plane.ControlPlane]) -> type[server.BaseHTTPRequestHandler]:
    class Handler(server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self._handle('GET')

        def do_POST(self) -> None:
            self._handle('POST')

        def _handle(self, method: str) -> None:
            self.connection.settimeout(5)
            try:
                if len(self.path) > 4096:
                    raise console_auth.ConsoleError('invalid_path')
                url = parse.urlsplit(self.path)
                parts = url.path.split('/')
                if len(parts) < 6 or parts[1:4] != ['v1', 'console', 'apps'] or url.scheme != '' or url.netloc != '':
                    raise console_auth.ConsoleError('not_found', 404)
                if re.search(r'%(?![0-9a-fA-F]{2})', url.path) is not None:
                    raise console_auth.ConsoleError('invalid_path')
                app = console_auth.identifier(parse.unquote(parts[4], errors='strict'))
                route = '/' + '/'.join(parse.unquote(part, errors='strict') for part in parts[5:])
                headers = self.headers.get_all('Authorization', [])
                if len(headers) != 1:
                    raise console_auth.ConsoleError('unauthorized', 401)
                principal = authorizer.authorize(headers[0], app, method, route)
                service = services.get(storage.Scope(principal.tenant_id, app))
                if service is None:
                    raise console_auth.ConsoleError('forbidden', 403)
                query_items = parse.parse_qsl(url.query, keep_blank_values=True, max_num_fields=4, errors='strict')
                if len({key for key, _ in query_items}) != len(query_items):
                    raise console_auth.ConsoleError('invalid_query')
                query = dict(query_items)
                if method == 'GET':
                    status, result = 200, service.get(route, query)
                else:
                    if len(query) > 0:
                        raise console_auth.ConsoleError('invalid_query')
                    lengths = self.headers.get_all('Content-Length', [])
                    if len(lengths) != 1 or re.fullmatch(r'[0-9]{1,6}', lengths[0]) is None or self.headers.get('Transfer-Encoding') is not None:
                        raise console_auth.ConsoleError('invalid_framing')
                    length = int(lengths[0])
                    if not 1 <= length <= MAX_BODY_BYTES:
                        raise console_auth.ConsoleError('body_too_large', 413)
                    if self.headers.get_content_type() != 'application/json':
                        raise console_auth.ConsoleError('json_required', 415)
                    raw = self.rfile.read(length)
                    if len(raw) != length:
                        raise console_auth.ConsoleError('invalid_framing')
                    body = json.loads(raw, object_pairs_hook=_pairs, parse_constant=_constant)
                    if not isinstance(body, dict):
                        raise console_auth.ConsoleError('invalid_body')
                    status, result = service.mutate(route, body, principal.actor)
            except console_auth.ConsoleError as error:
                status, result = error.status, {'error': error.reason}
            except (ValueError, UnicodeError, RecursionError, TypeError) as error:
                status, result = 400, {'error': 'invalid_request'}
            except TimeoutError:
                status, result = 408, {'error': 'request_timeout'}
            except (psycopg.Error, fernet.InvalidToken):
                status, result = 503, {'error': 'backend_unavailable'}
            encoded = json.dumps(result, allow_nan=False).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(encoded)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.end_headers()
            self.wfile.write(encoded)

        def log_message(self, format: str, *args: typing.Any) -> None:
            # Console credentials and secrets must never enter access logs.
            pass

    return Handler


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=pathlib.Path, required=True, help='deployment-owned principal JSON file')
    parser.add_argument('--dsn-env', default='RASP_POSTGRES_DSN')
    parser.add_argument('--encryption-key-env', default='RASP_CONTROL_ENCRYPTION_KEY')
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=8080)
    arguments = parser.parse_args()
    try:
        authorizer = console_auth.load(arguments.config)
        dsn = os.environ[arguments.dsn_env]
        master = os.environ[arguments.encryption_key_env].encode()
        fernet.Fernet(master)
    except (KeyError, OSError, ValueError, console_auth.ConsoleError):
        parser.error('valid principal configuration, database DSN and encryption key are required')
    with contextlib.ExitStack() as stack:
        services = {}
        for scope in authorizer.scopes():
            store = stack.enter_context(postgres.PostgresStore(dsn, scope))
            services[scope] = control_plane.ControlPlane(store, master)
        backend = stack.enter_context(server.ThreadingHTTPServer((arguments.host, arguments.port), make_handler(authorizer, services)))
        backend.serve_forever()


if __name__ == '__main__':
    main()
