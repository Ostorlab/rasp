"""Durable scoped console state. Mutations and their audit records commit together."""
from __future__ import annotations

import base64
import contextlib
import hashlib
import hmac
import json
import time
import typing
import uuid

import psycopg
from psycopg.types import json as pg_json
from cryptography import fernet
from cryptography.hazmat.primitives import serialization

from rasp_verifier import console_auth
from rasp_verifier import console_policy
from rasp_verifier import jose
from rasp_verifier import postgres

KEY_OVERLAP_SECONDS = console_policy.MAX_POLICY_TTL + 60
RISK_LEVELS = ('none', 'low', 'medium', 'high', 'critical')
LIST_KINDS = {'/installs': 'install', '/policies': 'console_policy', '/secrets': 'console_secret',
              '/deliveries': 'console_delivery', '/audit': 'console_audit', '/bypass-watch': 'console_event'}


class ControlPlane:
    def __init__(self, store: postgres.PostgresStore, encryption_key: bytes) -> None:
        self.store = store
        self.scope = store.scope
        self.cipher = fernet.Fernet(encryption_key)
        self.cursor_key = hashlib.sha256(encryption_key + b'rasp-console-cursor-v1').digest()
        with self._locked() as (connection, state):
            if len(state['keys']) == 0:
                state['keys'] = [self._new_key('policy'), self._new_key('policy', prepared=True), self._new_key('token')]
                self._write(connection, 'console_state', 'state', state)

    def _read(self, connection: psycopg.Connection, kind: str, record_id: str) -> dict[str, typing.Any] | None:
        row = connection.execute('SELECT value FROM rasp_records WHERE tenant_id=%s AND app_id=%s AND kind=%s AND record_id=%s',
                                 (self.scope.tenant_id, self.scope.app_id, kind, record_id)).fetchone()
        return None if row is None else row[0]

    def _write(self, connection: psycopg.Connection, kind: str, record_id: str, value: dict[str, typing.Any]) -> None:
        connection.execute('INSERT INTO rasp_records VALUES (%s,%s,%s,%s,%s) ON CONFLICT (tenant_id,app_id,kind,record_id) DO UPDATE SET value=EXCLUDED.value',
                           (self.scope.tenant_id, self.scope.app_id, kind, record_id, pg_json.Jsonb(value)))

    @contextlib.contextmanager
    def _locked(self) -> typing.Iterator[tuple[psycopg.Connection, dict[str, typing.Any]]]:
        with self.store.transaction() as connection:
            connection.execute('INSERT INTO rasp_records VALUES (%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING',
                               (self.scope.tenant_id, self.scope.app_id, 'console_state', 'state', pg_json.Jsonb(
                                   {'revision': 0, 'active': None, 'candidate': None, 'percent': 0, 'keys': []})))
            row = connection.execute('SELECT value FROM rasp_records WHERE tenant_id=%s AND app_id=%s AND kind=%s AND record_id=%s FOR UPDATE',
                                     (self.scope.tenant_id, self.scope.app_id, 'console_state', 'state')).fetchone()
            yield connection, row[0]

    def _new_key(self, purpose: str, *, prepared: bool = False) -> dict[str, typing.Any]:
        key = jose.SigningKey.generate()
        return {'purpose': purpose, 'kid': key.kid, 'ciphertext': self.cipher.encrypt(key.to_pem()).decode(),
                'publicKey': base64.b64encode(key.private_key.public_key().public_bytes(
                    serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).decode(),
                'jwk': key.public_jwk(), 'createdAt': int(time.time()), 'retireAt': None, 'prepared': prepared}

    def _public_keys(self, state: dict[str, typing.Any]) -> dict[str, typing.Any]:
        now = int(time.time())
        keys = [key for key in state['keys'] if key['retireAt'] is None or key['retireAt'] > now]
        return {'active': {key['purpose']: key['kid'] for key in keys if key['retireAt'] is None and key['prepared'] is False},
                'policyKeys': {key['kid']: key['publicKey'] for key in keys if key['purpose'] == 'policy'},
                'jwks': {'keys': [key['jwk'] for key in keys if key['purpose'] == 'token']},
                'overlapSeconds': KEY_OVERLAP_SECONDS}

    def _audit(self, connection: psycopg.Connection, actor: str, action: str, target: str) -> None:
        record_id = f'{time.time_ns():020d}-{uuid.uuid4().hex}'
        self._write(connection, 'console_audit', record_id, {'id': record_id, 'receivedAt': time.time(),
                    'actor': actor, 'action': action.lstrip('/') + '.requested', 'target': target})

    def _policy(self, connection: psycopg.Connection, state: dict[str, typing.Any], protection: dict[str, typing.Any],
                ttl: int, percent: int) -> dict[str, typing.Any]:
        revision = console_policy.integer(state['revision'] + 1, 1, 9223372036854775807)
        state['revision'] = revision
        now = int(time.time())
        key_record = next(key for key in state['keys'] if key['purpose'] == 'policy' and key['retireAt'] is None and key['prepared'] is False)
        key = jose.SigningKey.from_pem(self.cipher.decrypt(key_record['ciphertext'].encode()))
        policy = {'revision': revision, 'issuedAt': now, 'expiresAt': now + ttl, 'config': protection,
                  'ttlSeconds': ttl, 'envelope': console_policy.sign(key, self.scope, revision, now, ttl, protection)}
        self._write(connection, 'console_policy', f'{revision:020d}', policy)
        if percent == 100:
            state['active'], state['candidate'], state['percent'] = revision, None, 0
        else:
            state['candidate'], state['percent'] = revision, percent
        return self._policy_metadata(policy, state)

    @staticmethod
    def _policy_metadata(value: dict[str, typing.Any], state: dict[str, typing.Any]) -> dict[str, typing.Any]:
        status = 'stable' if value['revision'] == state['active'] else 'candidate' if value['revision'] == state['candidate'] else 'historical'
        return {**value, 'status': status}

    def mutate(self, path: str, body: dict[str, typing.Any], actor: str) -> tuple[int, dict[str, typing.Any]]:
        routes = {'/policies/drafts': {'config', 'ttlSeconds'}, '/policies/publish': {'draftId', 'percent'},
                  '/policies/rollout': {'revision', 'percent'}, '/policies/rollback': {'revision'},
                  '/secrets': {'name', 'value', 'scopes', 'maxRisk', 'ttlSeconds'}, '/keys/rotate': {'purpose'},
                  '/telemetry/events': {'installId', 'risk', 'kind', 'signals', 'source', 'policyRevision'},
                  '/telemetry/deliveries': {'eventId', 'status', 'attempts', 'nextAttemptAt', 'lastError'}}
        if path not in routes:
            raise console_auth.ConsoleError('not_found', 404)
        if set(body) != routes[path]:
            raise console_auth.ConsoleError('invalid_fields')
        with self._locked() as (connection, state):
            status = 200
            if path == '/policies/drafts':
                protection = console_policy.config(body['config'])
                ttl = console_policy.integer(body['ttlSeconds'], 60, console_policy.MAX_POLICY_TTL)
                result = {'draftId': uuid.uuid4().hex, 'config': protection, 'ttlSeconds': ttl, 'createdAt': int(time.time())}
                self._write(connection, 'console_draft', result['draftId'], result)
                status, target = 201, result['draftId']
            elif path == '/policies/publish':
                draft_id = console_auth.identifier(body['draftId'])
                draft = self._read(connection, 'console_draft', draft_id)
                if draft is None:
                    raise console_auth.ConsoleError('not_found', 404)
                if 'publishedRevision' in draft:
                    raise console_auth.ConsoleError('already_published', 409)
                percent = console_policy.integer(body['percent'], 0, 100)
                if state['candidate'] is not None:
                    raise console_auth.ConsoleError('candidate_requires_promotion_or_rollback', 409)
                result = self._policy(connection, state, draft['config'], draft['ttlSeconds'], percent)
                draft['publishedRevision'] = result['revision']
                self._write(connection, 'console_draft', draft_id, draft)
                target = str(result['revision'])
            elif path == '/policies/rollout':
                revision = console_policy.integer(body['revision'], 1, 9223372036854775807)
                percent = console_policy.integer(body['percent'], 0, 100)
                if revision != state['candidate'] or percent < state['percent']:
                    raise console_auth.ConsoleError('rollout_conflict', 409)
                value = self._read(connection, 'console_policy', f'{revision:020d}')
                if value['expiresAt'] <= time.time():
                    raise console_auth.ConsoleError('policy_expired', 409)
                state['percent'] = percent
                if percent == 100:
                    state['active'], state['candidate'], state['percent'] = revision, None, 0
                result, target = self._policy_metadata(value, state), str(revision)
            elif path == '/policies/rollback':
                revision = console_policy.integer(body['revision'], 1, 9223372036854775807)
                previous = self._read(connection, 'console_policy', f'{revision:020d}')
                if previous is None:
                    raise console_auth.ConsoleError('not_found', 404)
                result = self._policy(connection, state, previous['config'], previous['ttlSeconds'], 100)
                target = str(result['revision'])
            elif path == '/secrets':
                name = console_auth.identifier(body['name'])
                value = body['value']
                if not isinstance(value, str) or not 1 <= len(value.encode()) <= 16384:
                    raise console_auth.ConsoleError('invalid_secret')
                scopes = console_policy.strings(body['scopes'])
                for scope in scopes:
                    console_auth.identifier(scope)
                if body['maxRisk'] not in RISK_LEVELS[:-1]:
                    raise console_auth.ConsoleError('invalid_risk')
                ttl = console_policy.integer(body['ttlSeconds'], 1, 3600)
                previous = self._read(connection, 'console_secret', name)
                version = 1 if previous is None else previous['version'] + 1
                result = {'name': name, 'version': version, 'scopes': scopes, 'maxRisk': body['maxRisk'],
                          'ttlSeconds': ttl, 'updatedAt': time.time()}
                self._write(connection, 'console_secret', name, {**result, 'ciphertext': self.cipher.encrypt(value.encode()).decode()})
                status, target = 201, name
            elif path == '/telemetry/events':
                target, result = self._event(body)
                self._write(connection, 'console_event', target, result)
                status = 201
            elif path == '/telemetry/deliveries':
                target, result = self._delivery(body)
                self._write(connection, 'console_delivery', target, result)
                status = 201
            else:
                purpose = body['purpose']
                if purpose not in ('token', 'policy'):
                    raise console_auth.ConsoleError('invalid_key_purpose')
                state['keys'] = [key for key in state['keys'] if key['retireAt'] is None or key['retireAt'] > time.time()]
                for key in state['keys']:
                    if key['purpose'] == purpose and key['retireAt'] is None and key['prepared'] is False:
                        key['retireAt'] = int(time.time()) + KEY_OVERLAP_SECONDS
                if purpose == 'policy':
                    new = next(key for key in state['keys'] if key['purpose'] == 'policy' and key['prepared'] is True)
                    new['prepared'] = False
                    state['keys'].append(self._new_key('policy', prepared=True))
                else:
                    new = self._new_key(purpose)
                    state['keys'].append(new)
                result, target = self._public_keys(state), new['kid']
            self._write(connection, 'console_state', 'state', state)
            self._audit(connection, actor, path, target)
            return status, result

    def _cursor(self, path: str, last: str) -> str:
        value = json.dumps({'scope': [self.scope.tenant_id, self.scope.app_id], 'path': path, 'last': last}, separators=(',', ':')).encode()
        return jose.b64u_encode(value) + '.' + jose.b64u_encode(hmac.digest(self.cursor_key, value, 'sha256'))

    def _after(self, path: str, cursor: str | None) -> str | None:
        if cursor is None:
            return None
        try:
            if len(cursor) > 2048:
                raise ValueError('cursor too long')
            encoded, signature = cursor.split('.')
            value = jose.b64u_decode(encoded)
            if hmac.compare_digest(hmac.digest(self.cursor_key, value, 'sha256'), jose.b64u_decode(signature)) is False:
                raise ValueError('invalid signature')
            data = json.loads(value)
            if data['scope'] != [self.scope.tenant_id, self.scope.app_id] or data['path'] != path or not isinstance(data['last'], str):
                raise ValueError('wrong cursor scope')
            return data['last']
        except (ValueError, TypeError, KeyError, jose.JoseError) as error:
            raise console_auth.ConsoleError('invalid_cursor') from error

    def _summary(self, connection: psycopg.Connection, state: dict[str, typing.Any]) -> dict[str, typing.Any]:
        rows = connection.execute('SELECT kind,count(*) FROM rasp_records WHERE tenant_id=%s AND app_id=%s GROUP BY kind',
                                  (self.scope.tenant_id, self.scope.app_id)).fetchall()
        counts = dict(rows)
        rows = connection.execute("SELECT value->>'risk',count(*) FROM rasp_records WHERE tenant_id=%s AND app_id=%s AND kind='console_event' GROUP BY value->>'risk'",
                                  (self.scope.tenant_id, self.scope.app_id)).fetchall()
        risks = dict(rows)
        pending = connection.execute("SELECT count(*) FROM rasp_records WHERE tenant_id=%s AND app_id=%s AND kind='console_delivery' AND value->>'status'='pending'",
                                     (self.scope.tenant_id, self.scope.app_id)).fetchone()[0]
        return {'tenantId': self.scope.tenant_id, 'appId': self.scope.app_id, 'installs': counts.get('install', 0),
                'builds': counts.get('build', 0), 'events': counts.get('console_event', 0), 'pendingDeliveries': pending,
                'riskCounts': {risk: risks.get(risk, 0) for risk in RISK_LEVELS}, 'activePolicyRevision': state['active'],
                'candidatePolicyRevision': state['candidate'], 'rolloutPercent': state['percent'] if state['candidate'] is not None else None}

    def get(self, path: str, query: dict[str, str]) -> dict[str, typing.Any]:
        if not set(query) <= {'limit', 'cursor'}:
            raise console_auth.ConsoleError('invalid_query')
        with self.store.transaction() as connection:
            state = self._read(connection, 'console_state', 'state')
            if path in ('/summary', '/keys'):
                if len(query) > 0:
                    raise console_auth.ConsoleError('invalid_query')
                return self._summary(connection, state) if path == '/summary' else self._public_keys(state)
            kind = LIST_KINDS.get(path)
            parameters: list[typing.Any] = [self.scope.tenant_id, self.scope.app_id]
            conditions = 'tenant_id=%s AND app_id=%s AND kind=%s'
            if path.startswith('/installs/') and path.endswith('/timeline'):
                install = console_auth.identifier(path[len('/installs/'):-len('/timeline')])
                if self._read(connection, 'install', install) is None:
                    raise console_auth.ConsoleError('not_found', 404)
                kind = 'console_event'
                conditions += " AND value->>'installId'=%s"
            if kind is None:
                raise console_auth.ConsoleError('not_found', 404)
            parameters.append(kind)
            if path.startswith('/installs/'):
                parameters.append(install)
            if path == '/bypass-watch':
                conditions += " AND (value->>'risk' IN ('high','critical') OR value->>'kind' IN ('attestation_failed','token_denied','bypass'))"
            try:
                limit = console_policy.integer(int(query.get('limit', '50')), 1, 100)
            except ValueError as error:
                raise console_auth.ConsoleError('invalid_limit') from error
            last = self._after(path, query.get('cursor'))
            if last is not None:
                conditions += ' AND record_id < %s'
                parameters.append(last)
            parameters.append(limit + 1)
            rows = connection.execute('SELECT record_id,value FROM rasp_records WHERE ' + conditions + ' ORDER BY record_id DESC LIMIT %s', parameters).fetchall()
            page = rows[:limit]
            items = []
            for record_id, value in page:
                if kind == 'install':
                    value = {'installId': value['install_id'], 'platform': value.get('platform', 'android'),
                             'securityLevel': value['security_level'], 'boundAt': value['bound_at']}
                elif kind == 'console_secret':
                    value = {key: value[key] for key in ('name', 'version', 'scopes', 'maxRisk', 'ttlSeconds', 'updatedAt')}
                elif kind == 'console_policy':
                    value = self._policy_metadata(value, state)
                items.append(value)
            return {'items': items, 'nextCursor': self._cursor(path, page[-1][0]) if len(rows) > limit else None}

    def selected_policy(self, install_id: str) -> dict[str, str] | None:
        """Trusted gateway helper; authenticate the install before calling this method."""
        console_auth.identifier(install_id)
        bucket = int.from_bytes(hashlib.sha256(f'{self.scope.tenant_id}/{self.scope.app_id}/{install_id}'.encode()).digest()[:8], 'big') % 100
        with self.store.transaction() as connection:
            state = self._read(connection, 'console_state', 'state')
            revision = state['candidate'] if state['candidate'] is not None and bucket < state['percent'] else state['active']
            if revision is None:
                return None
            policy = self._read(connection, 'console_policy', f'{revision:020d}')
            return policy['envelope'] if policy['expiresAt'] > time.time() else None

    def _event(self, value: dict[str, typing.Any]) -> tuple[str, dict[str, typing.Any]]:
        """Persist a trusted pipeline event; never treat arbitrary client claims as verified telemetry."""
        if set(value) != {'installId', 'risk', 'kind', 'signals', 'source', 'policyRevision'} or value['risk'] not in RISK_LEVELS:
            raise console_auth.ConsoleError('invalid_event')
        for name in ('installId', 'kind', 'source'):
            console_auth.identifier(value[name])
        console_policy.strings(value['signals'], console_policy.THREATS)
        if value['policyRevision'] is not None:
            console_policy.integer(value['policyRevision'], 1, 9223372036854775807)
        record_id = f'{time.time_ns():020d}-{uuid.uuid4().hex}'
        return record_id, {**value, 'id': record_id, 'receivedAt': time.time()}

    def _delivery(self, value: dict[str, typing.Any]) -> tuple[str, dict[str, typing.Any]]:
        """Persist an actual delivery worker outcome; this method performs no network delivery."""
        if set(value) != {'eventId', 'status', 'attempts', 'nextAttemptAt', 'lastError'} or value['status'] not in ('pending', 'delivered', 'failed'):
            raise console_auth.ConsoleError('invalid_delivery')
        console_auth.identifier(value['eventId'])
        console_policy.integer(value['attempts'], 0, 1000000)
        if value['nextAttemptAt'] is not None and (type(value['nextAttemptAt']) not in (int, float) or not 0 <= value['nextAttemptAt'] <= 9007199254740991):
            raise console_auth.ConsoleError('invalid_delivery')
        if value['lastError'] is not None and (not isinstance(value['lastError'], str) or len(value['lastError']) > 256):
            raise console_auth.ConsoleError('invalid_delivery')
        record_id = value['eventId']
        return record_id, value


    def record_event(self, value: dict[str, typing.Any]) -> str:
        return self.mutate('/telemetry/events', value, 'trusted-ingestion')[1]['id']

    def record_delivery(self, value: dict[str, typing.Any]) -> str:
        return self.mutate('/telemetry/deliveries', value, 'trusted-ingestion')[1]['eventId']

    def token_signing_key(self) -> jose.SigningKey:
        """Load the current shared trust-service key on every token issuance."""
        with self.store.transaction() as connection:
            state = self._read(connection, 'console_state', 'state')
            record = next(key for key in state['keys'] if key['purpose'] == 'token' and key['retireAt'] is None)
            return jose.SigningKey.from_pem(self.cipher.decrypt(record['ciphertext'].encode()))

    def token_jwks(self) -> dict[str, typing.Any]:
        return self.get('/keys', {})['jwks']
