"""Real scoped console HTTP, persistence, signing, and authorization regressions."""
from __future__ import annotations

import base64
import concurrent.futures
import hashlib
import json
import os
import threading
import time
import unittest
import urllib.error
import urllib.request
import uuid

import psycopg
from psycopg import sql
from http import server as http_server

from cryptography import fernet

from rasp_verifier import console_auth
from rasp_verifier import console_server
from rasp_verifier import console_policy
from rasp_verifier import control_plane
from rasp_verifier import jose
from rasp_verifier import postgres
from rasp_verifier import storage
from tests import test_trust


class PrincipalTest(unittest.TestCase):
    def testAuthenticate_whenBearerInvalidOrGrantMissing_failsClosed(self) -> None:
        principal = console_auth.Principal('reader', 'tenant', hashlib.sha256(b'local-reader').hexdigest(), {'com.example': 'reader'})
        authorizer = console_auth.Authorizer([principal])
        for header in ('', 'Basic local-reader', 'Bearer invalid', 'Bearer local-reader extra'):
            with self.subTest(header=header), self.assertRaises(console_auth.ConsoleError) as caught:
                authorizer.authorize(header, 'com.example', 'GET', '/summary')
            self.assertEqual(caught.exception.status, 401)
        for method, app, route in (('GET', 'other.app', '/summary'), ('POST', 'com.example', '/secrets')):
            with self.assertRaises(console_auth.ConsoleError) as caught:
                authorizer.authorize('Bearer local-reader', app, method, route)
            self.assertEqual(caught.exception.status, 403)


@unittest.skipUnless(os.environ.get('RASP_TEST_POSTGRES_DSN'), 'requires isolated PostgreSQL DSN')
class ControlPlaneTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tenant = uuid.uuid4().hex
        self.app = 'com.example'
        self.master_key = fernet.Fernet.generate_key()
        self.store = postgres.PostgresStore(os.environ['RASP_TEST_POSTGRES_DSN'], storage.Scope(self.tenant, self.app))
        self.other = self.store.scoped(storage.Scope('other-' + self.tenant, self.app))
        self.service = control_plane.ControlPlane(self.store, self.master_key)
        self.other_service = control_plane.ControlPlane(self.other, self.master_key)
        self.addCleanup(self.store.close)
        self.addCleanup(self.other.close)
        principals = [console_auth.Principal(role, self.tenant, hashlib.sha256(role.encode()).hexdigest(), {self.app: role})
                      for role in ('reader', 'operator', 'admin')]
        principals.append(console_auth.Principal('other', self.other.scope.tenant_id, hashlib.sha256(b'other').hexdigest(), {self.app: 'admin'}))
        authorizer = console_auth.Authorizer(principals)
        self.backend = http_server.ThreadingHTTPServer(('127.0.0.1', 0), console_server.make_handler(authorizer,
            {self.store.scope: self.service, self.other.scope: self.other_service}))
        worker = threading.Thread(target=self.backend.serve_forever, daemon=True)
        worker.start()
        self.addCleanup(self.backend.server_close)
        self.addCleanup(worker.join, 2)
        self.addCleanup(self.backend.shutdown)
        self.base = f'http://127.0.0.1:{self.backend.server_port}/v1/console/apps/{self.app}'

    def request(self, path: str, body: dict | None = None, token: str = 'admin') -> tuple[int, dict]:
        headers = {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'}
        request = urllib.request.Request(self.base + path, None if body is None else json.dumps(body).encode(), headers)
        try:
            with urllib.request.urlopen(request) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read())

    def publish(self, config: dict, percent: int = 100) -> dict:
        status, draft = self.request('/policies/drafts', {'config': config, 'ttlSeconds': 3600})
        self.assertEqual(status, 201)
        status, published = self.request('/policies/publish', {'draftId': draft['draftId'], 'percent': percent})
        self.assertEqual(status, 200)
        return published

    def testConsole_whenCredentialMissingOrReaderWrites_refusesAndLeavesNoAudit(self) -> None:
        self.assertEqual(self.request('/summary', token='')[0], 401)
        self.assertEqual(self.request('/secrets', {'name': 'denied', 'value': 'never-store'}, 'reader')[0], 403)
        self.assertEqual(self.request('/keys/rotate', {'purpose': 'token'}, 'operator')[0], 403)
        self.assertEqual(self.request('/audit')[1]['items'], [])

    def testSummary_whenScopeHasNoTelemetry_returnsHonestEmptyState(self) -> None:
        status, summary = self.request('/summary')
        self.assertEqual(status, 200)
        self.assertEqual(summary['tenantId'], self.tenant)
        self.assertEqual([summary[key] for key in ('events', 'builds', 'installs', 'pendingDeliveries')], [0, 0, 0, 0])
        for path in ('/installs', '/bypass-watch', '/deliveries', '/policies', '/secrets', '/audit'):
            self.assertEqual(self.request(path)[1]['items'], [])

    def testPolicies_whenPublishedRolledOutAndRestored_signsIncreasingRevisions(self) -> None:
        first = self.publish({'checkIntervalSeconds': 30})
        second = self.publish({'checkIntervalSeconds': 15}, percent=10)
        self.assertGreater(second['revision'], first['revision'])
        summary = self.request('/summary')[1]
        self.assertEqual(summary['activePolicyRevision'], first['revision'])
        self.assertEqual(summary['candidatePolicyRevision'], second['revision'])
        self.assertEqual(self.request('/policies/rollout', {'revision': second['revision'], 'percent': 100})[0], 200)
        status, restored = self.request('/policies/rollback', {'revision': first['revision']})
        self.assertEqual(status, 200)
        self.assertGreater(restored['revision'], second['revision'])
        payload = json.loads(jose.b64u_decode(restored['envelope']['payload']))
        self.assertEqual(payload['config'], {'checkIntervalSeconds': 30})
        self.assertEqual((payload['tenantId'], payload['appId']), (self.tenant, self.app))
        keys = self.request('/keys')[1]['policyKeys']
        public = jose.load_public_key_der(base64.b64decode(keys[restored['envelope']['kid']]))
        jose.verify_proof(public, jose.b64u_decode(restored['envelope']['payload']), restored['envelope']['signature'])
        with self.assertRaises(jose.JoseError):
            jose.verify_proof(public, b'altered', restored['envelope']['signature'])
        self.assertEqual(len(jose.b64u_decode(restored['envelope']['signature'])), 64)
        restarted = control_plane.ControlPlane(self.store, self.master_key)
        self.assertEqual(restarted.get('/summary', {})['activePolicyRevision'], restored['revision'])
        actions = [row['action'] for row in self.request('/audit')[1]['items']]
        self.assertIn('policies/publish.requested', actions)
        self.assertIn('policies/rollback.requested', actions)

    def testPublish_whenDraftRaced_allocatesOneRevisionAndOneAudit(self) -> None:
        draft = self.request('/policies/drafts', {'config': {}, 'ttlSeconds': 3600})[1]
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            results = list(executor.map(lambda _: self.request('/policies/publish', {'draftId': draft['draftId'], 'percent': 100})[0], range(4)))
        self.assertEqual(results.count(200), 1)
        self.assertEqual(results.count(409), 3)
        actions = [row['action'] for row in self.request('/audit')[1]['items']]
        self.assertEqual(actions.count('policies/publish.requested'), 1)

    def testSecrets_whenVersionReplaced_encryptsAndRedactsEveryResponse(self) -> None:
        secret = {'name': 'bank.api', 'value': 'secret-do-not-expose', 'scopes': ['test:read'], 'maxRisk': 'low', 'ttlSeconds': 300}
        status, first = self.request('/secrets', secret)
        self.assertEqual(status, 201)
        self.assertEqual(first['version'], 1)
        self.assertEqual(self.request('/secrets', secret)[1]['version'], 2)
        for path in ('/secrets', '/audit', '/summary'):
            encoded = json.dumps(self.request(path)[1])
            self.assertNotIn(secret['value'], encoded)
            self.assertNotIn('ciphertext', encoded)
        stored = self.store.get('console_secret', secret['name'])
        self.assertNotIn(secret['value'], json.dumps(stored))
        self.assertEqual(fernet.Fernet(self.master_key).decrypt(stored['ciphertext'].encode()).decode(), secret['value'])
        self.assertEqual(self.request('/secrets', token='other')[1]['items'], [])
        self.assertEqual(self.request('/audit', token='other')[1]['items'], [])

    def testKeys_whenRotated_preservesPublicOverlapWithoutExposingPrivateMaterial(self) -> None:
        published = self.publish({})
        before = self.request('/keys')[1]
        status, after = self.request('/keys/rotate', {'purpose': 'policy'})
        self.assertEqual(status, 200)
        self.assertNotEqual(before['active']['policy'], after['active']['policy'])
        self.assertIn(published['envelope']['kid'], after['policyKeys'])
        self.assertNotIn('PRIVATE', json.dumps(after))
        self.assertNotIn('ciphertext', json.dumps(after))
        self.assertEqual(self.request('/keys/rotate', {'purpose': 'token'})[0], 200)
        self.assertEqual(len(self.request('/keys')[1]['jwks']['keys']), 2)

    def testLists_whenRecordsPersisted_observesRealCountsAndSignedScopedPagination(self) -> None:
        self.store.put('install', 'one', {'install_id': 'one', 'platform': 'ios', 'security_level': 'app_attest', 'bound_at': time.time(), 'public_key_der': 'private-marker'})
        self.store.put('build', 'one', {'build_key': 'hidden-key'})
        self.service.record_event({'installId': 'one', 'risk': 'high', 'kind': 'attestation_failed', 'signals': ['root'], 'source': 'trust', 'policyRevision': 1})
        self.service.record_delivery({'eventId': 'event-1', 'status': 'pending', 'attempts': 0, 'nextAttemptAt': None, 'lastError': None})
        self.assertEqual(self.request('/summary')[1]['riskCounts']['high'], 1)
        self.assertEqual(self.request('/summary')[1]['pendingDeliveries'], 1)
        self.assertEqual(len(self.request('/installs/one/timeline')[1]['items']), 1)
        self.assertEqual(len(self.request('/bypass-watch')[1]['items']), 1)
        self.assertNotIn('private-marker', json.dumps(self.request('/installs')[1]))
        self.publish({})
        self.publish({'checkIntervalSeconds': 30})
        first = self.request('/policies?limit=1')[1]
        cursor = first['nextCursor']
        self.assertIsNotNone(cursor)
        second = self.request('/policies?limit=1&cursor=' + cursor)[1]
        self.assertNotEqual(first['items'][0]['revision'], second['items'][0]['revision'])
        self.assertEqual(self.request('/policies?cursor=' + cursor, token='other')[0], 400)
        self.assertEqual(self.request('/audit?cursor=' + cursor)[0], 400)
        self.assertEqual(self.request('/policies?cursor=' + cursor[:-1] + '!')[0], 400)

    def testScope_whenSameTenantOtherApplication_hidesPoliciesAndRejectsUnassignedGrant(self) -> None:
        self.publish({})
        alternate = self.store.scoped(storage.Scope(self.tenant, 'other.app'))
        self.addCleanup(alternate.close)
        plane = control_plane.ControlPlane(alternate, self.master_key)
        self.assertEqual(plane.get('/policies', {})['items'], [])
        self.assertIsNone(alternate.get('console_policy', f'{1:020d}'))
        original = self.base
        self.base = original.replace(self.app, 'other.app')
        try:
            self.assertEqual(self.request('/summary')[0], 403)
        finally:
            self.base = original

    def testPolicySelection_whenCandidatePromotedOrExpired_preservesRevisionAndFailsClosed(self) -> None:
        stable = self.publish({})
        candidate = self.publish({'checkIntervalSeconds': 30}, 0)
        envelope = self.service.selected_policy('authenticated-install')
        self.assertEqual(json.loads(jose.b64u_decode(envelope['payload']))['revision'], stable['revision'])
        self.request('/policies/rollout', {'revision': candidate['revision'], 'percent': 100})
        envelope = self.service.selected_policy('authenticated-install')
        self.assertEqual(json.loads(jose.b64u_decode(envelope['payload']))['revision'], candidate['revision'])
        policy_id = f'{candidate["revision"]:020d}'
        expired = self.store.get('console_policy', policy_id)
        expired['expiresAt'] = int(time.time()) - 1
        self.store.put('console_policy', policy_id, expired)
        self.assertIsNone(self.service.selected_policy('authenticated-install'))

    def testInputs_whenMalformedOrUnsupported_rejectsWithoutMutation(self) -> None:
        for body in ({'config': {'devMode': True}, 'ttlSeconds': 60}, {'config': {'checkIntervalSeconds': True}, 'ttlSeconds': 60},
                     {'config': {'pins': {'example.com': ['bad']}}, 'ttlSeconds': 60},
                     {'config': {'pins': {'example.com': None}}, 'ttlSeconds': 60},
                     {'config': {'policy': {'tamper': ['wipeSecrets']}}, 'ttlSeconds': 60},
                     {'config': {'checkIntervalSeconds': 3601}, 'ttlSeconds': 60}, {'config': {}, 'ttlSeconds': 59}):
            self.assertEqual(self.request('/policies/drafts', body)[0], 400)
        self.assertEqual(self.request('/keys/rotate', {'purpose': 'unknown'})[0], 400)
        self.assertEqual(self.request('/policies?limit=101')[0], 400)
        self.assertEqual(self.request('/summary?tenantId=other')[0], 400)
        self.assertEqual(self.request('/audit')[1]['items'], [])

    @unittest.skipUnless(os.environ.get('RASP_TEST_ADMIN_DSN'), 'requires isolated owner DSN for trigger fault injection')
    def testAtomicity_whenAuditCannotInsert_rollsBackSecretWrite(self) -> None:
        function_name = 'audit_fault_' + self.tenant
        with psycopg.connect(os.environ['RASP_TEST_ADMIN_DSN']) as connection:
            connection.execute(sql.SQL("CREATE FUNCTION {}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture audit failure'; END $$").format(sql.Identifier(function_name)))
            connection.execute(sql.SQL("CREATE TRIGGER {} BEFORE INSERT ON rasp_records FOR EACH ROW WHEN (NEW.kind = 'console_audit' AND NEW.tenant_id = {}) EXECUTE FUNCTION {}()").format(
                sql.Identifier(function_name), sql.Literal(self.tenant), sql.Identifier(function_name)))
        try:
            status, result = self.request('/secrets', {'name': 'rollback', 'value': 'must-rollback', 'scopes': [], 'maxRisk': 'none', 'ttlSeconds': 300})
            self.assertEqual(status, 503)
            self.assertIsNone(self.store.get('console_secret', 'rollback'))
            self.assertEqual(self.request('/audit')[1]['items'], [])
            self.assertNotIn('fixture audit failure', json.dumps(result))
        finally:
            with psycopg.connect(os.environ['RASP_TEST_ADMIN_DSN']) as connection:
                connection.execute(sql.SQL('DROP TRIGGER {} ON rasp_records').format(sql.Identifier(function_name)))
                connection.execute(sql.SQL('DROP FUNCTION {}()').format(sql.Identifier(function_name)))

    def testTokenKeys_whenConsoleRotates_updatesTrustIssuanceAndKeepsOldTokensValid(self) -> None:
        flow = test_trust.TrustFlow()
        flow.setUp()
        flow.trust.signing_key_provider = self.service.token_signing_key
        flow.trust.jwks_provider = self.service.token_jwks
        chain, _ = flow._bind()
        first = flow._token(chain)['token']
        old_kid = json.loads(jose.b64u_decode(first.split('.')[0]))['kid']
        self.assertEqual(self.request('/keys/rotate', {'purpose': 'token'})[0], 200)
        second = flow._token(chain)['token']
        new_kid = json.loads(jose.b64u_decode(second.split('.')[0]))['kid']
        self.assertNotEqual(old_kid, new_kid)
        jose.decode_jwt(first, flow.trust.jwks()['keys'])
        jose.decode_jwt(second, flow.trust.jwks()['keys'])

    def testTelemetry_whenAdminIngests_persistsRealRowsAndReaderCannotForge(self) -> None:
        event = {'installId': 'reported', 'risk': 'critical', 'kind': 'bypass', 'signals': ['hooking'], 'source': 'trusted-worker', 'policyRevision': None}
        self.assertEqual(self.request('/telemetry/events', event, 'reader')[0], 403)
        self.assertEqual(self.request('/telemetry/events', event, 'operator')[0], 403)
        status, stored = self.request('/telemetry/events', event)
        self.assertEqual(status, 201)
        delivery = {'eventId': stored['id'], 'status': 'pending', 'attempts': 0, 'nextAttemptAt': None, 'lastError': None}
        self.assertEqual(self.request('/telemetry/deliveries', delivery)[0], 201)
        self.assertEqual(self.request('/summary')[1]['events'], 1)
        self.assertEqual(self.request('/summary')[1]['pendingDeliveries'], 1)
        self.assertEqual(self.request('/summary', token='other')[1]['events'], 0)

    def testPolicyKeys_whenRotated_activatesPreviouslyPublishedBootstrapKey(self) -> None:
        before = self.request('/keys')[1]
        prepared = set(before['policyKeys']) - {before['active']['policy']}
        self.assertEqual(len(prepared), 1)
        rotated = self.request('/keys/rotate', {'purpose': 'policy'})[1]
        self.assertIn(rotated['active']['policy'], prepared)

    def testRollout_whenCandidateWouldBeReplacedOrDecreased_rejectsWithoutDowngrade(self) -> None:
        self.publish({})
        candidate = self.publish({'checkIntervalSeconds': 30}, 10)
        self.assertEqual(self.request('/policies/rollout', {'revision': candidate['revision'], 'percent': 5})[0], 409)
        draft = self.request('/policies/drafts', {'config': {}, 'ttlSeconds': 60})[1]
        self.assertEqual(self.request('/policies/publish', {'draftId': draft['draftId'], 'percent': 10})[0], 409)


class PolicyValidationTest(unittest.TestCase):
    def testPolicy_whenSdkReactionsAndWipeConfigured_acceptsSeparateControls(self) -> None:
        value = {'policy': {'tamper': ['report', 'silentDegrade']}, 'wipeOnThreats': ['hooking'],
                 'checkIntervalSeconds': 3600, 'reactionDelayMillis': 0,
                 'accessibilityAllowlist': ['org.example.assistive'], 'pins': {'example.com': [base64.b64encode(b'x' * 32).decode()]}}
        self.assertEqual(console_policy.config(value), value)

    def testPolicy_whenPinValueIsWrongType_raisesControlledError(self) -> None:
        for value in (None, 1, 'digest', [], ['bad']):
            with self.subTest(value=value), self.assertRaises(console_auth.ConsoleError):
                console_policy.config({'pins': {'example.com': value}})

    def testPolicy_whenPinHostIsMixedCase_rejectsCrossPlatformAmbiguity(self) -> None:
        with self.assertRaises(console_auth.ConsoleError):
            console_policy.config({'pins': {'API.example.com': [base64.b64encode(b'x' * 32).decode()]}})
