"""Validate protection settings and sign the mobile SignedPolicy envelope."""
from __future__ import annotations

import base64
import json
import re
import typing

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils

from rasp_verifier import console_auth
from rasp_verifier import jose
from rasp_verifier import storage

MAX_POLICY_TTL = 604800
THREATS = {'root', 'emulator', 'debugger', 'hooking', 'tamper', 'untrustedInstaller', 'devOptions', 'adbEnabled',
           'noScreenLock', 'accessibilityAbuse', 'overlay', 'screenCapture', 'screenRecording', 'screenMirroring',
           'remoteAccessApp', 'activeCall', 'netMitm', 'detectorFailure'}
REACTIONS = {'report', 'warnUser', 'blockSensitive', 'secureScreen', 'closeApp', 'silentDegrade'}


def integer(value: typing.Any, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise console_auth.ConsoleError('invalid_integer')
    return value


def strings(value: typing.Any, allowed: set[str] | None = None) -> list[str]:
    if not isinstance(value, list) or len(value) > 100 or len(set(item for item in value if isinstance(item, str))) != len(value):
        raise console_auth.ConsoleError('invalid_list')
    for item in value:
        if not isinstance(item, str) or not 1 <= len(item) <= 256 or (allowed is not None and item not in allowed):
            raise console_auth.ConsoleError('invalid_list')
    return value


def config(value: typing.Any) -> dict[str, typing.Any]:
    allowed = {'policy', 'checkIntervalSeconds', 'accessibilityAllowlist', 'pins', 'wipeOnThreats', 'reactionDelayMillis'}
    if not isinstance(value, dict) or len(json.dumps(value)) > 32768 or not set(value) <= allowed:
        raise console_auth.ConsoleError('invalid_policy_configuration')
    if 'checkIntervalSeconds' in value:
        integer(value['checkIntervalSeconds'], 5, 3600)
    if 'reactionDelayMillis' in value:
        integer(value['reactionDelayMillis'], 0, 60000)
    if 'wipeOnThreats' in value:
        strings(value['wipeOnThreats'], THREATS)
    if 'accessibilityAllowlist' in value:
        for package in strings(value['accessibilityAllowlist']):
            if re.fullmatch(r'[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+', package) is None:
                raise console_auth.ConsoleError('invalid_package')
    if 'policy' in value:
        policies = value['policy']
        if not isinstance(policies, dict) or not set(policies) <= THREATS:
            raise console_auth.ConsoleError('invalid_threat')
        for reactions in policies.values():
            strings(reactions, REACTIONS)
    if 'pins' in value:
        pins = value['pins']
        if not isinstance(pins, dict) or len(pins) > 100:
            raise console_auth.ConsoleError('invalid_pins')
        for host, digests in pins.items():
            if not isinstance(host, str) or host != host.lower() or re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?', host) is None:
                raise console_auth.ConsoleError('invalid_pins')
            validated = strings(digests)
            if len(validated) == 0:
                raise console_auth.ConsoleError('invalid_pins')
            for digest in validated:
                try:
                    if len(base64.b64decode(digest, validate=True)) != 32:
                        raise console_auth.ConsoleError('invalid_pins')
                except ValueError as error:
                    raise console_auth.ConsoleError('invalid_pins') from error
    return value


def sign(key: jose.SigningKey, scope: storage.Scope, revision: int, issued_at: int, ttl: int,
         protection: dict[str, typing.Any]) -> dict[str, str]:
    value = {'tenantId': scope.tenant_id, 'appId': scope.app_id, 'revision': revision,
             'issuedAt': issued_at, 'expiresAt': issued_at + ttl, 'config': protection}
    payload = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
    der = key.private_key.sign(payload, ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(der)
    return {'kid': key.kid, 'payload': jose.b64u_encode(payload),
            'signature': jose.b64u_encode(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}
