"""Deployment-owned console principals: bearer hashes, tenant identity and app roles."""
from __future__ import annotations

import dataclasses
import hashlib
import hmac
import json
import pathlib
import re
import typing

from rasp_verifier import storage

ROLES = {'reader': 0, 'operator': 1, 'admin': 2}
IDENTIFIER = re.compile(r'[A-Za-z0-9_.:@-]{1,128}')


class ConsoleError(Exception):
    def __init__(self, reason: str, status: int = 400) -> None:
        super().__init__(reason)
        self.reason = reason
        self.status = status


def identifier(value: typing.Any) -> str:
    if not isinstance(value, str) or IDENTIFIER.fullmatch(value) is None:
        raise ConsoleError('invalid_identifier')
    return value


@dataclasses.dataclass(frozen=True)
class Principal:
    actor: str
    tenant_id: str
    token_sha256: str
    applications: dict[str, str]

    def __post_init__(self) -> None:
        identifier(self.actor)
        identifier(self.tenant_id)
        if re.fullmatch(r'[0-9a-f]{64}', self.token_sha256) is None or len(self.applications) == 0:
            raise ConsoleError('invalid_principal')
        for app, role in self.applications.items():
            identifier(app)
            if role not in ROLES:
                raise ConsoleError('invalid_role')


class Authorizer:
    def __init__(self, principals: list[Principal]) -> None:
        if len(principals) == 0 or len({item.token_sha256 for item in principals}) != len(principals):
            raise ConsoleError('invalid_principals')
        self.principals = principals

    def authorize(self, header: str, app: str, method: str, path: str) -> Principal:
        if len(header) > 4096 or re.fullmatch(r'Bearer [A-Za-z0-9_-]{1,2048}', header) is None:
            raise ConsoleError('unauthorized', 401)
        digest = hashlib.sha256(header[7:].encode()).hexdigest()
        principal = next((item for item in self.principals if hmac.compare_digest(item.token_sha256, digest)), None)
        if principal is None:
            raise ConsoleError('unauthorized', 401)
        role = principal.applications.get(app)
        required = 0 if method == 'GET' else 2 if path in ('/keys/rotate', '/telemetry/events', '/telemetry/deliveries') else 1
        if role is None or ROLES[role] < required:
            raise ConsoleError('forbidden', 403)
        return principal

    def scopes(self) -> set[storage.Scope]:
        return {storage.Scope(item.tenant_id, app) for item in self.principals for app in item.applications}


def load(path: pathlib.Path) -> Authorizer:
    if path.stat().st_size > 65536:
        raise ConsoleError('configuration_too_large')
    try:
        value = json.loads(path.read_text())
        if not isinstance(value, dict) or set(value) != {'principals'} or not isinstance(value['principals'], list):
            raise ConsoleError('invalid_configuration')
        principals = []
        for item in value['principals']:
            if not isinstance(item, dict) or set(item) != {'id', 'tenantId', 'tokenSha256', 'applications'} or not isinstance(item['applications'], dict):
                raise ConsoleError('invalid_configuration')
            principals.append(Principal(item['id'], item['tenantId'], item['tokenSha256'], item['applications']))
        return Authorizer(principals)
    except (ValueError, TypeError) as error:
        raise ConsoleError('invalid_configuration') from error
