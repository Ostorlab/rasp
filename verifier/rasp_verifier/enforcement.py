"""Check an authorized staging endpoint using real, externally supplied proofs.

The valid request executes once and can have side effects. Use an expendable test
account. Expired and current tokens must come from the real trust service; this
tool only inspects expiry, it cannot establish a fixture's signature validity.
"""

from __future__ import annotations

import argparse
import base64
import dataclasses
import ipaddress
import json
import math
import pathlib
import re
import time
import urllib.error
import urllib.parse
import urllib.request

_INTEGRITY_PREFIX = "x-integrity-"
_REQUIRED_HEADERS = {
    "x-integrity-token",
    "x-integrity-key",
    "x-integrity-sig",
    "x-integrity-ts",
    "x-integrity-counter",
}
_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9a-z-]+$")


@dataclasses.dataclass(frozen=True)
class ProbeRequest:
    url: str
    method: str
    body: bytes
    headers: dict[str, str]


@dataclasses.dataclass(frozen=True)
class ProbeResult:
    name: str
    status: int
    passed: bool
    detail: str


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: object,
        code: int,
        msg: str,
        headers: object,
        newurl: str,
    ) -> None:
        return None


def _normalize_headers(headers: dict[str, str]) -> dict[str, str]:
    if not isinstance(headers, dict):
        raise TypeError("headers must be an object")
    normalized: dict[str, str] = {}
    for name, value in headers.items():
        if not isinstance(name, str) or not isinstance(value, str):
            raise TypeError("headers must contain only string names and values")
        key = name.lower()
        if (
            key in normalized
            or _HEADER_NAME.fullmatch(key) is None
            or "\r" in value
            or "\n" in value
        ):
            raise ValueError("invalid or duplicate request header")
        if key in {"host", "content-length", "transfer-encoding", "connection"}:
            raise ValueError("transport headers must not be supplied in fixtures")
        normalized[key] = value
    if _REQUIRED_HEADERS.issubset(normalized) is False:
        raise ValueError("fixture is missing an integrity proof header")
    return normalized


def _expiry(token: str) -> int:
    if len(token) > 32768 or len(token.split(".")) != 3:
        raise ValueError("fixture must contain a compact JWT")
    segment = token.split(".")[1]
    try:
        payload = json.loads(
            base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
        )
    except (ValueError, UnicodeError) as error:
        raise ValueError("invalid fixture JWT payload") from error
    if not isinstance(payload, dict) or type(payload.get("exp")) is not int:
        raise ValueError("fixture JWT must contain integer exp")
    return payload["exp"]


def _validate_url(url: str, allow_loopback_http: bool) -> None:
    if not isinstance(url, str):
        raise TypeError("endpoint must be a string")
    parsed = urllib.parse.urlsplit(url)
    if parsed.hostname is None or parsed.username is not None or parsed.fragment != "":
        raise ValueError("endpoint must have a host, no user info, and no fragment")
    if parsed.scheme == "https":
        return
    if parsed.scheme == "http" and allow_loopback_http is True:
        try:
            address = ipaddress.ip_address(parsed.hostname)
        except ValueError as error:
            raise ValueError(
                "cleartext is allowed only for literal loopback addresses"
            ) from error
        if address.is_loopback is True:
            return
    raise ValueError("HTTPS is required; loopback HTTP needs explicit opt-in")


def check(
    request: ProbeRequest,
    expired_headers: dict[str, str],
    *,
    timeout: float = 10,
    allow_loopback_http: bool = False,
) -> list[ProbeResult]:
    """Send three negative probes, one positive control, and its exact replay.

    Only 401/403 count as an enforcement rejection. Redirects, connection errors,
    missing routes, rate limits, and server failures fail the gate.
    """
    _validate_url(request.url, allow_loopback_http)
    if math.isfinite(timeout) is False or timeout <= 0 or timeout > 60:
        raise ValueError("timeout must be finite and between 0 and 60 seconds")
    if request.method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
        raise ValueError("unsupported HTTP method")
    current = _normalize_headers(request.headers)
    expired = _normalize_headers(expired_headers)
    account_headers = {
        key: value
        for key, value in current.items()
        if not key.startswith(_INTEGRITY_PREFIX)
    }
    expired_account = {
        key: value
        for key, value in expired.items()
        if not key.startswith(_INTEGRITY_PREFIX)
    }
    if account_headers != expired_account:
        raise ValueError(
            "expired fixture must preserve account and application headers"
        )
    now = time.time()
    if _expiry(current["x-integrity-token"]) <= now:
        raise ValueError("positive-control token has already expired")
    if _expiry(expired["x-integrity-token"]) >= now - 60:
        raise ValueError("expired fixture must be expired by at least 60 seconds")
    missing = {
        key: value for key, value in current.items() if key != "x-integrity-token"
    }
    invalid = {**current, "x-integrity-token": "invalid"}
    cases = [
        ("missing_token", missing),
        ("invalid_token", invalid),
        ("expired_token", expired),
        ("valid_request", current),
        ("replayed_request", current),
    ]
    opener = urllib.request.build_opener(_NoRedirect(), urllib.request.ProxyHandler({}))
    results: list[ProbeResult] = []
    for name, headers in cases:
        probe = urllib.request.Request(
            request.url, request.body, headers, method=request.method
        )
        try:
            with opener.open(probe, timeout=timeout) as response:
                status = response.status
        except urllib.error.HTTPError as error:
            status = error.code
            error.close()
        except (urllib.error.URLError, TimeoutError, OSError):
            results.append(ProbeResult(name, 0, False, "connection failed"))
            continue
        expected = (
            200 <= status < 300 if name == "valid_request" else status in {401, 403}
        )
        results.append(
            ProbeResult(
                name,
                status,
                expected,
                "accepted" if expected else "unexpected HTTP status",
            )
        )
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "fixture",
        type=pathlib.Path,
        help="private JSON request fixture; never commit credentials",
    )
    parser.add_argument("--allow-loopback-http", action="store_true")
    parser.add_argument("--timeout", type=float, default=10)
    args = parser.parse_args()
    try:
        fixture = json.loads(args.fixture.read_text())
        request = ProbeRequest(
            fixture["url"],
            fixture["method"],
            base64.b64decode(fixture["bodyBase64"], validate=True),
            fixture["headers"],
        )
        results = check(
            request,
            fixture["expiredHeaders"],
            timeout=args.timeout,
            allow_loopback_http=args.allow_loopback_http,
        )
    except (ValueError, KeyError, TypeError, OSError):
        print(
            json.dumps(
                {
                    "passed": False,
                    "error": "invalid or unreadable fixture/configuration",
                }
            )
        )
        return 2
    print(
        json.dumps(
            {
                "passed": all(result.passed for result in results),
                "probes": [dataclasses.asdict(result) for result in results],
            },
            indent=2,
        )
    )
    return 0 if all(result.passed for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
