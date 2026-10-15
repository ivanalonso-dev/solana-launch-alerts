"""Solana Launch Alerts: verify signed launch-risk alert webhooks and parse alerts (spec version 2026-10).

No dependencies beyond the Python standard library.

    from solana_launch_alerts import verify_request, parse_alert

    if not verify_request(request.headers, raw_body, secret):
        return 401
    alert = parse_alert(raw_body)
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from typing import Any, Mapping, Optional, Union

__all__ = [
    "API_VERSION", "KNOWN_TYPES", "LEVELS", "DEFAULT_TOLERANCE_S",
    "sign", "verify_signature", "verify_request", "parse_alert",
    "Alert", "Operator", "InvalidAlert",
]
__version__ = "1.0.0"

API_VERSION = "2026-10"
DEFAULT_TOLERANCE_S = 300
KNOWN_TYPES = frozenset({
    "operator_launch", "operator_cluster_buy", "coordinated_support", "linked_wallet_buy",
    "funding_batch", "linked_wallet", "profit_sweep", "exit_route",
})
LEVELS = ("RELATED", "COORDINATED", "SUSPECTED", "CONFIRMED")

Bytesish = Union[bytes, bytearray, str]


def _b(x: Bytesish) -> bytes:
    return x.encode("utf-8") if isinstance(x, str) else bytes(x)


def sign(secret: str, timestamp: Union[str, int], raw_body: Bytesish) -> str:
    """Hex HMAC-SHA256 of "<timestamp>.<raw body>". Used by providers, and by tests."""
    msg = str(timestamp).encode("ascii") + b"." + _b(raw_body)
    return hmac.new(_b(secret), msg, hashlib.sha256).hexdigest()


def verify_signature(secret: str, timestamp: Optional[Union[str, int]], raw_body: Bytesish,
                     signature: Optional[str], tolerance_s: int = DEFAULT_TOLERANCE_S,
                     now: Optional[float] = None) -> bool:
    """True only if the timestamp is fresh and the signature matches, compared in constant time."""
    if not secret or timestamp is None or not signature:
        return False
    try:
        ts = int(str(timestamp).strip())
    except ValueError:
        return False
    current = time.time() if now is None else now
    if abs(current - ts) > tolerance_s:
        return False
    expected = sign(secret, str(timestamp).strip(), raw_body)
    return hmac.compare_digest(expected, signature.strip().lower())


def _header(headers: Mapping[str, Any], name: str) -> Optional[str]:
    getter = getattr(headers, "get", None)
    if getter is not None:
        value = getter(name)
        if value is not None:
            return str(value)
    wanted = name.lower()
    for key, value in dict(headers).items():
        if str(key).lower() == wanted:
            return str(value)
    return None


def verify_request(headers: Mapping[str, Any], raw_body: Bytesish, secret: str, provider: str = "Trenchwatch",
                   tolerance_s: int = DEFAULT_TOLERANCE_S, now: Optional[float] = None) -> bool:
    """Verify a webhook request from its headers (X-<Provider>-Timestamp / X-<Provider>-Signature)."""
    ts = _header(headers, f"X-{provider}-Timestamp")
    sig = _header(headers, f"X-{provider}-Signature")
    return verify_signature(secret, ts, raw_body, sig, tolerance_s=tolerance_s, now=now)


class InvalidAlert(ValueError):
    """The body is not a valid launch alert."""


@dataclass(frozen=True)
class Operator:
    id: str
    address: Optional[str] = None


@dataclass(frozen=True)
class Alert:
    api_version: str
    id: str
    type: str
    level: str
    detected_at_utc: str
    token: Optional[str]
    operator: Operator
    summary: str
    evidence: list
    transaction: Optional[str]
    sandbox: bool
    raw: dict = field(repr=False, compare=False, default_factory=dict)

    @property
    def is_known_type(self) -> bool:
        """False for codes added after this SDK version; ignore or log those."""
        return self.type in KNOWN_TYPES

    @property
    def level_rank(self) -> int:
        """0 (RELATED) to 3 (CONFIRMED), for filtering by minimum strength."""
        return LEVELS.index(self.level)


def _need(d: dict, key: str, types: tuple, nullable: bool = False) -> Any:
    if key not in d:
        raise InvalidAlert(f"missing field: {key}")
    value = d[key]
    if value is None and nullable:
        return None
    if not isinstance(value, types) or isinstance(value, bool) and bool not in types:
        raise InvalidAlert(f"wrong type for field: {key}")
    return value


def parse_alert(body: Union[Bytesish, dict]) -> Alert:
    """Parse and check an alert. Unknown fields are kept in .raw; unknown type codes are accepted."""
    if isinstance(body, dict):
        d = body
    else:
        try:
            d = json.loads(_b(body).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            raise InvalidAlert(f"body is not valid JSON: {e}") from None
    if not isinstance(d, dict):
        raise InvalidAlert("alert must be a JSON object")
    level = _need(d, "level", (str,))
    if level not in LEVELS:
        raise InvalidAlert(f"unknown level: {level}")
    op = _need(d, "operator", (dict,))
    op_id = _need(op, "id", (str,))
    op_addr = op.get("address")
    if op_addr is not None and not isinstance(op_addr, str):
        raise InvalidAlert("wrong type for field: operator.address")
    evidence = _need(d, "evidence", (list,))
    if not all(isinstance(e, dict) for e in evidence):
        raise InvalidAlert("evidence items must be objects")
    for key in ("id", "type"):
        if not _need(d, key, (str,)):
            raise InvalidAlert(f"empty field: {key}")
    return Alert(
        api_version=_need(d, "api_version", (str,)),
        id=d["id"],
        type=d["type"],
        level=level,
        detected_at_utc=_need(d, "detected_at_utc", (str,)),
        token=_need(d, "token", (str,), nullable=True),
        operator=Operator(id=op_id, address=op_addr),
        summary=_need(d, "summary", (str,)),
        evidence=list(evidence),
        transaction=_need(d, "transaction", (str,), nullable=True),
        sandbox=_need(d, "sandbox", (bool,)),
        raw=d,
    )
