import json
from pathlib import Path

import pytest

from solana_launch_alerts import (
    InvalidAlert, KNOWN_TYPES, parse_alert, sign, verify_request, verify_signature,
)

ROOT = Path(__file__).resolve().parents[2]
VECTORS = json.loads((ROOT / "examples" / "test-vectors.json").read_text(encoding="utf-8"))
SECRET, TS = VECTORS["secret"], VECTORS["timestamp"]
NOW = int(TS) + 10
EXAMPLES = sorted((ROOT / "examples").glob("[a-z]*_*.json"))


@pytest.mark.parametrize("case", VECTORS["cases"], ids=lambda c: c["name"])
def test_vectors_sign(case):
    assert sign(SECRET, TS, case["body"]) == case["signature"]


@pytest.mark.parametrize("case", VECTORS["cases"], ids=lambda c: c["name"])
def test_vectors_verify(case):
    assert verify_signature(SECRET, TS, case["body"].encode("utf-8"), case["signature"], now=NOW)


def test_rejects_tampered_body():
    case = VECTORS["cases"][0]
    assert not verify_signature(SECRET, TS, case["body"] + " ", case["signature"], now=NOW)


def test_rejects_wrong_secret():
    case = VECTORS["cases"][0]
    assert not verify_signature("other", TS, case["body"], case["signature"], now=NOW)


@pytest.mark.parametrize("delta", [301, -301, 10_000])
def test_rejects_stale_or_future_timestamp(delta):
    case = VECTORS["cases"][0]
    assert not verify_signature(SECRET, TS, case["body"], case["signature"], now=int(TS) + delta)


@pytest.mark.parametrize("ts,sig", [(None, "ab"), (TS, None), (TS, ""), ("not-a-number", "ab")])
def test_rejects_missing_or_malformed(ts, sig):
    assert not verify_signature(SECRET, ts, b"{}", sig, now=NOW)


def test_signature_is_case_insensitive():
    case = VECTORS["cases"][0]
    assert verify_signature(SECRET, TS, case["body"], case["signature"].upper(), now=NOW)


def test_verify_request_headers_any_case():
    case = VECTORS["cases"][2]
    headers = {"x-trenchwatch-timestamp": TS, "X-TRENCHWATCH-SIGNATURE": case["signature"]}
    assert verify_request(headers, case["body"].encode("utf-8"), SECRET, now=NOW)


def test_verify_request_other_provider():
    case = VECTORS["cases"][0]
    headers = {"X-Acme-Timestamp": TS, "X-Acme-Signature": case["signature"]}
    assert verify_request(headers, case["body"], SECRET, provider="Acme", now=NOW)
    assert not verify_request(headers, case["body"], SECRET, now=NOW)


@pytest.mark.parametrize("path", EXAMPLES, ids=lambda p: p.stem)
def test_examples_parse(path):
    alert = parse_alert(path.read_bytes())
    assert alert.type == path.stem
    assert alert.is_known_type
    assert alert.sandbox is True


@pytest.mark.parametrize("path", EXAMPLES, ids=lambda p: p.stem)
def test_examples_match_json_schema(path):
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads((ROOT / "schema" / "launch-alert.v1.schema.json").read_text(encoding="utf-8"))
    jsonschema.validate(json.loads(path.read_text(encoding="utf-8")), schema)


def _example():
    return json.loads(EXAMPLES[0].read_text(encoding="utf-8"))


def test_unknown_type_and_fields_are_accepted():
    d = _example()
    d["type"], d["new_field"] = "future_code", 1
    alert = parse_alert(d)
    assert not alert.is_known_type and alert.raw["new_field"] == 1


@pytest.mark.parametrize("mutate", [
    lambda d: d.pop("id"),
    lambda d: d.update(level="HIGH"),
    lambda d: d.update(sandbox="yes"),
    lambda d: d.update(operator={}),
    lambda d: d.update(evidence=["x"]),
    lambda d: d.update(token=5),
])
def test_invalid_alerts_raise(mutate):
    d = _example()
    mutate(d)
    with pytest.raises(InvalidAlert):
        parse_alert(d)


def test_bad_json_raises():
    with pytest.raises(InvalidAlert):
        parse_alert(b"{not json")


def test_level_rank_order():
    d = _example()
    ranks = []
    for level in ("RELATED", "COORDINATED", "SUSPECTED", "CONFIRMED"):
        d["level"] = level
        ranks.append(parse_alert(d).level_rank)
    assert ranks == [0, 1, 2, 3]


def test_known_types_listed_in_spec():
    spec = (ROOT / "SPEC.md").read_text(encoding="utf-8")
    assert all(f"`{t}`" in spec for t in KNOWN_TYPES)
