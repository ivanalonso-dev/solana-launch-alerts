# Solana Launch Alerts

**An open standard for launch-risk alerts on Solana launchpads, with small SDKs to receive them safely.**

Security providers, wallets, launchpads and trading terminals all want to warn users about risky token launches. Today every provider invents its own payload and its own webhook signing, so each integration is built from scratch. This project defines one simple format and one signing scheme, and ships verified reference SDKs for TypeScript and Python.

- **[SPEC.md](SPEC.md):** the alert object, the alert types, the evidence levels and the webhook signing rules.
- **[schema/](schema/launch-alert.v1.schema.json):** JSON Schema (draft 2020-12) of an alert.
- **[typescript/](typescript/)** and **[python/](python/):** reference SDKs, no runtime dependencies.
- **[examples/](examples/):** synthetic example alerts and cross-language signature test vectors.

MIT licence. Maintained by [EMERGE](#maintainers); used in production by Trenchwatch.

---

## What an alert looks like

```json
{
  "api_version": "2026-10",
  "id": "EX-0002",
  "type": "operator_cluster_buy",
  "level": "COORDINATED",
  "detected_at_utc": "2026-10-15 01:00:05",
  "token": "<mint address>",
  "operator": {"id": "TW-9001", "address": "<operator address>"},
  "summary": "5 wallets linked to tracked operator TW-9001 bought this token shortly after launch.",
  "evidence": [{"step": "buy", "wallet": "<address>", "transaction": "<signature>"}],
  "transaction": "<signature>",
  "sandbox": true
}
```

Eight stable alert types (`operator_launch`, `operator_cluster_buy`, `coordinated_support`, `linked_wallet_buy`, `funding_batch`, `linked_wallet`, `profit_sweep`, `exit_route`) and four evidence levels (`RELATED`, `COORDINATED`, `SUSPECTED`, `CONFIRMED`). The format says **what** was observed, never **how** a provider detected it.

## Receiving alerts

Every webhook carries `X-<Provider>-Timestamp` and `X-<Provider>-Signature`, the hex HMAC-SHA256 of `"<timestamp>.<raw body>"`. The SDKs check freshness (5 minutes), compare in constant time and parse the alert.

### TypeScript / Node.js (18+)

```bash
npm install solana-launch-alerts
```

```ts
import express from "express";
import { verifyRequest, parseAlert, isKnownType } from "solana-launch-alerts";

const app = express();

// Keep the RAW body: the signature covers the exact bytes sent.
app.post("/alerts", express.raw({ type: "application/json" }), (req, res) => {
  if (!verifyRequest(req.headers, req.body, process.env.WEBHOOK_SECRET!)) return res.sendStatus(401);
  const alert = parseAlert(req.body);
  res.sendStatus(200);                       // answer fast, work afterwards
  if (alert.sandbox || !isKnownType(alert.type)) return;
  queueForReview(alert);                     // your code; use alert.id to drop duplicates
});
```

### Python (3.9+)

```bash
pip install solana-launch-alerts
```

```python
import os
from fastapi import FastAPI, Request, Response
from solana_launch_alerts import verify_request, parse_alert

app = FastAPI()

@app.post("/alerts")
async def alerts(request: Request):
    raw = await request.body()               # the raw bytes, before any JSON parsing
    if not verify_request(request.headers, raw, os.environ["WEBHOOK_SECRET"]):
        return Response(status_code=401)
    alert = parse_alert(raw)
    if not alert.sandbox and alert.is_known_type:
        queue_for_review(alert)              # your code; use alert.id to drop duplicates
    return Response(status_code=200)
```

Another provider's headers? Pass its name: `verify_request(headers, raw, secret, provider="Acme")` / `verifyRequest(headers, raw, secret, { provider: "Acme" })`.

## Sending alerts (providers)

Build the alert object as in [SPEC.md](SPEC.md), serialise it once, then sign those exact bytes:

```python
from solana_launch_alerts import sign
body = json.dumps(alert).encode()
ts = str(int(time.time()))
headers = {"X-Acme-Timestamp": ts, "X-Acme-Signature": sign(secret, ts, body)}
```

Retries keep the same `id` and are signed again with a fresh timestamp.

## Tests

Both SDKs are tested against the same vectors in [`examples/test-vectors.json`](examples/test-vectors.json).

```bash
cd python && pip install -e ".[test]" && pytest
cd typescript && npm install && npm test
```

## Responsible use

Alerts are probabilistic observations from public on-chain data. They describe addresses and patterns, not people, and are not financial advice. Show them to users as context, not as accusations, and keep ordinary users' wallets out of public outputs.

## Contributing

Issues and pull requests are welcome, especially new alert types proposed by other providers, and SDKs in other languages that pass the test vectors.

## Maintainers

Built and maintained by Ivan Alonso ([EMERGE](https://github.com/ivanalonso-dev)), creator of Trenchwatch, real-time detection of serial operators on Solana launchpads. Contact: [emerge.trenchwatch@gmail.com](mailto:emerge.trenchwatch@gmail.com) · X: [@TrenchwatchTech](https://x.com/TrenchwatchTech)
