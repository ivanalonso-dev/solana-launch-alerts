# Solana Launch Alerts — Specification v1 (`2026-10`)

An open, provider-neutral format for **launch-risk alerts** on Solana token launchpads, and a simple, safe way to deliver them by webhook.

Any security provider, wallet, launchpad or trading terminal can **emit** or **consume** alerts in this format. When providers share one format, a platform can combine signals from several sources without writing a new integration for each.

Status: stable. Version identifier: `2026-10`. Licence: MIT.

The key words MUST, SHOULD and MAY are used as in RFC 2119.

---

## 1. The alert object

An alert is a single JSON object (UTF-8). The JSON Schema is in [`schema/launch-alert.v1.schema.json`](schema/launch-alert.v1.schema.json).

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `api_version` | string | yes | Version of this format. `"2026-10"` for v1. |
| `id` | string | yes | Unique alert id chosen by the provider. Retries of the same alert MUST keep the same `id`. |
| `type` | string | yes | What happened. See §2. Consumers MUST ignore codes they do not know. |
| `level` | string | yes | Strength of the evidence. See §3. |
| `detected_at_utc` | string | yes | When the provider detected the event, in UTC. `YYYY-MM-DD HH:MM:SS` or ISO 8601. |
| `token` | string \| null | yes | Mint address of the token concerned, or `null` when the alert is about wallets only. |
| `operator` | object | yes | The operator the alert is attributed to: `id` (provider's stable operator id, string) and `address` (string or `null`). |
| `summary` | string | yes | One or two plain-English sentences a person can read. |
| `evidence` | array of objects | yes | On-chain facts behind the alert. Each item SHOULD include `step` and `transaction` (a signature). Items MAY include other keys. May be empty. |
| `transaction` | string \| null | yes | The main transaction signature, when there is one. |
| `sandbox` | boolean | yes | `true` for synthetic or test alerts. Consumers MUST NOT act on sandbox alerts in production. |

Providers MAY add fields. Consumers MUST ignore fields they do not recognise.

Addresses and signatures are base58 strings as used on Solana.

## 2. Alert types

Codes are stable: once published, a code keeps its meaning. New codes MAY be added at any time.

| `type` | What happened |
| --- | --- |
| `operator_launch` | A known operator created a new token. |
| `operator_cluster_buy` | Several wallets linked to one known operator bought a token shortly after its launch. |
| `coordinated_support` | Wallets linked to an operator bought that operator's own new token. |
| `linked_wallet_buy` | A single wallet linked to a known operator bought a token. |
| `funding_batch` | An operator funded a set of new wallets at once. |
| `linked_wallet` | A new wallet was linked to a known operator. |
| `profit_sweep` | Proceeds were consolidated into an operator's main wallet. |
| `exit_route` | Proceeds from several wallets converged on a common destination. |

How a provider decides that any of these happened is the provider's own business. This format describes **what** was observed, not **how** it was detected.

## 3. Evidence levels

Levels are categories, not scores. In increasing strength:

| `level` | Meaning |
| --- | --- |
| `RELATED` | A transactional relationship was observed. On its own it does not prove common control. |
| `COORDINATED` | Coordinated technical or timing behaviour between linked wallets. |
| `SUSPECTED` | Several independent signals point to artificial demand. |
| `CONFIRMED` | Assigned only after external verification, never automatically. |

## 4. Webhook delivery

### 4.1 Request

The provider sends each alert as the body of an HTTPS `POST` with `Content-Type: application/json` and two headers:

| Header | Value |
| --- | --- |
| `X-<Provider>-Timestamp` | Unix time in seconds when the request was signed, as a decimal string. |
| `X-<Provider>-Signature` | Lowercase hex HMAC-SHA256 of the signing string (§4.2), keyed with the consumer's webhook secret. |

`<Provider>` is the provider's name, for example `X-Trenchwatch-Timestamp` and `X-Trenchwatch-Signature`.

### 4.2 Signing string

```
<timestamp> + "." + <raw request body bytes>
```

The signature covers the **raw bytes** of the body exactly as sent. Consumers MUST verify against the raw body, before any JSON parsing or re-serialisation.

### 4.3 Verification (consumer)

A consumer MUST:

1. Reject the request if either header is missing.
2. Reject the request if the timestamp is more than **300 seconds** away from the current time (replay protection).
3. Compute the expected signature and compare it with the received one in **constant time**.
4. Only then parse the JSON.

### 4.4 Response, retries and duplicates

- The consumer SHOULD answer `2xx` within 5 seconds and do heavy work afterwards.
- If the provider does not receive a `2xx`, it SHOULD retry with backoff. Retries MUST keep the same `id`, and each retry is signed again with a fresh timestamp.
- Consumers SHOULD use `id` to ignore duplicates.

## 5. Responsible use

- Alerts are probabilistic observations from public on-chain data. They describe **addresses and patterns, not people**, and are not financial advice.
- Providers SHOULD NOT include ordinary users' wallet addresses in public outputs.
- Consumers SHOULD show alerts to users as context, not as accusations.

## 6. Test vectors

[`examples/test-vectors.json`](examples/test-vectors.json) contains fixed inputs and the expected signatures. Every implementation SHOULD pass them.

## 7. Changes

| Version | Date | Change |
| --- | --- | --- |
| `2026-10` | 2026-10 | First public version. |
