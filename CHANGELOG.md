# Changelog

## 1.0.0 — October 2026

- Specification `2026-10`: alert object, eight alert types, four evidence levels, webhook signing.
- JSON Schema of the alert object.
- TypeScript SDK: `sign`, `verifySignature`, `verifyRequest`, `parseAlert`, `isKnownType`, `levelRank`.
- Python SDK: `sign`, `verify_signature`, `verify_request`, `parse_alert`, `Alert.is_known_type`, `Alert.level_rank`.
- Synthetic example alerts and cross-language signature test vectors.
