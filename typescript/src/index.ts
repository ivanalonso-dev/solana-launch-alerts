/**
 * Solana Launch Alerts: verify signed launch-risk alert webhooks and parse alerts (spec version 2026-10).
 * Node.js 18+, no dependencies.
 *
 *   import { verifyRequest, parseAlert } from "solana-launch-alerts";
 *   if (!verifyRequest(req.headers, rawBody, secret)) return res.status(401).end();
 *   const alert = parseAlert(rawBody);
 */
import { createHmac, timingSafeEqual } from "node:crypto";

export const API_VERSION = "2026-10";
export const DEFAULT_TOLERANCE_S = 300;
export const KNOWN_TYPES = [
  "operator_launch", "operator_cluster_buy", "coordinated_support", "linked_wallet_buy",
  "funding_batch", "linked_wallet", "profit_sweep", "exit_route",
] as const;
export const LEVELS = ["RELATED", "COORDINATED", "SUSPECTED", "CONFIRMED"] as const;

export type KnownType = (typeof KNOWN_TYPES)[number];
export type Level = (typeof LEVELS)[number];
export type RawBody = string | Uint8Array;

export interface Operator { id: string; address: string | null }
export interface EvidenceItem { step?: string; transaction?: string | null; [key: string]: unknown }
export interface Alert {
  api_version: string;
  id: string;
  /** A KnownType, or a newer code this SDK does not know yet (ignore or log it). */
  type: KnownType | (string & {});
  level: Level;
  detected_at_utc: string;
  token: string | null;
  operator: Operator;
  summary: string;
  evidence: EvidenceItem[];
  transaction: string | null;
  sandbox: boolean;
  [key: string]: unknown;
}

export interface VerifyOptions { toleranceSeconds?: number; now?: number }
export interface RequestOptions extends VerifyOptions { provider?: string }

export class InvalidAlertError extends Error {
  constructor(message: string) { super(message); this.name = "InvalidAlertError"; }
}

const toBytes = (b: RawBody): Buffer => (typeof b === "string" ? Buffer.from(b, "utf8") : Buffer.from(b));

/** Hex HMAC-SHA256 of "<timestamp>.<raw body>". Used by providers, and by tests. */
export function sign(secret: string, timestamp: string | number, rawBody: RawBody): string {
  return createHmac("sha256", secret)
    .update(Buffer.concat([Buffer.from(`${timestamp}.`, "ascii"), toBytes(rawBody)]))
    .digest("hex");
}

/** True only if the timestamp is fresh and the signature matches, compared in constant time. */
export function verifySignature(
  secret: string,
  timestamp: string | number | null | undefined,
  rawBody: RawBody,
  signature: string | null | undefined,
  options: VerifyOptions = {},
): boolean {
  if (!secret || timestamp === null || timestamp === undefined || !signature) return false;
  const tsText = String(timestamp).trim();
  if (!/^-?\d+$/.test(tsText)) return false;
  const now = options.now ?? Date.now() / 1000;
  if (Math.abs(now - Number(tsText)) > (options.toleranceSeconds ?? DEFAULT_TOLERANCE_S)) return false;
  const expected = Buffer.from(sign(secret, tsText, rawBody), "utf8");
  const received = Buffer.from(signature.trim().toLowerCase(), "utf8");
  return expected.length === received.length && timingSafeEqual(expected, received);
}

type HeaderBag = Record<string, string | string[] | undefined> | { get(name: string): string | null };

function header(headers: HeaderBag, name: string): string | undefined {
  if (typeof (headers as { get?: unknown }).get === "function") {
    return (headers as { get(name: string): string | null }).get(name) ?? undefined;
  }
  const wanted = name.toLowerCase();
  for (const [key, value] of Object.entries(headers as Record<string, string | string[] | undefined>)) {
    if (key.toLowerCase() === wanted) return Array.isArray(value) ? value[0] : value;
  }
  return undefined;
}

/** Verify a webhook request from its headers (X-<Provider>-Timestamp / X-<Provider>-Signature).
 *  Works with Node/Express header objects and with Fetch API Headers. Pass the RAW body. */
export function verifyRequest(headers: HeaderBag, rawBody: RawBody, secret: string, options: RequestOptions = {}): boolean {
  const provider = options.provider ?? "Trenchwatch";
  return verifySignature(
    secret,
    header(headers, `X-${provider}-Timestamp`),
    rawBody,
    header(headers, `X-${provider}-Signature`),
    options,
  );
}

export const isKnownType = (type: string): type is KnownType => (KNOWN_TYPES as readonly string[]).includes(type);
/** 0 (RELATED) to 3 (CONFIRMED), for filtering by minimum strength. */
export const levelRank = (level: Level): number => LEVELS.indexOf(level);

function need(d: Record<string, unknown>, key: string, kind: "string" | "boolean" | "object" | "array", nullable = false): unknown {
  if (!(key in d)) throw new InvalidAlertError(`missing field: ${key}`);
  const v = d[key];
  if (v === null && nullable) return null;
  const ok = kind === "array" ? Array.isArray(v)
    : kind === "object" ? v !== null && typeof v === "object" && !Array.isArray(v)
    : typeof v === kind;
  if (!ok) throw new InvalidAlertError(`wrong type for field: ${key}`);
  return v;
}

/** Parse and check an alert. Unknown fields are kept; unknown type codes are accepted. */
export function parseAlert(body: RawBody | Record<string, unknown>): Alert {
  let d: unknown;
  if (typeof body === "string" || body instanceof Uint8Array) {
    try { d = JSON.parse(toBytes(body).toString("utf8")); }
    catch (e) { throw new InvalidAlertError(`body is not valid JSON: ${(e as Error).message}`); }
  } else {
    d = body;
  }
  if (d === null || typeof d !== "object" || Array.isArray(d)) throw new InvalidAlertError("alert must be a JSON object");
  const o = d as Record<string, unknown>;
  for (const k of ["api_version", "detected_at_utc", "summary"]) need(o, k, "string");
  for (const k of ["id", "type"]) if (!need(o, k, "string")) throw new InvalidAlertError(`empty field: ${k}`);
  const level = need(o, "level", "string") as string;
  if (!(LEVELS as readonly string[]).includes(level)) throw new InvalidAlertError(`unknown level: ${level}`);
  const op = need(o, "operator", "object") as Record<string, unknown>;
  need(op, "id", "string");
  if (op.address !== undefined && op.address !== null && typeof op.address !== "string") {
    throw new InvalidAlertError("wrong type for field: operator.address");
  }
  const evidence = need(o, "evidence", "array") as unknown[];
  if (!evidence.every((e) => e !== null && typeof e === "object" && !Array.isArray(e))) {
    throw new InvalidAlertError("evidence items must be objects");
  }
  need(o, "token", "string", true);
  need(o, "transaction", "string", true);
  need(o, "sandbox", "boolean");
  return { ...o, operator: { id: op.id as string, address: (op.address as string | null | undefined) ?? null } } as Alert;
}
