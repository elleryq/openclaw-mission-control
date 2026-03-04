import { createHash, randomUUID } from "crypto";
import { readFile } from "fs/promises";
import { join } from "path";
import { getOpenClawHome } from "@/lib/paths";
import {
  ensureUsageDb,
  sqliteValue,
  usageDbGetMeta,
  usageDbQuery,
  usageDbSetMeta,
  usageDbTransaction,
} from "@/lib/usage-db";
import type { ProviderBillingProviderSnapshot, ProviderBillingRow } from "@/lib/usage-types";

export type CollectorResult = {
  provider: string;
  available: boolean;
  reason?: string;
  requiredCredential?: string;
  fetchedAtMs?: number;
  bucketCount?: number;
};

export type NormalizedProviderBillingBucket = {
  provider: string;
  accountScope: string;
  fullModel: string | null;
  bucketStartMs: number;
  bucketEndMs: number;
  bucketGranularity: "day";
  currency: "USD";
  requests: number | null;
  inputTokens: number | null;
  outputTokens: number | null;
  reasoningTokens: number | null;
  spendUsd: number | null;
  providerReference: string | null;
  payload: unknown;
  dataLatencyNote: string | null;
  isFinal: boolean;
};

type ProviderStatusMeta = {
  available: boolean;
  reason?: string;
  requiredCredential?: string;
  fetchedAtMs?: number;
};

const OPENCLAW_HOME = getOpenClawHome();
const SUPPORTED_PROVIDERS = ["openrouter", "openai", "anthropic"] as const;

function parseDotEnv(content: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of content.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const idx = trimmed.indexOf("=");
    if (idx <= 0) continue;
    const key = trimmed.slice(0, idx).trim();
    let value = trimmed.slice(idx + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    out[key] = value;
  }
  return out;
}

async function readOpenClawEnv(): Promise<Record<string, string>> {
  try {
    const raw = await readFile(join(OPENCLAW_HOME, ".env"), "utf-8");
    return parseDotEnv(raw);
  } catch {
    return {};
  }
}

export async function resolveBillingCredential(
  envKeys: string[],
): Promise<{ value: string | null; requiredCredential: string }> {
  const env = await readOpenClawEnv();
  for (const key of envKeys) {
    if (typeof process.env[key] === "string" && process.env[key]?.trim()) {
      return { value: String(process.env[key]).trim(), requiredCredential: key };
    }
    if (typeof env[key] === "string" && env[key].trim()) {
      return { value: env[key].trim(), requiredCredential: key };
    }
  }
  return { value: null, requiredCredential: envKeys[0] || "UNKNOWN_CREDENTIAL" };
}

export function utcDayRange(input: string | number | Date): {
  bucketStartMs: number;
  bucketEndMs: number;
} {
  const date = new Date(input);
  const bucketStartMs = Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate());
  return {
    bucketStartMs,
    bucketEndMs: bucketStartMs + 24 * 60 * 60 * 1000,
  };
}

export async function saveProviderCollectorStatus(result: CollectorResult): Promise<void> {
  const payload: ProviderStatusMeta = {
    available: result.available,
    reason: result.reason,
    requiredCredential: result.requiredCredential,
    fetchedAtMs: result.fetchedAtMs,
  };
  await usageDbSetMeta(`provider.${result.provider}.status`, JSON.stringify(payload));
  if (result.fetchedAtMs) {
    await usageDbSetMeta(`provider.${result.provider}.last_fetch_ms`, String(result.fetchedAtMs));
  }
}

export async function loadProviderCollectorStatus(provider: string): Promise<ProviderStatusMeta | null> {
  const raw = await usageDbGetMeta(`provider.${provider}.status`);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as ProviderStatusMeta;
  } catch {
    return null;
  }
}

export async function upsertProviderBillingBuckets(
  rows: NormalizedProviderBillingBucket[],
  fetchedAtMs: number,
): Promise<void> {
  await ensureUsageDb();
  const statements = rows.map((row) => {
    const payloadHash = createHash("sha256")
      .update(JSON.stringify(row.payload || null))
      .digest("hex");
    const id = `${row.provider}:${row.accountScope}:${row.fullModel || "*"}:${row.bucketStartMs}`;
    return [
      "INSERT INTO provider_billing_buckets (",
      "id, provider, account_scope, full_model, bucket_start_ms, bucket_end_ms,",
      "bucket_granularity, currency, requests, input_tokens, output_tokens, reasoning_tokens,",
      "spend_usd, provider_payload_hash, provider_reference, fetched_at_ms, data_latency_note, is_final",
      ") VALUES (",
      [
        sqliteValue(id),
        sqliteValue(row.provider),
        sqliteValue(row.accountScope),
        row.fullModel ? sqliteValue(row.fullModel) : "NULL",
        row.bucketStartMs,
        row.bucketEndMs,
        sqliteValue(row.bucketGranularity),
        sqliteValue(row.currency),
        row.requests == null ? "NULL" : row.requests,
        row.inputTokens == null ? "NULL" : row.inputTokens,
        row.outputTokens == null ? "NULL" : row.outputTokens,
        row.reasoningTokens == null ? "NULL" : row.reasoningTokens,
        row.spendUsd == null ? "NULL" : row.spendUsd,
        sqliteValue(payloadHash),
        row.providerReference ? sqliteValue(row.providerReference) : "NULL",
        fetchedAtMs,
        row.dataLatencyNote ? sqliteValue(row.dataLatencyNote) : "NULL",
        row.isFinal ? 1 : 0,
      ].join(", "),
      ") ON CONFLICT(id) DO UPDATE SET",
      "bucket_end_ms = excluded.bucket_end_ms,",
      "bucket_granularity = excluded.bucket_granularity,",
      "currency = excluded.currency,",
      "requests = excluded.requests,",
      "input_tokens = excluded.input_tokens,",
      "output_tokens = excluded.output_tokens,",
      "reasoning_tokens = excluded.reasoning_tokens,",
      "spend_usd = excluded.spend_usd,",
      "provider_payload_hash = excluded.provider_payload_hash,",
      "provider_reference = excluded.provider_reference,",
      "fetched_at_ms = excluded.fetched_at_ms,",
      "data_latency_note = excluded.data_latency_note,",
      "is_final = excluded.is_final;",
    ].join(" ");
  });
  for (let i = 0; i < statements.length; i += 100) {
    await usageDbTransaction(statements.slice(i, i + 100));
  }
}

export async function getProviderBillingRows(provider: string, limitDays = 31): Promise<ProviderBillingRow[]> {
  const cutoff = Date.now() - limitDays * 24 * 60 * 60 * 1000;
  const rows = await usageDbQuery<{
    account_scope?: string;
    full_model?: string | null;
    bucket_start_ms?: number;
    bucket_end_ms?: number;
    spend_usd?: number | null;
    requests?: number | null;
    input_tokens?: number | null;
    output_tokens?: number | null;
    reasoning_tokens?: number | null;
    is_final?: number | boolean;
  }>(
    [
      "SELECT account_scope, full_model, bucket_start_ms, bucket_end_ms, spend_usd, requests,",
      "input_tokens, output_tokens, reasoning_tokens, is_final",
      "FROM provider_billing_buckets",
      `WHERE provider = ${sqliteValue(provider)} AND bucket_start_ms >= ${cutoff}`,
      "ORDER BY bucket_start_ms ASC, full_model ASC;",
    ].join(" "),
  );
  return rows.map((row) => ({
    accountScope: String(row.account_scope || "default"),
    fullModel: row.full_model == null ? null : String(row.full_model),
    bucketStartMs: Number(row.bucket_start_ms || 0),
    bucketEndMs: Number(row.bucket_end_ms || 0),
    spendUsd: row.spend_usd == null ? null : Number(row.spend_usd),
    requests: row.requests == null ? null : Number(row.requests),
    inputTokens: row.input_tokens == null ? null : Number(row.input_tokens),
    outputTokens: row.output_tokens == null ? null : Number(row.output_tokens),
    reasoningTokens: row.reasoning_tokens == null ? null : Number(row.reasoning_tokens),
    isFinal: Boolean(row.is_final),
  }));
}

function providerFreshness(provider: string, lastFetchMs: number | null): "fresh" | "stale" | "unknown" {
  if (!lastFetchMs) return "unknown";
  const ageMs = Date.now() - lastFetchMs;
  const maxAge =
    provider === "openrouter"
      ? 30 * 60 * 1000
      : provider === "openai"
        ? 15 * 60 * 1000
        : provider === "anthropic"
          ? 10 * 60 * 1000
          : 15 * 60 * 1000;
  return ageMs <= maxAge ? "fresh" : "stale";
}

export async function getProviderSnapshot(provider: string): Promise<ProviderBillingProviderSnapshot> {
  await ensureUsageDb();
  const rows = await getProviderBillingRows(provider);
  const status = await loadProviderCollectorStatus(provider);
  const lastFetchRaw = await usageDbGetMeta(`provider.${provider}.last_fetch_ms`);
  const lastFetchMs = lastFetchRaw ? Number(lastFetchRaw) || null : null;
  const freshness = providerFreshness(provider, lastFetchMs);

  const totalUsd30d = rows.reduce((sum, row) => sum + (row.spendUsd || 0), 0);
  const monthStart = Date.UTC(new Date().getUTCFullYear(), new Date().getUTCMonth(), 1);
  const currentMonthUsd = rows
    .filter((row) => row.bucketStartMs >= monthStart)
    .reduce((sum, row) => sum + (row.spendUsd || 0), 0);

  const available = status?.available ?? rows.length > 0;
  return {
    provider,
    available,
    reason: available ? undefined : status?.reason || "Billing access not configured",
    requiredCredential: available ? undefined : status?.requiredCredential,
    freshness,
    bucketGranularity: rows.length > 0 ? "day" : null,
    latestBucketStartMs: rows.length > 0 ? rows[rows.length - 1].bucketStartMs : null,
    totalUsd30d: rows.length > 0 ? totalUsd30d : null,
    currentMonthUsd: rows.length > 0 ? currentMonthUsd : null,
    rows,
  };
}

export async function getAllProviderSnapshots(): Promise<ProviderBillingProviderSnapshot[]> {
  return Promise.all(SUPPORTED_PROVIDERS.map((provider) => getProviderSnapshot(provider)));
}

export async function maybeCollectProvider(
  provider: "openrouter" | "openai" | "anthropic",
): Promise<CollectorResult> {
  if (provider === "openrouter") {
    const mod = await import("./openrouter");
    return mod.collectOpenRouterBilling();
  }
  if (provider === "openai") {
    const mod = await import("./openai");
    return mod.collectOpenAIBilling();
  }
  const mod = await import("./anthropic");
  return mod.collectAnthropicBilling();
}

export async function ensureProviderBillingFreshness(): Promise<CollectorResult[]> {
  const results: CollectorResult[] = [];
  for (const provider of SUPPORTED_PROVIDERS) {
    const lastFetchRaw = await usageDbGetMeta(`provider.${provider}.last_fetch_ms`);
    const lastFetchMs = lastFetchRaw ? Number(lastFetchRaw) || 0 : 0;
    const shouldCollect =
      !lastFetchMs ||
      providerFreshness(provider, lastFetchMs) !== "fresh";
    if (shouldCollect) {
      results.push(await maybeCollectProvider(provider));
    }
  }
  return results;
}

export function defaultCollectorUnavailable(
  provider: string,
  requiredCredential: string,
): CollectorResult {
  return {
    provider,
    available: false,
    reason: "Billing access not configured",
    requiredCredential,
  };
}

export function currentUtcDayStartMs(): number {
  const now = new Date();
  return Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());
}

export function newCollectorReference(provider: string): string {
  return `${provider}:${randomUUID()}`;
}
