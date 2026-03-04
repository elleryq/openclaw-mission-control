import {
  ensureUsageDb,
  sqliteValue,
  usageDbGetMeta,
  usageDbQuery,
  usageDbSetMeta,
  usageDbTransaction,
} from "@/lib/usage-db";
import type { ReconciliationRow, ReconciliationStatus, ReconciliationSummary } from "@/lib/usage-types";

type LocalAggregateRow = {
  provider: string;
  full_model: string | null;
  bucket_start_ms: number;
  bucket_end_ms: number;
  estimated_spend_usd: number | null;
  total_tokens: number | null;
};

type ProviderAggregateRow = {
  provider: string;
  account_scope: string;
  full_model: string | null;
  bucket_start_ms: number;
  bucket_end_ms: number;
  spend_usd: number | null;
  input_tokens: number | null;
  output_tokens: number | null;
  reasoning_tokens: number | null;
  fetched_at_ms: number;
};

function buildKey(provider: string, accountScope: string, bucketStartMs: number, fullModel: string | null): string {
  return `${provider}:${accountScope}:${bucketStartMs}:${fullModel || "*"}`;
}

function classifyStatus(
  localUsd: number | null,
  providerUsd: number | null,
  stale: boolean,
): { status: ReconciliationStatus; diffUsd: number | null; diffPct: number | null } {
  if (stale) {
    return { status: "stale", diffUsd: null, diffPct: null };
  }
  if (localUsd != null && providerUsd == null) {
    return { status: "estimated-only", diffUsd: null, diffPct: null };
  }
  if (localUsd == null && providerUsd != null) {
    return { status: "provider-only", diffUsd: null, diffPct: null };
  }
  if (localUsd == null && providerUsd == null) {
    return { status: "stale", diffUsd: null, diffPct: null };
  }
  const diffUsd = (providerUsd || 0) - (localUsd || 0);
  const base = Math.max(Math.abs(providerUsd || 0), Math.abs(localUsd || 0), 0.000001);
  const diffPct = Math.abs(diffUsd) / base * 100;
  const threshold = Math.max(0.5, base * 0.05);
  return {
    status: Math.abs(diffUsd) <= threshold ? "reconciled" : "mismatch",
    diffUsd,
    diffPct,
  };
}

function toNumber(value: unknown): number | null {
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
}

export async function runUsageReconciliation(now = Date.now()): Promise<{ summary: ReconciliationSummary; rows: ReconciliationRow[] }> {
  await ensureUsageDb();
  const localRows = await usageDbQuery<LocalAggregateRow>(
    `
WITH per_model AS (
  SELECT
    provider,
    full_model,
    CAST((observed_at_ms / 86400000) AS INTEGER) * 86400000 AS bucket_start_ms,
    CAST((observed_at_ms / 86400000) AS INTEGER) * 86400000 + 86400000 AS bucket_end_ms,
    SUM(estimated_cost_usd) AS estimated_spend_usd,
    SUM(total_tokens_delta) AS total_tokens
  FROM usage_events
  GROUP BY provider, full_model, bucket_start_ms
),
per_provider AS (
  SELECT
    provider,
    NULL AS full_model,
    CAST((observed_at_ms / 86400000) AS INTEGER) * 86400000 AS bucket_start_ms,
    CAST((observed_at_ms / 86400000) AS INTEGER) * 86400000 + 86400000 AS bucket_end_ms,
    SUM(estimated_cost_usd) AS estimated_spend_usd,
    SUM(total_tokens_delta) AS total_tokens
  FROM usage_events
  GROUP BY provider, bucket_start_ms
)
SELECT * FROM per_model
UNION ALL
SELECT * FROM per_provider;
`,
  );

  const providerRows = await usageDbQuery<ProviderAggregateRow>(
    `
SELECT
  provider,
  account_scope,
  full_model,
  bucket_start_ms,
  bucket_end_ms,
  spend_usd,
  input_tokens,
  output_tokens,
  reasoning_tokens,
  fetched_at_ms
FROM provider_billing_buckets;
`,
  );

  const localMap = new Map<string, LocalAggregateRow>();
  localRows.forEach((row) => {
    localMap.set(buildKey(row.provider, "default", Number(row.bucket_start_ms || 0), row.full_model || null), row);
  });

  const providerMap = new Map<string, ProviderAggregateRow>();
  providerRows.forEach((row) => {
    providerMap.set(
      buildKey(
        row.provider,
        row.account_scope || "default",
        Number(row.bucket_start_ms || 0),
        row.full_model || null,
      ),
      row,
    );
  });

  const keys = new Set<string>([...localMap.keys(), ...providerMap.keys()]);
  const statements: string[] = [];
  const rows: ReconciliationRow[] = [];
  const summary: ReconciliationSummary = {
    reconciledBuckets: 0,
    mismatchBuckets: 0,
    estimatedOnlyBuckets: 0,
    providerOnlyBuckets: 0,
    staleBuckets: 0,
  };

  const providerLastFetchEntries = await usageDbQuery<{ key?: string; value?: string }>(
    `SELECT key, value FROM usage_meta WHERE key LIKE 'provider.%.last_fetch_ms';`,
  );
  const providerLastFetch = new Map<string, number>();
  providerLastFetchEntries.forEach((row) => {
    const key = String(row.key || "");
    const provider = key.split(".")[1];
    const value = Number(row.value || 0);
    if (provider && Number.isFinite(value) && value > 0) providerLastFetch.set(provider, value);
  });

  for (const key of keys) {
    const local = localMap.get(key);
    const provider = providerMap.get(key);
    const providerId = provider?.provider || local?.provider || "unknown";
    const lastFetchMs = providerLastFetch.get(providerId) || 0;
    const stale =
      !lastFetchMs ||
      (providerId === "openrouter" && now - lastFetchMs > 30 * 60 * 1000) ||
      (providerId === "openai" && now - lastFetchMs > 15 * 60 * 1000) ||
      (providerId === "anthropic" && now - lastFetchMs > 10 * 60 * 1000);
    const localUsd = toNumber(local?.estimated_spend_usd);
    const providerUsd = toNumber(provider?.spend_usd);
    const classified = classifyStatus(localUsd, providerUsd, stale);
    summary[
      classified.status === "reconciled"
        ? "reconciledBuckets"
        : classified.status === "mismatch"
          ? "mismatchBuckets"
          : classified.status === "estimated-only"
            ? "estimatedOnlyBuckets"
            : classified.status === "provider-only"
              ? "providerOnlyBuckets"
              : "staleBuckets"
    ] += 1;
    const bucketStartMs = Number(provider?.bucket_start_ms || local?.bucket_start_ms || 0);
    const bucketEndMs = Number(provider?.bucket_end_ms || local?.bucket_end_ms || (bucketStartMs + 86_400_000));
    const fullModel = provider?.full_model || local?.full_model || null;
    rows.push({
      provider: providerId,
      fullModel,
      bucketStartMs,
      status: classified.status,
      localEstimatedSpendUsd: localUsd,
      providerReportedSpendUsd: providerUsd,
      diffUsd: classified.diffUsd,
      diffPct: classified.diffPct,
    });
    statements.push(
      [
        "INSERT INTO reconciliation_buckets (",
        "id, provider, account_scope, full_model, bucket_start_ms, bucket_end_ms, bucket_granularity,",
        "local_estimated_spend_usd, provider_reported_spend_usd, local_estimated_tokens, provider_reported_tokens,",
        "diff_usd, diff_pct, status, last_reconciled_at_ms",
        ") VALUES (",
        [
          sqliteValue(`${providerId}:default:${fullModel || "*"}:${bucketStartMs}`),
          sqliteValue(providerId),
          sqliteValue(provider?.account_scope || "default"),
          fullModel ? sqliteValue(fullModel) : "NULL",
          bucketStartMs,
          bucketEndMs,
          sqliteValue("day"),
          localUsd == null ? "NULL" : localUsd,
          providerUsd == null ? "NULL" : providerUsd,
          local?.total_tokens == null ? "NULL" : Number(local.total_tokens),
          provider
            ? (Number(provider.input_tokens || 0) + Number(provider.output_tokens || 0) + Number(provider.reasoning_tokens || 0))
            : "NULL",
          classified.diffUsd == null ? "NULL" : classified.diffUsd,
          classified.diffPct == null ? "NULL" : classified.diffPct,
          sqliteValue(classified.status),
          now,
        ].join(", "),
        ") ON CONFLICT(id) DO UPDATE SET",
        "local_estimated_spend_usd = excluded.local_estimated_spend_usd,",
        "provider_reported_spend_usd = excluded.provider_reported_spend_usd,",
        "local_estimated_tokens = excluded.local_estimated_tokens,",
        "provider_reported_tokens = excluded.provider_reported_tokens,",
        "diff_usd = excluded.diff_usd,",
        "diff_pct = excluded.diff_pct,",
        "status = excluded.status,",
        "last_reconciled_at_ms = excluded.last_reconciled_at_ms;",
      ].join(" "),
    );
  }

  for (let i = 0; i < statements.length; i += 100) {
    await usageDbTransaction(statements.slice(i, i + 100));
  }
  await usageDbSetMeta("reconciliation.last_run_ms", String(now));

  rows.sort((a, b) => b.bucketStartMs - a.bucketStartMs || a.provider.localeCompare(b.provider));
  return { summary, rows };
}

export async function readReconciliationSnapshot(): Promise<{
  summary: ReconciliationSummary;
  rows: ReconciliationRow[];
  lastRunMs: number | null;
}> {
  await ensureUsageDb();
  const dbRows = await usageDbQuery<{
    provider?: string;
    full_model?: string | null;
    bucket_start_ms?: number;
    status?: ReconciliationStatus;
    local_estimated_spend_usd?: number | null;
    provider_reported_spend_usd?: number | null;
    diff_usd?: number | null;
    diff_pct?: number | null;
  }>(
    `
SELECT provider, full_model, bucket_start_ms, status, local_estimated_spend_usd,
provider_reported_spend_usd, diff_usd, diff_pct
FROM reconciliation_buckets
ORDER BY bucket_start_ms DESC, provider ASC
LIMIT 200;
`,
  );
  const rows: ReconciliationRow[] = dbRows.map((row) => ({
    provider: String(row.provider || "unknown"),
    fullModel: row.full_model == null ? null : String(row.full_model),
    bucketStartMs: Number(row.bucket_start_ms || 0),
    status: (row.status || "stale") as ReconciliationStatus,
    localEstimatedSpendUsd: toNumber(row.local_estimated_spend_usd),
    providerReportedSpendUsd: toNumber(row.provider_reported_spend_usd),
    diffUsd: toNumber(row.diff_usd),
    diffPct: toNumber(row.diff_pct),
  }));
  const summary: ReconciliationSummary = {
    reconciledBuckets: rows.filter((row) => row.status === "reconciled").length,
    mismatchBuckets: rows.filter((row) => row.status === "mismatch").length,
    estimatedOnlyBuckets: rows.filter((row) => row.status === "estimated-only").length,
    providerOnlyBuckets: rows.filter((row) => row.status === "provider-only").length,
    staleBuckets: rows.filter((row) => row.status === "stale").length,
  };
  const lastRunRaw = await usageDbGetMeta("reconciliation.last_run_ms");
  return {
    summary,
    rows,
    lastRunMs: lastRunRaw ? Number(lastRunRaw) || null : null,
  };
}
