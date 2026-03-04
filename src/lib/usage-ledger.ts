import { randomUUID } from "crypto";
import { estimateCostUsd } from "@/lib/model-metadata";
import { fetchOpenRouterPricing } from "@/lib/openrouter-pricing";
import type { NormalizedGatewaySession } from "@/lib/gateway-sessions";
import { readUsageHistory } from "@/lib/usage-history";
import {
  ensureUsageDb,
  sqliteValue,
  usageDbExec,
  usageDbGetMeta,
  usageDbQuery,
  usageDbSetMeta,
  usageDbTransaction,
} from "@/lib/usage-db";
import type { UsageActivityPoint, UsageApiBucket, UsageWindow } from "@/lib/usage-types";

type UsageEventRow = {
  observedAtMs: number;
  sessionId: string;
  agentId: string;
  provider: string;
  fullModel: string;
  model: string;
  inputTokensDelta: number;
  outputTokensDelta: number;
  reasoningTokensDelta: number;
  cacheReadTokensDelta: number;
  cacheWriteTokensDelta: number;
  totalTokensDelta: number;
  estimatedCostUsd: number | null;
  source: string;
};

type WatermarkRow = {
  session_id: string;
  last_updated_at_ms: number;
  agent_id: string;
  provider: string;
  full_model: string;
  model: string;
  input_tokens_total: number;
  output_tokens_total: number;
  reasoning_tokens_total: number;
  cache_read_tokens_total: number;
  cache_write_tokens_total: number;
  total_tokens_total: number;
};

type LedgerHistorical = {
  byModel: Record<string, { totalTokens: number; estimatedCostUsd: number; sessions: number }>;
  byAgent: Record<string, { totalTokens: number; estimatedCostUsd: number; sessions: number }>;
  costTimeSeries: { ts: number; costUsd: number; tokens: number }[];
  totalEstimatedUsd: number;
  totalTokens: number;
  rowCount: number;
};

type LedgerUsageSnapshot = {
  windows: Record<UsageWindow, UsageApiBucket>;
  activitySeries: Record<UsageWindow, UsageActivityPoint[]>;
  activitySeriesByModel: Record<string, Record<UsageWindow, UsageActivityPoint[]>>;
  historical: LedgerHistorical;
  estimatedSpend: {
    totalUsd: number | null;
    windows: Record<UsageWindow, { usd: number | null; coveragePct: number }>;
    byModel: Array<{ fullModel: string; usd: number | null; coveragePct: number }>;
  };
  localTelemetryMs: number | null;
};

type IngestResult = {
  insertedEvents: number;
  resetSessions: string[];
  localTelemetryMs: number | null;
};

const LEDGER_WINDOWS: UsageWindow[] = ["last1h", "last24h", "last7d", "allTime"];

function modelProvider(fullModel: string): string {
  return String(fullModel || "").split("/")[0]?.trim().toLowerCase() || "unknown";
}

function toNumber(value: unknown): number {
  const n = Number(value);
  return Number.isFinite(n) ? n : 0;
}

function toNullableNumber(value: unknown): number | null {
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
}

function windowStart(now: number, window: UsageWindow): number {
  switch (window) {
    case "last1h":
      return now - 60 * 60 * 1000;
    case "last24h":
      return now - 24 * 60 * 60 * 1000;
    case "last7d":
      return now - 7 * 24 * 60 * 60 * 1000;
    case "allTime":
    default:
      return 0;
  }
}

function bucketForWindow(rows: UsageEventRow[], now: number, window: UsageWindow): UsageApiBucket {
  const start = windowStart(now, window);
  const sessions = new Set<string>();
  let inputTokens = 0;
  let outputTokens = 0;
  let totalTokens = 0;
  for (const row of rows) {
    if (row.observedAtMs < start) continue;
    inputTokens += row.inputTokensDelta;
    outputTokens += row.outputTokensDelta;
    totalTokens += row.totalTokensDelta;
    sessions.add(row.sessionId);
  }
  return {
    inputTokens,
    outputTokens,
    totalTokens,
    sessions: sessions.size,
  };
}

function buildSeries(
  rows: UsageEventRow[],
  now: number,
  modelFilter?: string,
): Record<UsageWindow, UsageActivityPoint[]> {
  const filtered = modelFilter ? rows.filter((row) => row.fullModel === modelFilter) : rows;

  const buildFixed = (windowMs: number, binMs: number): UsageActivityPoint[] => {
    const bins = Math.max(1, Math.ceil(windowMs / binMs));
    const start = now - bins * binMs;
    const points: UsageActivityPoint[] = Array.from({ length: bins }, (_, i) => ({
      ts: start + i * binMs,
      input: 0,
      output: 0,
      total: 0,
      sessions: 0,
    }));
    const sessionSets = Array.from({ length: bins }, () => new Set<string>());
    for (const row of filtered) {
      if (row.observedAtMs < start || row.observedAtMs > now) continue;
      const idx = Math.floor((row.observedAtMs - start) / binMs);
      if (idx < 0 || idx >= points.length) continue;
      points[idx].input += row.inputTokensDelta;
      points[idx].output += row.outputTokensDelta;
      points[idx].total += row.totalTokensDelta;
      sessionSets[idx].add(row.sessionId);
    }
    return points.map((point, index) => ({
      ...point,
      sessions: sessionSets[index].size,
    }));
  };

  const observed = filtered.map((row) => row.observedAtMs).filter((value) => value > 0);
  const earliest = observed.length ? Math.min(...observed) : now - 24 * 60 * 60 * 1000;
  const spanMs = Math.max(now - earliest, 60 * 60 * 1000);
  const targetBins = 30;
  const rawBinMs = Math.ceil(spanMs / targetBins);
  const binFloor = 15 * 60 * 1000;
  const dynamicBinMs = Math.max(binFloor, Math.ceil(rawBinMs / binFloor) * binFloor);
  const dynamicWindowMs = dynamicBinMs * targetBins;

  return {
    last1h: buildFixed(60 * 60 * 1000, 5 * 60 * 1000),
    last24h: buildFixed(24 * 60 * 60 * 1000, 60 * 60 * 1000),
    last7d: buildFixed(7 * 24 * 60 * 60 * 1000, 6 * 60 * 60 * 1000),
    allTime: buildFixed(dynamicWindowMs, dynamicBinMs),
  };
}

async function loadUsageEvents(): Promise<UsageEventRow[]> {
  await ensureUsageDb();
  const rows = await usageDbQuery<{
    observed_at_ms?: number;
    session_id?: string;
    agent_id?: string;
    provider?: string;
    full_model?: string;
    model?: string;
    input_tokens_delta?: number;
    output_tokens_delta?: number;
    reasoning_tokens_delta?: number;
    cache_read_tokens_delta?: number;
    cache_write_tokens_delta?: number;
    total_tokens_delta?: number;
    estimated_cost_usd?: number;
    source?: string;
  }>(
    [
      "SELECT",
      "observed_at_ms, session_id, agent_id, provider, full_model, model,",
      "input_tokens_delta, output_tokens_delta, reasoning_tokens_delta,",
      "cache_read_tokens_delta, cache_write_tokens_delta, total_tokens_delta,",
      "estimated_cost_usd, source",
      "FROM usage_events",
      "ORDER BY observed_at_ms ASC;",
    ].join(" "),
  );
  return rows.map((row) => ({
    observedAtMs: toNumber(row.observed_at_ms),
    sessionId: String(row.session_id || ""),
    agentId: String(row.agent_id || "unknown"),
    provider: String(row.provider || "unknown"),
    fullModel: String(row.full_model || "unknown"),
    model: String(row.model || "unknown"),
    inputTokensDelta: toNumber(row.input_tokens_delta),
    outputTokensDelta: toNumber(row.output_tokens_delta),
    reasoningTokensDelta: toNumber(row.reasoning_tokens_delta),
    cacheReadTokensDelta: toNumber(row.cache_read_tokens_delta),
    cacheWriteTokensDelta: toNumber(row.cache_write_tokens_delta),
    totalTokensDelta: toNumber(row.total_tokens_delta),
    estimatedCostUsd: toNullableNumber(row.estimated_cost_usd),
    source: String(row.source || "unknown"),
  }));
}

async function loadWatermarks(sessionIds: string[]): Promise<Map<string, WatermarkRow>> {
  if (sessionIds.length === 0) return new Map();
  const ids = sessionIds.map((sessionId) => sqliteValue(sessionId)).join(", ");
  const rows = await usageDbQuery<WatermarkRow>(
    `SELECT * FROM session_watermarks WHERE session_id IN (${ids});`,
  );
  return new Map(rows.map((row) => [String(row.session_id), row]));
}

async function migrateLegacyUsageHistory(): Promise<void> {
  await ensureUsageDb();
  const migrated = await usageDbGetMeta("migration.usage_history_csv.v1");
  if (migrated === "done") return;

  const rows = await readUsageHistory();
  if (rows.length === 0) {
    await usageDbSetMeta("migration.usage_history_csv.v1", "done");
    return;
  }

  const statements: string[] = [];
  rows.forEach((row, index) => {
    const observedAtMs = new Date(row.timestamp).getTime();
    const fullModel = String(row.fullModel || "unknown");
    const provider = modelProvider(fullModel);
    const eventId = `legacy:${row.sessionId}:${observedAtMs}:${index}`;
    statements.push(
      [
        "INSERT OR IGNORE INTO usage_events (",
        "id, observed_at_ms, session_id, agent_id, provider, full_model, model,",
        "input_tokens_delta, output_tokens_delta, reasoning_tokens_delta,",
        "cache_read_tokens_delta, cache_write_tokens_delta, total_tokens_delta,",
        "estimated_cost_usd, source, raw_updated_at_ms, created_at_ms",
        ") VALUES (",
        [
          sqliteValue(eventId),
          Number.isFinite(observedAtMs) ? observedAtMs : Date.now(),
          sqliteValue(row.sessionId || `legacy-session-${index}`),
          sqliteValue(row.agentId || "unknown"),
          sqliteValue(provider),
          sqliteValue(fullModel),
          sqliteValue(fullModel.split("/").pop() || fullModel),
          row.inputTokens || 0,
          row.outputTokens || 0,
          0,
          row.cacheReadTokens || 0,
          row.cacheWriteTokens || 0,
          row.totalTokens || 0,
          row.estimatedCostUsd == null ? "NULL" : row.estimatedCostUsd,
          sqliteValue("legacy-csv-import"),
          Number.isFinite(observedAtMs) ? observedAtMs : "NULL",
          Number.isFinite(observedAtMs) ? observedAtMs : Date.now(),
        ].join(", "),
        ");",
      ].join(" "),
    );
  });

  for (let i = 0; i < statements.length; i += 200) {
    await usageDbTransaction(statements.slice(i, i + 200));
  }
  await usageDbSetMeta("migration.usage_history_csv.v1", "done");
}

export async function ingestGatewaySessionsToLedger(
  sessions: NormalizedGatewaySession[],
): Promise<IngestResult> {
  await migrateLegacyUsageHistory();
  const now = Date.now();
  const dynamicPricing = await fetchOpenRouterPricing().catch(() => null);
  const watermarks = await loadWatermarks(sessions.map((session) => session.sessionId));
  const statements: string[] = [];
  const resetSessions: string[] = [];
  let insertedEvents = 0;
  let latestObserved = 0;

  for (const session of sessions) {
    const sessionId = String(session.sessionId || "").trim();
    if (!sessionId) continue;
    const provider = modelProvider(session.fullModel);
    const observedAtMs = session.updatedAt > 0 ? session.updatedAt : now;
    latestObserved = Math.max(latestObserved, observedAtMs);
    const existing = watermarks.get(sessionId);
    const inputTotal = session.inputTokens;
    const outputTotal = session.outputTokens;
    const reasoningTotal = 0;
    const cacheReadTotal = session.cacheReadTokens;
    const cacheWriteTotal = session.cacheWriteTokens;
    const totalTotal = session.totalTokens;

    const needsReset =
      !existing ||
      existing.full_model !== session.fullModel ||
      existing.model !== session.model ||
      existing.provider !== provider ||
      existing.agent_id !== (session.agentId || "unknown") ||
      inputTotal < toNumber(existing.input_tokens_total) ||
      outputTotal < toNumber(existing.output_tokens_total) ||
      cacheReadTotal < toNumber(existing.cache_read_tokens_total) ||
      cacheWriteTotal < toNumber(existing.cache_write_tokens_total) ||
      totalTotal < toNumber(existing.total_tokens_total);

    if (needsReset) {
      if (existing) resetSessions.push(sessionId);
      statements.push(
        [
          "INSERT INTO session_watermarks (",
          "session_id, last_seen_at_ms, last_updated_at_ms, agent_id, provider, full_model, model,",
          "input_tokens_total, output_tokens_total, reasoning_tokens_total, cache_read_tokens_total, cache_write_tokens_total, total_tokens_total",
          ") VALUES (",
          [
            sqliteValue(sessionId),
            now,
            observedAtMs,
            sqliteValue(session.agentId || "unknown"),
            sqliteValue(provider),
            sqliteValue(session.fullModel),
            sqliteValue(session.model),
            inputTotal,
            outputTotal,
            reasoningTotal,
            cacheReadTotal,
            cacheWriteTotal,
            totalTotal,
          ].join(", "),
          ") ON CONFLICT(session_id) DO UPDATE SET",
          `last_seen_at_ms = ${now},`,
          `last_updated_at_ms = ${observedAtMs},`,
          `agent_id = ${sqliteValue(session.agentId || "unknown")},`,
          `provider = ${sqliteValue(provider)},`,
          `full_model = ${sqliteValue(session.fullModel)},`,
          `model = ${sqliteValue(session.model)},`,
          `input_tokens_total = ${inputTotal},`,
          `output_tokens_total = ${outputTotal},`,
          `reasoning_tokens_total = ${reasoningTotal},`,
          `cache_read_tokens_total = ${cacheReadTotal},`,
          `cache_write_tokens_total = ${cacheWriteTotal},`,
          `total_tokens_total = ${totalTotal};`,
        ].join(" "),
      );
      continue;
    }

    const inputDelta = Math.max(0, inputTotal - toNumber(existing.input_tokens_total));
    const outputDelta = Math.max(0, outputTotal - toNumber(existing.output_tokens_total));
    const reasoningDelta = 0;
    const cacheReadDelta = Math.max(0, cacheReadTotal - toNumber(existing.cache_read_tokens_total));
    const cacheWriteDelta = Math.max(0, cacheWriteTotal - toNumber(existing.cache_write_tokens_total));
    const totalDelta = Math.max(
      0,
      Math.max(totalTotal - toNumber(existing.total_tokens_total), inputDelta + outputDelta),
    );
    const changed =
      inputDelta > 0 ||
      outputDelta > 0 ||
      cacheReadDelta > 0 ||
      cacheWriteDelta > 0 ||
      totalDelta > 0;

    if (changed) {
      const estimatedCostUsd = estimateCostUsd(
        session.fullModel,
        inputDelta,
        outputDelta,
        cacheReadDelta,
        cacheWriteDelta,
        dynamicPricing || undefined,
      );
      statements.push(
        [
          "INSERT OR IGNORE INTO usage_events (",
          "id, observed_at_ms, session_id, agent_id, provider, full_model, model,",
          "input_tokens_delta, output_tokens_delta, reasoning_tokens_delta,",
          "cache_read_tokens_delta, cache_write_tokens_delta, total_tokens_delta,",
          "estimated_cost_usd, source, raw_updated_at_ms, created_at_ms",
          ") VALUES (",
          [
            sqliteValue(randomUUID()),
            observedAtMs,
            sqliteValue(sessionId),
            sqliteValue(session.agentId || "unknown"),
            sqliteValue(provider),
            sqliteValue(session.fullModel),
            sqliteValue(session.model),
            inputDelta,
            outputDelta,
            reasoningDelta,
            cacheReadDelta,
            cacheWriteDelta,
            totalDelta,
            estimatedCostUsd == null ? "NULL" : estimatedCostUsd,
            sqliteValue("gateway-session-delta"),
            observedAtMs,
            now,
          ].join(", "),
          ");",
        ].join(" "),
      );
      insertedEvents += 1;
    }

    statements.push(
      [
        "UPDATE session_watermarks SET",
        `last_seen_at_ms = ${now},`,
        `last_updated_at_ms = ${observedAtMs},`,
        `agent_id = ${sqliteValue(session.agentId || "unknown")},`,
        `provider = ${sqliteValue(provider)},`,
        `full_model = ${sqliteValue(session.fullModel)},`,
        `model = ${sqliteValue(session.model)},`,
        `input_tokens_total = ${inputTotal},`,
        `output_tokens_total = ${outputTotal},`,
        `reasoning_tokens_total = ${reasoningTotal},`,
        `cache_read_tokens_total = ${cacheReadTotal},`,
        `cache_write_tokens_total = ${cacheWriteTotal},`,
        `total_tokens_total = ${totalTotal}`,
        `WHERE session_id = ${sqliteValue(sessionId)};`,
      ].join(" "),
    );
  }

  if (statements.length > 0) {
    await usageDbTransaction(statements);
  }
  if (latestObserved > 0) {
    await usageDbSetMeta("local.last_ingest_ms", String(latestObserved));
  }

  return {
    insertedEvents,
    resetSessions,
    localTelemetryMs: latestObserved || null,
  };
}

export async function readLedgerUsageSnapshot(now = Date.now()): Promise<LedgerUsageSnapshot> {
  await migrateLegacyUsageHistory();
  const rows = await loadUsageEvents();

  const windows = {
    last1h: bucketForWindow(rows, now, "last1h"),
    last24h: bucketForWindow(rows, now, "last24h"),
    last7d: bucketForWindow(rows, now, "last7d"),
    allTime: bucketForWindow(rows, now, "allTime"),
  };

  const activitySeries = buildSeries(rows, now);
  const models = Array.from(new Set(rows.map((row) => row.fullModel))).sort((a, b) => a.localeCompare(b));
  const activitySeriesByModel: Record<string, Record<UsageWindow, UsageActivityPoint[]>> = {};
  models.forEach((fullModel) => {
    activitySeriesByModel[fullModel] = buildSeries(rows, now, fullModel);
  });

  const historicalByModel: LedgerHistorical["byModel"] = {};
  const historicalByAgent: LedgerHistorical["byAgent"] = {};
  const historicalSessionByModel = new Map<string, Set<string>>();
  const historicalSessionByAgent = new Map<string, Set<string>>();
  const hourBuckets = new Map<number, { costUsd: number; tokens: number }>();
  const byModelCoverage = new Map<string, { priced: number; total: number; usd: number }>();
  let totalEstimatedUsd = 0;
  let totalTokens = 0;

  for (const row of rows) {
    const cost = row.estimatedCostUsd ?? 0;
    totalEstimatedUsd += cost;
    totalTokens += row.totalTokensDelta;

    if (!historicalByModel[row.fullModel]) {
      historicalByModel[row.fullModel] = { totalTokens: 0, estimatedCostUsd: 0, sessions: 0 };
    }
    historicalByModel[row.fullModel].totalTokens += row.totalTokensDelta;
    historicalByModel[row.fullModel].estimatedCostUsd += cost;
    if (!historicalSessionByModel.has(row.fullModel)) {
      historicalSessionByModel.set(row.fullModel, new Set());
    }
    historicalSessionByModel.get(row.fullModel)?.add(row.sessionId);

    if (!historicalByAgent[row.agentId]) {
      historicalByAgent[row.agentId] = { totalTokens: 0, estimatedCostUsd: 0, sessions: 0 };
    }
    historicalByAgent[row.agentId].totalTokens += row.totalTokensDelta;
    historicalByAgent[row.agentId].estimatedCostUsd += cost;
    if (!historicalSessionByAgent.has(row.agentId)) {
      historicalSessionByAgent.set(row.agentId, new Set());
    }
    historicalSessionByAgent.get(row.agentId)?.add(row.sessionId);

    const hourKey = Math.floor(row.observedAtMs / 3_600_000) * 3_600_000;
    const bucket = hourBuckets.get(hourKey) || { costUsd: 0, tokens: 0 };
    bucket.costUsd += cost;
    bucket.tokens += row.totalTokensDelta;
    hourBuckets.set(hourKey, bucket);

    const coverage = byModelCoverage.get(row.fullModel) || { priced: 0, total: 0, usd: 0 };
    coverage.total += 1;
    if (row.estimatedCostUsd != null) {
      coverage.priced += 1;
      coverage.usd += row.estimatedCostUsd;
    }
    byModelCoverage.set(row.fullModel, coverage);
  }

  Object.entries(historicalByModel).forEach(([fullModel, entry]) => {
    entry.sessions = historicalSessionByModel.get(fullModel)?.size || 0;
  });
  Object.entries(historicalByAgent).forEach(([agentId, entry]) => {
    entry.sessions = historicalSessionByAgent.get(agentId)?.size || 0;
  });

  const historical: LedgerHistorical = {
    byModel: historicalByModel,
    byAgent: historicalByAgent,
    costTimeSeries: Array.from(hourBuckets.entries())
      .sort((a, b) => a[0] - b[0])
      .map(([ts, data]) => ({ ts, costUsd: data.costUsd, tokens: data.tokens })),
    totalEstimatedUsd,
    totalTokens,
    rowCount: rows.length,
  };

  const estimatedSpend = {
    totalUsd: rows.length > 0 ? totalEstimatedUsd : null,
    windows: LEDGER_WINDOWS.reduce(
      (acc, window) => {
        const start = windowStart(now, window);
        const inWindow = rows.filter((row) => row.observedAtMs >= start);
        const priced = inWindow.filter((row) => row.estimatedCostUsd != null);
        acc[window] = {
          usd: inWindow.length > 0 ? priced.reduce((sum, row) => sum + (row.estimatedCostUsd ?? 0), 0) : null,
          coveragePct: inWindow.length > 0 ? Math.round((priced.length / inWindow.length) * 100) : 100,
        };
        return acc;
      },
      {} as Record<UsageWindow, { usd: number | null; coveragePct: number }>,
    ),
    byModel: Array.from(byModelCoverage.entries())
      .map(([fullModel, coverage]) => ({
        fullModel,
        usd: coverage.total > 0 ? coverage.usd : null,
        coveragePct: coverage.total > 0 ? Math.round((coverage.priced / coverage.total) * 100) : 100,
      }))
      .sort((a, b) => (b.usd || 0) - (a.usd || 0)),
  };

  const localTelemetryMeta = await usageDbGetMeta("local.last_ingest_ms");

  return {
    windows,
    activitySeries,
    activitySeriesByModel,
    historical,
    estimatedSpend,
    localTelemetryMs: localTelemetryMeta ? Number(localTelemetryMeta) || null : null,
  };
}

export async function clearUsageSchedulerBootstrap(): Promise<void> {
  await usageDbExec(`DELETE FROM usage_meta WHERE key = ${sqliteValue("scheduler.last_ensure_ms")};`);
}
