export type UsageWindow = "last1h" | "last24h" | "last7d" | "allTime";

export type UsageApiBucket = {
  inputTokens: number;
  outputTokens: number;
  totalTokens: number;
  sessions: number;
};

export type UsageActivityPoint = {
  ts: number;
  input: number;
  output: number;
  total: number;
  sessions: number;
};

export type ProviderBillingFreshness = "fresh" | "stale" | "unknown";

export type ProviderBillingRow = {
  accountScope: string;
  fullModel: string | null;
  bucketStartMs: number;
  bucketEndMs: number;
  spendUsd: number | null;
  requests: number | null;
  inputTokens: number | null;
  outputTokens: number | null;
  reasoningTokens: number | null;
  isFinal: boolean;
};

export type ProviderBillingProviderSnapshot = {
  provider: string;
  available: boolean;
  reason?: string;
  requiredCredential?: string;
  freshness: ProviderBillingFreshness;
  bucketGranularity: "day" | null;
  latestBucketStartMs: number | null;
  totalUsd30d: number | null;
  currentMonthUsd: number | null;
  rows: ProviderBillingRow[];
};

export type ReconciliationStatus =
  | "estimated-only"
  | "provider-only"
  | "reconciled"
  | "mismatch"
  | "stale";

export type ReconciliationRow = {
  provider: string;
  fullModel: string | null;
  bucketStartMs: number;
  status: ReconciliationStatus;
  localEstimatedSpendUsd: number | null;
  providerReportedSpendUsd: number | null;
  diffUsd: number | null;
  diffPct: number | null;
};

export type ReconciliationSummary = {
  reconciledBuckets: number;
  mismatchBuckets: number;
  estimatedOnlyBuckets: number;
  providerOnlyBuckets: number;
  staleBuckets: number;
};

export type UsageApiResponse = {
  ok: true;
  asOfMs: number;
  liveTelemetry: {
    totals: {
      sessions: number;
      agents: number;
      models: number;
      inputTokens: number;
      outputTokens: number;
      reasoningTokens: number;
      cacheReadTokens: number;
      cacheWriteTokens: number;
      totalTokens: number;
    };
    windows: Record<UsageWindow, UsageApiBucket>;
    byModel: Array<{
      fullModel: string;
      provider: string;
      sessions: number;
      totalTokens: number;
      inputTokens: number;
      outputTokens: number;
      estimatedCostUsd: number | null;
    }>;
    byAgent: Array<{
      agentId: string;
      sessions: number;
      totalTokens: number;
      estimatedCostUsd: number | null;
    }>;
    sourceLabel: "Local telemetry";
  };
  estimatedSpend: {
    totalUsd: number | null;
    windows: Record<UsageWindow, { usd: number | null; coveragePct: number }>;
    byModel: Array<{
      fullModel: string;
      usd: number | null;
      coveragePct: number;
    }>;
    sourceLabel: "Estimated from local telemetry and pricing";
  };
  providerBilling: {
    providers: ProviderBillingProviderSnapshot[];
  };
  reconciliation: {
    summary: ReconciliationSummary;
    rows: ReconciliationRow[];
  };
  freshness: {
    localTelemetryMs: number | null;
    providerBillingByProvider: Record<string, number | null>;
    reconciliationMs: number | null;
  };
  coverage: {
    estimatedPricingCoveragePct: number;
    invoiceGradeProviders: string[];
    estimateOnlyProviders: string[];
  };
  diagnostics: {
    warnings: string[];
    sourceErrors: Array<{ source: string; error: string }>;
  };
};

export type UsageMetaRow = {
  key: string;
  value: string;
  updated_at_ms: number;
};

export type UsageAlertKind = "token-usage" | "estimated-spend" | "provider-spend";
export type UsageAlertScopeType = "model" | "provider" | "global";
export type UsageAlertTimeline =
  | "last1h"
  | "last24h"
  | "last7d"
  | "todayUtc"
  | "monthUtc";

export type UsageAlertRuleRecord = {
  id: string;
  kind: UsageAlertKind;
  scopeType: UsageAlertScopeType;
  scopeValue: string | null;
  timeline: UsageAlertTimeline;
  thresholdType: "gte";
  thresholdValue: number;
  deliveryMode: string;
  deliveryChannel: string | null;
  deliveryTo: string | null;
  bestEffort: boolean;
  enabled: boolean;
  cooldownWindowKey: string | null;
  createdAt: number;
  updatedAt: number;
};

export type UsageAlertFiringRecord = {
  id: string;
  ruleId: string;
  windowKey: string;
  observedValue: number;
  message: string;
  firedAt: number;
  deliveryStatus: "pending" | "sent" | "failed";
  deliveryError: string | null;
};
