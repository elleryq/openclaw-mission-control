import { defaultCollectorUnavailable, newCollectorReference, resolveBillingCredential, saveProviderCollectorStatus, upsertProviderBillingBuckets, utcDayRange, type CollectorResult, type NormalizedProviderBillingBucket } from "@/lib/provider-billing/shared";

type OpenRouterCredits = {
  total_credits: number;
  total_usage: number;
};

type OpenRouterActivityRow = {
  date: string;
  model: string;
  provider_name: string;
  usage: number;
  requests: number;
  prompt_tokens: number;
  completion_tokens: number;
  reasoning_tokens: number;
};

const OR_BASE = "https://openrouter.ai/api/v1";

async function orFetch<T>(path: string, key: string): Promise<T> {
  const res = await fetch(`${OR_BASE}${path}`, {
    headers: { Authorization: `Bearer ${key}` },
    cache: "no-store",
  });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`OpenRouter ${path} returned ${res.status}: ${body.slice(0, 200)}`);
  }
  return (await res.json()) as T;
}

export async function collectOpenRouterBilling(): Promise<CollectorResult> {
  const credential = await resolveBillingCredential(["OPENROUTER_MANAGEMENT_KEY"]);
  if (!credential.value) {
    const unavailable = defaultCollectorUnavailable("openrouter", credential.requiredCredential);
    await saveProviderCollectorStatus(unavailable);
    return unavailable;
  }

  try {
    const fetchedAtMs = Date.now();
    const [creditsRaw, activityRaw] = await Promise.all([
      orFetch<{ data?: OpenRouterCredits }>("/credits", credential.value),
      orFetch<{ data?: OpenRouterActivityRow[] }>("/activity", credential.value),
    ]);
    const activity = Array.isArray(activityRaw.data) ? activityRaw.data : [];
    const currentUtcDayStart = new Date().toISOString().slice(0, 10);
    const rows: NormalizedProviderBillingBucket[] = activity.map((row) => {
      const { bucketStartMs, bucketEndMs } = utcDayRange(row.date);
      return {
        provider: "openrouter",
        accountScope: "default",
        fullModel: row.model || null,
        bucketStartMs,
        bucketEndMs,
        bucketGranularity: "day",
        currency: "USD",
        requests: Number.isFinite(row.requests) ? row.requests : null,
        inputTokens: Number.isFinite(row.prompt_tokens) ? row.prompt_tokens : null,
        outputTokens: Number.isFinite(row.completion_tokens) ? row.completion_tokens : null,
        reasoningTokens: Number.isFinite(row.reasoning_tokens) ? row.reasoning_tokens : null,
        spendUsd: Number.isFinite(row.usage) ? row.usage : null,
        providerReference: newCollectorReference("openrouter"),
        payload: row,
        dataLatencyNote:
          row.date === currentUtcDayStart
            ? "Daily data may lag near UTC rollover."
            : null,
        isFinal: row.date !== currentUtcDayStart,
      };
    });
    await upsertProviderBillingBuckets(rows, fetchedAtMs);
    const result: CollectorResult = {
      provider: "openrouter",
      available: true,
      fetchedAtMs,
      bucketCount: rows.length,
      reason:
        creditsRaw.data && Number.isFinite(creditsRaw.data.total_usage)
          ? undefined
          : undefined,
    };
    await saveProviderCollectorStatus(result);
    return result;
  } catch (err) {
    const result: CollectorResult = {
      provider: "openrouter",
      available: false,
      reason: err instanceof Error ? err.message : String(err),
      requiredCredential: credential.requiredCredential,
    };
    await saveProviderCollectorStatus(result);
    return result;
  }
}
