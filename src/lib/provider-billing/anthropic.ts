import { defaultCollectorUnavailable, resolveBillingCredential, saveProviderCollectorStatus, upsertProviderBillingBuckets, utcDayRange, type CollectorResult, type NormalizedProviderBillingBucket } from "@/lib/provider-billing/shared";

type AnthropicBucket = {
  starting_at?: string;
  ending_at?: string;
  model?: string | null;
  amount?: { value?: number; currency?: string };
  cost_usd?: number;
  input_tokens?: number;
  output_tokens?: number;
  requests?: number;
};

type AnthropicCostResponse = {
  data?: AnthropicBucket[];
};

export async function collectAnthropicBilling(): Promise<CollectorResult> {
  const credential = await resolveBillingCredential(["ANTHROPIC_ADMIN_API_KEY", "ANTHROPIC_API_KEY"]);
  if (!credential.value) {
    const unavailable = defaultCollectorUnavailable("anthropic", credential.requiredCredential);
    await saveProviderCollectorStatus(unavailable);
    return unavailable;
  }

  try {
    const start = new Date(Date.now() - 31 * 24 * 60 * 60 * 1000).toISOString();
    const end = new Date().toISOString();
    const url = new URL("https://api.anthropic.com/v1/organizations/cost_report/messages");
    url.searchParams.set("starting_at", start);
    url.searchParams.set("ending_at", end);
    url.searchParams.set("bucket_width", "1d");
    const res = await fetch(url, {
      headers: {
        "x-api-key": credential.value,
        "anthropic-version": "2023-06-01",
        "anthropic-beta": "usage-cost-2025-01-24",
      },
      cache: "no-store",
    });
    if (!res.ok) {
      const body = await res.text().catch(() => "");
      throw new Error(`Anthropic cost report returned ${res.status}: ${body.slice(0, 200)}`);
    }
    const payload = (await res.json()) as AnthropicCostResponse;
    const data = Array.isArray(payload.data) ? payload.data : [];
    const fetchedAtMs = Date.now();
    const todayStart = Date.UTC(new Date().getUTCFullYear(), new Date().getUTCMonth(), new Date().getUTCDate());
    const rows: NormalizedProviderBillingBucket[] = data.map((bucket) => {
      const range = utcDayRange(bucket.starting_at || Date.now());
      return {
        provider: "anthropic",
        accountScope: "default",
        fullModel: bucket.model || null,
        bucketStartMs: range.bucketStartMs,
        bucketEndMs: range.bucketEndMs,
        bucketGranularity: "day",
        currency: "USD",
        requests: Number.isFinite(bucket.requests) ? Number(bucket.requests) : null,
        inputTokens: Number.isFinite(bucket.input_tokens) ? Number(bucket.input_tokens) : null,
        outputTokens: Number.isFinite(bucket.output_tokens) ? Number(bucket.output_tokens) : null,
        reasoningTokens: null,
        spendUsd:
          Number.isFinite(bucket.cost_usd)
            ? Number(bucket.cost_usd)
            : Number.isFinite(bucket.amount?.value)
              ? Number(bucket.amount?.value)
              : null,
        providerReference: null,
        payload: bucket,
        dataLatencyNote:
          range.bucketStartMs >= todayStart ? "Current-day billing can lag provider reporting." : null,
        isFinal: range.bucketStartMs < todayStart,
      };
    });
    await upsertProviderBillingBuckets(rows, fetchedAtMs);
    const result: CollectorResult = {
      provider: "anthropic",
      available: true,
      fetchedAtMs,
      bucketCount: rows.length,
    };
    await saveProviderCollectorStatus(result);
    return result;
  } catch (err) {
    const result: CollectorResult = {
      provider: "anthropic",
      available: false,
      reason: err instanceof Error ? err.message : String(err),
      requiredCredential: credential.requiredCredential,
    };
    await saveProviderCollectorStatus(result);
    return result;
  }
}
