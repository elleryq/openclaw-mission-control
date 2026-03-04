import { defaultCollectorUnavailable, resolveBillingCredential, saveProviderCollectorStatus, upsertProviderBillingBuckets, utcDayRange, type CollectorResult, type NormalizedProviderBillingBucket } from "@/lib/provider-billing/shared";

type OpenAiCostBucket = {
  start_time?: number;
  end_time?: number;
  results?: Array<{
    amount?: { value?: number; currency?: string };
    line_item?: string | null;
    organization_id?: string | null;
    project_id?: string | null;
  }>;
};

type OpenAiCostsResponse = {
  data?: OpenAiCostBucket[];
};

export async function collectOpenAIBilling(): Promise<CollectorResult> {
  const credential = await resolveBillingCredential(["OPENAI_ADMIN_API_KEY", "OPENAI_API_KEY"]);
  if (!credential.value) {
    const unavailable = defaultCollectorUnavailable("openai", credential.requiredCredential);
    await saveProviderCollectorStatus(unavailable);
    return unavailable;
  }

  try {
    const nowSec = Math.floor(Date.now() / 1000);
    const startSec = nowSec - 31 * 24 * 60 * 60;
    const url = new URL("https://api.openai.com/v1/organization/costs");
    url.searchParams.set("start_time", String(startSec));
    url.searchParams.set("bucket_width", "1d");
    url.searchParams.set("limit", "31");
    const res = await fetch(url, {
      headers: { Authorization: `Bearer ${credential.value}` },
      cache: "no-store",
    });
    if (!res.ok) {
      const body = await res.text().catch(() => "");
      throw new Error(`OpenAI costs returned ${res.status}: ${body.slice(0, 200)}`);
    }
    const payload = (await res.json()) as OpenAiCostsResponse;
    const data = Array.isArray(payload.data) ? payload.data : [];
    const fetchedAtMs = Date.now();
    const todayStart = Date.UTC(new Date().getUTCFullYear(), new Date().getUTCMonth(), new Date().getUTCDate());
    const rows: NormalizedProviderBillingBucket[] = data.map((bucket) => {
      const bucketStartMs = toMs(bucket.start_time);
      const bucketEndMs = toMs(bucket.end_time) || (bucketStartMs ? bucketStartMs + 86_400_000 : utcDayRange(Date.now()).bucketEndMs);
      const spendUsd = Array.isArray(bucket.results)
        ? bucket.results.reduce((sum, result) => sum + (Number(result.amount?.value) || 0), 0)
        : 0;
      const scope = Array.isArray(bucket.results)
        ? String(bucket.results[0]?.project_id || bucket.results[0]?.organization_id || "default")
        : "default";
      return {
        provider: "openai",
        accountScope: scope,
        fullModel: null,
        bucketStartMs,
        bucketEndMs,
        bucketGranularity: "day",
        currency: "USD",
        requests: null,
        inputTokens: null,
        outputTokens: null,
        reasoningTokens: null,
        spendUsd,
        providerReference: null,
        payload: bucket,
        dataLatencyNote: bucketStartMs >= todayStart ? "Current-day costs can lag provider reporting." : null,
        isFinal: bucketStartMs < todayStart,
      };
    });
    await upsertProviderBillingBuckets(rows, fetchedAtMs);
    const result: CollectorResult = {
      provider: "openai",
      available: true,
      fetchedAtMs,
      bucketCount: rows.length,
    };
    await saveProviderCollectorStatus(result);
    return result;
  } catch (err) {
    const result: CollectorResult = {
      provider: "openai",
      available: false,
      reason: err instanceof Error ? err.message : String(err),
      requiredCredential: credential.requiredCredential,
    };
    await saveProviderCollectorStatus(result);
    return result;
  }
}

function toMs(value: unknown): number {
  const n = Number(value);
  if (!Number.isFinite(n) || n <= 0) return 0;
  return n < 1_000_000_000_000 ? Math.trunc(n * 1000) : Math.trunc(n);
}
