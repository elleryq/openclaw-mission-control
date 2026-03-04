import { getGatewayToken } from "@/lib/paths";
import { gatewayCall } from "@/lib/openclaw";
import { usageDbGetMeta, usageDbSetMeta } from "@/lib/usage-db";

type CronJob = {
  id?: string;
  name?: string;
  description?: string;
  enabled?: boolean;
  schedule?: { kind?: string; everyMs?: number };
  payload?: { kind?: string; text?: string };
  delivery?: { mode?: string; to?: string };
};

type CronList = { jobs?: CronJob[] };

type SchedulerJob = {
  name: string;
  everyMs: number;
  task: string;
};

const JOBS: SchedulerJob[] = [
  { name: "mc-usage-ingest", everyMs: 60_000, task: "ingest" },
  { name: "mc-billing-openrouter", everyMs: 15 * 60_000, task: "collect-provider&provider=openrouter" },
  { name: "mc-billing-openai", everyMs: 5 * 60_000, task: "collect-provider&provider=openai" },
  { name: "mc-billing-anthropic", everyMs: 2 * 60_000, task: "collect-provider&provider=anthropic" },
  { name: "mc-reconcile-usage", everyMs: 5 * 60_000, task: "reconcile" },
  { name: "mc-alert-evaluator", everyMs: 60_000, task: "alerts" },
];

function buildWebhookUrl(origin: string, task: string): string | null {
  const gatewayToken = getGatewayToken();
  if (!origin || !gatewayToken) return null;
  const url = new URL("/api/usage/internal", origin);
  url.searchParams.set("task", task.split("&")[0]);
  for (const chunk of task.split("&").slice(1)) {
    const [key, value] = chunk.split("=");
    if (key) url.searchParams.set(key, value || "");
  }
  url.searchParams.set("token", gatewayToken);
  return url.toString();
}

function needsUpdate(job: CronJob | undefined, expectedEveryMs: number, webhookUrl: string): boolean {
  if (!job) return true;
  return (
    job.enabled !== true ||
    job.schedule?.kind !== "every" ||
    Number(job.schedule?.everyMs || 0) !== expectedEveryMs ||
    job.delivery?.mode !== "webhook" ||
    String(job.delivery?.to || "") !== webhookUrl ||
    job.payload?.kind !== "systemEvent"
  );
}

export async function ensureUsageScheduler(origin: string): Promise<{ ensured: boolean; reason?: string }> {
  const lastEnsureRaw = await usageDbGetMeta("scheduler.last_ensure_ms");
  const lastEnsure = lastEnsureRaw ? Number(lastEnsureRaw) || 0 : 0;
  if (lastEnsure > 0 && Date.now() - lastEnsure < 6 * 60 * 60 * 1000) {
    return { ensured: false, reason: "recently-ensured" };
  }

  const token = getGatewayToken();
  if (!origin || !token) {
    return { ensured: false, reason: "missing-origin-or-token" };
  }

  const existing = await gatewayCall<CronList>("cron.list", {}, 15000);
  const jobs = Array.isArray(existing.jobs) ? existing.jobs : [];

  for (const desired of JOBS) {
    const webhookUrl = buildWebhookUrl(origin, desired.task);
    if (!webhookUrl) continue;
    const current = jobs.find((job) => job.name === desired.name);
    if (!needsUpdate(current, desired.everyMs, webhookUrl)) continue;
    if (current?.id) {
      await gatewayCall(
        "cron.update",
        {
          id: current.id,
          patch: {
            enabled: true,
            description: "Mission Control system-managed usage job",
            schedule: { kind: "every", everyMs: desired.everyMs },
            payload: { kind: "systemEvent", text: desired.name },
            delivery: { mode: "webhook", to: webhookUrl, bestEffort: true },
          },
        },
        15000,
      );
      continue;
    }
    await gatewayCall(
      "cron.add",
      {
        name: desired.name,
        description: "Mission Control system-managed usage job",
        schedule: { kind: "every", everyMs: desired.everyMs },
        sessionTarget: "main",
        payload: { kind: "systemEvent", text: desired.name },
        delivery: { mode: "webhook", to: webhookUrl, bestEffort: true },
        enabled: true,
      },
      15000,
    );
  }

  await usageDbSetMeta("scheduler.last_ensure_ms", String(Date.now()));
  return { ensured: true };
}
