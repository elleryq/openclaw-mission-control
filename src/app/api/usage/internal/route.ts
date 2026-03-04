import { NextRequest, NextResponse } from "next/server";
import { getGatewayToken } from "@/lib/paths";
import { fetchGatewaySessions } from "@/lib/gateway-sessions";
import { ingestGatewaySessionsToLedger } from "@/lib/usage-ledger";
import { maybeCollectProvider } from "@/lib/provider-billing/shared";
import { runUsageReconciliation } from "@/lib/reconciliation";
import { evaluateAndStoreUsageAlerts } from "@/lib/usage-alerts";
import { ensureUsageScheduler } from "@/lib/usage-scheduler";

export const dynamic = "force-dynamic";

function unauthorized() {
  return NextResponse.json({ ok: false, error: "Unauthorized" }, { status: 401 });
}

async function handleTask(task: string, request: NextRequest) {
  if (task === "ingest") {
    const sessions = await fetchGatewaySessions(12000);
    const result = await ingestGatewaySessionsToLedger(sessions);
    return NextResponse.json({ ok: true, task, ...result });
  }
  if (task === "collect-provider") {
    const provider = String(request.nextUrl.searchParams.get("provider") || "").trim();
    if (provider !== "openrouter" && provider !== "openai" && provider !== "anthropic") {
      return NextResponse.json({ ok: false, error: "Unsupported provider" }, { status: 400 });
    }
    const result = await maybeCollectProvider(provider);
    return NextResponse.json({ ok: true, task, result });
  }
  if (task === "reconcile") {
    const result = await runUsageReconciliation();
    return NextResponse.json({ ok: true, task, summary: result.summary, rows: result.rows.length });
  }
  if (task === "alerts") {
    const result = await evaluateAndStoreUsageAlerts();
    return NextResponse.json({ ok: true, task, evaluations: result.evaluations.length, firings: result.firings.length });
  }
  if (task === "ensure-scheduler") {
    const result = await ensureUsageScheduler(request.nextUrl.origin);
    return NextResponse.json({ ok: true, task, result });
  }
  return NextResponse.json({ ok: false, error: "Unknown task" }, { status: 400 });
}

function isAuthorized(request: NextRequest): boolean {
  const expected = process.env.MISSION_CONTROL_USAGE_WEBHOOK_TOKEN || getGatewayToken();
  if (!expected) return false;
  const token =
    request.nextUrl.searchParams.get("token") ||
    request.headers.get("x-mission-control-token") ||
    "";
  return token === expected;
}

export async function GET(request: NextRequest) {
  if (!isAuthorized(request)) return unauthorized();
  const task = String(request.nextUrl.searchParams.get("task") || "").trim();
  return handleTask(task, request);
}

export async function POST(request: NextRequest) {
  if (!isAuthorized(request)) return unauthorized();
  const task = String(request.nextUrl.searchParams.get("task") || "").trim();
  return handleTask(task, request);
}
