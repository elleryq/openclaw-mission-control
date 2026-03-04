import { NextRequest, NextResponse } from "next/server";
import { getProviderSnapshot, maybeCollectProvider } from "@/lib/provider-billing/shared";

export const dynamic = "force-dynamic";

type RouteContext = {
  params: Promise<{ provider: string }>;
};

export async function GET(request: NextRequest, context: RouteContext) {
  try {
    const { provider } = await context.params;
    if (provider !== "openrouter" && provider !== "openai" && provider !== "anthropic") {
      return NextResponse.json({ ok: false, error: "Unsupported provider" }, { status: 404 });
    }
    if (request.nextUrl.searchParams.get("refresh") === "1") {
      await maybeCollectProvider(provider);
    }
    const snapshot = await getProviderSnapshot(provider);
    return NextResponse.json({ ok: true, provider, snapshot });
  } catch (err) {
    return NextResponse.json(
      { ok: false, error: err instanceof Error ? err.message : String(err) },
      { status: 500 },
    );
  }
}
