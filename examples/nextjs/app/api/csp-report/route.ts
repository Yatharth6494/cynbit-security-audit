export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  const declared = Number(request.headers.get("content-length") || 0);
  if (declared > 16384) return new Response(null, { status: 413 });

  const raw = await request.text();
  if (raw.length > 16384) return new Response(null, { status: 413 });

  return new Response(null, { status: 204 });
}
