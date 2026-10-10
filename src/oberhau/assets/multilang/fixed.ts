// Static negative control; a constant destination is not itself a proof of safety.
export async function GET(request: any) {
  const ignored = request.nextUrl.searchParams.get("url");
  return fetch("https://example.invalid/fixed-fixture");
}
