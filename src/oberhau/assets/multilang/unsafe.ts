// Static Next.js-shaped fixture. No server is started.
export async function GET(request: any) {
  const url = request.nextUrl.searchParams.get("url");
  return fetch(url);
}
