type LoggingRequest = Pick<Request, "url" | "headers">;

/** Keep private unlock requests and responses out of API Security telemetry. */
export function shouldLogApiSecurity(request: LoggingRequest): boolean {
  let pathname: string;
  try {
    const url = new URL(request.url);
    if (url.protocol !== "http:" && url.protocol !== "https:") return false;

    // Be conservative about case and path decoding across proxies. Normalize
    // dot segments after decoding too, because encoded separators can hide them.
    const segments: string[] = [];
    for (const segment of decodeURIComponent(url.pathname).toLowerCase().split(/[\\/]+/)) {
      if (segment === "..") segments.pop();
      else if (segment && segment !== ".") segments.push(segment);
    }
    pathname = `/${segments.join("/")}`;
  } catch {
    // An unparseable URL must never cause sensitive traffic to be recorded.
    return false;
  }

  if (pathname === "/api/testing-tools" || pathname.startsWith("/api/testing-tools/")) {
    return false;
  }

  // Preserve the existing content-type rule for every other endpoint.
  return request.headers.get("content-type") === "application/json";
}
