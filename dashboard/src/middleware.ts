import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

/**
 * Next.js Edge Middleware — Route Protection
 *
 * Runs on every matched request BEFORE the page renders.
 * Checks for the `packetlens_token` cookie set by AuthContext.
 *
 * Note: This is a lightweight gate. The real auth validation happens
 * server-side when the API rejects requests with invalid/expired JWTs.
 * This middleware only prevents the flash of the dashboard UI for
 * unauthenticated users.
 */
export function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;

  // Allow public routes
  const publicPaths = ["/login", "/api", "/_next", "/favicon.ico"];
  if (publicPaths.some((p) => pathname.startsWith(p))) {
    return NextResponse.next();
  }

  // Check for auth token cookie
  const token = request.cookies.get("packetlens_token")?.value;

  if (!token) {
    // Redirect to login with return URL
    const loginUrl = new URL("/login", request.url);
    loginUrl.searchParams.set("from", pathname);
    return NextResponse.redirect(loginUrl);
  }

  return NextResponse.next();
}

export const config = {
  // Match all routes except static files and API
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
