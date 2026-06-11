import type { NextConfig } from "next";

// Proxy /api/* on this (Vercel) origin to the platform backend. This makes the OAuth flow
// same-origin from the browser's point of view: the callback's Set-Cookie (va_session) is
// received from the dashboard's own domain, so the browser scopes the session cookie to the
// dashboard — which is what lets server-side rendering read & forward it to the API.
// Destination is the backend base URL (API_URL), e.g. https://vulnadvisor-api.onrender.com.
const API_TARGET = process.env.API_URL ?? "http://localhost:8000";

// `next dev` needs eval (sourcemaps/HMR) and a websocket; the production build must not.
const isDev = process.env.NODE_ENV === "development";

const CSP = [
  "default-src 'self'",
  // Next.js bootstraps hydration with inline scripts; no eval in production.
  `script-src 'self' 'unsafe-inline'${isDev ? " 'unsafe-eval'" : ""}`,
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "font-src 'self' data:",
  `connect-src 'self'${isDev ? " ws:" : ""}`,
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join("; ");

const SECURITY_HEADERS = [
  { key: "Content-Security-Policy", value: CSP },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
  // frame-ancestors covers modern browsers; this is the legacy equivalent.
  { key: "X-Frame-Options", value: "DENY" },
];

const nextConfig: NextConfig = {
  async headers() {
    return [
      {
        source: "/:path*",
        headers: SECURITY_HEADERS,
      },
    ];
  },
  async rewrites() {
    return [
      {
        source: "/api/:path*",
        destination: `${API_TARGET}/:path*`,
      },
    ];
  },
};

export default nextConfig;
