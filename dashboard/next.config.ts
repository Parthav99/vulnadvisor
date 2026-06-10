import type { NextConfig } from "next";

// Proxy /api/* on this (Vercel) origin to the platform backend. This makes the OAuth flow
// same-origin from the browser's point of view: the callback's Set-Cookie (va_session) is
// received from the dashboard's own domain, so the browser scopes the session cookie to the
// dashboard — which is what lets server-side rendering read & forward it to the API.
// Destination is the backend base URL (API_URL), e.g. https://vulnadvisor-api.onrender.com.
const API_TARGET = process.env.API_URL ?? "http://localhost:8000";

const nextConfig: NextConfig = {
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
