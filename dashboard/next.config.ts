import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Produce a self-contained build for Docker deployment.
  // Outputs to .next/standalone with a minimal server.js
  // that doesn't require the full node_modules tree.
  output: "standalone",
};

export default nextConfig;
