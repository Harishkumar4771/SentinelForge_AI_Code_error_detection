import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: "standalone",
  async rewrites() {
    return [
      {
        source: "/api/:path*",
        destination: "https://" + "sentinelforge-ai-code-error-detection.onrender.com" + "/api/:path*",
      },
    ];
  },
};

export default nextConfig;
