import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Minimal self-contained server output for the Docker runtime stage
  // (backend/../frontend/Dockerfile copies .next/standalone) — §58.
  output: "standalone",
};

export default nextConfig;
