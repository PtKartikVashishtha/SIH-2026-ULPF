/** @type {import('next').NextConfig} */
const nextConfig = {
  output: process.platform === "win32" && !process.env.FORCE_STANDALONE ? undefined : "standalone",
};
export default nextConfig;
