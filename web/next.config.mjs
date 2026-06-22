import { getProxyDestination } from './config/api-origin.mjs'

/** @type {import('next').NextConfig} */
const nextConfig = {
  async rewrites() {
    return [
      {
        source: '/api/:path*',
        destination: getProxyDestination(process.env),
      },
    ]
  },
}

export default nextConfig
