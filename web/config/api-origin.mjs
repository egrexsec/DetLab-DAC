export function getInternalApiOrigin(env = process.env) {
  return env.DETLAB_INTERNAL_API_ORIGIN || 'http://127.0.0.1:8000'
}

export function getProxyDestination(env = process.env) {
  const origin = getInternalApiOrigin(env).replace(/\/$/, '')
  return `${origin}/:path*`
}
