/** @type {import('next').NextConfig} */
const isGitHubPages = process.env.GITHUB_PAGES === 'true'
const repoBasePath = '/DetLab-DAC'

const nextConfig = {
  output: 'export',
  trailingSlash: true,
  basePath: isGitHubPages ? repoBasePath : '',
  assetPrefix: isGitHubPages ? `${repoBasePath}/` : '',
}

export default nextConfig
