import type { Metadata } from 'next'
import type { ReactNode } from 'react'

export const metadata: Metadata = {
  title: 'DetLab | Detection Engineering, Threat Hunting, DFIR, and Security Documentation',
  description:
    'Build detections, investigate threats, document hunts and incidents, and convert learning into reusable portfolio-ready security knowledge.',
}

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body style={{ margin: 0 }}>{children}</body>
    </html>
  )
}
