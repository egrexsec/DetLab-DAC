import type { Metadata } from 'next'
import type { ReactNode } from 'react'

export const metadata: Metadata = {
  title: 'DetLab | Security Documentation Website',
  description:
    'A website-only security documentation platform for detections, threat hunts, investigations, DFIR notes, and learning paths — with a future path to becoming a reusable self-hosted template.',
}

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body
        style={{
          margin: 0,
          fontFamily:
            'Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
          background: '#020617',
          color: '#e2e8f0',
        }}
      >
        {children}
      </body>
    </html>
  )
}
