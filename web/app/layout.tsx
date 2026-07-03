import type { Metadata } from 'next'
import type { ReactNode } from 'react'

export const metadata: Metadata = {
  title: 'DetLab-DAC | Detection Engineering Documentation',
  description:
    'A static detection-engineering documentation site for publishing detections across Sigma, SPL, KQL, EQL, ES|QL, and related rule dialects.',
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
