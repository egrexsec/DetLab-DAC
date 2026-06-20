import type { Metadata } from 'next'
import type { ReactNode } from 'react'

export const metadata: Metadata = {
  title: 'DetLab | Detection-First Threat Hunting & DFIR Platform',
  description:
    'Select a detection and immediately pivot into ATT&CK context, investigation guidance, DFIR artifacts, related detections, and cloud telemetry.',
}

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body style={{ margin: 0 }}>{children}</body>
    </html>
  )
}
