async function getHealth() {
  try {
    const response = await fetch('http://localhost:8000/health', {
      cache: 'no-store'
    })

    return response.json()
  } catch {
    return { status: 'offline' }
  }
}

export default async function HomePage() {
  const health = await getHealth()

  return (
    <main style={{ padding: '2rem', fontFamily: 'Arial' }}>
      <h1>DetLab Dashboard</h1>

      <div style={{ marginTop: '2rem' }}>
        <h2>Platform Status</h2>
        <p>API Status: {health.status}</p>
      </div>

      <div style={{ marginTop: '2rem' }}>
        <h2>Capabilities</h2>

        <ul>
          <li>ATT&CK Analytics</li>
          <li>Detection Scoring</li>
          <li>Behavioral Sequences</li>
          <li>Pack Registry</li>
          <li>Trust Verification</li>
          <li>Governance Reporting</li>
        </ul>
      </div>
    </main>
  )
}
