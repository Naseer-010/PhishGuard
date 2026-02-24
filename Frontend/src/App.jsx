import './App.css'

const features = [
	{
		title: 'URL Scanner',
		description: 'Quickly check suspicious links before opening them.',
	},
	{
		title: 'Email Checks',
		description: 'Review sender and content patterns for phishing signals.',
	},
	{
		title: 'Threat Alerts',
		description: 'Get clear risk levels and recommended next actions.',
	},
]

function App() {
	return (
		<div className="app">
			<header className="header">
				<div className="brand">
					<span className="brand-dot" aria-hidden="true" />
					<h1>PhishGuard</h1>
				</div>
				<button type="button" className="button-secondary">
					Dashboard (Soon)
				</button>
			</header>

			<main className="container">
				<section className="hero">
					<p className="eyebrow">Phishing Protection MVP</p>
					<h2>Protect users from malicious links and fake emails.</h2>
					<p className="hero-text">
						This is the basic frontend foundation for PhishGuard. Add backend
						integration and real-time detection next.
					</p>

					<div className="scan-box">
						<label htmlFor="url" className="scan-label">
							Test a URL
						</label>
						<div className="scan-row">
							<input
								id="url"
								type="url"
								placeholder="https://example.com"
								className="scan-input"
							/>
							<button type="button" className="button-primary">
								Scan
							</button>
						</div>
					</div>
				</section>

				<section className="stats-grid" aria-label="quick stats">
					<article className="card">
						<h3>0</h3>
						<p>Scans Completed</p>
					</article>
					<article className="card">
						<h3>Low</h3>
						<p>Current System Risk</p>
					</article>
					<article className="card">
						<h3>Ready</h3>
						<p>Frontend Status</p>
					</article>
				</section>

				<section className="features">
					<h2>Core Features (Basic)</h2>
					<div className="features-grid">
						{features.map((feature) => (
							<article key={feature.title} className="feature-card">
								<h3>{feature.title}</h3>
								<p>{feature.description}</p>
							</article>
						))}
					</div>
				</section>
			</main>
		</div>
	)
}

export default App
