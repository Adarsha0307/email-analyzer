import { useState } from 'react';
import { postJson } from './api.js';

const EMPTY_ERROR_RESULT = {
  score: 0,
  label: 'Error',
  issues: ['The analyzer could not complete this request.'],
  recommendations: [],
};

function safetyColor(score) {
  if (score >= 80) return '#4fd1c5';
  if (score >= 50) return '#ffb020';
  return '#ff6b6b';
}

function riskColor(score) {
  if (score >= 80) return '#e53e3e';
  if (score >= 60) return '#ff6b6b';
  if (score >= 40) return '#ffb020';
  if (score >= 20) return '#68d391';
  return '#4fd1c5';
}

function TextResult({ result, scoreLabel }) {
  if (!result) return null;
  const issues = Array.isArray(result.issues) ? result.issues : EMPTY_ERROR_RESULT.issues;
  const recommendations = Array.isArray(result.recommendations) ? result.recommendations : [];

  return (
    <div className="analysis-result fade-in" aria-live="polite">
      <p className="result-summary">
        <strong>{scoreLabel}:</strong>{' '}
        <span className="result-score" style={{ color: safetyColor(result.score) }}>
          {result.score}/100
        </span>{' '}
        <span className="result-label">{result.label}</span>
      </p>
      <div className="analysis-section">
        <span className="section-title">Findings</span>
        <ul>{issues.map((issue, index) => <li key={index} className="finding-item">{issue}</li>)}</ul>
      </div>
      {recommendations.length > 0 && (
        <div className="analysis-section">
          <span className="section-title">Recommendations</span>
          <ul>{recommendations.map((item, index) => <li key={index} className="rec-item">{item}</li>)}</ul>
        </div>
      )}
    </div>
  );
}

function AnalyzerPage() {
  const [url, setUrl] = useState('');
  const [emailText, setEmailText] = useState('');
  const [password, setPassword] = useState('');
  const [urlResult, setUrlResult] = useState(null);
  const [emailResult, setEmailResult] = useState(null);
  const [passwordResult, setPasswordResult] = useState(null);
  const [urlLoading, setUrlLoading] = useState(false);
  const [emailLoading, setEmailLoading] = useState(false);
  const [passwordLoading, setPasswordLoading] = useState(false);
  const [showTech, setShowTech] = useState(false);

  async function analyzeUrl() {
    if (!url.trim() || urlLoading) return;
    setUrlLoading(true);
    setUrlResult(null);
    setShowTech(false);
    try {
      setUrlResult(await postJson('/api/analyze/url', { url }));
    } catch (error) {
      setUrlResult({ error: error.message, riskScore: 0, label: 'Scan error' });
    } finally {
      setUrlLoading(false);
    }
  }

  async function analyzeEmail() {
    if (!emailText.trim() || emailLoading) return;
    setEmailLoading(true);
    setEmailResult(null);
    try {
      setEmailResult(await postJson('/api/analyze/email', { text: emailText }));
    } catch (error) {
      setEmailResult({ ...EMPTY_ERROR_RESULT, issues: [error.message] });
    } finally {
      setEmailLoading(false);
    }
  }

  async function analyzePassword() {
    if (!password || passwordLoading) return;
    setPasswordLoading(true);
    setPasswordResult(null);
    try {
      setPasswordResult(await postJson('/api/analyze/password', { password }));
    } catch (error) {
      setPasswordResult({ ...EMPTY_ERROR_RESULT, issues: [error.message] });
    } finally {
      setPasswordLoading(false);
    }
  }

  function renderUrlResult() {
    if (!urlResult) return null;
    if (urlResult.error) {
      return (
        <div className="analysis-result error-result fade-in" role="alert">
          <strong>{urlResult.ssrfWarning ? 'Unsafe target blocked' : 'Scan error'}</strong>
          <p>{urlResult.error || urlResult.message}</p>
        </div>
      );
    }

    const score = urlResult.riskScore ?? urlResult.score ?? 0;
    const color = urlResult.color || riskColor(score);
    const findings = Array.isArray(urlResult.findings) ? urlResult.findings : [];
    const signals = Array.isArray(urlResult.signals) ? urlResult.signals : [];
    const tech = urlResult.technical || {};

    return (
      <div className="analysis-result fade-in" aria-live="polite">
        <div className="score-display-box">
          <div className="score-display-number" style={{ color }}>{score}/100</div>
          <div className="score-display-label" style={{ color }}>{urlResult.label || 'Unknown'}</div>
          {urlResult.confidence !== undefined && (
            <div className="score-display-meta">
              Confidence: {urlResult.confidence}%
              {urlResult.hardOverrideApplied && <span className="override-note">Threat intelligence confirmed</span>}
            </div>
          )}
          <div className="score-display-url">{urlResult.url}</div>
        </div>

        {signals.length > 0 && (
          <div className="signal-list">
            <p className="signal-heading">Signal breakdown</p>
            {signals.map((signal, index) => (
              <div className="signal" key={`${signal.name}-${index}`}>
                <div className="signal-row">
                  <span>{signal.name}</span>
                  <span style={{ color: riskColor(signal.rawScore) }}>{signal.rawScore}/100</span>
                </div>
                <div className="signal-track" aria-hidden="true">
                  <div className="signal-fill" style={{ width: `${signal.rawScore}%`, background: riskColor(signal.rawScore) }} />
                </div>
              </div>
            ))}
            <div className="signal-footer">Weighted aggregation of {signals.length} independent checks</div>
          </div>
        )}

        {findings.length > 0 && (
          <div className="url-findings">
            <p className="signal-heading">Findings ({findings.length})</p>
            {findings.map((finding, index) => (
              <article className={`url-finding severity-${finding.severity || 'info'}`} key={`${finding.title}-${index}`}>
                <div className="finding-title">
                  {finding.title}
                  <span className="finding-severity">{finding.severity || 'info'}</span>
                  {finding.source && <span className="finding-source">{finding.source.replace(/_/g, ' ')}</span>}
                </div>
                <div className="finding-desc">{finding.description}</div>
                {finding.brand && <div className="finding-brand">Impersonated brand: {finding.brand}</div>}
              </article>
            ))}
          </div>
        )}

        {tech.hostname && (
          <div className="technical-section">
            <button type="button" onClick={() => setShowTech((value) => !value)} className="secondary-btn">
              {showTech ? 'Hide' : 'Show'} technical details
            </button>
            {showTech && (
              <div className="tech-details-box">
                <div className="tech-row"><span className="tech-label">Hostname</span><span className="tech-value">{tech.hostname}</span></div>
                {tech.protocol && <div className="tech-row"><span className="tech-label">Protocol</span><span>{tech.protocol}</span></div>}
                {tech.ip && <div className="tech-row"><span className="tech-label">IP address</span><span>{tech.ip}</span></div>}
                {tech.registeredDomain && <div className="tech-row"><span className="tech-label">Registered domain</span><span>{tech.registeredDomain}</span></div>}
                {tech.tld && <div className="tech-row"><span className="tech-label">TLD</span><span>{tech.tld}</span></div>}
                {tech.sslIssuer && <div className="tech-row"><span className="tech-label">SSL issuer</span><span>{tech.sslIssuer}</span></div>}
                {tech.sslProtocol && <div className="tech-row"><span className="tech-label">TLS protocol</span><span>{tech.sslProtocol}</span></div>}
                {tech.sslExpiresDays !== undefined && <div className="tech-row"><span className="tech-label">SSL expires in</span><span>{tech.sslExpiresDays} days</span></div>}
                {tech.redirectCount !== undefined && <div className="tech-row"><span className="tech-label">Redirects</span><span>{tech.redirectCount}</span></div>}
                {tech.finalUrl && tech.finalUrl !== urlResult.url && <div className="tech-row"><span className="tech-label">Final URL</span><span className="tech-value">{tech.finalUrl}</span></div>}
                {tech.homographRisk && (
                  <div className="homograph-warning">
                    <strong>Homograph attack detected</strong>
                    <div>{tech.homographRisk.description}</div>
                    <div className="tech-warning">Risk: {tech.homographRisk.risk}</div>
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </div>
    );
  }

  return (
    <main className="content-panel">
      <section className="page-stack">
        <header className="page-header">
          <div>
            <p className="eyebrow">N001 / Threat analysis console</p>
            <h1>Inspect before you trust.</h1>
            <p className="page-copy">Analyze URLs, suspicious email content, and password strength from one focused workspace.</p>
          </div>
          <div className="system-status"><span /> Analyzer online</div>
        </header>

        <section className="panel-grid">
          <article className="panel-card">
            <div className="card-index">01 / URL</div>
            <h2>URL reputation scan</h2>
            <p className="page-copy">Checks threat intelligence, DNS, SSL, redirects, brand impersonation, and URL structure.</p>
            <label className="input-label" htmlFor="url-input">URL to inspect</label>
            <textarea id="url-input" className="input-area" placeholder="https://suspicious-login-portal.net" value={url} onChange={(event) => setUrl(event.target.value)} />
            <button type="button" className={`primary-btn ${urlLoading ? 'btn-loading' : ''}`} onClick={analyzeUrl} disabled={urlLoading || !url.trim()}>
              {urlLoading ? 'Scanning URL...' : 'Scan URL'}
            </button>
            {renderUrlResult()}
          </article>

          <article className="panel-card">
            <div className="card-index">02 / EMAIL</div>
            <h2>Phishing email review</h2>
            <p className="page-copy">Detects urgency, deceptive requests, suspicious links, impersonation, and financial bait.</p>
            <label className="input-label" htmlFor="email-input">Email text or headers</label>
            <textarea id="email-input" className="input-area" placeholder="Paste suspicious email text, headers, or links here..." value={emailText} onChange={(event) => setEmailText(event.target.value)} />
            <button type="button" className={`primary-btn ${emailLoading ? 'btn-loading' : ''}`} onClick={analyzeEmail} disabled={emailLoading || !emailText.trim()}>
              {emailLoading ? 'Analyzing email...' : 'Analyze email'}
            </button>
            <TextResult result={emailResult} scoreLabel="Safety score" />
          </article>
        </section>

        <section className="panel-card password-card">
          <div>
            <div className="card-index">03 / PASSWORD</div>
            <h2>Password strength auditor</h2>
            <p className="page-copy">Evaluates length, character diversity, and common weak patterns. Passwords stay local to this server and are not sent to AI providers.</p>
          </div>
          <div className="password-control">
            <label className="input-label" htmlFor="password-input">Password to audit</label>
            <input id="password-input" type="password" className="input-area" autoComplete="off" placeholder="Enter a password to review" value={password} onChange={(event) => setPassword(event.target.value)} />
            <button type="button" className={`primary-btn ${passwordLoading ? 'btn-loading' : ''}`} onClick={analyzePassword} disabled={passwordLoading || !password}>
              {passwordLoading ? 'Auditing password...' : 'Audit password'}
            </button>
          </div>
          <TextResult result={passwordResult} scoreLabel="Strength score" />
        </section>
      </section>
    </main>
  );
}

export default AnalyzerPage;
