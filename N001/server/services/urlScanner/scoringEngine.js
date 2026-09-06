const WEIGHTS = {
  threatIntel: 0.3,
  domainAnalysis: 0.2,
  sslAnalysis: 0.15,
  redirectAnalysis: 0.15,
  urlHeuristics: 0.12,
  brandImpersonation: 0.08,
};

const RISK_LEVELS = [
  { min: 0, max: 19, label: 'Minimal risk', classification: 'minimal', color: '#4fd1c5' },
  { min: 20, max: 39, label: 'Low risk', classification: 'low', color: '#68d391' },
  { min: 40, max: 59, label: 'Medium risk', classification: 'medium', color: '#ffb020' },
  { min: 60, max: 79, label: 'High risk', classification: 'high', color: '#ff6b6b' },
  { min: 80, max: 100, label: 'Critical risk', classification: 'critical', color: '#e53e3e' },
];

function riskLevel(score) {
  return RISK_LEVELS.find((level) => score >= level.min && score <= level.max) || RISK_LEVELS[0];
}

export function calculateRiskScore(results) {
  const threatIntel = results.threatIntel || { combinedScore: 0, combinedConfidence: 0, anyDetected: false };
  const domain = results.domainAnalysis || { riskScore: 0, findings: [] };
  const ssl = results.sslAnalysis || { riskScore: 0, findings: [], valid: false };
  const redirects = results.redirectAnalysis || { riskScore: 0, findings: [] };
  const heuristics = results.urlHeuristics || { riskScore: 0, findings: [] };
  const brands = results.brandImpersonationFindings || [];
  const threatScore = threatIntel.anyDetected ? Math.max(threatIntel.combinedScore, 70) : threatIntel.combinedScore;

  const signals = [
    { name: 'Threat Intelligence', rawScore: threatScore, weight: WEIGHTS.threatIntel, confidence: threatIntel.combinedConfidence || 0.5 },
    { name: 'Domain Analysis', rawScore: domain.riskScore, weight: WEIGHTS.domainAnalysis, confidence: domain.findings.length ? 0.8 : 0.4 },
    { name: 'SSL/TLS', rawScore: ssl.riskScore, weight: WEIGHTS.sslAnalysis, confidence: ssl.findings.length || !ssl.valid ? 0.9 : 0.5 },
    { name: 'Redirect Analysis', rawScore: redirects.riskScore, weight: WEIGHTS.redirectAnalysis, confidence: redirects.findings.length ? 0.85 : 0.4 },
    { name: 'URL Heuristics', rawScore: heuristics.riskScore, weight: WEIGHTS.urlHeuristics, confidence: heuristics.findings.length ? 0.75 : 0.3 },
    { name: 'Brand Impersonation', rawScore: brands.length ? 80 : 0, weight: WEIGHTS.brandImpersonation, confidence: brands.length ? 0.95 : 0.5 },
  ].map((signal) => ({
    ...signal,
    rawScore: Math.round(signal.rawScore),
    weighted: signal.rawScore * signal.weight,
    maxPossible: 100 * signal.weight,
  }));

  const weighted = signals.reduce((total, signal) => total + signal.weighted, 0);
  const maximum = signals.reduce((total, signal) => total + signal.maxPossible, 0);
  const calculated = Math.round((weighted / maximum) * 100);
  const activeConfidences = signals.filter((signal) => signal.rawScore > 0).map((signal) => signal.confidence);
  const confidence = activeConfidences.length
    ? Math.round(activeConfidences.reduce((total, value) => total + value, 0) / activeConfidences.length * 100)
    : 50;
  const finalScore = threatIntel.anyDetected ? Math.max(calculated, 90) : calculated;
  const level = riskLevel(finalScore);

  return {
    riskScore: finalScore,
    confidence: threatIntel.anyDetected ? Math.max(confidence, 95) : confidence,
    classification: level.classification,
    label: level.label,
    color: level.color,
    hardOverrideApplied: threatIntel.anyDetected,
    signals,
  };
}

export function aggregateFindings(results) {
  const findings = [];
  for (const threat of results.threatIntel?.threats || []) {
    if (threat.detected) {
      findings.push({ severity: 'critical', category: 'threat_intelligence', title: `${threat.source.replace(/_/g, ' ')} detection`, description: threat.note, source: threat.source });
    }
  }
  findings.push(...(results.domainAnalysis?.findings || []));
  findings.push(...(results.sslAnalysis?.findings || []));
  findings.push(...(results.redirectAnalysis?.findings || []));
  findings.push(...(results.urlHeuristics?.findings || []));
  findings.push(...(results.brandImpersonationFindings || []));
  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  return findings.sort((a, b) => (order[a.severity] ?? 5) - (order[b.severity] ?? 5));
}
