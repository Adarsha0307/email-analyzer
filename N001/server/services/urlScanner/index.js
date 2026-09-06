import { normalizeUrl, validateUrlSafety, isPrivateIpAddress } from './normalizer.js';
import { checkAllSources } from './threatIntel.js';
import { analyzeDomain, resolveIp } from './domainAnalysis.js';
import { checkSslCertificate } from './sslAnalysis.js';
import { analyzeRedirects } from './redirectAnalysis.js';
import { detectBrandImpersonation } from './brandImpersonation.js';
import { analyzeUrlHeuristics } from './heuristics.js';
import { calculateRiskScore, aggregateFindings } from './scoringEngine.js';
import { getCachedResult, cacheResult } from './cache.js';

export async function scanUrl(url, options = {}) {
  const { useCache = true, followRedirects = true, checkSsl = true } = options;
  const normalized = normalizeUrl(url);
  if (normalized.error) {
    return {
      error: normalized.error,
      ssrfWarning: normalized.ssrfWarning || false,
      url,
      riskScore: 0,
      confidence: 100,
      classification: 'error',
      label: 'Invalid URL',
      color: '#999',
      findings: [{ severity: 'high', category: 'validation', title: 'Invalid URL', description: normalized.error }],
    };
  }

  if (useCache) {
    const cached = await getCachedResult(normalized.normalized);
    if (cached) return { ...cached.result, cached: true };
  }

  const ip = await resolveIp(normalized.hostname);
  if (ip && isPrivateIpAddress(ip)) {
    return {
      error: 'The hostname resolves to a private or local network address and was blocked.',
      ssrfWarning: true,
      url: normalized.normalized,
      riskScore: 0,
      confidence: 100,
      classification: 'error',
      label: 'Blocked target',
      color: '#999',
      findings: [],
    };
  }

  const domainResults = await analyzeDomain(normalized.hostname, ip);
  const sslPort = normalized.port ? Number(normalized.port) : 443;
  const shouldCheckSsl = checkSsl && normalized.protocol === 'https:';
  const [threatIntel, ssl, redirects, heuristics] = await Promise.all([
    checkAllSources(normalized.normalized, normalized.hostname, ip),
    shouldCheckSsl
      ? checkSslCertificate(normalized.hostname, sslPort)
      : Promise.resolve({ valid: false, findings: [], riskScore: 0 }),
    followRedirects
      ? analyzeRedirects(normalized.normalized)
      : Promise.resolve({ chain: [], redirectCount: 0, finalUrl: normalized.normalized, findings: [], riskScore: 0, sameDomain: true }),
    Promise.resolve(analyzeUrlHeuristics(normalized.normalized, normalized.hostname, normalized.pathname)),
  ]);

  const brands = detectBrandImpersonation(normalized.hostname, domainResults.registrableDomain);
  const allResults = {
    threatIntel,
    domainAnalysis: domainResults,
    sslAnalysis: ssl,
    redirectAnalysis: redirects,
    urlHeuristics: heuristics,
    brandImpersonationFindings: brands,
  };
  const scoring = calculateRiskScore(allResults);
  const findings = aggregateFindings(allResults);
  for (const warning of validateUrlSafety(normalized.normalized).reverse()) {
    findings.unshift({ severity: warning.severity, category: warning.category, title: warning.category === 'protocol' ? 'Unencrypted protocol' : 'Suspicious URL structure', description: warning.message });
  }

  const result = {
    url: normalized.normalized,
    originalUrl: url,
    ...scoring,
    findings,
    technical: {
      hostname: normalized.hostname,
      protocol: normalized.protocol,
      ip: ip || domainResults.ip,
      registeredDomain: domainResults.registrableDomain,
      tld: domainResults.tld,
      mxRecords: domainResults.mxRecords,
      nameservers: domainResults.nameservers,
      sslIssuer: ssl.issuer,
      sslValid: ssl.valid,
      sslProtocol: ssl.protocol,
      sslExpiresDays: ssl.remainingDays,
      redirectCount: redirects.redirectCount,
      finalUrl: redirects.finalUrl,
      redirectChain: redirects.chain,
      homographRisk: normalized.homographRisk,
    },
  };

  if (useCache) await cacheResult(normalized.normalized, result);
  return result;
}
