import dns from 'node:dns/promises';
import { isLocalHostname, isPrivateIpAddress } from './normalizer.js';

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);
const MAX_REDIRECTS = 10;
const ALLOWED_REDIRECT_HOSTS = new Set([
  // Populate with exact trusted hosts for outbound scanning.
  // Example: 'example.com',
]);
const ALLOWED_REDIRECT_DOMAIN_SUFFIXES = [
  // Populate with trusted parent domains.
  // Example: '.example.com',
];

function isAllowedHostname(hostname) {
  const value = String(hostname || '').toLowerCase().replace(/\.$/, '');
  if (!value) return false;
  if (ALLOWED_REDIRECT_HOSTS.has(value)) return true;
  return ALLOWED_REDIRECT_DOMAIN_SUFFIXES.some((suffix) => value.endsWith(suffix));
}

async function assertPublicTarget(url) {
  const parsed = new URL(url);
  if (!['http:', 'https:'].includes(parsed.protocol) || isLocalHostname(parsed.hostname)) {
    throw new Error('Redirect targets a blocked local or unsupported address.');
  }
  if (!isAllowedHostname(parsed.hostname)) {
    throw new Error('Redirect targets a hostname outside the allowed outbound policy.');
  }
  const addresses = await dns.lookup(parsed.hostname, { all: true });
  if (addresses.some(({ address }) => isPrivateIpAddress(address))) {
    throw new Error('Redirect resolves to a private network address.');
  }
}

export async function analyzeRedirects(url, timeout = 10000) {
  const findings = [];
  const chain = [];
  let riskScore = 0;
  let currentUrl = url;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);

  try {
    for (let index = 0; index < MAX_REDIRECTS; index += 1) {
      await assertPublicTarget(currentUrl);
      const response = await fetch(currentUrl, {
        method: 'HEAD',
        redirect: 'manual',
        signal: controller.signal,
        headers: { 'User-Agent': 'N001SecurityScanner/1.0' },
      });
      chain.push({ url: currentUrl, statusCode: response.status });
      if (!REDIRECT_STATUSES.has(response.status)) break;

      const location = response.headers.get('location');
      if (!location) break;
      const nextUrl = new URL(location, currentUrl).href;
      if (chain.some((entry) => entry.url === nextUrl)) {
        findings.push({ severity: 'high', category: 'redirect', title: 'Redirect loop detected', description: 'The URL redirects to a previously visited address.' });
        riskScore += 40;
        break;
      }
      currentUrl = nextUrl;
    }
  } catch (error) {
    if (error.name === 'AbortError') {
      findings.push({ severity: 'medium', category: 'redirect', title: 'Redirect analysis timed out', description: `Redirect analysis exceeded ${timeout}ms.` });
      riskScore += 10;
    } else {
      findings.push({ severity: 'low', category: 'redirect', title: 'Redirect analysis stopped', description: error.message });
    }
  } finally {
    clearTimeout(timer);
  }

  const domains = [...new Set(chain.map((entry) => new URL(entry.url).hostname))];
  if (domains.length > 1) {
    findings.push({ severity: 'high', category: 'redirect', title: 'Cross-domain redirect', description: `The URL traverses ${domains.length} domains: ${domains.join(' -> ')}.` });
    riskScore += 20;
  }
  if (chain[0]?.url.startsWith('https://') && chain.slice(1).some((entry) => entry.url.startsWith('http://'))) {
    findings.push({ severity: 'critical', category: 'redirect', title: 'Protocol downgrade', description: 'The redirect chain downgrades HTTPS to unencrypted HTTP.' });
    riskScore += 50;
  }

  return {
    chain,
    redirectCount: Math.max(0, chain.length - 1),
    finalUrl: chain.at(-1)?.url || url,
    findings,
    riskScore: Math.min(100, riskScore),
    sameDomain: domains.length <= 1,
  };
}
