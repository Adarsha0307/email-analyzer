import dns from 'node:dns/promises';

const SUSPICIOUS_TLDS = ['xyz', 'top', 'work', 'country', 'zip', 'click', 'link', 'download', 'stream', 'trade', 'review', 'science', 'win', 'bid', 'date', 'faith', 'racing', 'accountant', 'party', 'gdn', 'men', 'loan', 'cam', 'rest'];
const FREE_TLDS = ['tk', 'ml', 'ga', 'cf', 'gq', 'sbs'];

export async function resolveIp(hostname) {
  try {
    const addresses = await dns.resolve4(hostname);
    return addresses[0] || null;
  } catch {
    try {
      const addresses = await dns.resolve6(hostname);
      return addresses[0] || null;
    } catch {
      return null;
    }
  }
}

async function resolveMxRecords(hostname) {
  try {
    const records = await dns.resolveMx(hostname);
    return records.sort((a, b) => a.priority - b.priority).map((record) => record.exchange);
  } catch {
    return [];
  }
}

async function resolveNameservers(hostname) {
  try {
    return await dns.resolveNs(hostname);
  } catch {
    return [];
  }
}

export async function analyzeDomain(hostname, resolvedIp = null) {
  const findings = [];
  let riskScore = 0;
  const parts = hostname.split('.');
  const tld = parts.at(-1)?.toLowerCase() || '';
  const registrableDomain = parts.length >= 2 ? parts.slice(-2).join('.') : hostname;

  if (SUSPICIOUS_TLDS.includes(tld)) {
    findings.push({ severity: 'medium', category: 'tld', title: 'Suspicious top-level domain', description: `The .${tld} TLD has a comparatively high rate of abusive registrations.` });
    riskScore += 15;
  }
  if (FREE_TLDS.includes(tld)) {
    findings.push({ severity: 'high', category: 'tld', title: 'Free domain TLD', description: `The .${tld} TLD is commonly associated with disposable or abusive registrations.` });
    riskScore += 20;
  }
  if (parts.length > 3) {
    findings.push({ severity: 'medium', category: 'subdomains', title: 'Excessive subdomains', description: `The hostname has ${parts.length - 2} subdomain levels, which can disguise the registered domain.` });
    riskScore += 10;
  }

  const ip = resolvedIp || await resolveIp(hostname);
  if (!ip) {
    findings.push({ severity: 'high', category: 'dns', title: 'DNS resolution failed', description: 'The domain could not be resolved to an IP address.' });
    riskScore += 30;
  }

  const [mxRecords, nameservers] = await Promise.all([resolveMxRecords(hostname), resolveNameservers(hostname)]);
  if (mxRecords.length === 0 && parts.length >= 2) {
    findings.push({ severity: 'low', category: 'dns', title: 'No mail exchanger records', description: 'The domain has no MX records. This is normal for some sites but uncommon for business email domains.' });
    riskScore += 5;
  }

  return {
    registrableDomain,
    tld,
    ip,
    mxRecords,
    nameservers,
    subdomainCount: Math.max(0, parts.length - 2),
    findings,
    riskScore: Math.min(100, riskScore),
  };
}
