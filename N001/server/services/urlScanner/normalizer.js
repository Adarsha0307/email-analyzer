import net from 'node:net';
import { domainToUnicode } from 'node:url';

const HOMOGRAPH_MAP = {
  '\u0430': 'a', '\u0435': 'e', '\u0456': 'i', '\u043e': 'o', '\u0441': 'c', '\u0440': 'p', '\u0445': 'x', '\u0443': 'y',
  '\u0458': 'j', '\u049b': 'k', '\u043f': 'n', '\u04bb': 'h', '\u0432': 'b', '\u043c': 'm',
};

export function isPrivateIpAddress(address) {
  const value = String(address || '').toLowerCase().split('%')[0];
  if (net.isIPv4(value)) {
    const [a, b] = value.split('.').map(Number);
    return a === 0 || a === 10 || a === 127 || a >= 224
      || (a === 100 && b >= 64 && b <= 127)
      || (a === 169 && b === 254)
      || (a === 172 && b >= 16 && b <= 31)
      || (a === 192 && (b === 0 || b === 168))
      || (a === 198 && (b === 18 || b === 19));
  }
  if (net.isIPv6(value)) {
    if (value === '::' || value === '::1') return true;
    if (value.startsWith('fc') || value.startsWith('fd') || /^fe[89ab]/.test(value) || value.startsWith('ff')) return true;
    const mapped = value.match(/::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    return mapped ? isPrivateIpAddress(mapped[1]) : false;
  }
  return false;
}

export function isLocalHostname(hostname) {
  const value = String(hostname || '').toLowerCase().replace(/\.$/, '');
  return value === 'localhost' || value.endsWith('.localhost') || isPrivateIpAddress(value);
}

function detectHomograph(hostname) {
  const unicodeHostname = domainToUnicode(hostname).toLowerCase();
  if (/^[a-z0-9.-]+$/.test(unicodeHostname)) return null;
  const suspiciousChars = [...unicodeHostname].filter((char) => HOMOGRAPH_MAP[char]);
  if (suspiciousChars.length <= 1) return null;
  return {
    risk: suspiciousChars.length >= 4 ? 'high' : 'medium',
    characters: [...new Set(suspiciousChars)],
    description: 'Hostname contains non-Latin characters that visually resemble Latin letters.',
  };
}

export function normalizeUrl(rawUrl) {
  if (typeof rawUrl !== 'string' || !rawUrl.trim()) return { error: 'No URL provided.' };
  let value = rawUrl.trim();
  if (/^[a-z][a-z\d+.-]*:/i.test(value) && !/^https?:\/\//i.test(value)) {
    return { error: 'Only HTTP and HTTPS URLs can be scanned.' };
  }
  if (!/^https?:\/\//i.test(value)) value = `https://${value}`;

  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    return { error: 'Invalid URL format.' };
  }
  if (!parsed.hostname) return { error: 'URL must include a hostname.' };

  const protocol = parsed.protocol.toLowerCase();
  const hostname = parsed.hostname.toLowerCase().replace(/\.$/, '');
  if (isLocalHostname(hostname)) {
    return { error: 'URL points to a private or local network address and was blocked.', ssrfWarning: true };
  }

  parsed.hostname = hostname;
  if ((protocol === 'http:' && parsed.port === '80') || (protocol === 'https:' && parsed.port === '443')) parsed.port = '';

  return {
    normalized: parsed.href,
    protocol,
    hostname,
    port: parsed.port || null,
    pathname: parsed.pathname,
    search: parsed.search,
    hash: parsed.hash,
    homographRisk: detectHomograph(hostname),
    ssrfWarning: false,
  };
}

export function validateUrlSafety(normalizedUrl) {
  const warnings = [];
  const parsed = new URL(normalizedUrl);
  if (parsed.protocol === 'http:') {
    warnings.push({ severity: 'medium', category: 'protocol', message: 'URL uses unencrypted HTTP instead of HTTPS.' });
  }
  if (parsed.username || parsed.password) {
    warnings.push({ severity: 'high', category: 'url_structure', message: 'URL embeds credentials before the hostname, which can disguise its destination.' });
  }
  return warnings;
}
