const PHISHING_KEYWORDS = ['login', 'verify', 'secure', 'account', 'update', 'wallet', 'password', 'bank', 'payment', 'confirm', 'signin', 'auth', 'credential', 'recover', 'unlock', 'reset', 'activate', 'restore', 'alert', 'suspended', 'refund', 'prize', 'gift', 'claim', 'reward', 'security'];
const SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'tiny.cc', 'cut.ly', 'rb.gy', 'short.link', 'v.gd'];

export function analyzeUrlHeuristics(url, hostname, pathname) {
  const findings = [];
  let riskScore = 0;
  const lowerUrl = url.toLowerCase();
  const pathWords = (pathname || '').toLowerCase().split(/[/\-_.=]+/).filter(Boolean);

  if (SHORTENERS.includes(hostname)) {
    findings.push({ severity: 'medium', category: 'url_structure', title: 'Shortened URL', description: 'A URL shortener hides the final destination domain.' });
    riskScore += 15;
  }
  const keywords = PHISHING_KEYWORDS.filter((keyword) => pathWords.includes(keyword));
  if (keywords.length > 0) {
    findings.push({ severity: keywords.length > 3 ? 'high' : 'medium', category: 'url_structure', title: 'Phishing-related keywords', description: `The URL path contains: ${keywords.join(', ')}.` });
    riskScore += Math.min(30, keywords.length * 8);
  }
  if (url.length > 200) {
    findings.push({ severity: 'medium', category: 'url_structure', title: 'Unusually long URL', description: `The URL is ${url.length} characters long and may be hiding suspicious parameters.` });
    riskScore += 10;
  }
  if (url.includes('@')) {
    findings.push({ severity: 'high', category: 'url_structure', title: 'At-sign in URL', description: 'An at-sign can make a URL appear to point to a different hostname.' });
    riskScore += 20;
  }
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
    findings.push({ severity: 'high', category: 'url_structure', title: 'Raw IP address URL', description: 'Legitimate public services rarely use an IP address instead of a domain.' });
    riskScore += 25;
  }

  const suspiciousParameters = ['redirect', 'url', 'link', 'goto', 'return', 'next', 'dest', 'target', 'continue'];
  const parameters = new URL(url).searchParams;
  if (suspiciousParameters.some((name) => parameters.has(name))) {
    findings.push({ severity: 'high', category: 'url_structure', title: 'Redirect parameter', description: 'The URL contains a parameter commonly used for open redirects.' });
    riskScore += 20;
  }

  return { findings, riskScore: Math.min(100, riskScore) };
}
