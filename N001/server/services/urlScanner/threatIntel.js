import { fetchWithTimeout } from '../../utils/fetchWithTimeout.js';

const SOURCES = [
  { id: 'google_safe_browsing', weight: 0.35 },
  { id: 'virustotal', weight: 0.25 },
  { id: 'urlhaus', weight: 0.15 },
  { id: 'phishtank', weight: 0.15 },
  { id: 'abuseipdb', weight: 0.1 },
];

async function checkGoogleSafeBrowsing(url) {
  const apiKey = process.env.GOOGLE_SAFE_BROWSING_KEY;
  if (!apiKey) return { detected: false, source: 'google_safe_browsing', note: 'No API key configured' };
  try {
    const response = await fetchWithTimeout(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client: { clientId: 'n001', clientVersion: '1.0.0' },
        threatInfo: {
          threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: [{ url }],
        },
      }),
    });
    if (!response.ok) return { detected: false, source: 'google_safe_browsing', note: `API error ${response.status}` };
    const data = await response.json();
    const threats = (data.matches || []).map((match) => match.threatType);
    return { detected: threats.length > 0, source: 'google_safe_browsing', threats, note: threats.length ? `Flagged for ${threats.join(', ')}` : 'No threats found' };
  } catch (error) {
    return { detected: false, source: 'google_safe_browsing', note: `Check failed: ${error.message}` };
  }
}

async function checkVirusTotal(url) {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  if (!apiKey) return { detected: false, source: 'virustotal', note: 'No API key configured' };
  try {
    const submission = await fetchWithTimeout('https://www.virustotal.com/api/v3/urls', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'x-apikey': apiKey },
      body: new URLSearchParams({ url }),
    });
    if (!submission.ok) return { detected: false, source: 'virustotal', note: `Submission failed: ${submission.status}` };
    const analysisId = (await submission.json()).data?.id;
    if (!analysisId) return { detected: false, source: 'virustotal', note: 'No analysis ID returned' };
    await new Promise((resolve) => setTimeout(resolve, 3000));
    const report = await fetchWithTimeout(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, { headers: { 'x-apikey': apiKey } });
    if (!report.ok) return { detected: false, source: 'virustotal', note: `Report failed: ${report.status}` };
    const stats = (await report.json()).data?.attributes?.stats || {};
    const detections = (stats.malicious || 0) + (stats.suspicious || 0);
    return { detected: detections > 0, source: 'virustotal', detections, malicious: stats.malicious || 0, suspicious: stats.suspicious || 0, note: detections ? `${detections} engines flagged this URL` : 'No engines flagged this URL' };
  } catch (error) {
    return { detected: false, source: 'virustotal', note: `Check failed: ${error.message}` };
  }
}

async function checkUrlhaus(url) {
  try {
    const response = await fetchWithTimeout('https://urlhaus-api.abuse.ch/v1/url/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ url }),
    });
    if (!response.ok) return { detected: false, source: 'urlhaus', note: `API error ${response.status}` };
    const data = await response.json();
    const detected = data.query_status === 'ok';
    return { detected, source: 'urlhaus', threat: data.threat, note: detected ? `Listed as ${data.threat || 'malware'}` : 'URL not found' };
  } catch (error) {
    return { detected: false, source: 'urlhaus', note: `Check failed: ${error.message}` };
  }
}

async function checkPhishTank(url) {
  try {
    const values = { url, format: 'json' };
    if (process.env.PHISHTANK_API_KEY) values.app_key = process.env.PHISHTANK_API_KEY;
    const response = await fetchWithTimeout('https://checkurl.phishtank.com/checkurl/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams(values),
    });
    if (!response.ok) return { detected: false, source: 'phishtank', note: `API error ${response.status}` };
    const data = await response.json();
    const detected = data.results?.in_phish_tank === true;
    return { detected, source: 'phishtank', note: detected ? 'Confirmed phishing URL' : 'URL not found' };
  } catch (error) {
    return { detected: false, source: 'phishtank', note: `Check failed: ${error.message}` };
  }
}

async function checkAbuseIpDb(ip) {
  const apiKey = process.env.ABUSEIPDB_API_KEY;
  if (!apiKey || !ip) return { detected: false, source: 'abuseipdb', note: 'No API key or IP available' };
  try {
    const response = await fetchWithTimeout(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`, {
      headers: { Key: apiKey, Accept: 'application/json' },
    });
    if (!response.ok) return { detected: false, source: 'abuseipdb', note: `API error ${response.status}` };
    const data = (await response.json()).data || {};
    const score = data.abuseConfidenceScore || 0;
    return { detected: score > 50, source: 'abuseipdb', abuseConfidenceScore: score, note: score > 50 ? `IP has ${score}% abuse confidence` : 'IP has a clean reputation' };
  } catch (error) {
    return { detected: false, source: 'abuseipdb', note: `Check failed: ${error.message}` };
  }
}

function scoreResult(result) {
  if (!result?.detected) return { score: 0, confidence: 0 };
  const weight = SOURCES.find((source) => source.id === result.source)?.weight || 0.1;
  if (result.source === 'virustotal') {
    const ratio = (result.malicious || 0) / 90;
    return { score: Math.min(100, ratio * 300 * weight), confidence: Math.min(1, ratio * 2) * weight };
  }
  if (result.source === 'abuseipdb') {
    return { score: (result.abuseConfidenceScore / 100) * 60 * weight, confidence: (result.abuseConfidenceScore / 100) * 0.8 * weight };
  }
  return { score: 70 * weight, confidence: 0.7 * weight };
}

export async function checkAllSources(url, hostname, ip) {
  const settled = await Promise.allSettled([
    checkGoogleSafeBrowsing(url),
    checkVirusTotal(url),
    checkUrlhaus(url),
    checkPhishTank(url),
    checkAbuseIpDb(ip),
  ]);
  const threats = settled.filter((result) => result.status === 'fulfilled').map((result) => result.value);
  const totals = threats.reduce((sum, threat) => {
    const scored = scoreResult(threat);
    return { score: sum.score + scored.score, confidence: sum.confidence + scored.confidence };
  }, { score: 0, confidence: 0 });
  return {
    threats,
    anyDetected: threats.some((threat) => threat.detected),
    combinedScore: Math.min(100, totals.score),
    combinedConfidence: Math.min(1, totals.confidence),
    sourcesChecked: SOURCES.length,
  };
}
