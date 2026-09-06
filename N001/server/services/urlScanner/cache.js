import crypto from 'node:crypto';

const cache = new Map();
const MAX_ENTRIES = 500;
const DURATIONS = {
  malicious: 24 * 60 * 60 * 1000,
  clean: 6 * 60 * 60 * 1000,
  unknown: 2 * 60 * 60 * 1000,
};

function hashUrl(url) {
  return crypto.createHash('sha256').update(url.toLowerCase()).digest('hex');
}

function durationFor(classification) {
  if (classification === 'critical' || classification === 'high') return DURATIONS.malicious;
  if (classification === 'minimal' || classification === 'low') return DURATIONS.clean;
  return DURATIONS.unknown;
}

export async function getCachedResult(url) {
  const key = hashUrl(url);
  const entry = cache.get(key);
  if (!entry) return null;
  if (entry.expiresAt <= Date.now()) {
    cache.delete(key);
    return null;
  }
  return { cached: true, result: entry.result, checkedAt: entry.checkedAt };
}

export async function cacheResult(url, result) {
  if (cache.size >= MAX_ENTRIES) cache.delete(cache.keys().next().value);
  cache.set(hashUrl(url), {
    result,
    checkedAt: new Date().toISOString(),
    expiresAt: Date.now() + durationFor(result.classification),
  });
}
