// Claude Code subscription usage: the same per-window percentages its own /usage
// screen shows, read with the OAuth token Claude Code already stored when you
// signed in. Nothing is stored here and no new login is asked for.
//
// Two consumers: the phone's Usage panel (GET /api/usage) and the watcher's usage
// guard, which looks before it pops. Both treat every failure here as "unknown",
// and the guard fails OPEN on unknown - a bridge that refuses to run because a
// usage endpoint blinked is worse than one that occasionally spends past a line.

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const USAGE_URL = 'https://api.anthropic.com/api/oauth/usage';

// A file on Windows and Linux; on macOS Claude Code keeps the same JSON in the
// login keychain under this service name. A missing item or a locked keychain
// falls through to the file, so a hand-placed credentials file still works.
function readCredentials({ platform = process.platform, home = os.homedir() } = {}) {
  if (platform === 'darwin') {
    try {
      const out = execFileSync('security', ['find-generic-password', '-s', 'Claude Code-credentials', '-w'],
        { encoding: 'utf8', timeout: 3000, stdio: ['ignore', 'pipe', 'ignore'] });
      return JSON.parse(out.trim());
    } catch (e) { /* fall through to the file */ }
  }
  return JSON.parse(fs.readFileSync(path.join(home, '.claude', '.credentials.json'), 'utf8'));
}

// Two response shapes have existed: a `limits` list, and named windows. Either
// becomes [{ name, percent, resetsAt }].
function gaugesFrom(data) {
  const gauges = [];
  if (data && Array.isArray(data.limits)) {
    for (const l of data.limits) {
      if (l && typeof l.percent === 'number') gauges.push({ name: l.kind || l.group || 'unknown', percent: l.percent, resetsAt: l.resets_at || null });
    }
  }
  if (!gauges.length && data) {
    for (const key of ['five_hour', 'seven_day', 'seven_day_opus', 'seven_day_sonnet']) {
      const w = data[key];
      if (w && typeof w.utilization === 'number') gauges.push({ name: key, percent: w.utilization, resetsAt: w.resets_at || null });
    }
  }
  return gauges;
}

// -> { gauges, checkedAt } or { error, hint }. Never throws.
async function fetchUsage({ readCreds = readCredentials, fetchImpl = fetch } = {}) {
  let token;
  try {
    const cred = readCreds();
    const oauth = cred.claudeAiOauth || cred.oauth || {};
    token = oauth.accessToken || oauth.access_token;
    if (!token) return { error: 'no_token', hint: 'Claude Code has no stored sign-in. Run `claude` once and sign in.' };
    if (oauth.expiresAt && Date.now() > oauth.expiresAt) {
      return { error: 'token_expired', hint: 'Run any `claude` command to refresh its stored sign-in.' };
    }
  } catch (e) {
    return { error: 'no_credentials', hint: 'Could not read Claude Code\'s stored sign-in (only subscription sign-ins have usage gauges).' };
  }
  try {
    const res = await fetchImpl(USAGE_URL, {
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', 'anthropic-beta': 'oauth-2025-04-20', 'User-Agent': 'halyard-usage/1.0' },
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) {
      return { error: `http_${res.status}`, hint: res.status === 401 ? 'Sign-in rejected. Run any `claude` command to refresh it.' : 'Unexpected response from the usage endpoint.' };
    }
    return { gauges: gaugesFrom(await res.json()), checkedAt: new Date().toISOString() };
  } catch (e) {
    return { error: 'unreachable', hint: e.message };
  }
}

// The gauge that should hold a message, or null. Fails open: an error, no
// gauges, or a guard set to 0 all return null.
function blockingGauge(usage, maxPercent) {
  if (!(Number(maxPercent) > 0) || !usage || usage.error || !Array.isArray(usage.gauges)) return null;
  const over = usage.gauges.filter((g) => typeof g.percent === 'number' && g.percent >= maxPercent);
  if (!over.length) return null;
  return over.sort((a, b) => b.percent - a.percent)[0];
}

module.exports = { fetchUsage, gaugesFrom, blockingGauge, readCredentials, USAGE_URL };
