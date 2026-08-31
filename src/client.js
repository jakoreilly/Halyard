// The tiny HTTP client the watcher and the CLI use to talk to the server.
//
// Everything goes over loopback HTTP even when the watcher is running inside
// the same process as the server. That is a deliberate choice: it means
// `halyard watch` as a separate process, a watcher on a schedule, and the
// built-in loop are all the SAME code path, so a bug can only be in one place.
// The cost is a loopback round trip per event, which is nothing next to the
// cost of spawning a language model.
//
// 127.0.0.1 rather than localhost, always: the server binds loopback IPv4, and
// a `localhost` that resolves to ::1 first fails every call with a connection
// error that reads like the bridge is down.

function baseUrl(cfg) {
  const host = cfg.host === '0.0.0.0' || cfg.host === '::' ? '127.0.0.1' : cfg.host;
  return `http://${host.includes(':') ? `[${host}]` : host}:${cfg.port}`;
}

function createClient(cfg, token, { timeoutMs = 15000 } = {}) {
  const base = baseUrl(cfg);

  async function call(method, path, body) {
    const url = `${base}${path}${path.includes('?') ? '&' : '?'}token=${encodeURIComponent(token)}`;
    const res = await fetch(url, {
      method,
      headers: body === undefined ? {} : { 'content-type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(timeoutMs),
    });
    const text = await res.text();
    let parsed = null;
    try { parsed = text ? JSON.parse(text) : null; } catch (e) { parsed = { raw: text }; }
    if (!res.ok) {
      const err = new Error(`${method} ${path} -> ${res.status}`);
      err.status = res.status;
      err.body = parsed;
      throw err;
    }
    return parsed;
  }

  return {
    base,
    get: (p) => call('GET', p),
    post: (p, b) => call('POST', p, b === undefined ? {} : b),
    del: (p) => call('DELETE', p),
    // Best-effort variants for the paths where a failed call must not end the
    // run. Losing an activity update is cosmetic; losing the run is not.
    async tryGet(p) { try { return await call('GET', p); } catch (e) { return null; } },
    async tryPost(p, b) { try { return await call('POST', p, b === undefined ? {} : b); } catch (e) { return null; } },
  };
}

module.exports = { createClient, baseUrl };
