// Web Push (RFC 8291 payload encryption + RFC 8292 VAPID), implemented on
// node:crypto alone so the repo's zero-dependency rule survives.
//
// Why this exists alongside the ntfy.sh path already in server.js: ntfy works,
// but it posts the reply text to a public third-party server and needs a second
// app installed on the phone. This delivers the same "your pocket buzzes with
// the screen off" behaviour straight from this machine to the browser's own push
// service, with the body encrypted end-to-end - the push service relays bytes it
// cannot read. Both paths are opt-in and independent; having neither configured
// is the old behaviour.
//
// The one thing this cannot do is bypass the browser's requirement for a secure
// context: the phone must reach the bridge over HTTPS (Tailscale Serve) or
// localhost, or `navigator.serviceWorker.pushManager` is simply absent and the
// page falls back to in-page Notifications.

const crypto = require('crypto');

const CURVE = 'prime256v1';

// ---------------------------------------------------------------------------
// Small encoding helpers

function b64url(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromB64url(str) {
  return Buffer.from(String(str).replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

// A P-256 public key in the raw uncompressed form (0x04 || X || Y) that both the
// Push API and VAPID speak. Node hands back SPKI DER, whose final 65 bytes are
// exactly that point.
function rawPublicKey(keyObject) {
  const der = keyObject.export({ type: 'spki', format: 'der' });
  return der.subarray(der.length - 65);
}

function rawPrivateKey(keyObject) {
  const jwk = keyObject.export({ format: 'jwk' });
  return fromB64url(jwk.d);
}

// ---------------------------------------------------------------------------
// VAPID keys

function generateVapidKeys() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: CURVE });
  return {
    publicKey: b64url(rawPublicKey(publicKey)),
    privateKey: b64url(rawPrivateKey(privateKey)),
  };
}

// Rebuilds a signing KeyObject from the stored raw scalar. Going through JWK
// avoids hand-assembling DER: the curve point is recomputed by node from d.
function privateKeyObjectFrom(privateKeyB64, publicKeyB64) {
  const pub = fromB64url(publicKeyB64);
  return crypto.createPrivateKey({
    key: {
      kty: 'EC',
      crv: 'P-256',
      d: privateKeyB64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
      x: b64url(pub.subarray(1, 33)),
      y: b64url(pub.subarray(33, 65)),
    },
    format: 'jwk',
  });
}

// RFC 8292. `aud` is the push service's ORIGIN, not the full endpoint - sending
// the endpoint makes FCM reject the request with 401, which is indistinguishable
// from a bad key unless you know to look.
function vapidHeader(endpoint, keys, subject) {
  const aud = new URL(endpoint).origin;
  const header = b64url(JSON.stringify({ typ: 'JWT', alg: 'ES256' }));
  const payload = b64url(
    JSON.stringify({
      aud,
      // 12h, comfortably inside the 24h maximum the spec allows.
      exp: Math.floor(Date.now() / 1000) + 12 * 3600,
      sub: subject,
    })
  );
  const signingInput = `${header}.${payload}`;
  // ieee-p1363 gives the raw r||s pair JWS requires; node's default DER encoding
  // is silently accepted by nothing and produces a 401 from every push service.
  const signature = crypto.sign('sha256', Buffer.from(signingInput), {
    key: privateKeyObjectFrom(keys.privateKey, keys.publicKey),
    dsaEncoding: 'ieee-p1363',
  });
  return `vapid t=${signingInput}.${b64url(signature)}, k=${keys.publicKey}`;
}

// ---------------------------------------------------------------------------
// Payload encryption (RFC 8291, aes128gcm)

function hmac(key, data) {
  return crypto.createHmac('sha256', key).update(data).digest();
}

// HKDF with the single-block expand this spec always uses (every output here is
// <= 32 bytes), so the counter is a constant 0x01.
function hkdf(salt, ikm, info, length) {
  const prk = hmac(salt, ikm);
  return hmac(prk, Buffer.concat([Buffer.from(info), Buffer.from([1])])).subarray(0, length);
}

function encryptPayload(plaintext, uaPublicB64, authSecretB64) {
  const uaPublic = fromB64url(uaPublicB64);
  const authSecret = fromB64url(authSecretB64);

  const ecdh = crypto.createECDH(CURVE);
  ecdh.generateKeys();
  const asPublic = ecdh.getPublicKey();
  const sharedSecret = ecdh.computeSecret(uaPublic);

  // The key-derivation info string binds the two public keys into the KDF, which
  // is what stops a push service from swapping in its own ephemeral key.
  const keyInfo = Buffer.concat([Buffer.from('WebPush: info\0'), uaPublic, asPublic]);
  const ikm = hkdf(authSecret, sharedSecret, keyInfo, 32);

  const salt = crypto.randomBytes(16);
  const cek = hkdf(salt, ikm, 'Content-Encoding: aes128gcm\0', 16);
  const nonce = hkdf(salt, ikm, 'Content-Encoding: nonce\0', 12);

  // 0x02 is the last-record padding delimiter. One record only: these payloads
  // are a few hundred bytes and the record size below is 4096.
  const padded = Buffer.concat([Buffer.from(plaintext, 'utf8'), Buffer.from([2])]);
  const cipher = crypto.createCipheriv('aes-128-gcm', cek, nonce);
  const ciphertext = Buffer.concat([cipher.update(padded), cipher.final(), cipher.getAuthTag()]);

  const recordSize = Buffer.alloc(4);
  recordSize.writeUInt32BE(4096, 0);

  return Buffer.concat([salt, recordSize, Buffer.from([asPublic.length]), asPublic, ciphertext]);
}

// ---------------------------------------------------------------------------
// Delivery

// Resolves to { ok, status, gone } rather than throwing. `gone` (404/410) is the
// push service saying this subscription is permanently dead - the caller prunes
// on that and only on that, so a transient 5xx never silently unsubscribes a
// phone that is merely offline.
async function sendNotification(subscription, payload, keys, subject, ttlSeconds = 86400) {
  const endpoint = subscription && subscription.endpoint;
  if (!endpoint) return { ok: false, status: 0, gone: false, error: 'no endpoint' };

  try {
    const body = encryptPayload(payload, subscription.keys.p256dh, subscription.keys.auth);
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'Content-Encoding': 'aes128gcm',
        'Content-Type': 'application/octet-stream',
        TTL: String(ttlSeconds),
        Authorization: vapidHeader(endpoint, keys, subject),
      },
      body,
    });
    return { ok: res.ok, status: res.status, gone: res.status === 404 || res.status === 410 };
  } catch (e) {
    return { ok: false, status: 0, gone: false, error: e.message };
  }
}

module.exports = { generateVapidKeys, vapidHeader, encryptPayload, sendNotification, b64url, fromB64url };
