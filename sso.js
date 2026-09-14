// =============================================
// AURA PORTAL — Token SSO compartido con Ventas / Cobros / Operaciones
// Idéntico al sso.js de los 3 portales — HMAC-SHA256, sin dependencias externas.
// Este es el único de los 4 que además FIRMA tokens (los portales solo verifican).
// =============================================
const crypto = require('crypto');

function secret() {
  const s = process.env.SSO_SHARED_SECRET;
  if (!s) throw new Error('SSO_SHARED_SECRET no configurado');
  return s;
}

function b64url(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64urlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return Buffer.from(str, 'base64');
}

/**
 * Firma un token SSO de un solo uso (TTL corto — se consume al instante al
 * hacer clic en una tarjeta del portal).
 */
function signSsoToken(payload, ttlSeconds = 60) {
  const body = { ...payload, exp: Math.floor(Date.now() / 1000) + ttlSeconds };
  const payloadB64 = b64url(JSON.stringify(body));
  const sig = crypto.createHmac('sha256', secret()).update(payloadB64).digest();
  return `${payloadB64}.${b64url(sig)}`;
}

function verifySsoToken(token) {
  try {
    if (!token || typeof token !== 'string') return null;
    const parts = token.split('.');
    if (parts.length !== 2) return null;
    const [payloadB64, sigB64] = parts;
    const expected = crypto.createHmac('sha256', secret()).update(payloadB64).digest();
    const got = b64urlDecode(sigB64);
    if (expected.length !== got.length || !crypto.timingSafeEqual(expected, got)) return null;
    const body = JSON.parse(b64urlDecode(payloadB64).toString('utf8'));
    if (!body.exp || body.exp < Math.floor(Date.now() / 1000)) return null;
    return body;
  } catch (e) {
    return null;
  }
}

module.exports = { signSsoToken, verifySsoToken };
