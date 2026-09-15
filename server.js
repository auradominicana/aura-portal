// =============================================
// AURA PORTAL — Hub de acceso único a Ventas, Cobros y Operaciones
// Login propio (Mariel, coordinadora administrativa) + SSO hacia los 3 sistemas.
// Sin base de datos: una sola cuenta admin definida por variables de entorno.
// =============================================
require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');
const { signSsoToken } = require('./sso');

const app = express();
const PORT = process.env.PORT || 4200;

// ── Sistemas del portal ─────────────────────────────────────────────
const SISTEMAS = {
  ventas: {
    nombre: 'Ventas',
    icono: '🤝',
    descripcion: 'Para validar información de un cliente o lead puntual',
    url: process.env.CRM_URL || 'https://crm.aura.com.do',
    ssoPath: '/auth/sso',
  },
  cobros: {
    nombre: 'Cobros',
    icono: '💳',
    descripcion: 'Azul Recurrente, Cuotas, CXC y autorizaciones',
    url: process.env.COBROS_URL || 'https://aura-cobros-production.up.railway.app',
    ssoPath: '/auth/sso',
  },
  operaciones: {
    nombre: 'Operaciones',
    icono: '🔧',
    descripcion: 'Rutero técnico, instalaciones y mantenimientos',
    url: process.env.RUTERO_URL || 'https://rutero-aura-production.up.railway.app',
    ssoPath: '/auth/sso',
  },
};

// Token compartido con los endpoints públicos de score (mismo que usa el Rutero
// para /api/solicitudes-facturacion/public, etc.)
const OPS_PUBLIC_TOKEN = process.env.OPS_PUBLIC_TOKEN || 'AURA-COBROS-2026';

// ── Admin único: Mariel ──────────────────────────────────────────────
const ADMIN_EMAIL = (process.env.HUB_ADMIN_EMAIL || 'mariel@aura.com.do').toLowerCase();
const ADMIN_NOMBRE = process.env.HUB_ADMIN_NOMBRE || 'Mariel';
// Hash de bcrypt de la contraseña — generado con:
//   node -e "console.log(require('bcryptjs').hashSync('TU_CLAVE',10))"
const ADMIN_PASSWORD_HASH = process.env.HUB_ADMIN_PASSWORD_HASH;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ── Sesión propia del hub: cookie firmada (HMAC), sin servidor de sesiones ──
function cookieSecret() {
  return process.env.SSO_SHARED_SECRET || 'cambia-esto';
}
function signSession(email) {
  const body = { email, exp: Date.now() + 12 * 60 * 60 * 1000 }; // 12h
  const b64 = Buffer.from(JSON.stringify(body)).toString('base64url');
  const sig = crypto.createHmac('sha256', cookieSecret()).update(b64).digest('base64url');
  return `${b64}.${sig}`;
}
function verifySession(cookieVal) {
  try {
    if (!cookieVal) return null;
    const [b64, sig] = cookieVal.split('.');
    const expected = crypto.createHmac('sha256', cookieSecret()).update(b64).digest('base64url');
    if (sig !== expected) return null;
    const body = JSON.parse(Buffer.from(b64, 'base64url').toString('utf8'));
    if (!body.exp || body.exp < Date.now()) return null;
    return body;
  } catch (e) { return null; }
}
function parseCookies(req) {
  const raw = req.headers.cookie || '';
  const out = {};
  raw.split(';').forEach(p => {
    const i = p.indexOf('=');
    if (i > -1) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  });
  return out;
}
function requireHubAuth(req, res, next) {
  const cookies = parseCookies(req);
  const session = verifySession(cookies.hub_session);
  if (!session) return res.redirect('/login.html');
  req.hubUser = session;
  next();
}

// ── LOGIN ─────────────────────────────────────────────────────────────
app.post('/api/login', (req, res) => {
  const { email, password } = req.body || {};
  if (!ADMIN_PASSWORD_HASH) {
    return res.status(500).json({ ok: false, error: 'HUB_ADMIN_PASSWORD_HASH no configurado en el servidor' });
  }
  if (String(email || '').toLowerCase().trim() !== ADMIN_EMAIL || !bcrypt.compareSync(password || '', ADMIN_PASSWORD_HASH)) {
    return res.status(401).json({ ok: false, error: 'Correo o contraseña incorrectos' });
  }
  const token = signSession(ADMIN_EMAIL);
  res.setHeader('Set-Cookie', `hub_session=${token}; HttpOnly; Path=/; Max-Age=${12 * 3600}; SameSite=Lax`);
  res.json({ ok: true, nombre: ADMIN_NOMBRE });
});

app.post('/api/logout', (req, res) => {
  res.setHeader('Set-Cookie', 'hub_session=; HttpOnly; Path=/; Max-Age=0');
  res.json({ ok: true });
});

app.get('/api/me', (req, res) => {
  const cookies = parseCookies(req);
  const session = verifySession(cookies.hub_session);
  res.json({ ok: !!session, nombre: session ? ADMIN_NOMBRE : null, email: session ? session.email : null });
});

// ── Lista de sistemas (para pintar las tarjetas) ────────────────────
app.get('/api/sistemas', requireHubAuth, (req, res) => {
  res.json(Object.entries(SISTEMAS).map(([id, s]) => ({ id, nombre: s.nombre, icono: s.icono, descripcion: s.descripcion })));
});

// ── Lanzar un sistema con SSO ────────────────────────────────────────
app.post('/api/portal/launch', requireHubAuth, (req, res) => {
  const sistema = SISTEMAS[req.body?.sistema];
  if (!sistema) return res.status(400).json({ ok: false, error: 'Sistema no reconocido' });
  const token = signSsoToken({ email: req.hubUser.email, nombre: ADMIN_NOMBRE, target: req.body.sistema });
  res.json({ ok: true, url: `${sistema.url}${sistema.ssoPath}?token=${encodeURIComponent(token)}` });
});

// ── Score General de la coordinadora — promedio PONDERADO de 6 partes,
//    leídas en vivo de Cobros y Operaciones. Pesos elegidos así: los dos
//    scores compuestos (Contable/Operativa, que ya promedian varios
//    sub-indicadores cada uno) pesan más que las 4 señales puntuales nuevas:
//      Gestión Contable ......... 20%
//      Gestión Operativa ........ 20%
//      Contratos al día ......... 15%
//      Clientes al día en mnto. . 15%   (inverso de "atrasados +3 meses sin visita")
//      Backlog de Coordinación .. 15%   (Facturación+SolCobro+Autorizaciones+Suspensiones)
//      Cartera sana (sin riesgo). 15%   (inverso de candidatos a suspensión, 6+ meses sin pagar)
const PESOS_SCORE = { contable: 0.20, operativo: 0.20, contratos: 0.15, atrasados: 0.15, backlog: 0.15, suspension: 0.15 };

app.get('/api/score-general', requireHubAuth, async (req, res) => {
  async function leer(url) {
    try {
      const r = await fetch(`${url}?token=${encodeURIComponent(OPS_PUBLIC_TOKEN)}`, { signal: AbortSignal.timeout(8000) });
      if (!r.ok) return null;
      return await r.json();
    } catch (e) { return null; }
  }
  const [contable, operativo, kpiContratos, kpisExtraCobros, kpisExtraOp] = await Promise.all([
    leer(`${SISTEMAS.cobros.url}/api/score-gestion/public`),
    leer(`${SISTEMAS.operaciones.url}/api/score-operativo/public`),
    leer(`${SISTEMAS.operaciones.url}/api/kpi-contratos/public`),
    leer(`${SISTEMAS.cobros.url}/api/kpis-extra/public`),
    leer(`${SISTEMAS.operaciones.url}/api/kpis-extra-op/public`),
  ]);
  const contratos = (kpiContratos && typeof kpiContratos.pctAlDia === 'number')
    ? { score: kpiContratos.pctAlDia, label: `${kpiContratos.alDia ?? '—'} al día · ${kpiContratos.vencidos ?? '—'} vencidos`, actualizadoEn: kpiContratos.actualizadoEn }
    : null;
  const atrasados = (kpisExtraOp && typeof kpisExtraOp.pctAlDiaMantenimiento === 'number')
    ? { score: kpisExtraOp.pctAlDiaMantenimiento, label: `${kpisExtraOp.atrasados ?? '—'} atrasados de ${kpisExtraOp.totalHist ?? '—'}`, actualizadoEn: kpisExtraOp.actualizadoEn }
    : null;
  const backlog = (kpisExtraCobros && typeof kpisExtraCobros.backlogScore === 'number')
    ? { score: kpisExtraCobros.backlogScore, label: `${kpisExtraCobros.backlog?.total ?? '—'} solicitudes pendientes entre áreas`, actualizadoEn: kpisExtraCobros.actualizadoEn }
    : null;
  const suspension = (kpisExtraCobros && typeof kpisExtraCobros.pctSinRiesgoSuspension === 'number')
    ? { score: kpisExtraCobros.pctSinRiesgoSuspension, label: `${kpisExtraCobros.candidatosSuspension ?? '—'} candidatos a suspensión`, actualizadoEn: kpisExtraCobros.actualizadoEn }
    : null;

  const componentes = { contable, operativo, contratos, atrasados, backlog, suspension };
  let sumaPonderada = 0, sumaPesos = 0;
  for (const [key, peso] of Object.entries(PESOS_SCORE)) {
    const c = componentes[key];
    if (c && typeof c.score === 'number') { sumaPonderada += c.score * peso; sumaPesos += peso; }
  }
  const general = sumaPesos > 0 ? Math.round(sumaPonderada / sumaPesos) : null;

  res.json({
    general,
    contable: contable || { score: null, label: 'Sin datos aún' },
    operativo: operativo || { score: null, label: 'Sin datos aún' },
    contratos: contratos || { score: null, label: 'Sin datos aún' },
    atrasados: atrasados || { score: null, label: 'Sin datos aún' },
    backlog: backlog || { score: null, label: 'Sin datos aún' },
    suspension: suspension || { score: null, label: 'Sin datos aún' },
    // Informativos, no entran al promedio
    info: {
      carteraPendiente: kpisExtraCobros?.carteraPendiente ?? null,
      recuperadoPeriodo: kpisExtraCobros?.recuperadoPeriodo ?? null,
      averiasPendientes: kpisExtraOp?.averiasPendientes ?? null,
    },
  });
});

// ── KPI de Contratos (al día / vencidos) — pedido puntual, se muestra aparte
//    del Score General, no se promedia con los demás ──
app.get('/api/kpi-contratos', requireHubAuth, async (req, res) => {
  try {
    const r = await fetch(`${SISTEMAS.operaciones.url}/api/kpi-contratos/public?token=${encodeURIComponent(OPS_PUBLIC_TOKEN)}`, { signal: AbortSignal.timeout(8000) });
    res.json(r.ok ? await r.json() : { alDia: null, vencidos: null, porVencer30: null, pctAlDia: null });
  } catch (e) {
    res.json({ alDia: null, vencidos: null, porVencer30: null, pctAlDia: null });
  }
});

// ── Estáticos ─────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));
app.get('/', requireHubAuth, (req, res) => res.sendFile(path.join(__dirname, 'public/index.html')));

app.listen(PORT, () => console.log(`🚪 Portal Aura escuchando en :${PORT}`));
