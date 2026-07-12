const jwt = require('jsonwebtoken');
const { pool } = require('./db');

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-verander-mij';
if (JWT_SECRET === 'dev-secret-verander-mij') {
  console.warn('WAARSCHUWING: JWT_SECRET staat niet in de omgevingsvariabelen — gebruik de standaardwaarde niet als dit door onbekende mensen gebruikt wordt.');
}

// Simpele, geheugen-gebaseerde rate limiter voor de publieke auth-routes (/register, /login).
// Nu de app door mensen gebruikt kan worden die je niet kent, is dit een basisdrempel tegen
// geautomatiseerd wachtwoorden-raden (brute force) en spam-registraties. Telt per IP-adres.
const attemptsByIp = new Map();
const RATE_LIMIT_WINDOW_MS = 15 * 60 * 1000; // 15 minuten
const RATE_LIMIT_MAX = 20; // max pogingen per IP binnen dat venster

function rateLimitAuth(req, res, next) {
  const ip = req.ip || req.connection?.remoteAddress || 'unknown';
  const now = Date.now();
  const entry = attemptsByIp.get(ip);

  if (!entry || now > entry.resetAt) {
    attemptsByIp.set(ip, { count: 1, resetAt: now + RATE_LIMIT_WINDOW_MS });
    return next();
  }

  if (entry.count >= RATE_LIMIT_MAX) {
    return res.status(429).json({ error: 'Te veel pogingen. Probeer het over een paar minuten opnieuw.' });
  }

  entry.count += 1;
  next();
}

// Voorkomt dat de Map onbeperkt blijft groeien met oude, verlopen IP's.
setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of attemptsByIp) {
    if (now > entry.resetAt) attemptsByIp.delete(ip);
  }
}, RATE_LIMIT_WINDOW_MS).unref();

function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Geen token meegegeven' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.userId;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Ongeldig of verlopen token' });
  }
}

// Voor de admin-tool ("Schermtijd Test"): een apart token met payload { admin: true } i.p.v. een
// userId, zodat een gewoon ouder-token nooit toegang geeft tot admin-routes en andersom. Zie
// routes/admin.js voor de login (die het admin-wachtwoord uit ADMIN_PASSWORD vergelijkt).
function requireAdmin(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Geen token meegegeven' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload.admin !== true) return res.status(403).json({ error: 'Geen adminrechten' });
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Ongeldig of verlopen token' });
  }
}

async function requireDeviceAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Geen device-token meegegeven' });

  try {
    const result = await pool.query(
      'SELECT id, child_id AS "childId", name, platform, device_token AS "deviceToken", locked_date AS "lockedDate" FROM devices WHERE device_token = $1',
      [token]
    );
    const device = result.rows[0];
    if (!device) return res.status(401).json({ error: 'Onbekend apparaat' });

    req.device = device;
    await pool.query('UPDATE devices SET last_seen = now() WHERE id = $1', [device.id]);
    next();
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Databasefout' });
  }
}

module.exports = { requireAuth, requireDeviceAuth, requireAdmin, rateLimitAuth, JWT_SECRET };
