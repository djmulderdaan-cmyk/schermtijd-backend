const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { pool } = require('../db');
const { requireAdmin, rateLimitAuth, JWT_SECRET } = require('../middleware');

const router = express.Router();

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
if (!ADMIN_PASSWORD) {
  console.warn('WAARSCHUWING: ADMIN_PASSWORD staat niet in de omgevingsvariabelen — de admin-tool (Schermtijd Test) is uitgeschakeld totdat je die instelt.');
}

// Vergelijkt twee strings zonder dat de tijd die dat kost iets verraadt over waar het verschil
// zit (voorkomt timing-aanvallen op het wachtwoord). Beide kanten moeten evenlang zijn voor
// crypto.timingSafeEqual, dus eerst even de lengte checken.
function safeEqual(a, b) {
  const bufA = Buffer.from(String(a));
  const bufB = Buffer.from(String(b));
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

// Login voor de admin-tool: één vast wachtwoord (ADMIN_PASSWORD uit de omgevingsvariabelen),
// geen apart account in de users-tabel. Bewust gescheiden van het normale ouder-inloggen zodat
// een gelekt ouder-wachtwoord nooit toegang geeft tot alle accounts.
router.post('/login', rateLimitAuth, (req, res) => {
  if (!ADMIN_PASSWORD) return res.status(503).json({ error: 'Admin-tool is niet geconfigureerd op de server' });
  const { password } = req.body;
  if (!password || typeof password !== 'string' || !safeEqual(password, ADMIN_PASSWORD)) {
    return res.status(401).json({ error: 'Onjuist wachtwoord' });
  }
  const token = jwt.sign({ admin: true }, JWT_SECRET, { expiresIn: '12h' });
  res.json({ token });
});

router.use(requireAdmin);

// Overzicht van alle ouder-accounts met aantal kinderen/apparaten, voor het admin-dashboard.
router.get('/accounts', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT u.id, u.email, u.created_at AS "createdAt",
        COUNT(DISTINCT c.id) AS "childCount",
        COUNT(DISTINCT d.id) AS "deviceCount"
      FROM users u
      LEFT JOIN children c ON c.user_id = u.id
      LEFT JOIN devices d ON d.child_id = c.id
      GROUP BY u.id, u.email, u.created_at
      ORDER BY u.created_at DESC
    `);
    res.json(result.rows.map((r) => ({ ...r, childCount: Number(r.childCount), deviceCount: Number(r.deviceCount) })));
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Databasefout bij ophalen accounts' });
  }
});

// Detail van 1 account: alle kinderen met hun regel + gekoppelde apparaten.
router.get('/accounts/:id', async (req, res) => {
  try {
    const userId = Number(req.params.id);
    const userResult = await pool.query('SELECT id, email, created_at AS "createdAt" FROM users WHERE id = $1', [userId]);
    const user = userResult.rows[0];
    if (!user) return res.status(404).json({ error: 'Account niet gevonden' });

    const childrenResult = await pool.query('SELECT id, name FROM children WHERE user_id = $1', [userId]);
    const children = await Promise.all(
      childrenResult.rows.map(async (c) => {
        const ruleResult = await pool.query(
          'SELECT daily_limit_minutes AS "dailyLimitMinutes", window_start AS "windowStart", window_end AS "windowEnd", locked_date AS "lockedDate" FROM rules WHERE child_id = $1',
          [c.id]
        );
        const devicesResult = await pool.query(
          'SELECT id, name, platform, last_seen AS "lastSeen", locked_date AS "lockedDate" FROM devices WHERE child_id = $1',
          [c.id]
        );
        return { ...c, rule: ruleResult.rows[0] || null, devices: devicesResult.rows };
      })
    );

    res.json({ ...user, children });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Databasefout bij ophalen account' });
  }
});

// Account volledig verwijderen: alles eronder (usage_logs, devices, app_categories, category_rules,
// rules, children) wordt eerst opgeruimd i.v.m. de foreign keys, daarna de user zelf. Onomkeerbaar.
router.delete('/accounts/:id', async (req, res) => {
  const client = await pool.connect();
  try {
    const userId = Number(req.params.id);
    await client.query('BEGIN');

    const childrenResult = await client.query('SELECT id FROM children WHERE user_id = $1', [userId]);
    const childIds = childrenResult.rows.map((r) => r.id);

    if (childIds.length > 0) {
      const devicesResult = await client.query('SELECT id FROM devices WHERE child_id = ANY($1)', [childIds]);
      const deviceIds = devicesResult.rows.map((r) => r.id);
      if (deviceIds.length > 0) {
        await client.query('DELETE FROM usage_logs WHERE device_id = ANY($1)', [deviceIds]);
      }
      await client.query('DELETE FROM devices WHERE child_id = ANY($1)', [childIds]);
      await client.query('DELETE FROM app_categories WHERE child_id = ANY($1)', [childIds]);
      await client.query('DELETE FROM category_rules WHERE child_id = ANY($1)', [childIds]);
      await client.query('DELETE FROM pairing_codes WHERE child_id = ANY($1)', [childIds]);
      await client.query('DELETE FROM rules WHERE child_id = ANY($1)', [childIds]);
      await client.query('DELETE FROM children WHERE user_id = $1', [userId]);
    }

    const deleteResult = await client.query('DELETE FROM users WHERE id = $1', [userId]);
    if (deleteResult.rowCount === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Account niet gevonden' });
    }

    await client.query('COMMIT');
    res.json({ ok: true });
  } catch (e) {
    await client.query('ROLLBACK');
    console.error(e);
    res.status(500).json({ error: 'Databasefout bij verwijderen account' });
  } finally {
    client.release();
  }
});

// Wachtwoord van een account resetten (bv. als iemand er zelf niet meer in kan).
router.put('/accounts/:id/password', async (req, res) => {
  try {
    const userId = Number(req.params.id);
    const { newPassword } = req.body;
    if (!newPassword || typeof newPassword !== 'string' || newPassword.length < 8) {
      return res.status(400).json({ error: 'Nieuw wachtwoord moet minstens 8 tekens zijn' });
    }
    const hash = await bcrypt.hash(newPassword, 10);
    const result = await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [hash, userId]);
    if (result.rowCount === 0) return res.status(404).json({ error: 'Account niet gevonden' });
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Databasefout bij resetten wachtwoord' });
  }
});

// (Ont)grendelt een kind (alle apparaten), ongeacht wie de eigenaar is — voor ondersteuning/misbruik.
router.put('/children/:childId/lock', async (req, res) => {
  try {
    const childId = Number(req.params.childId);
    const { locked } = req.body;
    const today = new Date().toISOString().slice(0, 10);
    const result = await pool.query(
      'UPDATE rules SET locked_date = $1 WHERE child_id = $2',
      [locked ? today : null, childId]
    );
    if (result.rowCount === 0) return res.status(404).json({ error: 'Kind niet gevonden' });
    res.json({ ok: true, locked: !!locked });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Databasefout bij (ont)vergrendelen' });
  }
});

// (Ont)grendelt 1 specifiek apparaat, ongeacht wie de eigenaar is.
router.put('/devices/:deviceId/lock', async (req, res) => {
  try {
    const deviceId = Number(req.params.deviceId);
    const { locked } = req.body;
    const today = new Date().toISOString().slice(0, 10);
    const result = await pool.query(
      'UPDATE devices SET locked_date = $1 WHERE id = $2',
      [locked ? today : null, deviceId]
    );
    if (result.rowCount === 0) return res.status(404).json({ error: 'Apparaat niet gevonden' });
    res.json({ ok: true, locked: !!locked });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Databasefout bij (ont)vergrendelen van apparaat' });
  }
});

// Totaaloverzicht voor bovenaan het admin-dashboard.
router.get('/stats', async (req, res) => {
  try {
    const usersResult = await pool.query('SELECT COUNT(*) AS count FROM users');
    const childrenResult = await pool.query('SELECT COUNT(*) AS count FROM children');
    const devicesResult = await pool.query('SELECT COUNT(*) AS count FROM devices');
    const activeResult = await pool.query("SELECT COUNT(*) AS count FROM devices WHERE last_seen > now() - interval '24 hours'");
    res.json({
      totalAccounts: Number(usersResult.rows[0].count),
      totalChildren: Number(childrenResult.rows[0].count),
      totalDevices: Number(devicesResult.rows[0].count),
      activeDevices24h: Number(activeResult.rows[0].count),
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Databasefout bij ophalen statistieken' });
  }
});

module.exports = router;
