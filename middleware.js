const jwt = require('jsonwebtoken');
const { pool } = require('./db');

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-verander-mij';

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

module.exports = { requireAuth, requireDeviceAuth, JWT_SECRET };
