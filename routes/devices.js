const express = require('express');
const crypto = require('crypto');
const { pool } = require('../db');
const { requireDeviceAuth } = require('../middleware');
const { codeHashByChildId } = require('../emergencyCodes');

const router = express.Router();

// Apparaat koppelen met een koppelcode (geen auth nodig, de code IS de auth)
router.post('/pair', async (req, res) => {
  try {
    const { code, name, platform } = req.body;
    if (!code || !name || !platform) return res.status(400).json({ error: 'code, name en platform zijn verplicht' });
    if (!['windows', 'android'].includes(platform)) return res.status(400).json({ error: 'platform moet windows of android zijn' });

    const pairingResult = await pool.query(
      'SELECT code, child_id AS "childId", expires_at AS "expiresAt", used FROM pairing_codes WHERE code = $1',
      [code]
    );
    const pairing = pairingResult.rows[0];
    if (!pairing) return res.status(404).json({ error: 'Onbekende koppelcode' });
    if (pairing.used) return res.status(410).json({ error: 'Koppelcode is al gebruikt' });
    if (new Date(pairing.expiresAt) < new Date()) return res.status(410).json({ error: 'Koppelcode is verlopen' });

    const deviceToken = crypto.randomBytes(32).toString('hex');
    const deviceResult = await pool.query(
      'INSERT INTO devices (child_id, name, platform, device_token, last_seen) VALUES ($1, $2, $3, $4, now()) RETURNING id',
      [pairing.childId, name, platform, deviceToken]
    );
    await pool.query('UPDATE pairing_codes SET used = true WHERE code = $1', [code]);

    res.status(201).json({ deviceId: deviceResult.rows[0].id, deviceToken });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Databasefout bij koppelen' });
  }
});

router.use(requireDeviceAuth);

// Actieve regel ophalen: totale dagelijkse limiet, bedtijdvenster, directe vergrendelstatus, en
// categorielimieten + app->categorie-mapping (incl. "altijd toegestaan"), zodat het apparaat dit
// ook zonder internetverbinding lokaal kan afdwingen.
router.get('/:id/rule', async (req, res) => {
  try {
    if (req.device.id !== Number(req.params.id)) return res.status(403).json({ error: 'Niet jouw apparaat' });

    const ruleResult = await pool.query(
      'SELECT daily_limit_minutes AS "dailyLimitMinutes", window_start AS "windowStart", window_end AS "windowEnd", locked_date AS "lockedDate" FROM rules WHERE child_id = $1',
      [req.device.childId]
    );
    const categoryLimitsResult = await pool.query(
      'SELECT category, daily_limit_minutes AS "dailyLimitMinutes" FROM category_rules WHERE child_id = $1',
      [req.device.childId]
    );
    const appCategoriesResult = await pool.query(
      'SELECT app_name AS "appName", category, unlimited FROM app_categories WHERE child_id = $1',
      [req.device.childId]
    );

    const rule = ruleResult.rows[0] || { dailyLimitMinutes: 60, windowStart: '00:00', windowEnd: '23:59', lockedDate: null };
    const today = new Date().toISOString().slice(0, 10);
    // Vergrendeld als OF alle apparaten van dit kind vergrendeld zijn (rule.lockedDate, de
    // "vergrendel alles"-knop), OF dit specifieke apparaat individueel vergrendeld is.
    const locked = rule.lockedDate === today || req.device.lockedDate === today;
    res.json({
      dailyLimitMinutes: rule.dailyLimitMinutes,
      windowStart: rule.windowStart,
      windowEnd: rule.windowEnd,
      locked,
      categoryLimits: categoryLimitsResult.rows,
      appCategories: appCategoriesResult.rows,
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Databasefout bij ophalen regel' });
  }
});

// Noodcode-hash ophalen (voor lokale, offline ontgrendeling door een ouder op het kind-apparaat
// zelf). Geeft null terug als er nog geen noodcode is ingesteld. Zie emergencyCodes.js.
router.get('/:id/emergency-code', async (req, res) => {
  if (req.device.id !== Number(req.params.id)) return res.status(403).json({ error: 'Niet jouw apparaat' });
  res.json({ codeHash: codeHashByChildId.get(req.device.childId) || null });
});

// Verbruikte tijd posten (batch van 1 of meer regels)
router.post('/:id/usage', async (req, res) => {
  try {
    if (req.device.id !== Number(req.params.id)) return res.status(403).json({ error: 'Niet jouw apparaat' });

    const entries = Array.isArray(req.body.entries) ? req.body.entries : [req.body];
    const valid = entries.filter((row) => row.date && row.appName && typeof row.minutes === 'number');

    for (const row of valid) {
      await pool.query(
        'INSERT INTO usage_logs (device_id, date, app_name, minutes) VALUES ($1, $2, $3, $4)',
        [req.device.id, row.date, row.appName, row.minutes]
      );
    }

    res.status(201).json({ ok: true, count: valid.length });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Databasefout bij opslaan verbruik' });
  }
});

// Apparaat ontkoppelt zichzelf ("verwijderen"-knop in de kind-app). Bewust GEEN
// verwijderbeveiliging: dit werkt gewoon met het normale device-token, geen speciale Android
// device-admin/accessibility-rechten. De enige drempel is dat de kind-app hier pas naartoe
// gaat nadat de ouder in de app zelf met zijn echte account (e-mail + wachtwoord) heeft
// ingelogd — zie ParentAccessActivity in android-kind-app. Verwijdert ook de bijbehorende
// verbruikslogs, anders zou de foreign key naar devices dit tegenhouden.
router.delete('/me', async (req, res) => {
  try {
    await pool.query('DELETE FROM usage_logs WHERE device_id = $1', [req.device.id]);
    await pool.query('DELETE FROM devices WHERE id = $1', [req.device.id]);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Databasefout bij ontkoppelen' });
  }
});

// Status: verbruikt vs resterend vandaag
router.get('/:id/status', async (req, res) => {
  try {
    if (req.device.id !== Number(req.params.id)) return res.status(403).json({ error: 'Niet jouw apparaat' });

    const date = new Date().toISOString().slice(0, 10);
    const usageResult = await pool.query(
      "SELECT COALESCE(SUM(minutes), 0)::int AS \"totalMinutes\" FROM usage_logs WHERE device_id = $1 AND date = $2",
      [req.device.id, date]
    );
    const usedMinutes = usageResult.rows[0].totalMinutes;

    const ruleResult = await pool.query(
      'SELECT daily_limit_minutes AS "dailyLimitMinutes" FROM rules WHERE child_id = $1',
      [req.device.childId]
    );
    const dailyLimitMinutes = ruleResult.rows[0]?.dailyLimitMinutes ?? 60;

    res.json({
      date,
      usedMinutes,
      dailyLimitMinutes,
      remainingMinutes: Math.max(0, dailyLimitMinutes - usedMinutes),
      limitReached: usedMinutes >= dailyLimitMinutes,
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Databasefout bij ophalen status' });
  }
});

module.exports = router;
