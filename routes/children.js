const express = require('express');
const crypto = require('crypto');
const { pool } = require('../db');
const { requireAuth } = require('../middleware');
const { codeHashByChildId } = require('../emergencyCodes');

const router = express.Router();
router.use(requireAuth);

// Vaste categorieën. Bewust geen "webfilter"-categorie: er is geen contentfiltering in deze versie.
const VALID_CATEGORIES = ['games', 'social', 'video', 'education', 'other'];

async function ownsChild(userId, childId) {
  const result = await pool.query('SELECT id FROM children WHERE id = $1 AND user_id = $2', [childId, userId]);
  return result.rows.length > 0;
}

function today() {
  return new Date().toISOString().slice(0, 10);
}

// "locked_date" geldt alleen voor de dag waarop hij gezet is; de volgende dag klopt de datum
// niet meer met vandaag en is het kind automatisch weer ontgrendeld.
function isLocked(lockedDate) {
  return lockedDate === today();
}

// Kindprofiel aanmaken. Optioneel meteen een startconfiguratie meegeven (dailyLimitMinutes,
// windowStart, windowEnd) zodat een kind niet met de standaardwaarden (60 min, geen bedtijd)
// begint als de ouder dat al bij het aanmaken wil instellen — anders gelden gewoon de defaults.
router.post('/', async (req, res) => {
  try {
    const { name, dailyLimitMinutes, windowStart, windowEnd } = req.body;
    if (!name) return res.status(400).json({ error: 'name is verplicht' });

    const limit = typeof dailyLimitMinutes === 'number' && dailyLimitMinutes >= 0 ? dailyLimitMinutes : 60;
    const start = windowStart || '00:00';
    const end = windowEnd || '23:59';

    const childResult = await pool.query(
      'INSERT INTO children (user_id, name) VALUES ($1, $2) RETURNING id',
      [req.userId, name]
    );
    const childId = childResult.rows[0].id;
    await pool.query(
      'INSERT INTO rules (child_id, daily_limit_minutes, window_start, window_end) VALUES ($1, $2, $3, $4)',
      [childId, limit, start, end]
    );

    res.status(201).json({ id: childId, name });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Databasefout bij aanmaken kind' });
  }
});

// Kinderen van deze ouder
router.get('/', async (req, res) => {
  try {
    const childrenResult = await pool.query('SELECT id, name FROM children WHERE user_id = $1', [req.userId]);

    const withRules = await Promise.all(
      childrenResult.rows.map(async (c) => {
        const ruleResult = await pool.query(
          'SELECT daily_limit_minutes AS "dailyLimitMinutes", window_start AS "windowStart", window_end AS "windowEnd", locked_date AS "lockedDate" FROM rules WHERE child_id = $1',
          [c.id]
        );
        const devicesResult = await pool.query(
          'SELECT id, name, platform, last_seen AS "lastSeen", locked_date AS "lockedDate" FROM devices WHERE child_id = $1',
          [c.id]
        );
        const rule = ruleResult.rows[0] || null;
        const childLocked = rule ? isLocked(rule.lockedDate) : false;
        const devices = devicesResult.rows.map((d) => ({
          id: d.id,
          name: d.name,
          platform: d.platform,
          lastSeen: d.lastSeen,
          // Een apparaat is vergrendeld als het individueel vergrendeld is, óf als het hele kind
          // vergrendeld is via de "vergrendel alles"-knop.
          locked: childLocked || isLocked(d.lockedDate),
        }));
        return {
          ...c,
          rule: rule ? { ...rule, locked: childLocked } : null,
          devices,
        };
      })
    );

    res.json(withRules);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Databasefout bij ophalen kinderen' });
  }
});

// Dagelijkse limiet instellen
router.put('/:id/rule', async (req, res) => {
  try {
    const childId = Number(req.params.id);
    if (!(await ownsChild(req.userId, childId))) return res.status(404).json({ error: 'Kind niet gevonden' });

    const { dailyLimitMinutes, windowStart, windowEnd } = req.body;
    if (typeof dailyLimitMinutes !== 'number' || dailyLimitMinutes < 0) {
      return res.status(400).json({ error: 'dailyLimitMinutes moet een positief getal zijn' });
    }

    await pool.query(
      `UPDATE rules SET daily_limit_minutes = $1,
         window_start = COALESCE($2, window_start),
         window_end = COALESCE($3, window_end),
         updated_at = now()
       WHERE child_id = $4`,
      [dailyLimitMinutes, windowStart || null, windowEnd || null, childId]
    );

    const result = await pool.query(
      'SELECT daily_limit_minutes AS "dailyLimitMinutes", window_start AS "windowStart", window_end AS "windowEnd", locked_date AS "lockedDate" FROM rules WHERE child_id = $1',
      [childId]
    );
    const rule = result.rows[0];
    res.json({ ...rule, locked: isLocked(rule.lockedDate) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Databasefout bij instellen limiet' });
  }
});

// Direct vergrendelen/ontgrendelen ("Nu vergrendelen"-knop). Een vergrendeling geldt alleen voor
// vandaag: de volgende dag is het kind automatisch weer ontgrendeld (zie isLocked hierboven).
// Bellen (telefoon-app) blijft op Android altijd toegestaan, ook tijdens een vergrendeling —
// dat wordt clientside afgedwongen (zie android-kind-app), niet hier.
router.put('/:id/lock', async (req, res) => {
  try {
    const childId = Number(req.params.id);
    if (!(await ownsChild(req.userId, childId))) return res.status(404).json({ error: 'Kind niet gevonden' });

    const { locked } = req.body;
    await pool.query(
      'UPDATE rules SET locked_date = $1, updated_at = now() WHERE child_id = $2',
      [locked ? today() : null, childId]
    );

    res.json({ locked: Boolean(locked) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Databasefout bij (ont)vergrendelen' });
  }
});

// Eén specifiek apparaat van dit kind (ont)grendelen, los van de andere apparaten. Geldt net als
// de "vergrendel alles"-knop alleen voor vandaag. Bellen blijft op Android altijd toegestaan.
router.put('/:id/devices/:deviceId/lock', async (req, res) => {
  try {
    const childId = Number(req.params.id);
    const deviceId = Number(req.params.deviceId);
    if (!(await ownsChild(req.userId, childId))) return res.status(404).json({ error: 'Kind niet gevonden' });

    const { locked } = req.body;
    const result = await pool.query(
      'UPDATE devices SET locked_date = $1 WHERE id = $2 AND child_id = $3 RETURNING id',
      [locked ? today() : null, deviceId, childId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Apparaat niet gevonden' });

    res.json({ deviceId, locked: Boolean(locked) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Databasefout bij (ont)vergrendelen van apparaat' });
  }
});

// Noodcode instellen: de ouder-app hasht de PIN zelf (SHA-256) en stuurt alleen die hash op —
// de platte-tekst-PIN komt nooit op de server of in de database terecht. Het kind-apparaat haalt
// deze hash op zolang er internet is, slaat hem lokaal op, en kan daarna ook offline vergelijken
// of een ingevoerde PIN klopt. Zie emergencyCodes.js voor waarom dit bewust geen databasetabel is.
router.put('/:id/emergency-code', async (req, res) => {
  try {
    const childId = Number(req.params.id);
    if (!(await ownsChild(req.userId, childId))) return res.status(404).json({ error: 'Kind niet gevonden' });

    const { codeHash } = req.body;
    if (!codeHash || typeof codeHash !== 'string') {
      return res.status(400).json({ error: 'codeHash is verplicht (SHA-256-hex van de PIN)' });
    }

    codeHashByChildId.set(childId, codeHash);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Fout bij instellen noodcode' });
  }
});

// Koppelcode genereren om een device te koppelen
router.post('/:id/pairing-code', async (req, res) => {
  try {
    const childId = Number(req.params.id);
    if (!(await ownsChild(req.userId, childId))) return res.status(404).json({ error: 'Kind niet gevonden' });

    const code = crypto.randomInt(100000, 999999).toString();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);
    await pool.query(
      'INSERT INTO pairing_codes (code, child_id, expires_at) VALUES ($1, $2, $3)',
      [code, childId, expiresAt]
    );

    res.status(201).json({ code, expiresAt: expiresAt.toISOString() });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Databasefout bij aanmaken koppelcode' });
  }
});

// Verbruik van een kind bekijken (som van alle devices)
router.get('/:id/usage', async (req, res) => {
  try {
    const childId = Number(req.params.id);
    if (!(await ownsChild(req.userId, childId))) return res.status(404).json({ error: 'Kind niet gevonden' });

    const date = req.query.date || new Date().toISOString().slice(0, 10);

    const rowsResult = await pool.query(
      `SELECT d.id AS "deviceId", d.name AS "deviceName", d.platform, ul.app_name AS "appName", SUM(ul.minutes)::int AS minutes
       FROM usage_logs ul
       JOIN devices d ON d.id = ul.device_id
       WHERE d.child_id = $1 AND ul.date = $2
       GROUP BY d.id, ul.app_name
       ORDER BY minutes DESC`,
      [childId, date]
    );
    const rows = rowsResult.rows;

    const totalMinutes = rows.reduce((sum, r) => sum + r.minutes, 0);
    const ruleResult = await pool.query(
      'SELECT daily_limit_minutes AS "dailyLimitMinutes" FROM rules WHERE child_id = $1',
      [childId]
    );
    const dailyLimitMinutes = ruleResult.rows[0]?.dailyLimitMinutes ?? 60;

    res.json({
      date,
      totalMinutes,
      dailyLimitMinutes,
      remainingMinutes: Math.max(0, dailyLimitMinutes - totalMinutes),
      breakdown: rows,
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Databasefout bij ophalen verbruik' });
  }
});

// Categorieën en categorielimieten ophalen (voor het dashboard)
router.get('/:id/categories', async (req, res) => {
  try {
    const childId = Number(req.params.id);
    if (!(await ownsChild(req.userId, childId))) return res.status(404).json({ error: 'Kind niet gevonden' });

    const appsResult = await pool.query(
      'SELECT app_name AS "appName", category, unlimited FROM app_categories WHERE child_id = $1',
      [childId]
    );
    const limitsResult = await pool.query(
      'SELECT category, daily_limit_minutes AS "dailyLimitMinutes" FROM category_rules WHERE child_id = $1',
      [childId]
    );

    res.json({
      availableCategories: VALID_CATEGORIES,
      appCategories: appsResult.rows,
      categoryLimits: limitsResult.rows,
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Databasefout bij ophalen categorieën' });
  }
});

// Een app aan een categorie koppelen (bv. "Roblox" -> "games"), en/of als "altijd toegestaan"
// markeren. Een altijd-toegestane app telt niet mee voor de dagelijkse/categorielimiet en wordt
// nooit geblokkeerd, maar het verbruik wordt wel gewoon gelogd zodat de ouder het kan zien.
router.post('/:id/app-category', async (req, res) => {
  try {
    const childId = Number(req.params.id);
    if (!(await ownsChild(req.userId, childId))) return res.status(404).json({ error: 'Kind niet gevonden' });

    const { appName, category, unlimited } = req.body;
    const effectiveCategory = category || 'other';
    if (!appName || !VALID_CATEGORIES.includes(effectiveCategory)) {
      return res.status(400).json({ error: `category moet een van deze zijn: ${VALID_CATEGORIES.join(', ')}` });
    }

    await pool.query(
      `INSERT INTO app_categories (child_id, app_name, category, unlimited) VALUES ($1, $2, $3, $4)
       ON CONFLICT (child_id, app_name) DO UPDATE SET category = EXCLUDED.category, unlimited = EXCLUDED.unlimited`,
      [childId, appName, effectiveCategory, Boolean(unlimited)]
    );

    res.status(201).json({ appName, category: effectiveCategory, unlimited: Boolean(unlimited) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Databasefout bij koppelen categorie' });
  }
});

// Dagelijkse limiet voor een categorie instellen (bv. max 30 min/dag "games")
router.put('/:id/category-limit', async (req, res) => {
  try {
    const childId = Number(req.params.id);
    if (!(await ownsChild(req.userId, childId))) return res.status(404).json({ error: 'Kind niet gevonden' });

    const { category, dailyLimitMinutes } = req.body;
    if (!VALID_CATEGORIES.includes(category) || typeof dailyLimitMinutes !== 'number' || dailyLimitMinutes < 0) {
      return res.status(400).json({ error: 'Ongeldige category of dailyLimitMinutes' });
    }

    await pool.query(
      `INSERT INTO category_rules (child_id, category, daily_limit_minutes) VALUES ($1, $2, $3)
       ON CONFLICT (child_id, category) DO UPDATE SET daily_limit_minutes = EXCLUDED.daily_limit_minutes`,
      [childId, category, dailyLimitMinutes]
    );

    res.status(200).json({ category, dailyLimitMinutes });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Databasefout bij instellen categorielimiet' });
  }
});

module.exports = router;
