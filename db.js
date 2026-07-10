const { Pool } = require('pg');

// Verbindt met de Retool-database (of elke andere Postgres-server) via DATABASE_URL uit .env.
// Retool Database geeft je die connectiestring onder "Connect using" van je database-resource.
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes('sslmode=require')
    ? { rejectUnauthorized: false }
    : undefined,
});

async function init() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS children (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id),
      name TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS rules (
      id SERIAL PRIMARY KEY,
      child_id INTEGER NOT NULL UNIQUE REFERENCES children(id),
      daily_limit_minutes INTEGER NOT NULL DEFAULT 60,
      window_start TEXT DEFAULT '00:00',
      window_end TEXT DEFAULT '23:59',
      -- Datum (YYYY-MM-DD) waarop de ouder op "Nu vergrendelen" heeft gedrukt. Geldt alleen voor
      -- die dag: de volgende dag klopt deze datum niet meer met "vandaag" en is het kind automatisch
      -- weer ontgrendeld, zonder dat er iets hoeft te gebeuren.
      locked_date TEXT,
      updated_at TIMESTAMPTZ DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS devices (
      id SERIAL PRIMARY KEY,
      child_id INTEGER NOT NULL REFERENCES children(id),
      name TEXT NOT NULL,
      platform TEXT NOT NULL CHECK (platform IN ('windows', 'android')),
      device_token TEXT UNIQUE NOT NULL,
      last_seen TIMESTAMPTZ,
      -- Datum (YYYY-MM-DD) waarop dit specifieke apparaat vergrendeld is via "per apparaat
      -- vergrendelen". Werkt net als rules.locked_date maar dan voor 1 apparaat i.p.v. alle
      -- apparaten van een kind tegelijk; geldt alleen voor die dag.
      locked_date TEXT,
      created_at TIMESTAMPTZ DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS pairing_codes (
      code TEXT PRIMARY KEY,
      child_id INTEGER NOT NULL REFERENCES children(id),
      expires_at TIMESTAMPTZ NOT NULL,
      used BOOLEAN DEFAULT false
    );

    CREATE TABLE IF NOT EXISTS usage_logs (
      id SERIAL PRIMARY KEY,
      device_id INTEGER NOT NULL REFERENCES devices(id),
      date TEXT NOT NULL,
      app_name TEXT NOT NULL,
      minutes INTEGER NOT NULL,
      created_at TIMESTAMPTZ DEFAULT now()
    );

    -- Welke categorie een app heeft (bv. "com.instagram.android" -> "social"), per kind
    -- ingesteld door de ouder. Vaste categorieën: games, social, video, education, other.
    -- "unlimited": app mag altijd gebruikt worden en telt niet mee voor de dagelijkse/categorielimiet,
    -- maar het verbruik wordt wel gewoon gelogd zodat de ouder het nog steeds kan zien.
    CREATE TABLE IF NOT EXISTS app_categories (
      id SERIAL PRIMARY KEY,
      child_id INTEGER NOT NULL REFERENCES children(id),
      app_name TEXT NOT NULL,
      category TEXT NOT NULL,
      unlimited BOOLEAN NOT NULL DEFAULT false,
      UNIQUE (child_id, app_name)
    );

    -- Dagelijkse limiet per categorie (los van de totale dagelijkse limiet).
    CREATE TABLE IF NOT EXISTS category_rules (
      id SERIAL PRIMARY KEY,
      child_id INTEGER NOT NULL REFERENCES children(id),
      category TEXT NOT NULL,
      daily_limit_minutes INTEGER NOT NULL,
      UNIQUE (child_id, category)
    );
  `);

  // Migratie voor databases die al bestonden vóór per-apparaat vergrendelen: voegt de kolom
  // alsnog toe als hij nog niet bestaat (CREATE TABLE IF NOT EXISTS raakt bestaande tabellen niet aan).
  await pool.query(`ALTER TABLE devices ADD COLUMN IF NOT EXISTS locked_date TEXT;`);
}

module.exports = { pool, init };
