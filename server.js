require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');

const { init } = require('./db');
const authRoutes = require('./routes/auth');
const childrenRoutes = require('./routes/children');
const devicesRoutes = require('./routes/devices');

const app = express();
// Nodig zodra dit achter een reverse proxy draait (bv. Render): anders ziet Express altijd het
// IP-adres van de proxy in plaats van de echte bezoeker, en werkt de rate limiter op /auth niet
// per persoon maar voor iedereen tegelijk.
app.set('trust proxy', 1);
app.use(cors());
app.use(express.json());

app.get('/api/health', (req, res) => res.json({ ok: true }));

app.use('/api/auth', authRoutes);
app.use('/api/children', childrenRoutes);
app.use('/api/devices', devicesRoutes);

// Ouder-dashboard (webinterface): een statische pagina die de API aanroept.
app.use(express.static(path.join(__dirname, 'public')));

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Interne serverfout' });
});

const PORT = process.env.PORT || 3000;

init()
  .then(() => {
    app.listen(PORT, () => console.log('Schermtijd-backend draait op http://localhost:' + PORT));
  })
  .catch((err) => {
    console.error('Kon database niet initialiseren:', err);
    process.exit(1);
  });
