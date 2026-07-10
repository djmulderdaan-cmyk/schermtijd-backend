require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');

const { init } = require('./db');
const authRoutes = require('./routes/auth');
const childrenRoutes = require('./routes/children');
const devicesRoutes = require('./routes/devices');

const app = express();
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
