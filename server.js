/**
 * VulnLab - Intentionally Vulnerable Web App for Security Training
 * ⚠️  FOR EDUCATIONAL / CTF USE ONLY — DO NOT DEPLOY ON PUBLIC INTERNET ⚠️
 */

const express = require('express');
const session = require('express-session');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const bodyParser = require('body-parser');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

// ─── Middleware ────────────────────────────────────────────────────────────────
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/admin', express.static(path.join(__dirname, 'admin')));
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'html');
app.engine('html', require('fs').readFileSync.bind(require('fs')));

// Session (intentionally weak secret on vuln side, strong on admin)
app.use(session({
  secret: 'supersecret123',  // intentionally weak
  resave: false,
  saveUninitialized: true,
  cookie: { httpOnly: false } // intentionally no httpOnly for XSS demos
}));

// ─── Database & ML ────────────────────────────────────────────────────────────
const db = require('./api/db');
const { detectThreat, logEvent } = require('./ml/detector');

// Make io available globally for alerts
app.set('io', io);
global.io = io;

// ─── IP Ban middleware ────────────────────────────────────────────────────────
app.use(async (req, res, next) => {
  if (req.path.startsWith('/api/admin') || req.path.startsWith('/admin')) return next();
  const ip = req.ip || req.connection?.remoteAddress || '';
  const db = require('./api/db');
  await db.ready;
  const banned = await db.get('SELECT * FROM banned_ips WHERE ip = ?', [ip]);
  if (banned) {
    return res.status(403).send(`
      <html><body style="background:#060a0f;color:#ff3366;font-family:monospace;display:flex;align-items:center;justify-content:center;height:100vh;flex-direction:column;gap:1rem;">
        <div style="font-size:3rem;">🚫</div>
        <div style="font-size:1.2rem;font-weight:bold;">ACCESS DENIED</div>
        <div style="color:#566a8a;font-size:0.85rem;">Your IP (${ip}) has been banned by the administrator.</div>
        <div style="color:#566a8a;font-size:0.75rem;">Reason: ${banned.reason || 'No reason provided'}</div>
      </body></html>
    `);
  }
  next();
});


const vulnRoutes = require('./api/vuln-routes');
const adminRoutes = require('./api/admin-routes');

app.use('/api', vulnRoutes);
app.use('/api/admin', adminRoutes);

// ─── Page Routes ──────────────────────────────────────────────────────────────
const fs = require('fs');

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/dashboard', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'admin', 'index.html'));
});

// ─── Socket.IO (real-time alerts) ────────────────────────────────────────────
io.on('connection', (socket) => {
  console.log(`[WS] Client connected: ${socket.id}`);

  socket.on('admin-auth', (token) => {
    if (token === process.env.ADMIN_TOKEN || token === 'admin-secret-token') {
      socket.join('admin-room');
      socket.emit('admin-auth-ok');
      console.log('[WS] Admin authenticated via socket');
    }
  });

  socket.on('disconnect', () => {
    console.log(`[WS] Client disconnected: ${socket.id}`);
  });
});

// ─── Start ────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`
╔══════════════════════════════════════════════════════╗
║          VulnLab Security Training Platform          ║
║  ⚠️  FOR EDUCATIONAL USE ONLY — LOCAL NETWORK ONLY ⚠️  ║
╠══════════════════════════════════════════════════════╣
║  Vulnerable App  →  http://localhost:${PORT}           ║
║  Admin Dashboard →  http://localhost:${PORT}/admin     ║
║  Admin Password  →  admin / Admin@SecureLab2024!      ║
╚══════════════════════════════════════════════════════╝
  `);
});
