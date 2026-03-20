/**
 * Admin API Routes — Secure (bcrypt, parameterized queries, session auth)
 */
const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const db = require('./db');
const { trainModel, getModelInfo, addTrainingSample, updateThresholds, extractFeatures } = require('../ml/detector');

function adminAuth(req, res, next) {
  if (!req.session.admin) return res.status(401).json({ error: 'Admin authentication required' });
  next();
}

router.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Missing credentials' });
  const admin = await db.get('SELECT * FROM admin_users WHERE username = ?', [username]);
  if (!admin) return res.status(401).json({ error: 'Invalid credentials' });
  const valid = await bcrypt.compare(password, admin.password_hash);
  if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
  req.session.admin = { id: admin.id, username: admin.username };
  res.json({ success: true, username: admin.username });
});

router.post('/logout', (req, res) => { delete req.session.admin; res.json({ success: true }); });

router.get('/me', (req, res) => {
  if (req.session.admin) res.json({ loggedIn: true, admin: req.session.admin });
  else res.json({ loggedIn: false });
});

router.get('/threats', adminAuth, async (req, res) => {
  const { limit = 100, offset = 0, type, minScore } = req.query;
  let query = 'SELECT * FROM threat_events WHERE 1=1';
  const params = [];
  if (type) { query += ' AND threat_type = ?'; params.push(type); }
  if (minScore) { query += ' AND threat_score >= ?'; params.push(parseFloat(minScore)); }
  query += ' ORDER BY timestamp DESC LIMIT ? OFFSET ?';
  params.push(parseInt(limit), parseInt(offset));
  const events = await db.all(query, params);
  const total = (await db.get('SELECT COUNT(*) as c FROM threat_events')).c;
  const unread = (await db.get('SELECT COUNT(*) as c FROM threat_events WHERE acknowledged = 0')).c;
  res.json({ events, total, unread });
});

router.get('/threats/stats', adminAuth, async (req, res) => {
  const byType = await db.all(`SELECT threat_type, COUNT(*) as count, AVG(threat_score) as avg_score FROM threat_events GROUP BY threat_type ORDER BY count DESC`);
  const byHour = await db.all(`SELECT strftime('%H', timestamp) as hour, COUNT(*) as count FROM threat_events WHERE timestamp >= datetime('now', '-24 hours') GROUP BY hour ORDER BY hour`);
  const topIPs = await db.all(`SELECT ip, COUNT(*) as count, MAX(threat_score) as max_score FROM threat_events GROUP BY ip ORDER BY count DESC LIMIT 10`);
  const totals = await db.get(`SELECT COUNT(*) as total, SUM(CASE WHEN threat_score >= 0.78 THEN 1 ELSE 0 END) as high, SUM(CASE WHEN threat_score >= 0.55 AND threat_score < 0.78 THEN 1 ELSE 0 END) as medium, SUM(CASE WHEN acknowledged = 0 THEN 1 ELSE 0 END) as unread FROM threat_events`);
  res.json({ byType, byHour, topIPs, totals });
});

router.post('/threats/:id/acknowledge', adminAuth, async (req, res) => {
  await db.run('UPDATE threat_events SET acknowledged = 1 WHERE id = ?', [req.params.id]);
  res.json({ success: true });
});

router.post('/threats/acknowledge-all', adminAuth, async (req, res) => {
  await db.run('UPDATE threat_events SET acknowledged = 1');
  res.json({ success: true });
});

router.delete('/threats/:id', adminAuth, async (req, res) => {
  await db.run('DELETE FROM threat_events WHERE id = ?', [req.params.id]);
  res.json({ success: true });
});

router.get('/ml/info', adminAuth, async (req, res) => res.json(await getModelInfo()));

router.post('/ml/train', adminAuth, async (req, res) => {
  const result = await trainModel();
  if (global.io) global.io.to('admin-room').emit('ml-retrained', result);
  res.json(result);
});

router.post('/ml/label', adminAuth, async (req, res) => {
  const { eventId, label } = req.body;
  const event = await db.get('SELECT * FROM threat_events WHERE id = ?', [eventId]);
  if (!event) return res.status(404).json({ error: 'Event not found' });
  const features = extractFeatures(
    { ip: event.ip, headers: { 'user-agent': event.user_agent }, path: event.endpoint, method: event.method, query: {} },
    JSON.parse(event.payload || '{}')
  );
  await addTrainingSample(features, label === true || label === 1, event.threat_type, 'admin-label');
  await db.run('UPDATE threat_events SET acknowledged = 1 WHERE id = ?', [eventId]);
  res.json({ success: true, message: `Sample labeled as ${label ? 'THREAT' : 'BENIGN'} and added to training set` });
});

router.post('/ml/add-sample', adminAuth, async (req, res) => {
  const { payload, label, threatType } = req.body;
  const fakeReq = { ip: '127.0.0.1', headers: { 'user-agent': 'manual' }, path: '/manual', method: 'POST', query: {} };
  const features = extractFeatures(fakeReq, { input: payload });
  await addTrainingSample(features, label, threatType || 'MANUAL', 'manual');
  res.json({ success: true });
});

router.put('/ml/thresholds', adminAuth, (req, res) => {
  const { alert, high } = req.body;
  if (alert === undefined || high === undefined) return res.status(400).json({ error: 'alert and high required' });
  updateThresholds(parseFloat(alert), parseFloat(high));
  res.json({ success: true });
});

router.get('/ml/training-data', adminAuth, async (req, res) => {
  const data = await db.all('SELECT * FROM ml_training_data ORDER BY created_at DESC LIMIT 200');
  res.json({ data });
});

module.exports = router;

// ─── IP Management ────────────────────────────────────────────────────────────
router.get('/ips', adminAuth, async (req, res) => {
  const ips = await db.all(`
    SELECT
      ip,
      COUNT(*) as total_events,
      SUM(CASE WHEN threat_score >= 0.78 THEN 1 ELSE 0 END) as high_count,
      SUM(CASE WHEN threat_score >= 0.55 THEN 1 ELSE 0 END) as alert_count,
      MAX(threat_score) as max_score,
      MAX(timestamp) as last_seen,
      MIN(timestamp) as first_seen,
      GROUP_CONCAT(DISTINCT threat_type) as threat_types
    FROM threat_events
    GROUP BY ip
    ORDER BY total_events DESC
  `);
  const banned = await db.all('SELECT * FROM banned_ips ORDER BY banned_at DESC');
  const bannedSet = new Set(banned.map(b => b.ip));
  res.json({ ips: ips.map(i => ({ ...i, banned: bannedSet.has(i.ip) })), banned });
});

router.post('/ips/ban', adminAuth, async (req, res) => {
  const { ip, reason } = req.body;
  if (!ip) return res.status(400).json({ error: 'IP required' });
  try {
    await db.run('INSERT OR REPLACE INTO banned_ips (ip, reason, banned_at) VALUES (?,?,?)',
      [ip, reason || 'Manually banned by admin', new Date().toISOString()]);
    if (global.io) global.io.to('admin-room').emit('ip-banned', { ip, reason });
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

router.delete('/ips/ban/:ip', adminAuth, async (req, res) => {
  await db.run('DELETE FROM banned_ips WHERE ip = ?', [decodeURIComponent(req.params.ip)]);
  res.json({ success: true });
});

router.get('/ips/banned', adminAuth, async (req, res) => {
  const banned = await db.all('SELECT * FROM banned_ips ORDER BY banned_at DESC');
  res.json({ banned });
});

// ─── Users table ──────────────────────────────────────────────────────────────
router.get('/users', adminAuth, async (req, res) => {
  const users = await db.all('SELECT id, username, email, role, created_at FROM users');
  res.json({ users });
});

router.delete('/users/:id', adminAuth, async (req, res) => {
  await db.run('DELETE FROM users WHERE id = ?', [req.params.id]);
  res.json({ success: true });
});

// ─── Add user ─────────────────────────────────────────────────────────────────
router.post('/users', adminAuth, async (req, res) => {
  const { username, password, email, role } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  try {
    await db.run(
      'INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)',
      [username, password, email || '', role || 'user']
    );
    res.json({ success: true });
  } catch (e) {
    res.status(400).json({ error: e.message.includes('UNIQUE') ? 'Username already exists' : e.message });
  }
});
