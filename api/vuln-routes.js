/**
 * Vulnerable Routes — Intentionally insecure for security training
 * ⚠️ DO NOT USE IN PRODUCTION ⚠️
 */
const express = require('express');
const router = express.Router();
const db = require('./db');
const { detectThreat, logEvent } = require('../ml/detector');

function inspect(req, res, next) {
  const body = req.body || {};
  const detection = detectThreat(req, body);
  req.detection = detection;
  logEvent(req, body, detection);
  next();
}

// LOGIN — SQL Injectable
router.post('/login', inspect, async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ success: false, message: 'Missing credentials' });
  try {
    // ⚠️ INTENTIONALLY VULNERABLE: raw string concat
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
    let rows;
    try { rows = await db.rawQuery(query); }
    catch (sqlErr) { return res.status(500).json({ success: false, message: 'Database error: ' + sqlErr.message }); }
    const user = rows[0];
    if (user) {
      req.session.user = { id: user.id, username: user.username, role: user.role };
      return res.json({ success: true, user: { username: user.username, role: user.role }, redirect: '/dashboard' });
    }
    return res.status(401).json({ success: false, message: 'Invalid credentials' });
  } catch (e) {
    return res.status(500).json({ success: false, message: e.message });
  }
});

router.post('/logout', (req, res) => { req.session.destroy(); res.json({ success: true }); });

router.get('/me', (req, res) => {
  if (req.session.user) res.json({ loggedIn: true, user: req.session.user });
  else res.json({ loggedIn: false });
});

// SEARCH — SQL Injectable
router.get('/search', inspect, async (req, res) => {
  const { q } = req.query;
  if (!q) return res.json({ results: [] });
  try {
    const query = `SELECT id, title, content FROM posts WHERE title LIKE '%${q}%' OR content LIKE '%${q}%'`;
    const results = await db.rawQuery(query);
    res.json({ results });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POSTS — Stored XSS
router.get('/posts', inspect, async (req, res) => {
  const posts = await db.all('SELECT * FROM posts ORDER BY created_at DESC');
  res.json({ posts });
});

router.post('/posts', inspect, async (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Not authenticated' });
  const { title, content } = req.body;
  await db.run('INSERT INTO posts (title, content, author_id) VALUES (?, ?, ?)', [title, content, req.session.user.id]);
  res.json({ success: true });
});

// USER — IDOR
router.get('/user/:id', inspect, async (req, res) => {
  const user = await db.get('SELECT id, username, email, role FROM users WHERE id = ?', [req.params.id]);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ user });
});

// FILE — Path Traversal
router.get('/file', inspect, (req, res) => {
  const { name } = req.query;
  if (!name) return res.status(400).json({ error: 'name required' });
  const fs = require('fs'), path = require('path');
  const filePath = path.join(__dirname, '..', 'public', 'files', name);
  try { res.json({ content: fs.readFileSync(filePath, 'utf8') }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

// PING — Command Injection
router.post('/ping', inspect, (req, res) => {
  const { host } = req.body;
  if (!host) return res.status(400).json({ error: 'host required' });
  const { exec } = require('child_process');
  exec(`ping -c 1 ${host}`, { timeout: 3000 }, (err, stdout, stderr) => {
    res.json({ command: `ping -c 1 ${host}`, output: stdout || stderr || (err ? err.message : ''), error: !!err });
  });
});

// GREET — Reflected XSS
router.get('/greet', inspect, (req, res) => {
  res.send(`<html><body><h1>Hello, ${req.query.name}!</h1></body></html>`);
});

// SECRETS — Broken Access Control
router.get('/secrets', inspect, async (req, res) => {
  const secrets = await db.all('SELECT * FROM secrets');
  res.json({ secrets });
});

module.exports = router;
