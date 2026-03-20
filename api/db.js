/**
 * Database — uses sqlite3 (prebuilt binaries, no Visual Studio needed on Windows)
 */

const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');

const DB_PATH = path.join(__dirname, '..', 'data', 'lab.db');
if (!fs.existsSync(path.dirname(DB_PATH))) {
  fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
}

const rawDb = new sqlite3.Database(DB_PATH);

function run(sql, params = []) {
  return new Promise((resolve, reject) => {
    rawDb.run(sql, params, function(err) {
      if (err) reject(err); else resolve({ lastID: this.lastID, changes: this.changes });
    });
  });
}
function get(sql, params = []) {
  return new Promise((resolve, reject) => {
    rawDb.get(sql, params, (err, row) => { if (err) reject(err); else resolve(row); });
  });
}
function all(sql, params = []) {
  return new Promise((resolve, reject) => {
    rawDb.all(sql, params, (err, rows) => { if (err) reject(err); else resolve(rows); });
  });
}
function exec(sql) {
  return new Promise((resolve, reject) => {
    rawDb.exec(sql, (err) => { if (err) reject(err); else resolve(); });
  });
}

// Shim: prepare().get/all/run → async
function prepare(sql) {
  return {
    get: (...params) => get(sql, params),
    all: (...params) => all(sql, params),
    run: (...params) => run(sql, params),
  };
}

// Raw unparameterized query — for intentionally vulnerable endpoints
function rawQuery(sql) {
  return new Promise((resolve, reject) => {
    rawDb.all(sql, [], (err, rows) => { if (err) reject(err); else resolve(rows); });
  });
}

async function initSchema() {
  await exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL, email TEXT, role TEXT DEFAULT 'user',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS posts (
      id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, content TEXT,
      author_id INTEGER, created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS secrets (
      id INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT, value TEXT
    );
    CREATE TABLE IF NOT EXISTS threat_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT, user_agent TEXT,
      endpoint TEXT, method TEXT, payload TEXT, threat_type TEXT,
      threat_score REAL, confidence REAL, features TEXT,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, acknowledged INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS ml_training_data (
      id INTEGER PRIMARY KEY AUTOINCREMENT, features TEXT NOT NULL,
      label INTEGER NOT NULL, threat_type TEXT, source TEXT DEFAULT 'manual',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS admin_users (
      id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS banned_ips (
      ip TEXT PRIMARY KEY,
      reason TEXT,
      banned_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  `);

  const uc = await get('SELECT COUNT(*) as c FROM users');
  if (uc.c === 0) {
    await run('INSERT INTO users (username,password,email,role) VALUES (?,?,?,?)', ['admin','password123','admin@lab.local','admin']);
    await run('INSERT INTO users (username,password,email,role) VALUES (?,?,?,?)', ['alice','alice123','alice@lab.local','user']);
    await run('INSERT INTO users (username,password,email,role) VALUES (?,?,?,?)', ['bob','bob123','bob@lab.local','user']);
    await run('INSERT INTO secrets (key,value) VALUES (?,?)', ['FLAG_1','CTF{sql_injection_is_dangerous}']);
    await run('INSERT INTO secrets (key,value) VALUES (?,?)', ['FLAG_2','CTF{xss_stored_wins}']);
    await run('INSERT INTO secrets (key,value) VALUES (?,?)', ['DB_PASSWORD','super_secret_db_pass_do_not_leak']);
    await run('INSERT INTO secrets (key,value) VALUES (?,?)', ['API_KEY','sk-live-xxxx-xxxx-xxxx']);
    await run('INSERT INTO posts (title,content,author_id) VALUES (?,?,?)', ['Welcome to VulnLab','This is an intentionally vulnerable site for security training.',1]);
    await run('INSERT INTO posts (title,content,author_id) VALUES (?,?,?)', ['Hidden Note','<script>alert("XSS stored!")</script>',1]);
    console.log('[DB] Seeded vulnerable app data');
  }

  const ac = await get('SELECT COUNT(*) as c FROM admin_users');
  if (ac.c === 0) {
    const hash = bcrypt.hashSync('Admin@SecureLab2024!', 12);
    await run('INSERT INTO admin_users (username,password_hash) VALUES (?,?)', ['admin', hash]);
    console.log('[DB] Seeded admin user');
  }
}

const db = { run, get, all, prepare, rawQuery, exec, _raw: rawDb };
db.ready = initSchema().catch(e => console.error('[DB] Init error:', e));
module.exports = db;
