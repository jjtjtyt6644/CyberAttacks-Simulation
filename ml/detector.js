/**
 * ML Threat Detector — feature extraction + logistic regression
 * No external ML libraries required. Trains on SQLite data.
 */

const path = require('path');
const fs = require('fs');

const MODEL_PATH = path.join(__dirname, '..', 'data', 'model.json');

let model = {
  version: 1,
  trained_at: new Date().toISOString(),
  thresholds: { alert: 0.55, high: 0.78 },
  weights: {
    sql_keywords: 2.8, sql_operators: 2.2, sql_comment: 3.0, sql_union: 3.5, sql_quote_balance: 1.8,
    xss_script_tag: 3.2, xss_event_handler: 2.5, xss_js_proto: 2.0, xss_encoded_angle: 1.5,
    path_dotdot: 3.0, path_etc_passwd: 3.8, path_encoded_slash: 2.2,
    cmd_pipe: 2.8, cmd_backtick: 3.0, cmd_semicolon: 1.5, cmd_dollar_paren: 2.5,
    ssti_template: 2.8,
    rapid_requests: 2.0,
    long_payload: 1.2, many_special_chars: 1.0,
  },
  bias: -3.5
};

function loadModel() {
  try {
    if (fs.existsSync(MODEL_PATH)) {
      model = { ...model, ...JSON.parse(fs.readFileSync(MODEL_PATH, 'utf8')) };
      console.log(`[ML] Model loaded v${model.version}`);
    }
  } catch (e) { console.warn('[ML] Using default model'); }
}

function saveModel() {
  if (!fs.existsSync(path.dirname(MODEL_PATH)))
    fs.mkdirSync(path.dirname(MODEL_PATH), { recursive: true });
  fs.writeFileSync(MODEL_PATH, JSON.stringify(model, null, 2));
}

loadModel();

const ipRequestLog = new Map();
function getRecentRequestCount(ip) {
  const now = Date.now(), window = 60_000;
  let log = (ipRequestLog.get(ip) || []).filter(t => now - t < window);
  log.push(now);
  ipRequestLog.set(ip, log);
  return log.length;
}

function extractFeatures(req, body) {
  const payload = JSON.stringify(body || {}) + (req.url || '') + JSON.stringify(req.query || {});
  const p = payload.toLowerCase();
  const ip = req.ip || req.connection?.remoteAddress || 'unknown';
  const recentCount = getRecentRequestCount(ip);
  return {
    sql_keywords:       /\b(select|insert|update|delete|drop|create|alter|exec|union|from|where|having|information_schema)\b/.test(p) ? 1 : 0,
    sql_operators:      /(\bor\b|\band\b)\s+['"]?\w+['"]?\s*=\s*['"]?\w+['"]?/.test(p) ? 1 : 0,
    sql_comment:        /(--|#|\/\*|\*\/)/.test(payload) ? 1 : 0,
    sql_union:          /union\s+(all\s+)?select/i.test(payload) ? 1 : 0,
    sql_quote_balance:  (payload.split("'").length - 1) % 2 !== 0 ? 1 : 0,
    xss_script_tag:     /<\s*script/i.test(payload) ? 1 : 0,
    xss_event_handler:  /\bon\w+\s*=/i.test(payload) ? 1 : 0,
    xss_js_proto:       /(javascript:|vbscript:|data:text\/html)/i.test(payload) ? 1 : 0,
    xss_encoded_angle:  /(%3c|%3e|&lt;|&gt;)/i.test(payload) ? 1 : 0,
    path_dotdot:        /(\.\.[\/\\]){1,}/.test(payload) ? 1 : 0,
    path_etc_passwd:    /etc\/(passwd|shadow|hosts)/i.test(payload) ? 1 : 0,
    path_encoded_slash: /(%2f|%5c)/i.test(payload) ? 1 : 0,
    cmd_pipe:           /[|;`]/.test(payload) ? 1 : 0,
    cmd_backtick:       /`/.test(payload) ? 1 : 0,
    cmd_semicolon:      /;\s*(ls|cat|whoami|id|pwd|echo|curl|wget|nc|bash|sh)\b/i.test(payload) ? 1 : 0,
    cmd_dollar_paren:   /\$\(/.test(payload) ? 1 : 0,
    ssti_template:      /(\{\{|\}\}|\{%|%\}|<\?php|\$\{)/i.test(payload) ? 1 : 0,
    rapid_requests:     recentCount > 10 ? 1 : 0,
    long_payload:       payload.length > 500 ? 1 : 0,
    many_special_chars: (payload.match(/[<>'";\-\(\)\/\\\{\}]/g) || []).length > 15 ? 1 : 0,
  };
}

function score(features) {
  let z = model.bias;
  for (const [k, v] of Object.entries(features))
    if (model.weights[k] !== undefined) z += model.weights[k] * v;
  return 1 / (1 + Math.exp(-z));
}

function classifyThreat(features) {
  if (features.sql_union || features.sql_keywords) return 'SQL_INJECTION';
  if (features.xss_script_tag || features.xss_event_handler || features.xss_js_proto) return 'XSS';
  if (features.path_dotdot || features.path_etc_passwd) return 'PATH_TRAVERSAL';
  if (features.cmd_semicolon || features.cmd_backtick || features.cmd_dollar_paren) return 'CMD_INJECTION';
  if (features.ssti_template) return 'SSTI';
  if (features.rapid_requests) return 'BRUTE_FORCE';
  return 'ANOMALY';
}

function detectThreat(req, body) {
  const features = extractFeatures(req, body);
  const threatScore = score(features);
  const threatType = classifyThreat(features);
  return { features, threatScore, threatType, isAlert: threatScore >= model.thresholds.alert };
}

async function logEvent(req, body, detection) {
  // Lazy-load db to avoid circular require at startup
  const db = require('../api/db');
  await db.ready; // wait for schema init
  const { features, threatScore, threatType, isAlert } = detection;
  const payload = JSON.stringify(body).substring(0, 1000);
  const ip = req.ip || req.connection?.remoteAddress || 'unknown';

  const result = await db.run(
    `INSERT INTO threat_events (ip, user_agent, endpoint, method, payload, threat_type, threat_score, confidence, features)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [ip, req.headers?.['user-agent'] || 'unknown', req.path, req.method,
     payload, threatType, threatScore.toFixed(4), (threatScore * 100).toFixed(1), JSON.stringify(features)]
  );

  if (isAlert && global.io) {
    global.io.to('admin-room').emit('threat-alert', {
      id: result.lastID,
      ip, threatType,
      threatScore: parseFloat(threatScore.toFixed(4)),
      confidence: parseFloat((threatScore * 100).toFixed(1)),
      endpoint: req.path, method: req.method,
      payload: payload.substring(0, 200),
      timestamp: new Date().toISOString(),
      severity: threatScore >= model.thresholds.high ? 'HIGH' : 'MEDIUM'
    });
  }
  return { id: result.lastID, isAlert, threatScore, threatType };
}

async function trainModel() {
  const db = require('../api/db');
  await db.ready;
  const rows = await db.all('SELECT features, label FROM ml_training_data');
  if (rows.length < 5)
    return { success: false, message: `Need at least 5 training samples (have ${rows.length})` };

  console.log(`[ML] Training on ${rows.length} samples...`);
  const lr = 0.01, epochs = 200;
  const newWeights = { ...model.weights };
  let newBias = model.bias;

  for (let epoch = 0; epoch < epochs; epoch++) {
    for (const row of rows) {
      let features;
      try { features = JSON.parse(row.features); } catch { continue; }
      const label = row.label;
      let z = newBias;
      for (const [k, v] of Object.entries(features))
        if (newWeights[k] !== undefined) z += newWeights[k] * v;
      const pred = 1 / (1 + Math.exp(-z));
      const err = pred - label;
      newBias -= lr * err;
      for (const [k, v] of Object.entries(features))
        if (newWeights[k] !== undefined) newWeights[k] -= lr * err * v;
    }
  }

  model.weights = newWeights;
  model.bias = newBias;
  model.version += 1;
  model.trained_at = new Date().toISOString();
  saveModel();
  console.log(`[ML] Training complete v${model.version}`);
  return { success: true, samples: rows.length, epochs, version: model.version, trained_at: model.trained_at };
}

async function getModelInfo() {
  const db = require('../api/db');
  await db.ready;
  const row = await db.get('SELECT COUNT(*) as c FROM ml_training_data');
  return { version: model.version, trained_at: model.trained_at, thresholds: model.thresholds, weights: model.weights, sample_count: row.c };
}

async function addTrainingSample(features, label, threatType, source = 'manual') {
  const db = require('../api/db');
  await db.ready;
  await db.run('INSERT INTO ml_training_data (features, label, threat_type, source) VALUES (?, ?, ?, ?)',
    [JSON.stringify(features), label ? 1 : 0, threatType, source]);
}

function updateThresholds(alert, high) {
  model.thresholds.alert = alert;
  model.thresholds.high = high;
  saveModel();
}

module.exports = { detectThreat, logEvent, trainModel, getModelInfo, addTrainingSample, updateThresholds, extractFeatures };
