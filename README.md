# VulnLab — Security Training Platform

> ⚠️ **FOR EDUCATIONAL / CTF USE ONLY**
> Run **only on localhost or an isolated private network**. Never expose to the public internet.

A full-stack intentionally vulnerable web app with:
- 🔓 **Vulnerable site** with SQL Injection, XSS, Path Traversal, Command Injection, IDOR, and Broken Access Control
- 🔐 **Secure admin dashboard** (bcrypt + parameterized queries) with real-time WebSocket alerts
- 🤖 **AI/ML threat detector** that analyzes every request and alarms the admin panel
- 🧠 **Trainable ML model** — label events, add samples, retrain from the admin UI

---

## Quick Start

```bash
# 1. Install dependencies
npm install

# 2. Start the server (auto-seeds the database on first run)
npm start

# (Optional) Dev mode with auto-restart
npm run dev
```

Then open:
- **Vulnerable App** → http://localhost:3000
- **Login Page** → http://localhost:3000/login
- **Admin Dashboard** → http://localhost:3000/admin

---

## Credentials

| Site | Username | Password |
|------|----------|----------|
| Vulnerable App | `admin` | `password123` |
| Vulnerable App | `alice` | `alice123` |
| **Admin Dashboard** | `admin` | `Admin@SecureLab2024!` |

---

## Architecture

```
vuln-lab/
├── server.js           # Express + Socket.IO server
├── api/
│   ├── db.js           # SQLite database (schema + seed)
│   ├── vuln-routes.js  # ⚠️  Intentionally vulnerable endpoints
│   └── admin-routes.js # 🔐 Secure admin API
├── ml/
│   ├── detector.js     # Feature extraction + logistic regression
│   └── train.js        # CLI training script
├── public/
│   ├── index.html      # Landing page
│   ├── login.html      # Login with live AI threat meter
│   └── dashboard.html  # Exploit playground
├── admin/
│   └── index.html      # Admin security center
└── data/               # Auto-created
    ├── lab.db          # SQLite database
    └── model.json      # Saved ML model weights
```

---

## Vulnerabilities Included

| Vuln | Endpoint | OWASP |
|------|----------|-------|
| SQL Injection | `POST /api/login`, `GET /api/search` | A03 |
| Stored XSS | `POST /api/posts` | A03 |
| Reflected XSS | `GET /api/greet?name=` | A03 |
| Path Traversal | `GET /api/file?name=` | A01 |
| Command Injection | `POST /api/ping` | A03 |
| IDOR | `GET /api/user/:id` | A01 |
| Broken Access Control | `GET /api/secrets` | A01 |
| Weak Passwords | Users table | A07 |

---

## ML Threat Detection

The AI detector runs on **every request** to the vulnerable endpoints.

### How it works
1. **Feature extraction** — extracts 22 binary signals from the request payload (SQL keywords, XSS patterns, path traversal sequences, command injection chars, etc.)
2. **Logistic regression scoring** — weights the features to produce a 0–1 threat score
3. **Real-time alerting** — if score ≥ threshold (default 0.55), fires a WebSocket alert to the admin dashboard

### Training the model

**From the Admin Dashboard (recommended):**
1. Go to **Threat Events** tab
2. Click `🔴 Threat` or `🟢 Safe` on any logged event to label it as training data
3. Go to **ML Training** tab → click **⚡ Retrain Model**

**Add manual samples:**
- Go to **ML Training** → "Add Training Sample"
- Enter a payload, select threat/benign label and type, click Add
- Then retrain

**From the CLI:**
```bash
npm run train
```

### Adjust thresholds
In the ML Training tab, use the sliders to tune:
- **Alert threshold** — minimum score to trigger an alert (default 0.55)
- **High severity threshold** — score at which an event becomes "HIGH" (default 0.78)

---

## Example Exploits to Try

**SQL Injection (login bypass):**
```
username: admin' --
password: anything
```

**SQL Injection (data extraction via search):**
```
' UNION SELECT id, key, value FROM secrets--
```

**Stored XSS:**
```html
<img src=x onerror=alert(document.cookie)>
```

**Path Traversal:**
```
../../../etc/passwd
```

**Command Injection:**
```
127.0.0.1; whoami
127.0.0.1 | cat /etc/passwd
```

---

## CTF Flags

| Flag | Location |
|------|----------|
| `CTF{sql_injection_is_dangerous}` | `secrets` table — accessible via `/api/secrets` or SQLi |
| `CTF{xss_stored_wins}` | `secrets` table |

---

## Disclaimer

This project is for **security education only**. It intentionally contains dangerous vulnerabilities. Only run on:
- Your local machine (`localhost`)
- An isolated VM / lab network
- Never on a public IP or cloud server

##License

MIT
