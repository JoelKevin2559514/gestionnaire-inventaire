// ============================================================================
// Gestionnaire d'inventaire — serveur autonome
// Node.js + Express + SQLite intégré (node:sqlite, aucune compilation native)
// Démarrage : node server.js  (port via la variable PORT, écoute 0.0.0.0)
// ============================================================================
const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { DatabaseSync } = require('node:sqlite');

const app = express();
const PORT = process.env.PORT || 3000;
const HOST = '0.0.0.0';
// Fuseau horaire pour les ventes du jour / du mois (par défaut Montréal).
const TZ = process.env.TZ || 'America/Toronto';
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'data.sqlite');
const SESSION_DAYS = 7;

app.use(express.json({ limit: '8mb' }));
app.use(express.urlencoded({ extended: false }));
// Derrière Render, l'adresse IP réelle du visiteur arrive via l'en-tête
// X-Forwarded-For (indispensable pour limiter les tentatives par personne).
app.set('trust proxy', 1);

// En-têtes de sécurité de base.
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Referrer-Policy', 'no-referrer');
  next();
});

// Anti force brute sur la connexion : 10 échecs max par adresse IP
// pendant 15 minutes, puis blocage temporaire de 15 minutes.
const loginAttempts = new Map();
function loginRateLimit(req, res, next) {
  const key = req.ip || 'unknown';
  const now = Date.now();
  const rec = loginAttempts.get(key);
  if (rec && rec.blockedUntil > now) {
    return res.status(429).json({ error: 'Trop de tentatives. Réessayez dans quelques minutes.' });
  }
  if (rec && rec.resetAt < now) loginAttempts.delete(key);
  req._loginKey = key;
  next();
}
function recordFailedLogin(req) {
  const key = req._loginKey || 'unknown';
  const now = Date.now();
  const rec = loginAttempts.get(key) || { fails: 0, resetAt: now + 15 * 60 * 1000, blockedUntil: 0 };
  rec.fails += 1;
  if (rec.fails >= 10) rec.blockedUntil = now + 15 * 60 * 1000;
  loginAttempts.set(key, rec);
}
function recordSuccessfulLogin(req) {
  loginAttempts.delete(req._loginKey || 'unknown');
}

// ---------------------------------------------------------------------------
// Base de données
// ---------------------------------------------------------------------------
const db = new DatabaseSync(DB_PATH);

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin','employe','lecture')),
    must_change_password INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS articles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    photo TEXT NOT NULL DEFAULT '',
    price REAL NOT NULL DEFAULT 0,
    cost_price REAL,
    sku TEXT NOT NULL DEFAULT '',
    category TEXT NOT NULL DEFAULT '',
    stock INTEGER NOT NULL DEFAULT 0,
    low_threshold INTEGER NOT NULL DEFAULT 5,
    created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS movements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    article_id INTEGER NOT NULL REFERENCES articles(id),
    article_name TEXT NOT NULL,
    type TEXT NOT NULL CHECK (type IN ('entree','vente','sortie')),
    quantity INTEGER NOT NULL,
    unit_price REAL NOT NULL DEFAULT 0,
    total REAL NOT NULL DEFAULT 0,
    note TEXT NOT NULL DEFAULT '',
    user_id INTEGER,
    username TEXT NOT NULL DEFAULT '',
    day TEXT NOT NULL,
    created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS invoices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    number TEXT UNIQUE NOT NULL,
    client_name TEXT NOT NULL DEFAULT '',
    client_info TEXT NOT NULL DEFAULT '',
    subtotal REAL NOT NULL DEFAULT 0,
    tax_rate REAL NOT NULL DEFAULT 0,
    tax_amount REAL NOT NULL DEFAULT 0,
    total REAL NOT NULL DEFAULT 0,
    user_id INTEGER,
    username TEXT NOT NULL DEFAULT '',
    day TEXT NOT NULL,
    created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS invoice_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    invoice_id INTEGER NOT NULL REFERENCES invoices(id),
    article_id INTEGER,
    name TEXT NOT NULL,
    quantity INTEGER NOT NULL,
    unit_price REAL NOT NULL DEFAULT 0,
    total REAL NOT NULL DEFAULT 0
  );
  CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT UNIQUE NOT NULL,
    user_id INTEGER NOT NULL REFERENCES users(id),
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL
  );
`);

// Compte admin initial : admin / admin123 (à changer à la première connexion)
const userCount = db.prepare('SELECT COUNT(*) AS c FROM users').get().c;
if (userCount === 0) {
  const hash = bcrypt.hashSync('admin123', 10);
  db.prepare(
    'INSERT INTO users (username, password_hash, role, must_change_password, created_at) VALUES (?,?,?,?,?)'
  ).run('admin', hash, 'admin', 1, new Date().toISOString());
  console.log('Compte initial créé : admin / admin123 (à changer à la première connexion)');
}

// ---------------------------------------------------------------------------
// Utilitaires
// ---------------------------------------------------------------------------
const nowIso = () => new Date().toISOString();

// Jour local (AAAA-MM-JJ) dans le fuseau configuré — sert aux ventes du jour/mois.
function localDay(date = new Date()) {
  return new Intl.DateTimeFormat('en-CA', {
    timeZone: TZ, year: 'numeric', month: '2-digit', day: '2-digit',
  }).format(date);
}

// Échappe le HTML (indispensable : les noms/clients sont saisis par l'utilisateur).
function esc(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

// Monnaie affichée sur les factures (même réglage que dans public/app.js :
// changez ces deux lignes pour changer de monnaie partout).
const CURRENCY_SYMBOL = 'FCFA';
const CURRENCY_DECIMALS = 0;

const money = (n) => {
    const v = Math.round((Number(n) || 0) * 100) / 100;
    return v.toLocaleString('fr-FR', { minimumFractionDigits: CURRENCY_DECIMALS, maximumFractionDigits: CURRENCY_DECIMALS }) + ' ' + CURRENCY_SYMBOL;
};

function parseCookies(req) {
  const out = {};
  (req.headers.cookie || '').split(';').forEach((part) => {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  });
  return out;
}

function publicUser(u) {
  return { id: u.id, username: u.username, role: u.role, mustChangePassword: !!u.must_change_password };
}

// ---------------------------------------------------------------------------
// Authentification (session par cookie httpOnly)
// ---------------------------------------------------------------------------
function auth(req, res, next) {
  const token = parseCookies(req).session;
  if (!token) return res.status(401).json({ error: 'Non connecté.' });
  const row = db.prepare(`
    SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id
    WHERE s.token = ? AND s.expires_at > ?
  `).get(token, nowIso());
  if (!row) return res.status(401).json({ error: 'Session expirée. Reconnectez-vous.' });
  req.user = row;
  next();
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Action réservée à un rôle supérieur.' });
    }
    next();
  };
}

// ---------------------------------------------------------------------------
// Connexion / session
// ---------------------------------------------------------------------------
app.post('/api/login', loginRateLimit, (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Identifiant et mot de passe requis.' });
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(String(username).trim());
  if (!user || !bcrypt.compareSync(String(password), user.password_hash)) {
    recordFailedLogin(req);
    return res.status(401).json({ error: 'Identifiant ou mot de passe incorrect.' });
  }
  recordSuccessfulLogin(req);
  const token = crypto.randomBytes(32).toString('hex');
  const expires = new Date(Date.now() + SESSION_DAYS * 24 * 3600 * 1000).toISOString();
  db.prepare('INSERT INTO sessions (token, user_id, expires_at, created_at) VALUES (?,?,?,?)')
    .run(token, user.id, expires, nowIso());
  res.cookie('session', token, {
    httpOnly: true, path: '/', sameSite: 'lax',
    // En production (Render, HTTPS), le cookie ne voyage que sur HTTPS.
    secure: process.env.NODE_ENV === 'production',
    maxAge: SESSION_DAYS * 24 * 3600 * 1000,
  });
  res.json({ user: publicUser(user) });
});

app.post('/api/logout', auth, (req, res) => {
  db.prepare('DELETE FROM sessions WHERE token = ?').run(parseCookies(req).session);
  res.clearCookie('session', { path: '/' });
  res.json({ ok: true });
});

app.get('/api/me', auth, (req, res) => res.json({ user: publicUser(req.user) }));

app.post('/api/change-password', auth, (req, res) => {
  const { currentPassword, newPassword } = req.body || {};
  if (!newPassword || String(newPassword).length < 6) {
    return res.status(400).json({ error: 'Le nouveau mot de passe doit avoir au moins 6 caractères.' });
  }
  if (!bcrypt.compareSync(String(currentPassword || ''), req.user.password_hash)) {
    return res.status(400).json({ error: 'Le mot de passe actuel est incorrect.' });
  }
  db.prepare('UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?')
    .run(bcrypt.hashSync(String(newPassword), 10), req.user.id);
  res.json({ ok: true });
});

app.get('/api/health', (req, res) => res.json({ ok: true, time: nowIso() }));

// ---------------------------------------------------------------------------
// Utilisateurs (admin seulement)
// ---------------------------------------------------------------------------
app.get('/api/users', auth, requireRole('admin'), (req, res) => {
  const users = db.prepare('SELECT * FROM users ORDER BY username').all().map(publicUser);
  res.json(users);
});

app.post('/api/users', auth, requireRole('admin'), (req, res) => {
  const { username, password, role } = req.body || {};
  if (!username || !password || String(password).length < 6) {
    return res.status(400).json({ error: 'Identifiant et mot de passe (6 caractères min.) requis.' });
  }
  if (!['admin', 'employe', 'lecture'].includes(role)) {
    return res.status(400).json({ error: 'Rôle invalide.' });
  }
  try {
    const r = db.prepare(
      'INSERT INTO users (username, password_hash, role, must_change_password, created_at) VALUES (?,?,?,?,?)'
    ).run(String(username).trim(), bcrypt.hashSync(String(password), 10), role, 0, nowIso());
    res.status(201).json(publicUser(db.prepare('SELECT * FROM users WHERE id = ?').get(r.lastInsertRowid)));
  } catch (e) {
    res.status(400).json({ error: 'Cet identifiant existe déjà.' });
  }
});

app.put('/api/users/:id', auth, requireRole('admin'), (req, res) => {
  const target = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!target) return res.status(404).json({ error: 'Utilisateur introuvable.' });
  const { role, password } = req.body || {};
  if (role && !['admin', 'employe', 'lecture'].includes(role)) {
    return res.status(400).json({ error: 'Rôle invalide.' });
  }
  if (role) db.prepare('UPDATE users SET role = ? WHERE id = ?').run(role, target.id);
  if (password) {
    if (String(password).length < 6) return res.status(400).json({ error: 'Mot de passe trop court (6 caractères min.).' });
    db.prepare('UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?')
      .run(bcrypt.hashSync(String(password), 10), target.id);
  }
  res.json(publicUser(db.prepare('SELECT * FROM users WHERE id = ?').get(target.id)));
});

app.delete('/api/users/:id', auth, requireRole('admin'), (req, res) => {
  const target = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!target) return res.status(404).json({ error: 'Utilisateur introuvable.' });
  if (target.id === req.user.id) return res.status(400).json({ error: 'Vous ne pouvez pas supprimer votre propre compte.' });
  if (target.role === 'admin') {
    const admins = db.prepare("SELECT COUNT(*) AS c FROM users WHERE role = 'admin'").get().c;
    if (admins <= 1) return res.status(400).json({ error: 'Impossible de supprimer le dernier administrateur.' });
  }
  db.prepare('DELETE FROM sessions WHERE user_id = ?').run(target.id);
  db.prepare('DELETE FROM users WHERE id = ?').run(target.id);
  res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// Articles
// ---------------------------------------------------------------------------
app.get('/api/articles', auth, (req, res) => {
  res.json(db.prepare('SELECT * FROM articles ORDER BY name COLLATE NOCASE').all());
});

function validateArticle(b) {
  if (!b.name || !String(b.name).trim()) return 'Le nom de l’article est requis.';
  if (b.price == null || isNaN(Number(b.price)) || Number(b.price) < 0) return 'Le prix de vente doit être un nombre positif.';
  if (b.stock != null && (!Number.isInteger(Number(b.stock)) || Number(b.stock) < 0)) return 'Le stock doit être un nombre entier positif.';
  if (b.low_threshold != null && (!Number.isInteger(Number(b.low_threshold)) || Number(b.low_threshold) < 0)) return 'Le seuil d’alerte doit être un nombre entier positif.';
  if (b.cost_price != null && b.cost_price !== '' && (isNaN(Number(b.cost_price)) || Number(b.cost_price) < 0)) return 'Le prix coûtant doit être un nombre positif.';
  return null;
}

app.post('/api/articles', auth, requireRole('admin'), (req, res) => {
  const b = req.body || {};
  const err = validateArticle(b);
  if (err) return res.status(400).json({ error: err });
  const r = db.prepare(`
    INSERT INTO articles (name, description, photo, price, cost_price, sku, category, stock, low_threshold, created_at)
    VALUES (?,?,?,?,?,?,?,?,?,?)
  `).run(
    String(b.name).trim(), String(b.description || ''), String(b.photo || ''),
    Number(b.price), b.cost_price === '' || b.cost_price == null ? null : Number(b.cost_price),
    String(b.sku || ''), String(b.category || ''),
    Number(b.stock || 0), Number(b.low_threshold ?? 5), nowIso()
  );
  res.status(201).json(db.prepare('SELECT * FROM articles WHERE id = ?').get(r.lastInsertRowid));
});

app.put('/api/articles/:id', auth, requireRole('admin'), (req, res) => {
  const art = db.prepare('SELECT * FROM articles WHERE id = ?').get(req.params.id);
  if (!art) return res.status(404).json({ error: 'Article introuvable.' });
  const b = { ...art, ...(req.body || {}) };
  const err = validateArticle(b);
  if (err) return res.status(400).json({ error: err });
  db.prepare(`
    UPDATE articles SET name=?, description=?, photo=?, price=?, cost_price=?, sku=?, category=?, stock=?, low_threshold=? WHERE id=?
  `).run(
    String(b.name).trim(), String(b.description || ''), String(b.photo || ''),
    Number(b.price), b.cost_price === '' || b.cost_price == null ? null : Number(b.cost_price),
    String(b.sku || ''), String(b.category || ''),
    Number(b.stock), Number(b.low_threshold ?? 5), art.id
  );
  res.json(db.prepare('SELECT * FROM articles WHERE id = ?').get(art.id));
});

app.delete('/api/articles/:id', auth, requireRole('admin'), (req, res) => {
  const art = db.prepare('SELECT * FROM articles WHERE id = ?').get(req.params.id);
  if (!art) return res.status(404).json({ error: 'Article introuvable.' });
  db.prepare('DELETE FROM articles WHERE id = ?').run(art.id);
  res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// Mouvements de stock (entrée / vente / sortie)
// ---------------------------------------------------------------------------
function nextInvoiceNumber() {
  const year = new Date().getFullYear();
  const n = db.prepare("SELECT COUNT(*) AS c FROM invoices WHERE number LIKE ?").get(`FAC-${year}-%`).c;
  return `FAC-${year}-${String(n + 1).padStart(4, '0')}`;
}

function createInvoiceTx({ clientName, clientInfo, taxRate, lines, user }) {
  const subtotal = lines.reduce((s, l) => s + l.quantity * l.unit_price, 0);
  const taxAmount = subtotal * (taxRate / 100);
  const total = subtotal + taxAmount;
  const day = localDay();
  const r = db.prepare(`
    INSERT INTO invoices (number, client_name, client_info, subtotal, tax_rate, tax_amount, total, user_id, username, day, created_at)
    VALUES (?,?,?,?,?,?,?,?,?,?,?)
  `).run(nextInvoiceNumber(), clientName || '', clientInfo || '', subtotal, taxRate, taxAmount, total, user.id, user.username, day, nowIso());
  const invoiceId = r.lastInsertRowid;
  const ins = db.prepare('INSERT INTO invoice_items (invoice_id, article_id, name, quantity, unit_price, total) VALUES (?,?,?,?,?,?)');
  lines.forEach((l) => ins.run(invoiceId, l.article_id || null, l.name, l.quantity, l.unit_price, l.quantity * l.unit_price));
  return db.prepare('SELECT * FROM invoices WHERE id = ?').get(invoiceId);
}

app.post('/api/movements', auth, requireRole('admin', 'employe'), (req, res) => {
  const b = req.body || {};
  const art = db.prepare('SELECT * FROM articles WHERE id = ?').get(b.article_id);
  if (!art) return res.status(404).json({ error: 'Article introuvable.' });
  if (!['entree', 'vente', 'sortie'].includes(b.type)) return res.status(400).json({ error: 'Type de mouvement invalide.' });
  const qty = Number(b.quantity);
  if (!Number.isInteger(qty) || qty <= 0) return res.status(400).json({ error: 'La quantité doit être un entier supérieur à 0.' });
  const unitPrice = b.unit_price != null && b.unit_price !== ''
    ? Number(b.unit_price)
    : (b.type === 'vente' ? art.price : (art.cost_price ?? art.price));
  if (isNaN(unitPrice) || unitPrice < 0) return res.status(400).json({ error: 'Prix unitaire invalide.' });
  if ((b.type === 'vente' || b.type === 'sortie') && art.stock < qty) {
    return res.status(400).json({ error: `Stock insuffisant : il ne reste que ${art.stock} unité(s) de « ${art.name} ».` });
  }
  const total = qty * unitPrice;
  const day = localDay();
  let invoice = null;
  try {
    db.exec('BEGIN');
    const newStock = b.type === 'entree' ? art.stock + qty : art.stock - qty;
    db.prepare('UPDATE articles SET stock = ? WHERE id = ?').run(newStock, art.id);
    const r = db.prepare(`
      INSERT INTO movements (article_id, article_name, type, quantity, unit_price, total, note, user_id, username, day, created_at)
      VALUES (?,?,?,?,?,?,?,?,?,?,?)
    `).run(art.id, art.name, b.type, qty, unitPrice, total, String(b.note || ''), req.user.id, req.user.username, day, nowIso());
    if (b.type === 'vente' && b.generate_invoice) {
      invoice = createInvoiceTx({
        clientName: b.client_name || 'Client comptant', clientInfo: b.client_info || '',
        taxRate: Number(b.tax_rate || 0),
        lines: [{ article_id: art.id, name: art.name, quantity: qty, unit_price: unitPrice }],
        user: req.user,
      });
    }
    db.exec('COMMIT');
    const movement = db.prepare('SELECT * FROM movements WHERE id = ?').get(r.lastInsertRowid);
    res.status(201).json({ movement, stock: newStock, invoice });
  } catch (e) {
    try { db.exec('ROLLBACK'); } catch (_) {}
    res.status(500).json({ error: 'Erreur lors de l’enregistrement du mouvement.' });
  }
});

app.get('/api/movements', auth, (req, res) => {
  const { article_id, type, from, to } = req.query;
  const where = [];
  const params = [];
  if (article_id) { where.push('article_id = ?'); params.push(article_id); }
  if (type) { where.push('type = ?'); params.push(type); }
  if (from) { where.push('day >= ?'); params.push(from); }
  if (to) { where.push('day <= ?'); params.push(to); }
  const sql = `SELECT * FROM movements ${where.length ? 'WHERE ' + where.join(' AND ') : ''} ORDER BY id DESC LIMIT 500`;
  res.json(db.prepare(sql).all(...params));
});

// ---------------------------------------------------------------------------
// Tableau de bord
// ---------------------------------------------------------------------------
app.get('/api/dashboard', auth, (req, res) => {
  const today = localDay();
  const month = today.slice(0, 7);
  const salesToday = db.prepare("SELECT COALESCE(SUM(total),0) AS s FROM movements WHERE type='vente' AND day=?").get(today).s;
  const salesMonth = db.prepare("SELECT COALESCE(SUM(total),0) AS s FROM movements WHERE type='vente' AND substr(day,1,7)=?").get(month).s;
  const stockValue = db.prepare('SELECT COALESCE(SUM(stock*price),0) AS s FROM articles').get().s;
  const lowStock = db.prepare('SELECT * FROM articles WHERE stock > 0 AND stock <= low_threshold ORDER BY stock ASC').all();
  const outOfStock = db.prepare('SELECT * FROM articles WHERE stock = 0 ORDER BY name').all();
  const topSellers = db.prepare(`
    SELECT article_id, article_name, SUM(quantity) AS qty, SUM(total) AS revenue
    FROM movements WHERE type='vente' GROUP BY article_id, article_name ORDER BY qty DESC LIMIT 5
  `).all();
  // Série journalière : 30 derniers jours
  const daily = [];
  for (let i = 29; i >= 0; i--) {
    const d = new Date(Date.now() - i * 86400000);
    const day = localDay(d);
    const s = db.prepare("SELECT COALESCE(SUM(total),0) AS s FROM movements WHERE type='vente' AND day=?").get(day).s;
    daily.push({ day, label: day.slice(5), total: s });
  }
  // Série mensuelle : 12 derniers mois
  const monthly = [];
  const now = new Date();
  for (let i = 11; i >= 0; i--) {
    const d = new Date(now.getFullYear(), now.getMonth() - i, 1);
    const m = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`;
    const s = db.prepare("SELECT COALESCE(SUM(total),0) AS s FROM movements WHERE type='vente' AND substr(day,1,7)=?").get(m).s;
    monthly.push({ month: m, label: m, total: s });
  }
  res.json({
    today, salesToday, salesMonth, stockValue,
    articlesCount: db.prepare('SELECT COUNT(*) AS c FROM articles').get().c,
    lowStock, outOfStock, topSellers, daily, monthly,
  });
});

// ---------------------------------------------------------------------------
// Factures (facultatives — les ventes fonctionnent sans facture)
// ---------------------------------------------------------------------------
app.get('/api/invoices', auth, (req, res) => {
  const list = db.prepare('SELECT * FROM invoices ORDER BY id DESC LIMIT 200').all();
  const items = db.prepare('SELECT * FROM invoice_items').all();
  const byInvoice = {};
  items.forEach((it) => { (byInvoice[it.invoice_id] = byInvoice[it.invoice_id] || []).push(it); });
  res.json(list.map((inv) => ({ ...inv, items: byInvoice[inv.id] || [] })));
});

app.post('/api/invoices', auth, requireRole('admin', 'employe'), (req, res) => {
  const b = req.body || {};
  const lines = Array.isArray(b.lines) ? b.lines : [];
  if (!lines.length) return res.status(400).json({ error: 'La facture doit contenir au moins une ligne.' });
  const taxRate = Number(b.tax_rate || 0);
  if (isNaN(taxRate) || taxRate < 0) return res.status(400).json({ error: 'Taux de taxe invalide.' });
  const prepared = [];
  for (const l of lines) {
    const qty = Number(l.quantity);
    if (!Number.isInteger(qty) || qty <= 0) return res.status(400).json({ error: 'Quantité invalide sur une ligne.' });
    const art = l.article_id ? db.prepare('SELECT * FROM articles WHERE id = ?').get(l.article_id) : null;
    const name = art ? art.name : String(l.name || 'Article');
    const unit = l.unit_price != null && l.unit_price !== '' ? Number(l.unit_price) : (art ? art.price : 0);
    if (isNaN(unit) || unit < 0) return res.status(400).json({ error: 'Prix invalide sur une ligne.' });
    if (b.deduct_stock && art && art.stock < qty) {
      return res.status(400).json({ error: `Stock insuffisant pour « ${name} » : ${art.stock} restant(s).` });
    }
    prepared.push({ article_id: art ? art.id : null, name, quantity: qty, unit_price: unit });
  }
  try {
    db.exec('BEGIN');
    const invoice = createInvoiceTx({
      clientName: b.client_name || '', clientInfo: b.client_info || '',
      taxRate, lines: prepared, user: req.user,
    });
    if (b.deduct_stock) {
      const day = localDay();
      prepared.forEach((l) => {
        if (!l.article_id) return;
        const art = db.prepare('SELECT * FROM articles WHERE id = ?').get(l.article_id);
        db.prepare('UPDATE articles SET stock = ? WHERE id = ?').run(art.stock - l.quantity, art.id);
        db.prepare(`
          INSERT INTO movements (article_id, article_name, type, quantity, unit_price, total, note, user_id, username, day, created_at)
          VALUES (?,?,?,?,?,?,?,?,?,?,?)
        `).run(art.id, art.name, 'vente', l.quantity, l.unit_price, l.quantity * l.unit_price,
          `Facture ${invoice.number}`, req.user.id, req.user.username, day, nowIso());
      });
    }
    db.exec('COMMIT');
    res.status(201).json(invoice);
  } catch (e) {
    try { db.exec('ROLLBACK'); } catch (_) {}
    res.status(500).json({ error: 'Erreur lors de la création de la facture.' });
  }
});

app.get('/api/invoices/:id/html', auth, (req, res) => {
  const inv = db.prepare('SELECT * FROM invoices WHERE id = ?').get(req.params.id);
  if (!inv) return res.status(404).send('Facture introuvable.');
  const items = db.prepare('SELECT * FROM invoice_items WHERE invoice_id = ?').all(inv.id);
  const rows = items.map((it) => `
    <tr><td>${esc(it.name)}</td><td class="num">${it.quantity}</td>
    <td class="num">${money(it.unit_price)}</td><td class="num">${money(it.total)}</td></tr>`).join('');
  res.type('html').send(`<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8">
  <title>Facture ${esc(inv.number)}</title>
  <style>body{font-family:Arial,sans-serif;max-width:700px;margin:40px auto;padding:0 20px;color:#222}
  h1{font-size:24px}table{width:100%;border-collapse:collapse;margin:20px 0}
  th,td{border-bottom:1px solid #ddd;padding:8px;text-align:left}.num{text-align:right}
  .totaux{margin-left:auto;width:260px}.totaux div{display:flex;justify-content:space-between;padding:4px 0}
  .totaux .grand{font-weight:bold;border-top:2px solid #222}
  button{margin-top:20px;padding:10px 18px;font-size:16px;cursor:pointer}
  @media print{button{display:none}}</style></head><body>
  <h1>Facture ${esc(inv.number)}</h1>
  <p>Date : ${esc(inv.day)}<br>Client : ${esc(inv.client_name || '—')}<br>${esc(inv.client_info || '')}</p>
  <table><thead><tr><th>Article</th><th class="num">Qté</th><th class="num">Prix unit.</th><th class="num">Total</th></tr></thead>
  <tbody>${rows}</tbody></table>
  <div class="totaux">
    <div><span>Sous-total</span><span>${money(inv.subtotal)}</span></div>
    <div><span>Taxes (${inv.tax_rate} %)</span><span>${money(inv.tax_amount)}</span></div>
    <div class="grand"><span>Total</span><span>${money(inv.total)}</span></div>
  </div>
  <p>Merci de votre confiance !</p>
  <button onclick="window.print()">🖨️ Imprimer / Enregistrer en PDF</button>
  </body></html>`);
});

// ---------------------------------------------------------------------------
// Sauvegarde : export / import JSON (protège contre la perte de données
// sur les hébergeurs gratuits à disque éphémère)
// ---------------------------------------------------------------------------
app.get('/api/backup/export', auth, (req, res) => {
  const data = {
    version: 1,
    exportedAt: nowIso(),
    users: db.prepare('SELECT * FROM users').all(),
    articles: db.prepare('SELECT * FROM articles').all(),
    movements: db.prepare('SELECT * FROM movements').all(),
    invoices: db.prepare('SELECT * FROM invoices').all(),
    invoice_items: db.prepare('SELECT * FROM invoice_items').all(),
  };
  res.setHeader('Content-Disposition', `attachment; filename="inventaire-sauvegarde-${localDay()}.json"`);
  res.json(data);
});

app.post('/api/backup/import', auth, requireRole('admin'), (req, res) => {
  const d = req.body || {};
  if (!Array.isArray(d.articles) || !Array.isArray(d.users)) {
    return res.status(400).json({ error: 'Fichier de sauvegarde invalide.' });
  }
  try {
    db.exec('BEGIN');
    ['sessions', 'invoice_items', 'invoices', 'movements', 'articles', 'users'].forEach((t) => db.exec(`DELETE FROM ${t}`));
    const insUser = db.prepare('INSERT INTO users (id, username, password_hash, role, must_change_password, created_at) VALUES (?,?,?,?,?,?)');
    d.users.forEach((u) => insUser.run(u.id, u.username, u.password_hash, u.role, u.must_change_password ? 1 : 0, u.created_at || nowIso()));
    const insArt = db.prepare('INSERT INTO articles (id, name, description, photo, price, cost_price, sku, category, stock, low_threshold, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)');
    d.articles.forEach((a) => insArt.run(a.id, a.name, a.description || '', a.photo || '', a.price || 0, a.cost_price ?? null, a.sku || '', a.category || '', a.stock || 0, a.low_threshold ?? 5, a.created_at || nowIso()));
    const insMov = db.prepare('INSERT INTO movements (id, article_id, article_name, type, quantity, unit_price, total, note, user_id, username, day, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)');
    (d.movements || []).forEach((m) => insMov.run(m.id, m.article_id, m.article_name, m.type, m.quantity, m.unit_price || 0, m.total || 0, m.note || '', m.user_id || null, m.username || '', m.day || localDay(), m.created_at || nowIso()));
    const insInv = db.prepare('INSERT INTO invoices (id, number, client_name, client_info, subtotal, tax_rate, tax_amount, total, user_id, username, day, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)');
    (d.invoices || []).forEach((i) => insInv.run(i.id, i.number, i.client_name || '', i.client_info || '', i.subtotal || 0, i.tax_rate || 0, i.tax_amount || 0, i.total || 0, i.user_id || null, i.username || '', i.day || localDay(), i.created_at || nowIso()));
    const insItem = db.prepare('INSERT INTO invoice_items (id, invoice_id, article_id, name, quantity, unit_price, total) VALUES (?,?,?,?,?,?,?)');
    (d.invoice_items || []).forEach((it) => insItem.run(it.id, it.invoice_id, it.article_id || null, it.name, it.quantity, it.unit_price || 0, it.total || 0));
    // Sécurité : s'il n'y a plus aucun admin, on recrée le compte initial.
    const admins = db.prepare("SELECT COUNT(*) AS c FROM users WHERE role = 'admin'").get().c;
    if (admins === 0) {
      db.prepare('INSERT INTO users (username, password_hash, role, must_change_password, created_at) VALUES (?,?,?,?,?)')
        .run('admin', bcrypt.hashSync('admin123', 10), 'admin', 1, nowIso());
    }
    db.exec('COMMIT');
    res.json({ ok: true, restoredAdmin: admins === 0 });
  } catch (e) {
    try { db.exec('ROLLBACK'); } catch (_) {}
    res.status(500).json({ error: 'Import impossible : ' + e.message });
  }
});

// ---------------------------------------------------------------------------
// Interface web (fichiers statiques)
// Le dossier public/ peut se trouver à plusieurs endroits selon la façon dont
// les fichiers ont été téléversés sur l'hébergeur (racine du projet, dossier
// parent, etc.) : on cherche le premier emplacement qui contient index.html.
// ---------------------------------------------------------------------------
const PUBLIC_CANDIDATES = [
  path.join(__dirname, 'public'),
  path.join(__dirname, '..', 'public'),
  path.join(process.cwd(), 'public'),
  path.join(__dirname, 'gestionnaire-inventaire-code', 'public'),
  path.join(process.cwd(), 'gestionnaire-inventaire-code', 'public'),
];
const PUBLIC_DIR = PUBLIC_CANDIDATES.find((d) => fs.existsSync(path.join(d, 'index.html')));
// Copie de secours de l'interface, intégrée dans ce fichier (base64).
// Régénérée à chaque livraison : ne pas modifier à la main.
// EMBEDDED_FRONTEND_START
const EMBEDDED = {"index.html":"PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9ImZyIj4KPGhlYWQ+CjxtZXRhIGNoYXJzZXQ9InV0Zi04Ij4KPG1ldGEgbmFtZT0idmlld3BvcnQiIGNvbnRlbnQ9IndpZHRoPWRldmljZS13aWR0aCwgaW5pdGlhbC1zY2FsZT0xIj4KPHRpdGxlPkdlc3Rpb25uYWlyZSBkJ2ludmVudGFpcmU8L3RpdGxlPgo8bGluayByZWw9InN0eWxlc2hlZXQiIGhyZWY9InN0eWxlLmNzcyI+CjwvaGVhZD4KPGJvZHk+Cgo8IS0tID09PT09PT09PT09PT09PT09PT09IMOJQ1JBTiBERSBDT05ORVhJT04gPT09PT09PT09PT09PT09PT09PT0gLS0+CjxkaXYgaWQ9ImxvZ2luLXZpZXciIGNsYXNzPSJsb2dpbi13cmFwIj4KICA8ZGl2IGNsYXNzPSJsb2dpbi1jYXJkIj4KICAgIDxkaXYgY2xhc3M9ImxvZ28iPvCfk6Y8L2Rpdj4KICAgIDxoMT5HZXN0aW9ubmFpcmUgZCdpbnZlbnRhaXJlPC9oMT4KICAgIDxwIGNsYXNzPSJzdWJ0aXRsZSI+Vm9zIGFydGljbGVzLCB2b3MgdmVudGVzIGV0IHZvdHJlIHN0b2NrIOKAlCBwYXJ0b3V0LCBlbiDDqXF1aXBlLjwvcD4KICAgIDxmb3JtIGlkPSJsb2dpbi1mb3JtIj4KICAgICAgPGxhYmVsPklkZW50aWZpYW50CiAgICAgICAgPGlucHV0IHR5cGU9InRleHQiIGlkPSJsb2dpbi11c2VybmFtZSIgYXV0b2NvbXBsZXRlPSJ1c2VybmFtZSIgcGxhY2Vob2xkZXI9ImV4LiBhZG1pbiIgcmVxdWlyZWQ+CiAgICAgIDwvbGFiZWw+CiAgICAgIDxsYWJlbD5Nb3QgZGUgcGFzc2UKICAgICAgICA8aW5wdXQgdHlwZT0icGFzc3dvcmQiIGlkPSJsb2dpbi1wYXNzd29yZCIgYXV0b2NvbXBsZXRlPSJjdXJyZW50LXBhc3N3b3JkIiBwbGFjZWhvbGRlcj0i4oCi4oCi4oCi4oCi4oCi4oCi4oCi4oCiIiByZXF1aXJlZD4KICAgICAgPC9sYWJlbD4KICAgICAgPHAgaWQ9ImxvZ2luLWVycm9yIiBjbGFzcz0iZXJyb3IiIGhpZGRlbj48L3A+CiAgICAgIDxidXR0b24gdHlwZT0ic3VibWl0IiBjbGFzcz0iYnRuIHByaW1hcnkgYmlnIj5TZSBjb25uZWN0ZXI8L2J1dHRvbj4KICAgIDwvZm9ybT4KICAgIDxwIGNsYXNzPSJoaW50Ij5Db25uZWN0ZXotdm91cyBhdmVjIGxlIGNvbXB0ZSBxdWUgdm90cmUgYWRtaW5pc3RyYXRldXIgdm91cyBhIGNyw6nDqS48L3A+CiAgPC9kaXY+CjwvZGl2PgoKPCEtLSBDaGFuZ2VtZW50IGRlIG1vdCBkZSBwYXNzZSBvYmxpZ2F0b2lyZSAocHJlbWnDqHJlIGNvbm5leGlvbikgLS0+CjxkaXYgaWQ9InBhc3N3b3JkLXZpZXciIGNsYXNzPSJsb2dpbi13cmFwIiBoaWRkZW4+CiAgPGRpdiBjbGFzcz0ibG9naW4tY2FyZCI+CiAgICA8ZGl2IGNsYXNzPSJsb2dvIj7wn5SRPC9kaXY+CiAgICA8aDE+Q2hhbmdleiB2b3RyZSBtb3QgZGUgcGFzc2U8L2gxPgogICAgPHAgY2xhc3M9InN1YnRpdGxlIj5DJ2VzdCB2b3RyZSBwcmVtacOocmUgY29ubmV4aW9uIDogY2hvaXNpc3NleiB1biBtb3QgZGUgcGFzc2UgcGVyc29ubmVsLjwvcD4KICAgIDxmb3JtIGlkPSJwYXNzd29yZC1mb3JtIj4KICAgICAgPGxhYmVsPk1vdCBkZSBwYXNzZSBhY3R1ZWwKICAgICAgICA8aW5wdXQgdHlwZT0icGFzc3dvcmQiIGlkPSJwdy1jdXJyZW50IiBhdXRvY29tcGxldGU9ImN1cnJlbnQtcGFzc3dvcmQiIHJlcXVpcmVkPgogICAgICA8L2xhYmVsPgogICAgICA8bGFiZWw+Tm91dmVhdSBtb3QgZGUgcGFzc2UgKDYgY2FyYWN0w6hyZXMgbWluLikKICAgICAgICA8aW5wdXQgdHlwZT0icGFzc3dvcmQiIGlkPSJwdy1uZXciIGF1dG9jb21wbGV0ZT0ibmV3LXBhc3N3b3JkIiByZXF1aXJlZCBtaW5sZW5ndGg9IjYiPgogICAgICA8L2xhYmVsPgogICAgICA8bGFiZWw+Q29uZmlybWVyIGxlIG5vdXZlYXUgbW90IGRlIHBhc3NlCiAgICAgICAgPGlucHV0IHR5cGU9InBhc3N3b3JkIiBpZD0icHctY29uZmlybSIgYXV0b2NvbXBsZXRlPSJuZXctcGFzc3dvcmQiIHJlcXVpcmVkIG1pbmxlbmd0aD0iNiI+CiAgICAgIDwvbGFiZWw+CiAgICAgIDxwIGlkPSJwdy1lcnJvciIgY2xhc3M9ImVycm9yIiBoaWRkZW4+PC9wPgogICAgICA8YnV0dG9uIHR5cGU9InN1Ym1pdCIgY2xhc3M9ImJ0biBwcmltYXJ5IGJpZyI+RW5yZWdpc3RyZXI8L2J1dHRvbj4KICAgIDwvZm9ybT4KICA8L2Rpdj4KPC9kaXY+Cgo8IS0tID09PT09PT09PT09PT09PT09PT09IEFQUExJQ0FUSU9OID09PT09PT09PT09PT09PT09PT09IC0tPgo8ZGl2IGlkPSJhcHAtdmlldyIgaGlkZGVuPgogIDxoZWFkZXIgY2xhc3M9InRvcGJhciI+CiAgICA8ZGl2IGNsYXNzPSJicmFuZCI+8J+TpiA8c3Bhbj5JbnZlbnRhaXJlPC9zcGFuPjwvZGl2PgogICAgPGRpdiBjbGFzcz0idXNlcmJveCI+CiAgICAgIDxzcGFuIGlkPSJ1c2VyLWNoaXAiIGNsYXNzPSJjaGlwIj48L3NwYW4+CiAgICAgIDxidXR0b24gaWQ9ImxvZ291dC1idG4iIGNsYXNzPSJidG4gc21hbGwiPkTDqWNvbm5leGlvbjwvYnV0dG9uPgogICAgPC9kaXY+CiAgPC9oZWFkZXI+CgogIDxuYXYgY2xhc3M9InRhYnMiIGlkPSJ0YWJzIj4KICAgIDxidXR0b24gZGF0YS10YWI9ImRhc2hib2FyZCIgY2xhc3M9ImFjdGl2ZSI+8J+PoCBUYWJsZWF1IGRlIGJvcmQ8L2J1dHRvbj4KICAgIDxidXR0b24gZGF0YS10YWI9ImFydGljbGVzIj7wn5OmIEFydGljbGVzPC9idXR0b24+CiAgICA8YnV0dG9uIGRhdGEtdGFiPSJoaXN0b3J5Ij7wn5WRIEhpc3RvcmlxdWU8L2J1dHRvbj4KICAgIDxidXR0b24gZGF0YS10YWI9Imludm9pY2VzIj7wn6e+IEZhY3R1cmVzPC9idXR0b24+CiAgICA8YnV0dG9uIGRhdGEtdGFiPSJ0ZWFtIiBpZD0idGFiLXRlYW0tYnRuIj7wn5GlIMOJcXVpcGUgJmFtcDsgcsO0bGVzPC9idXR0b24+CiAgICA8YnV0dG9uIGRhdGEtdGFiPSJiYWNrdXAiPvCfkr4gU2F1dmVnYXJkZTwvYnV0dG9uPgogIDwvbmF2PgoKICA8bWFpbj4KICAgIDwhLS0gLS0tLS0gVGFibGVhdSBkZSBib3JkIC0tLS0tIC0tPgogICAgPHNlY3Rpb24gaWQ9InRhYi1kYXNoYm9hcmQiIGNsYXNzPSJ0YWItcGFnZSI+CiAgICAgIDxkaXYgY2xhc3M9Imhlcm8iPgogICAgICAgIDxkaXYgY2xhc3M9Imhlcm8tdGV4dCI+CiAgICAgICAgICA8aDIgaWQ9IndlbGNvbWUtdGl0bGUiPkJvbmpvdXIg8J+RizwvaDI+CiAgICAgICAgICA8cCBjbGFzcz0ibXV0ZWQiPlZvaWNpIGwnw6l0YXQgZGUgdm90cmUgaW52ZW50YWlyZSBhdWpvdXJkJ2h1aS48L3A+CiAgICAgICAgPC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0icXVpY2stYWN0aW9ucyI+CiAgICAgICAgICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgY2xhc3M9ImJ0biBwcmltYXJ5IiBvbmNsaWNrPSJvcGVuQXJ0aWNsZUZvcm0obnVsbCkiPu+8iyBOb3V2ZWwgYXJ0aWNsZTwvYnV0dG9uPgogICAgICAgICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJidG4iIG9uY2xpY2s9ImRvY3VtZW50LnF1ZXJ5U2VsZWN0b3IoJ1tkYXRhLXRhYj1oaXN0b3J5XScpLmNsaWNrKCkiPvCflZEgSGlzdG9yaXF1ZTwvYnV0dG9uPgogICAgICAgICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJidG4iIG9uY2xpY2s9ImRvY3VtZW50LnF1ZXJ5U2VsZWN0b3IoJ1tkYXRhLXRhYj1pbnZvaWNlc10nKS5jbGljaygpO2RvY3VtZW50LmdldEVsZW1lbnRCeUlkKCduZXctaW52b2ljZS1idG4nKS5jbGljaygpIj7wn6e+IE5vdXZlbGxlIGZhY3R1cmU8L2J1dHRvbj4KICAgICAgICA8L2Rpdj4KICAgICAgPC9kaXY+CgogICAgICA8ZGl2IGlkPSJhbGVydHMtYm94Ij48L2Rpdj4KCiAgICAgIDxkaXYgY2xhc3M9ImtwaXMiPgogICAgICAgIDxkaXYgY2xhc3M9ImtwaSI+PHNwYW4gY2xhc3M9ImtwaS1sYWJlbCI+VmVudGVzIGR1IGpvdXI8L3NwYW4+PHNwYW4gY2xhc3M9ImtwaS12YWx1ZSIgaWQ9ImtwaS10b2RheSI+4oCUPC9zcGFuPjwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9ImtwaSI+PHNwYW4gY2xhc3M9ImtwaS1sYWJlbCI+VmVudGVzIGR1IG1vaXM8L3NwYW4+PHNwYW4gY2xhc3M9ImtwaS12YWx1ZSIgaWQ9ImtwaS1tb250aCI+4oCUPC9zcGFuPjwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9ImtwaSI+PHNwYW4gY2xhc3M9ImtwaS1sYWJlbCI+VmFsZXVyIGR1IHN0b2NrPC9zcGFuPjxzcGFuIGNsYXNzPSJrcGktdmFsdWUiIGlkPSJrcGktc3RvY2siPuKAlDwvc3Bhbj48L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJrcGkiPjxzcGFuIGNsYXNzPSJrcGktbGFiZWwiPkFydGljbGVzPC9zcGFuPjxzcGFuIGNsYXNzPSJrcGktdmFsdWUiIGlkPSJrcGktY291bnQiPuKAlDwvc3Bhbj48L2Rpdj4KICAgICAgPC9kaXY+CgogICAgICA8ZGl2IGNsYXNzPSJjYXJkIj4KICAgICAgICA8ZGl2IGNsYXNzPSJjYXJkLWhlYWQiPgogICAgICAgICAgPGgzPvCfk4ogVmVudGVzPC9oMz4KICAgICAgICAgIDxkaXYgY2xhc3M9InNlZyI+CiAgICAgICAgICAgIDxidXR0b24gaWQ9ImNoYXJ0LWRhaWx5IiBjbGFzcz0iYWN0aXZlIj5Kb3VybmFsaWVyICgzMCBqKTwvYnV0dG9uPgogICAgICAgICAgICA8YnV0dG9uIGlkPSJjaGFydC1tb250aGx5Ij5NZW5zdWVsICgxMiBtb2lzKTwvYnV0dG9uPgogICAgICAgICAgPC9kaXY+CiAgICAgICAgPC9kaXY+CiAgICAgICAgPGNhbnZhcyBpZD0iY2hhcnQiIGhlaWdodD0iMTgwIj48L2NhbnZhcz4KICAgICAgPC9kaXY+CgogICAgICA8ZGl2IGNsYXNzPSJncmlkMiI+CiAgICAgICAgPGRpdiBjbGFzcz0iY2FyZCI+CiAgICAgICAgICA8aDM+8J+PhiBBcnRpY2xlcyBsZXMgcGx1cyB2ZW5kdXM8L2gzPgogICAgICAgICAgPHVsIGlkPSJ0b3Atc2VsbGVycyIgY2xhc3M9Imxpc3QiPjwvdWw+CiAgICAgICAgPC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0iY2FyZCI+CiAgICAgICAgICA8aDM+8J+VkSBEZXJuaWVycyBtb3V2ZW1lbnRzPC9oMz4KICAgICAgICAgIDx1bCBpZD0icmVjZW50LW1vdmVtZW50cyIgY2xhc3M9Imxpc3QiPjwvdWw+CiAgICAgICAgPC9kaXY+CiAgICAgIDwvZGl2PgogICAgPC9zZWN0aW9uPgoKICAgIDwhLS0gLS0tLS0gQXJ0aWNsZXMgLS0tLS0gLS0+CiAgICA8c2VjdGlvbiBpZD0idGFiLWFydGljbGVzIiBjbGFzcz0idGFiLXBhZ2UiIGhpZGRlbj4KICAgICAgPGRpdiBjbGFzcz0icGFnZS1oZWFkIj4KICAgICAgICA8ZGl2PgogICAgICAgICAgPGgyPkFydGljbGVzPC9oMj4KICAgICAgICAgIDxwIGNsYXNzPSJtdXRlZCI+QWpvdXRleiB1biBhcnRpY2xlIGVuIDMgw6l0YXBlcyA6IHBob3RvLCBub20gZXQgZGVzY3JpcHRpb24sIHB1aXMgcHJpeCBldCBzdG9jay48L3A+CiAgICAgICAgPC9kaXY+CiAgICAgICAgPGJ1dHRvbiBpZD0ibmV3LWFydGljbGUtYnRuIiBjbGFzcz0iYnRuIHByaW1hcnkiPu+8iyBOb3V2ZWwgYXJ0aWNsZTwvYnV0dG9uPgogICAgICA8L2Rpdj4KCiAgICAgIDxkaXYgY2xhc3M9InNlYXJjaC1yb3ciPgogICAgICAgIDxpbnB1dCB0eXBlPSJzZWFyY2giIGlkPSJhcnRpY2xlLXNlYXJjaCIgcGxhY2Vob2xkZXI9IvCflI0gUmVjaGVyY2hlciB1biBhcnRpY2xl4oCmIj4KICAgICAgICA8c2VsZWN0IGlkPSJhcnRpY2xlLWZpbHRlciI+CiAgICAgICAgICA8b3B0aW9uIHZhbHVlPSIiPlRvdXRlcyBsZXMgY2F0w6lnb3JpZXM8L29wdGlvbj4KICAgICAgICA8L3NlbGVjdD4KICAgICAgPC9kaXY+CgogICAgICA8ZGl2IGlkPSJhcnRpY2xlcy1ncmlkIiBjbGFzcz0iYXJ0aWNsZXMtZ3JpZCI+PC9kaXY+CiAgICA8L3NlY3Rpb24+CgogICAgPCEtLSAtLS0tLSBIaXN0b3JpcXVlIC0tLS0tIC0tPgogICAgPHNlY3Rpb24gaWQ9InRhYi1oaXN0b3J5IiBjbGFzcz0idGFiLXBhZ2UiIGhpZGRlbj4KICAgICAgPGgyPkhpc3RvcmlxdWUgZGVzIG1vdXZlbWVudHM8L2gyPgogICAgICA8cCBjbGFzcz0ibXV0ZWQiPlRvdXRlcyBsZXMgZW50csOpZXMsIHZlbnRlcyBldCBzb3J0aWVzIDogcXVpIGEgZmFpdCBxdW9pLCBxdWFuZCwgw6AgY29tYmllbiwgZXQgY29tYmllbiBpbCByZXN0ZS48L3A+CiAgICAgIDxkaXYgY2xhc3M9ImNhcmQiPgogICAgICAgIDxkaXYgY2xhc3M9ImZpbHRlcnMiPgogICAgICAgICAgPHNlbGVjdCBpZD0iaGlzdC10eXBlIj4KICAgICAgICAgICAgPG9wdGlvbiB2YWx1ZT0iIj5Ub3VzIGxlcyB0eXBlczwvb3B0aW9uPgogICAgICAgICAgICA8b3B0aW9uIHZhbHVlPSJlbnRyZWUiPkVudHLDqWVzPC9vcHRpb24+CiAgICAgICAgICAgIDxvcHRpb24gdmFsdWU9InZlbnRlIj5WZW50ZXM8L29wdGlvbj4KICAgICAgICAgICAgPG9wdGlvbiB2YWx1ZT0ic29ydGllIj5Tb3J0aWVzPC9vcHRpb24+CiAgICAgICAgICA8L3NlbGVjdD4KICAgICAgICAgIDxpbnB1dCB0eXBlPSJkYXRlIiBpZD0iaGlzdC1mcm9tIiB0aXRsZT0iRHUiPgogICAgICAgICAgPGlucHV0IHR5cGU9ImRhdGUiIGlkPSJoaXN0LXRvIiB0aXRsZT0iQXUiPgogICAgICAgICAgPGJ1dHRvbiBpZD0iaGlzdC1hcHBseSIgY2xhc3M9ImJ0biBzbWFsbCI+RmlsdHJlcjwvYnV0dG9uPgogICAgICAgIDwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9InRhYmxlLXdyYXAiPgogICAgICAgICAgPHRhYmxlPgogICAgICAgICAgICA8dGhlYWQ+PHRyPjx0aD5EYXRlPC90aD48dGg+QXJ0aWNsZTwvdGg+PHRoPlR5cGU8L3RoPjx0aD5RdMOpPC90aD48dGg+UHJpeCB1bml0LjwvdGg+PHRoPlRvdGFsPC90aD48dGg+UGFyPC90aD48dGg+Tm90ZTwvdGg+PC90cj48L3RoZWFkPgogICAgICAgICAgICA8dGJvZHkgaWQ9Imhpc3RvcnktYm9keSI+PC90Ym9keT4KICAgICAgICAgIDwvdGFibGU+CiAgICAgICAgPC9kaXY+CiAgICAgIDwvZGl2PgogICAgPC9zZWN0aW9uPgoKICAgIDwhLS0gLS0tLS0gRmFjdHVyZXMgLS0tLS0gLS0+CiAgICA8c2VjdGlvbiBpZD0idGFiLWludm9pY2VzIiBjbGFzcz0idGFiLXBhZ2UiIGhpZGRlbj4KICAgICAgPGRpdiBjbGFzcz0icGFnZS1oZWFkIj4KICAgICAgICA8ZGl2PgogICAgICAgICAgPGgyPkZhY3R1cmVzPC9oMj4KICAgICAgICAgIDxwIGNsYXNzPSJtdXRlZCI+TGEgZmFjdHVyZSBlc3QgPGI+ZmFjdWx0YXRpdmU8L2I+IDogdm91cyBwb3V2ZXogdmVuZHJlIHNhbnMgZW4gY3LDqWVyLiBDcsOpZXotZW4gdW5lIGljaSBxdWFuZCB1biBjbGllbnQgZW4gZGVtYW5kZSB1bmUuPC9wPgogICAgICAgIDwvZGl2PgogICAgICAgIDxidXR0b24gaWQ9Im5ldy1pbnZvaWNlLWJ0biIgY2xhc3M9ImJ0biBwcmltYXJ5Ij7vvIsgTm91dmVsbGUgZmFjdHVyZTwvYnV0dG9uPgogICAgICA8L2Rpdj4KICAgICAgPGRpdiBpZD0iaW52b2ljZXMtbGlzdCI+PC9kaXY+CiAgICA8L3NlY3Rpb24+CgogICAgPCEtLSAtLS0tLSDDiXF1aXBlICYgcsO0bGVzIC0tLS0tIC0tPgogICAgPHNlY3Rpb24gaWQ9InRhYi10ZWFtIiBjbGFzcz0idGFiLXBhZ2UiIGhpZGRlbj4KICAgICAgPGgyPsOJcXVpcGUgJmFtcDsgcsO0bGVzPC9oMj4KICAgICAgPHAgY2xhc3M9Im11dGVkIj5TZXVsIGwnYWRtaW5pc3RyYXRldXIgZ8OocmUgbGVzIGNvbXB0ZXMuPC9wPgogICAgICA8ZGl2IGNsYXNzPSJjYXJkIj4KICAgICAgICA8aDM+8J+RpCBBam91dGVyIHVuIHV0aWxpc2F0ZXVyPC9oMz4KICAgICAgICA8Zm9ybSBpZD0idXNlci1mb3JtIiBjbGFzcz0iZm9ybS1ncmlkIj4KICAgICAgICAgIDxsYWJlbD5JZGVudGlmaWFudCA8aW5wdXQgdHlwZT0idGV4dCIgaWQ9InVzZXItbmFtZSIgcmVxdWlyZWQgcGxhY2Vob2xkZXI9ImV4LiBtYXJpZSI+PC9sYWJlbD4KICAgICAgICAgIDxsYWJlbD5Nb3QgZGUgcGFzc2UgPGlucHV0IHR5cGU9InBhc3N3b3JkIiBpZD0idXNlci1wYXNzIiByZXF1aXJlZCBtaW5sZW5ndGg9IjYiIHBsYWNlaG9sZGVyPSI2IGNhcmFjdMOocmVzIG1pbi4iPjwvbGFiZWw+CiAgICAgICAgICA8bGFiZWw+UsO0bGUKICAgICAgICAgICAgPHNlbGVjdCBpZD0idXNlci1yb2xlIj4KICAgICAgICAgICAgICA8b3B0aW9uIHZhbHVlPSJlbXBsb3llIj5FbXBsb3nDqSDigJQgdmVuZCwgZmFjdHVyZSwgZ8OocmUgbGUgc3RvY2s8L29wdGlvbj4KICAgICAgICAgICAgICA8b3B0aW9uIHZhbHVlPSJhZG1pbiI+QWRtaW4g4oCUIHRvdXQsIHkgY29tcHJpcyBjYXRhbG9ndWUgZXQgdXRpbGlzYXRldXJzPC9vcHRpb24+CiAgICAgICAgICAgICAgPG9wdGlvbiB2YWx1ZT0ibGVjdHVyZSI+TGVjdHVyZSBzZXVsZSDigJQgY29uc3VsdGUgc2V1bGVtZW50PC9vcHRpb24+CiAgICAgICAgICAgIDwvc2VsZWN0PgogICAgICAgICAgPC9sYWJlbD4KICAgICAgICAgIDxidXR0b24gdHlwZT0ic3VibWl0IiBjbGFzcz0iYnRuIHByaW1hcnkiPkNyw6llciBsJ3V0aWxpc2F0ZXVyPC9idXR0b24+CiAgICAgICAgPC9mb3JtPgogICAgICA8L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0iY2FyZCI+CiAgICAgICAgPGgzPvCfkaUgTWVtYnJlcyBkZSBsJ8OpcXVpcGU8L2gzPgogICAgICAgIDx1bCBpZD0idXNlcnMtbGlzdCIgY2xhc3M9Imxpc3QiPjwvdWw+CiAgICAgIDwvZGl2PgogICAgICA8ZGl2IGNsYXNzPSJjYXJkIj4KICAgICAgICA8aDM+8J+UkCBSw7RsZXMgZXhwbGlxdcOpczwvaDM+CiAgICAgICAgPHVsIGNsYXNzPSJsaXN0Ij4KICAgICAgICAgIDxsaT48Yj5BZG1pbjwvYj4gOiBnw6hyZSBsZSBjYXRhbG9ndWUsIGxlcyBwcml4LCBsZXMgcGhvdG9zIGV0IGxlcyB1dGlsaXNhdGV1cnMuPC9saT4KICAgICAgICAgIDxsaT48Yj5FbXBsb3nDqTwvYj4gOiBlbnJlZ2lzdHJlIGxlcyB2ZW50ZXMgZXQgbGVzIGVudHLDqWVzL3NvcnRpZXMsIGNyw6llIGRlcyBmYWN0dXJlcy48L2xpPgogICAgICAgICAgPGxpPjxiPkxlY3R1cmUgc2V1bGU8L2I+IDogY29uc3VsdGUgbGUgdGFibGVhdSBkZSBib3JkIGV0IGxlcyBhcnRpY2xlcywgbmUgbW9kaWZpZSByaWVuLjwvbGk+CiAgICAgICAgPC91bD4KICAgICAgPC9kaXY+CiAgICA8L3NlY3Rpb24+CgogICAgPCEtLSAtLS0tLSBTYXV2ZWdhcmRlIC0tLS0tIC0tPgogICAgPHNlY3Rpb24gaWQ9InRhYi1iYWNrdXAiIGNsYXNzPSJ0YWItcGFnZSIgaGlkZGVuPgogICAgICA8aDI+U2F1dmVnYXJkZTwvaDI+CiAgICAgIDxwIGNsYXNzPSJtdXRlZCI+U3VyIHVuIGjDqWJlcmdldXIgZ3JhdHVpdCwgbGVzIGRvbm7DqWVzIHBldXZlbnQgw6p0cmUgZWZmYWPDqWVzIHNpIGxlIHNlcnZpY2UgZG9ydCB0cm9wIGxvbmd0ZW1wcy4KICAgICAgRXhwb3J0ZXogcsOpZ3VsacOocmVtZW50IHVuZSBjb3BpZSBkZSB2b3MgZG9ubsOpZXMgZXQgZ2FyZGV6LWxhIHByw6ljaWV1c2VtZW50LjwvcD4KICAgICAgPGRpdiBjbGFzcz0iY2FyZCI+CiAgICAgICAgPGgzPvCfkr4gRXhwb3J0ZXIgbWVzIGRvbm7DqWVzPC9oMz4KICAgICAgICA8cD5Uw6lsw6ljaGFyZ2UgdW4gZmljaGllciBKU09OIGF2ZWMgdG91cyB2b3MgYXJ0aWNsZXMsIG1vdXZlbWVudHMsIGZhY3R1cmVzIGV0IHV0aWxpc2F0ZXVycy48L3A+CiAgICAgICAgPGJ1dHRvbiBpZD0iZXhwb3J0LWJ0biIgY2xhc3M9ImJ0biBwcmltYXJ5Ij7irIfvuI8gRXhwb3J0ZXIgZW4gSlNPTjwvYnV0dG9uPgogICAgICA8L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0iY2FyZCI+CiAgICAgICAgPGgzPvCfk6UgUmVzdGF1cmVyIHVuZSBzYXV2ZWdhcmRlPC9oMz4KICAgICAgICA8cD5DaG9pc2lzc2V6IHVuIGZpY2hpZXIgSlNPTiBleHBvcnTDqSBwcsOpY8OpZGVtbWVudC4gPGI+QXR0ZW50aW9uIDo8L2I+IGxlcyBkb25uw6llcyBhY3R1ZWxsZXMgc2Vyb250IHJlbXBsYWPDqWVzLjwvcD4KICAgICAgICA8aW5wdXQgdHlwZT0iZmlsZSIgaWQ9ImltcG9ydC1maWxlIiBhY2NlcHQ9ImFwcGxpY2F0aW9uL2pzb24iPgogICAgICAgIDxidXR0b24gaWQ9ImltcG9ydC1idG4iIGNsYXNzPSJidG4iPlJlc3RhdXJlciBjZXR0ZSBzYXV2ZWdhcmRlPC9idXR0b24+CiAgICAgICAgPHAgaWQ9ImltcG9ydC1tc2ciIGNsYXNzPSJtdXRlZCI+PC9wPgogICAgICA8L2Rpdj4KICAgIDwvc2VjdGlvbj4KICA8L21haW4+CjwvZGl2PgoKPCEtLSA9PT09PT09PT09PT09PT09PT09PSBGRU7DilRSRVMgKG1vZGFsZXMpID09PT09PT09PT09PT09PT09PT09IC0tPgo8ZGl2IGlkPSJtb2RhbC1iYWNrZHJvcCIgY2xhc3M9Im1vZGFsLWJhY2tkcm9wIiBoaWRkZW4+CiAgPGRpdiBjbGFzcz0ibW9kYWwiIHJvbGU9ImRpYWxvZyIgYXJpYS1tb2RhbD0idHJ1ZSI+CiAgICA8YnV0dG9uIGNsYXNzPSJtb2RhbC1jbG9zZSIgaWQ9Im1vZGFsLWNsb3NlIj7inJU8L2J1dHRvbj4KICAgIDxkaXYgaWQ9Im1vZGFsLWNvbnRlbnQiPjwvZGl2PgogIDwvZGl2Pgo8L2Rpdj4KCjxkaXYgaWQ9InRvYXN0IiBjbGFzcz0idG9hc3QiIGhpZGRlbj48L2Rpdj4KCjxzY3JpcHQgc3JjPSJhcHAuanMiPjwvc2NyaXB0Pgo8L2JvZHk+CjwvaHRtbD4K","app.js":"Ly8gPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PQovLyBHZXN0aW9ubmFpcmUgZCdpbnZlbnRhaXJlIOKAlCBpbnRlcmZhY2UgKHZhbmlsbGEgSlMsIGF1Y3VuZSBkw6lwZW5kYW5jZSkKLy8gPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PQpjb25zdCAkID0gKHMpID0+IGRvY3VtZW50LnF1ZXJ5U2VsZWN0b3Iocyk7CmNvbnN0ICQkID0gKHMpID0+IGRvY3VtZW50LnF1ZXJ5U2VsZWN0b3JBbGwocyk7Cgpjb25zdCBzdGF0ZSA9IHsKICB1c2VyOiBudWxsLAogIGFydGljbGVzOiBbXSwKICBkYXNoYm9hcmQ6IG51bGwsCiAgY2hhcnRNb2RlOiAnZGFpbHknLAp9OwoKY29uc3QgUk9MRV9MQUJFTCA9IHsgYWRtaW46ICdBZG1pbicsIGVtcGxveWU6ICdFbXBsb3nDqScsIGxlY3R1cmU6ICdMZWN0dXJlIHNldWxlJyB9Owpjb25zdCBUWVBFX0xBQkVMID0geyBlbnRyZWU6ICdFbnRyw6llJywgdmVudGU6ICdWZW50ZScsIHNvcnRpZTogJ1NvcnRpZScgfTsKCmZ1bmN0aW9uIG1vbmV5KG4pIHsgcmV0dXJuIChNYXRoLnJvdW5kKChOdW1iZXIobikgfHwgMCkgKiAxMDApIC8gMTAwKS50b0ZpeGVkKDIpICsgJyAkJzsgfQpmdW5jdGlvbiBlc2MocykgewogIHJldHVybiBTdHJpbmcocyA/PyAnJykucmVwbGFjZSgvJi9nLCAnJmFtcDsnKS5yZXBsYWNlKC88L2csICcmbHQ7JykucmVwbGFjZSgvPi9nLCAnJmd0OycpCiAgICAucmVwbGFjZSgvIi9nLCAnJnF1b3Q7JykucmVwbGFjZSgvJy9nLCAnJiMzOTsnKTsKfQpmdW5jdGlvbiB0b2FzdChtc2cpIHsKICBjb25zdCB0ID0gJCgnI3RvYXN0Jyk7CiAgdC50ZXh0Q29udGVudCA9IG1zZzsKICB0LmhpZGRlbiA9IGZhbHNlOwogIGNsZWFyVGltZW91dCh0Ll90aW1lcik7CiAgdC5fdGltZXIgPSBzZXRUaW1lb3V0KCgpID0+IHsgdC5oaWRkZW4gPSB0cnVlOyB9LCAzNTAwKTsKfQpmdW5jdGlvbiBzaG93RXJyb3IoZWwsIG1zZykgeyBlbC50ZXh0Q29udGVudCA9IG1zZzsgZWwuaGlkZGVuID0gZmFsc2U7IH0KCmFzeW5jIGZ1bmN0aW9uIGFwaShwYXRoLCBvcHRzID0ge30pIHsKICBjb25zdCByZXMgPSBhd2FpdCBmZXRjaChwYXRoLCB7CiAgICAuLi5vcHRzLAogICAgaGVhZGVyczogeyAnQ29udGVudC1UeXBlJzogJ2FwcGxpY2F0aW9uL2pzb24nLCAuLi4ob3B0cy5oZWFkZXJzIHx8IHt9KSB9LAogIH0pOwogIGNvbnN0IGRhdGEgPSBhd2FpdCByZXMuanNvbigpLmNhdGNoKCgpID0+ICh7fSkpOwogIGlmICghcmVzLm9rKSB0aHJvdyBuZXcgRXJyb3IoZGF0YS5lcnJvciB8fCAnRXJyZXVyIHNlcnZldXIuJyk7CiAgcmV0dXJuIGRhdGE7Cn0KCi8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQovLyBNb2RhbGUKLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCmZ1bmN0aW9uIG9wZW5Nb2RhbChodG1sKSB7CiAgJCgnI21vZGFsLWNvbnRlbnQnKS5pbm5lckhUTUwgPSBodG1sOwogICQoJyNtb2RhbC1iYWNrZHJvcCcpLmhpZGRlbiA9IGZhbHNlOwp9CmZ1bmN0aW9uIGNsb3NlTW9kYWwoKSB7CiAgJCgnI21vZGFsLWJhY2tkcm9wJykuaGlkZGVuID0gdHJ1ZTsKICAkKCcjbW9kYWwtY29udGVudCcpLmlubmVySFRNTCA9ICcnOwp9CiQoJyNtb2RhbC1jbG9zZScpLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgY2xvc2VNb2RhbCk7CiQoJyNtb2RhbC1iYWNrZHJvcCcpLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKGUpID0+IHsgaWYgKGUudGFyZ2V0LmlkID09PSAnbW9kYWwtYmFja2Ryb3AnKSBjbG9zZU1vZGFsKCk7IH0pOwoKLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCi8vIEF1dGhlbnRpZmljYXRpb24KLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCmFzeW5jIGZ1bmN0aW9uIGNoZWNrU2Vzc2lvbigpIHsKICB0cnkgewogICAgY29uc3QgeyB1c2VyIH0gPSBhd2FpdCBhcGkoJy9hcGkvbWUnKTsKICAgIGVudGVyQXBwKHVzZXIpOwogIH0gY2F0Y2ggKF8pIHsKICAgIHNob3dWaWV3KCdsb2dpbicpOwogIH0KfQoKZnVuY3Rpb24gc2hvd1ZpZXcobmFtZSkgewogICQoJyNsb2dpbi12aWV3JykuaGlkZGVuID0gbmFtZSAhPT0gJ2xvZ2luJzsKICAkKCcjcGFzc3dvcmQtdmlldycpLmhpZGRlbiA9IG5hbWUgIT09ICdwYXNzd29yZCc7CiAgJCgnI2FwcC12aWV3JykuaGlkZGVuID0gbmFtZSAhPT0gJ2FwcCc7Cn0KCmZ1bmN0aW9uIGVudGVyQXBwKHVzZXIpIHsKICBzdGF0ZS51c2VyID0gdXNlcjsKICBpZiAodXNlci5tdXN0Q2hhbmdlUGFzc3dvcmQpIHsgc2hvd1ZpZXcoJ3Bhc3N3b3JkJyk7IHJldHVybjsgfQogIHNob3dWaWV3KCdhcHAnKTsKICAkKCcjdXNlci1jaGlwJykudGV4dENvbnRlbnQgPSBgJHt1c2VyLnVzZXJuYW1lfSDCtyAke1JPTEVfTEFCRUxbdXNlci5yb2xlXX1gOwogICQoJyN0YWItdGVhbS1idG4nKS5zdHlsZS5kaXNwbGF5ID0gdXNlci5yb2xlID09PSAnYWRtaW4nID8gJycgOiAnbm9uZSc7CiAgJCgnI25ldy1hcnRpY2xlLWJ0bicpLnN0eWxlLmRpc3BsYXkgPSB1c2VyLnJvbGUgPT09ICdhZG1pbicgPyAnJyA6ICdub25lJzsKICAkKCcjd2VsY29tZS10aXRsZScpLnRleHRDb250ZW50ID0gYEJvbmpvdXIgJHt1c2VyLnVzZXJuYW1lfSDwn5GLYDsKICBsb2FkRGFzaGJvYXJkKCk7CiAgbG9hZEFydGljbGVzKCk7CiAgbG9hZEludm9pY2VzKCk7CiAgaWYgKHVzZXIucm9sZSA9PT0gJ2FkbWluJykgbG9hZFVzZXJzKCk7Cn0KCiQoJyNsb2dpbi1mb3JtJykuYWRkRXZlbnRMaXN0ZW5lcignc3VibWl0JywgYXN5bmMgKGUpID0+IHsKICBlLnByZXZlbnREZWZhdWx0KCk7CiAgY29uc3QgZXJyID0gJCgnI2xvZ2luLWVycm9yJyk7CiAgZXJyLmhpZGRlbiA9IHRydWU7CiAgdHJ5IHsKICAgIGNvbnN0IHsgdXNlciB9ID0gYXdhaXQgYXBpKCcvYXBpL2xvZ2luJywgewogICAgICBtZXRob2Q6ICdQT1NUJywKICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoewogICAgICAgIHVzZXJuYW1lOiAkKCcjbG9naW4tdXNlcm5hbWUnKS52YWx1ZS50cmltKCksCiAgICAgICAgcGFzc3dvcmQ6ICQoJyNsb2dpbi1wYXNzd29yZCcpLnZhbHVlLAogICAgICB9KSwKICAgIH0pOwogICAgZW50ZXJBcHAodXNlcik7CiAgfSBjYXRjaCAoZXgpIHsgc2hvd0Vycm9yKGVyciwgZXgubWVzc2FnZSk7IH0KfSk7CgokKCcjcGFzc3dvcmQtZm9ybScpLmFkZEV2ZW50TGlzdGVuZXIoJ3N1Ym1pdCcsIGFzeW5jIChlKSA9PiB7CiAgZS5wcmV2ZW50RGVmYXVsdCgpOwogIGNvbnN0IGVyciA9ICQoJyNwdy1lcnJvcicpOwogIGVyci5oaWRkZW4gPSB0cnVlOwogIGNvbnN0IG53ID0gJCgnI3B3LW5ldycpLnZhbHVlOwogIGlmIChudyAhPT0gJCgnI3B3LWNvbmZpcm0nKS52YWx1ZSkgcmV0dXJuIHNob3dFcnJvcihlcnIsICdMZXMgZGV1eCBub3V2ZWF1eCBtb3RzIGRlIHBhc3NlIG5lIGNvcnJlc3BvbmRlbnQgcGFzLicpOwogIHRyeSB7CiAgICBhd2FpdCBhcGkoJy9hcGkvY2hhbmdlLXBhc3N3b3JkJywgewogICAgICBtZXRob2Q6ICdQT1NUJywKICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoeyBjdXJyZW50UGFzc3dvcmQ6ICQoJyNwdy1jdXJyZW50JykudmFsdWUsIG5ld1Bhc3N3b3JkOiBudyB9KSwKICAgIH0pOwogICAgdG9hc3QoJ01vdCBkZSBwYXNzZSBjaGFuZ8OpLiBCaWVudmVudWUgIScpOwogICAgc3RhdGUudXNlci5tdXN0Q2hhbmdlUGFzc3dvcmQgPSBmYWxzZTsKICAgIGVudGVyQXBwKHN0YXRlLnVzZXIpOwogIH0gY2F0Y2ggKGV4KSB7IHNob3dFcnJvcihlcnIsIGV4Lm1lc3NhZ2UpOyB9Cn0pOwoKJCgnI2xvZ291dC1idG4nKS5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsIGFzeW5jICgpID0+IHsKICBhd2FpdCBhcGkoJy9hcGkvbG9nb3V0JywgeyBtZXRob2Q6ICdQT1NUJyB9KS5jYXRjaCgoKSA9PiB7fSk7CiAgc3RhdGUudXNlciA9IG51bGw7CiAgc2hvd1ZpZXcoJ2xvZ2luJyk7Cn0pOwoKLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCi8vIE5hdmlnYXRpb24gcGFyIG9uZ2xldHMKLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCiQkKCcjdGFicyBidXR0b24nKS5mb3JFYWNoKChidG4pID0+IHsKICBidG4uYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCAoKSA9PiB7CiAgICAkJCgnI3RhYnMgYnV0dG9uJykuZm9yRWFjaCgoYikgPT4gYi5jbGFzc0xpc3QucmVtb3ZlKCdhY3RpdmUnKSk7CiAgICBidG4uY2xhc3NMaXN0LmFkZCgnYWN0aXZlJyk7CiAgICAkJCgnLnRhYi1wYWdlJykuZm9yRWFjaCgocCkgPT4geyBwLmhpZGRlbiA9IHRydWU7IH0pOwogICAgJCgnI3RhYi0nICsgYnRuLmRhdGFzZXQudGFiKS5oaWRkZW4gPSBmYWxzZTsKICAgIGlmIChidG4uZGF0YXNldC50YWIgPT09ICdkYXNoYm9hcmQnKSBsb2FkRGFzaGJvYXJkKCk7CiAgICBpZiAoYnRuLmRhdGFzZXQudGFiID09PSAnYXJ0aWNsZXMnKSBsb2FkQXJ0aWNsZXMoKTsKICAgIGlmIChidG4uZGF0YXNldC50YWIgPT09ICdoaXN0b3J5JykgbG9hZEhpc3RvcnkoKTsKICAgIGlmIChidG4uZGF0YXNldC50YWIgPT09ICdpbnZvaWNlcycpIGxvYWRJbnZvaWNlcygpOwogICAgaWYgKGJ0bi5kYXRhc2V0LnRhYiA9PT0gJ3RlYW0nKSBsb2FkVXNlcnMoKTsKICB9KTsKfSk7CgovLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KLy8gVGFibGVhdSBkZSBib3JkICsgZ3JhcGhpcXVlcyAoY2FudmFzLCBzYW5zIGTDqXBlbmRhbmNlKQovLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KYXN5bmMgZnVuY3Rpb24gbG9hZERhc2hib2FyZCgpIHsKICB0cnkgewogICAgc3RhdGUuZGFzaGJvYXJkID0gYXdhaXQgYXBpKCcvYXBpL2Rhc2hib2FyZCcpOwogIH0gY2F0Y2ggKGUpIHsgcmV0dXJuOyB9CiAgY29uc3QgZCA9IHN0YXRlLmRhc2hib2FyZDsKICAkKCcja3BpLXRvZGF5JykudGV4dENvbnRlbnQgPSBtb25leShkLnNhbGVzVG9kYXkpOwogICQoJyNrcGktbW9udGgnKS50ZXh0Q29udGVudCA9IG1vbmV5KGQuc2FsZXNNb250aCk7CiAgJCgnI2twaS1zdG9jaycpLnRleHRDb250ZW50ID0gbW9uZXkoZC5zdG9ja1ZhbHVlKTsKICAkKCcja3BpLWNvdW50JykudGV4dENvbnRlbnQgPSBkLmFydGljbGVzQ291bnQ7CgogIGNvbnN0IGJveCA9ICQoJyNhbGVydHMtYm94Jyk7CiAgbGV0IGh0bWwgPSAnJzsKICBpZiAoZC5vdXRPZlN0b2NrLmxlbmd0aCkgewogICAgaHRtbCArPSBgPGRpdiBjbGFzcz0iYWxlcnQgZGFuZ2VyIj7im5QgPGI+UnVwdHVyZSBkZSBzdG9jayA6PC9iPiAke2Qub3V0T2ZTdG9jay5tYXAoKGEpID0+IGVzYyhhLm5hbWUpKS5qb2luKCcsICcpfTwvZGl2PmA7CiAgfQogIGlmIChkLmxvd1N0b2NrLmxlbmd0aCkgewogICAgaHRtbCArPSBgPGRpdiBjbGFzcz0iYWxlcnQgd2FybiI+4pqg77iPIDxiPlN0b2NrIGJhcyA6PC9iPiAke2QubG93U3RvY2subWFwKChhKSA9PiBgJHtlc2MoYS5uYW1lKX0gKHBsdXMgcXVlICR7YS5zdG9ja30sIHNldWlsIDogJHthLmxvd190aHJlc2hvbGR9KWApLmpvaW4oJyDCtyAnKX08L2Rpdj5gOwogIH0KICBpZiAoIWQub3V0T2ZTdG9jay5sZW5ndGggJiYgIWQubG93U3RvY2subGVuZ3RoKSB7CiAgICBodG1sICs9IGA8ZGl2IGNsYXNzPSJhbGVydCBvayI+4pyFIFRvdXQgdmEgYmllbiA6IGF1Y3VuIGFydGljbGUgZW4gc3RvY2sgYmFzIG91IGVuIHJ1cHR1cmUuPC9kaXY+YDsKICB9CiAgYm94LmlubmVySFRNTCA9IGh0bWw7CgogICQoJyN0b3Atc2VsbGVycycpLmlubmVySFRNTCA9IGQudG9wU2VsbGVycy5sZW5ndGgKICAgID8gZC50b3BTZWxsZXJzLm1hcCgodCkgPT4gYDxsaT48c3Bhbj4ke2VzYyh0LmFydGljbGVfbmFtZSl9PC9zcGFuPjxiPiR7dC5xdHl9IHZlbmR1KHMpIMK3ICR7bW9uZXkodC5yZXZlbnVlKX08L2I+PC9saT5gKS5qb2luKCcnKQogICAgOiAnPGxpIGNsYXNzPSJtdXRlZCI+QXVjdW5lIHZlbnRlIGVucmVnaXN0csOpZSBwb3VyIGxlIG1vbWVudC48L2xpPic7CgogIGRyYXdDaGFydCgpOwogIGxvYWRSZWNlbnRNb3ZlbWVudHMoKTsKfQoKYXN5bmMgZnVuY3Rpb24gbG9hZFJlY2VudE1vdmVtZW50cygpIHsKICB0cnkgewogICAgY29uc3QgbGlzdCA9IGF3YWl0IGFwaSgnL2FwaS9tb3ZlbWVudHMnKTsKICAgICQoJyNyZWNlbnQtbW92ZW1lbnRzJykuaW5uZXJIVE1MID0gbGlzdC5zbGljZSgwLCA4KS5tYXAoKG0pID0+IGAKICAgICAgPGxpPjxzcGFuPjxzcGFuIGNsYXNzPSJ0YWcgJHttLnR5cGV9Ij4ke1RZUEVfTEFCRUxbbS50eXBlXX08L3NwYW4+ICR7ZXNjKG0uYXJ0aWNsZV9uYW1lKX0gw5cgJHttLnF1YW50aXR5fTwvc3Bhbj4KICAgICAgPGI+JHttb25leShtLnRvdGFsKX08L2I+PC9saT5gKS5qb2luKCcnKSB8fCAnPGxpIGNsYXNzPSJtdXRlZCI+QXVjdW4gbW91dmVtZW50LjwvbGk+JzsKICB9IGNhdGNoIChfKSB7fQp9CgokKCcjY2hhcnQtZGFpbHknKS5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsICgpID0+IHsgc3RhdGUuY2hhcnRNb2RlID0gJ2RhaWx5Jzsgc3luY0NoYXJ0U2VnKCk7IGRyYXdDaGFydCgpOyB9KTsKJCgnI2NoYXJ0LW1vbnRobHknKS5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsICgpID0+IHsgc3RhdGUuY2hhcnRNb2RlID0gJ21vbnRobHknOyBzeW5jQ2hhcnRTZWcoKTsgZHJhd0NoYXJ0KCk7IH0pOwpmdW5jdGlvbiBzeW5jQ2hhcnRTZWcoKSB7CiAgJCgnI2NoYXJ0LWRhaWx5JykuY2xhc3NMaXN0LnRvZ2dsZSgnYWN0aXZlJywgc3RhdGUuY2hhcnRNb2RlID09PSAnZGFpbHknKTsKICAkKCcjY2hhcnQtbW9udGhseScpLmNsYXNzTGlzdC50b2dnbGUoJ2FjdGl2ZScsIHN0YXRlLmNoYXJ0TW9kZSA9PT0gJ21vbnRobHknKTsKfQoKZnVuY3Rpb24gZHJhd0NoYXJ0KCkgewogIGNvbnN0IGNhbnZhcyA9ICQoJyNjaGFydCcpOwogIGlmICghc3RhdGUuZGFzaGJvYXJkKSByZXR1cm47CiAgY29uc3QgZGF0YSA9IHN0YXRlLmNoYXJ0TW9kZSA9PT0gJ2RhaWx5JyA/IHN0YXRlLmRhc2hib2FyZC5kYWlseSA6IHN0YXRlLmRhc2hib2FyZC5tb250aGx5OwogIGNvbnN0IGN0eCA9IGNhbnZhcy5nZXRDb250ZXh0KCcyZCcpOwogIGNvbnN0IGRwciA9IHdpbmRvdy5kZXZpY2VQaXhlbFJhdGlvIHx8IDE7CiAgY29uc3QgdyA9IGNhbnZhcy5jbGllbnRXaWR0aCB8fCA2MDA7CiAgY29uc3QgaCA9IDE4MDsKICBjYW52YXMud2lkdGggPSB3ICogZHByOwogIGNhbnZhcy5oZWlnaHQgPSBoICogZHByOwogIGN0eC5zY2FsZShkcHIsIGRwcik7CiAgY3R4LmNsZWFyUmVjdCgwLCAwLCB3LCBoKTsKICBjb25zdCBtYXggPSBNYXRoLm1heCguLi5kYXRhLm1hcCgocCkgPT4gcC50b3RhbCksIDEpOwogIGNvbnN0IGJhclcgPSBNYXRoLm1heCg0LCAodyAtIDEwKSAvIGRhdGEubGVuZ3RoIC0gNCk7CiAgZGF0YS5mb3JFYWNoKChwLCBpKSA9PiB7CiAgICBjb25zdCBiaCA9IChwLnRvdGFsIC8gbWF4KSAqIChoIC0gNDApOwogICAgY29uc3QgeCA9IDUgKyBpICogKCh3IC0gMTApIC8gZGF0YS5sZW5ndGgpOwogICAgY3R4LmZpbGxTdHlsZSA9ICcjMjU2M2ViJzsKICAgIGN0eC5maWxsUmVjdCh4LCBoIC0gMjQgLSBiaCwgYmFyVywgYmgpOwogICAgaWYgKGkgJSBNYXRoLmNlaWwoZGF0YS5sZW5ndGggLyA4KSA9PT0gMCkgewogICAgICBjdHguZmlsbFN0eWxlID0gJyM2YjcyODAnOwogICAgICBjdHguZm9udCA9ICcxMHB4IHNhbnMtc2VyaWYnOwogICAgICBjdHguZmlsbFRleHQocC5sYWJlbCwgeCwgaCAtIDgpOwogICAgfQogIH0pOwp9CndpbmRvdy5hZGRFdmVudExpc3RlbmVyKCdyZXNpemUnLCBkcmF3Q2hhcnQpOwoKLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCi8vIEFydGljbGVzCi8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQphc3luYyBmdW5jdGlvbiBsb2FkQXJ0aWNsZXMoKSB7CiAgdHJ5IHsKICAgIHN0YXRlLmFydGljbGVzID0gYXdhaXQgYXBpKCcvYXBpL2FydGljbGVzJyk7CiAgfSBjYXRjaCAoZSkgeyByZXR1cm47IH0KICBjb25zdCBxID0gKCQoJyNhcnRpY2xlLXNlYXJjaCcpLnZhbHVlIHx8ICcnKS50b0xvd2VyQ2FzZSgpOwogIGNvbnN0IGNhdCA9ICQoJyNhcnRpY2xlLWZpbHRlcicpLnZhbHVlOwogIGNvbnN0IGNhdHMgPSBbLi4ubmV3IFNldChzdGF0ZS5hcnRpY2xlcy5tYXAoKGEpID0+IGEuY2F0ZWdvcnkpLmZpbHRlcihCb29sZWFuKSldOwogICQoJyNhcnRpY2xlLWZpbHRlcicpLmlubmVySFRNTCA9ICc8b3B0aW9uIHZhbHVlPSIiPlRvdXRlcyBsZXMgY2F0w6lnb3JpZXM8L29wdGlvbj4nICsKICAgIGNhdHMubWFwKChjKSA9PiBgPG9wdGlvbiAke2MgPT09IGNhdCA/ICdzZWxlY3RlZCcgOiAnJ30+JHtlc2MoYyl9PC9vcHRpb24+YCkuam9pbignJyk7CiAgY29uc3QgbGlzdCA9IHN0YXRlLmFydGljbGVzLmZpbHRlcigoYSkgPT4KICAgICghcSB8fCAoYS5uYW1lICsgJyAnICsgKGEuZGVzY3JpcHRpb24gfHwgJycpICsgJyAnICsgKGEuc2t1IHx8ICcnKSkudG9Mb3dlckNhc2UoKS5pbmNsdWRlcyhxKSkgJiYKICAgICghY2F0IHx8IGEuY2F0ZWdvcnkgPT09IGNhdCkpOwogIGNvbnN0IGdyaWQgPSAkKCcjYXJ0aWNsZXMtZ3JpZCcpOwogIGlmICghbGlzdC5sZW5ndGgpIHsKICAgIGdyaWQuaW5uZXJIVE1MID0gJzxwIGNsYXNzPSJlbXB0eSI+QXVjdW4gYXJ0aWNsZSBwb3VyIGxlIG1vbWVudC48YnI+Q2xpcXVleiBzdXIgwqsg77yLIE5vdXZlbCBhcnRpY2xlIMK7IHBvdXIgYWpvdXRlciBsZSBwcmVtaWVyICE8L3A+JzsKICAgIHJldHVybjsKICB9CiAgZ3JpZC5pbm5lckhUTUwgPSBsaXN0Lm1hcCgoYSkgPT4gewogICAgY29uc3QgYmFkZ2UgPSBhLnN0b2NrID09PSAwCiAgICAgID8gJzxzcGFuIGNsYXNzPSJiYWRnZSBvdXQiPlJ1cHR1cmU8L3NwYW4+JwogICAgICA6IGEuc3RvY2sgPD0gYS5sb3dfdGhyZXNob2xkCiAgICAgICAgPyBgPHNwYW4gY2xhc3M9ImJhZGdlIHdhcm4iPlN0b2NrIGJhcyDCtyAke2Euc3RvY2t9PC9zcGFuPmAKICAgICAgICA6IGA8c3BhbiBjbGFzcz0iYmFkZ2Ugb2siPkVuIHN0b2NrIMK3ICR7YS5zdG9ja308L3NwYW4+YDsKICAgIGNvbnN0IGNhbk1vdmUgPSBzdGF0ZS51c2VyLnJvbGUgIT09ICdsZWN0dXJlJzsKICAgIGNvbnN0IHBob3RvID0gYS5waG90bwogICAgICA/IGA8aW1nIHNyYz0iJHtlc2MoYS5waG90byl9IiBhbHQ9IiI+YAogICAgICA6ICc8ZGl2IGNsYXNzPSJuby1waG90byI+8J+TpjwvZGl2Pic7CiAgICByZXR1cm4gYDxkaXYgY2xhc3M9ImFydGljbGUtY2FyZCI+JHtwaG90b30KICAgICAgPGRpdiBjbGFzcz0iYXJ0aWNsZS1ib2R5Ij4KICAgICAgICA8aDM+JHtlc2MoYS5uYW1lKX08L2gzPgogICAgICAgIDxwIGNsYXNzPSJkZXNjIj4ke2VzYyhhLmRlc2NyaXB0aW9uIHx8ICcnKX08L3A+CiAgICAgICAgPGRpdiBjbGFzcz0icHJpY2UiPiR7bW9uZXkoYS5wcmljZSl9PC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0ic3RvY2stbGluZSI+PHNwYW4gY2xhc3M9Im11dGVkIj4ke2VzYyhhLnNrdSB8fCAnJyl9ICR7YS5jYXRlZ29yeSA/ICfCtyAnICsgZXNjKGEuY2F0ZWdvcnkpIDogJyd9PC9zcGFuPiR7YmFkZ2V9PC9kaXY+CiAgICAgICAgJHtjYW5Nb3ZlID8gYAogICAgICAgIDxkaXYgY2xhc3M9InF0eS1yb3ciPgogICAgICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIiBvbmNsaWNrPSJxdWlja01vdmUoJHthLmlkfSwnZW50cmVlJywxKSI+77yLIEVudHLDqWU8L2J1dHRvbj4KICAgICAgICAgIDxidXR0b24gY2xhc3M9ImJ0biIgb25jbGljaz0icXVpY2tNb3ZlKCR7YS5pZH0sJ3ZlbnRlJywxKSI+8J+bkiBWZW5kcmU8L2J1dHRvbj4KICAgICAgICAgIDxidXR0b24gY2xhc3M9ImJ0biIgb25jbGljaz0ib3Blbk1vdmVNb2RhbCgke2EuaWR9LCdzb3J0aWUnKSI+4oiSIFNvcnRpZTwvYnV0dG9uPgogICAgICAgIDwvZGl2PmAgOiAnJ30KICAgICAgICAke3N0YXRlLnVzZXIucm9sZSA9PT0gJ2FkbWluJyA/IGAKICAgICAgICA8ZGl2IGNsYXNzPSJxdHktcm93Ij4KICAgICAgICAgIDxidXR0b24gY2xhc3M9ImJ0biBzbWFsbCIgb25jbGljaz0ib3BlbkFydGljbGVGb3JtKCR7YS5pZH0pIj7inI/vuI8gTW9kaWZpZXI8L2J1dHRvbj4KICAgICAgICAgIDxidXR0b24gY2xhc3M9ImJ0biBzbWFsbCBkYW5nZXIiIG9uY2xpY2s9ImRlbGV0ZUFydGljbGUoJHthLmlkfSwnJHtlc2MoYS5uYW1lLnJlcGxhY2UoLycvZywgJycpKX0nKSI+8J+Xke+4jyBTdXBwcmltZXI8L2J1dHRvbj4KICAgICAgICA8L2Rpdj5gIDogJyd9CiAgICAgIDwvZGl2PjwvZGl2PmA7CiAgfSkuam9pbignJyk7Cn0KCiQoJyNhcnRpY2xlLXNlYXJjaCcpLmFkZEV2ZW50TGlzdGVuZXIoJ2lucHV0JywgbG9hZEFydGljbGVzKTsKJCgnI2FydGljbGUtZmlsdGVyJykuYWRkRXZlbnRMaXN0ZW5lcignY2hhbmdlJywgbG9hZEFydGljbGVzKTsKJCgnI25ldy1hcnRpY2xlLWJ0bicpLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCkgPT4gb3BlbkFydGljbGVGb3JtKG51bGwpKTsKCi8vIFLDqWR1aXQgbGEgcGhvdG8gKG1heCA4MDAgcHgsIEpQRUcpIHBvdXIgZ2FyZGVyIGxhIGJhc2UgcGV0aXRlLgpmdW5jdGlvbiByZWFkUGhvdG9GaWxlKGZpbGUpIHsKICByZXR1cm4gbmV3IFByb21pc2UoKHJlc29sdmUsIHJlamVjdCkgPT4gewogICAgY29uc3QgcmVhZGVyID0gbmV3IEZpbGVSZWFkZXIoKTsKICAgIHJlYWRlci5vbmxvYWQgPSAoKSA9PiB7CiAgICAgIGNvbnN0IGltZyA9IG5ldyBJbWFnZSgpOwogICAgICBpbWcub25sb2FkID0gKCkgPT4gewogICAgICAgIGNvbnN0IG1heCA9IDgwMDsKICAgICAgICBjb25zdCBzY2FsZSA9IE1hdGgubWluKDEsIG1heCAvIE1hdGgubWF4KGltZy53aWR0aCwgaW1nLmhlaWdodCkpOwogICAgICAgIGNvbnN0IGNhbnZhcyA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2NhbnZhcycpOwogICAgICAgIGNhbnZhcy53aWR0aCA9IE1hdGgucm91bmQoaW1nLndpZHRoICogc2NhbGUpOwogICAgICAgIGNhbnZhcy5oZWlnaHQgPSBNYXRoLnJvdW5kKGltZy5oZWlnaHQgKiBzY2FsZSk7CiAgICAgICAgY2FudmFzLmdldENvbnRleHQoJzJkJykuZHJhd0ltYWdlKGltZywgMCwgMCwgY2FudmFzLndpZHRoLCBjYW52YXMuaGVpZ2h0KTsKICAgICAgICByZXNvbHZlKGNhbnZhcy50b0RhdGFVUkwoJ2ltYWdlL2pwZWcnLCAwLjgpKTsKICAgICAgfTsKICAgICAgaW1nLm9uZXJyb3IgPSByZWplY3Q7CiAgICAgIGltZy5zcmMgPSByZWFkZXIucmVzdWx0OwogICAgfTsKICAgIHJlYWRlci5vbmVycm9yID0gcmVqZWN0OwogICAgcmVhZGVyLnJlYWRBc0RhdGFVUkwoZmlsZSk7CiAgfSk7Cn0KCmxldCBhcnRpY2xlRm9ybVBob3RvID0gJyc7CmxldCBhcnRpY2xlU3RlcCA9IDE7CgpmdW5jdGlvbiBvcGVuQXJ0aWNsZUZvcm0oaWQpIHsKICBjb25zdCBhID0gaWQgPyBzdGF0ZS5hcnRpY2xlcy5maW5kKCh4KSA9PiB4LmlkID09PSBpZCkgOiBudWxsOwogIGFydGljbGVGb3JtUGhvdG8gPSBhID8gYS5waG90byA6ICcnOwogIGFydGljbGVTdGVwID0gMTsKICBvcGVuTW9kYWwoYAogICAgPGgyPiR7YSA/ICdNb2RpZmllciBs4oCZYXJ0aWNsZScgOiAnTm91dmVsIGFydGljbGUnfTwvaDI+CiAgICA8ZGl2IGNsYXNzPSJzdGVwcyI+PHNwYW4gaWQ9InN0ZXAtMSIgY2xhc3M9Im9uIj4xIMK3IFBob3RvPC9zcGFuPjxzcGFuIGlkPSJzdGVwLTIiPjIgwrcgTm9tICZhbXA7IGRlc2NyaXB0aW9uPC9zcGFuPjxzcGFuIGlkPSJzdGVwLTMiPjMgwrcgUHJpeCAmYW1wOyBzdG9jazwvc3Bhbj48L2Rpdj4KICAgIDxmb3JtIGlkPSJhcnRpY2xlLWZvcm0iPgogICAgICA8ZGl2IGNsYXNzPSJzdGVwLXBhbmUiIGRhdGEtcGFuZT0iMSI+CiAgICAgICAgPGxhYmVsPlBob3RvIGRlIGzigJlhcnRpY2xlIChmYWN1bHRhdGlmKQogICAgICAgICAgPGlucHV0IHR5cGU9ImZpbGUiIGlkPSJhZi1waG90byIgYWNjZXB0PSJpbWFnZS8qIiBjYXB0dXJlPSJlbnZpcm9ubWVudCI+CiAgICAgICAgPC9sYWJlbD4KICAgICAgICA8aW1nIGlkPSJhZi1wcmV2aWV3IiBjbGFzcz0icGhvdG8tcHJldmlldyIgJHthcnRpY2xlRm9ybVBob3RvID8gYHNyYz0iJHtlc2MoYXJ0aWNsZUZvcm1QaG90byl9ImAgOiAnaGlkZGVuJ30+CiAgICAgICAgPHAgY2xhc3M9Im11dGVkIj5VbmUgcGhvdG8gYWlkZSB0b3V0ZSBsJ8OpcXVpcGUgw6AgcmVjb25uYcOudHJlIGwnYXJ0aWNsZSBlbiB1biBjb3VwIGQnxZNpbC48L3A+CiAgICAgIDwvZGl2PgogICAgICA8ZGl2IGNsYXNzPSJzdGVwLXBhbmUiIGRhdGEtcGFuZT0iMiIgaGlkZGVuPgogICAgICAgIDxsYWJlbD5Ob20gZGUgbOKAmWFydGljbGUgKiA8aW5wdXQgdHlwZT0idGV4dCIgaWQ9ImFmLW5hbWUiIHJlcXVpcmVkIHZhbHVlPSIke2EgPyBlc2MoYS5uYW1lKSA6ICcnfSIgcGxhY2Vob2xkZXI9ImV4LiBDYXNxdWUgQmx1ZXRvb3RoIFgyMDAiPjwvbGFiZWw+CiAgICAgICAgPGxhYmVsPkRlc2NyaXB0aW9uIDx0ZXh0YXJlYSBpZD0iYWYtZGVzYyIgcGxhY2Vob2xkZXI9IkNvdWxldXIsIHRhaWxsZSwgcGFydGljdWxhcml0w6lz4oCmIj4ke2EgPyBlc2MoYS5kZXNjcmlwdGlvbiB8fCAnJykgOiAnJ308L3RleHRhcmVhPjwvbGFiZWw+CiAgICAgIDwvZGl2PgogICAgICA8ZGl2IGNsYXNzPSJzdGVwLXBhbmUiIGRhdGEtcGFuZT0iMyIgaGlkZGVuPgogICAgICAgIDxkaXYgY2xhc3M9ImZvcm0tZ3JpZCI+CiAgICAgICAgICA8bGFiZWw+UHJpeCBkZSB2ZW50ZSAoJCkgKiA8aW5wdXQgdHlwZT0ibnVtYmVyIiBpZD0iYWYtcHJpY2UiIHJlcXVpcmVkIG1pbj0iMCIgc3RlcD0iMC4wMSIgdmFsdWU9IiR7YSA/IGEucHJpY2UgOiAnJ30iIHBsYWNlaG9sZGVyPSIxOS45OSI+PC9sYWJlbD4KICAgICAgICAgIDxsYWJlbD5Qcml4IGNvw7t0YW50ICgkKSA8aW5wdXQgdHlwZT0ibnVtYmVyIiBpZD0iYWYtY29zdCIgbWluPSIwIiBzdGVwPSIwLjAxIiB2YWx1ZT0iJHthICYmIGEuY29zdF9wcmljZSAhPSBudWxsID8gYS5jb3N0X3ByaWNlIDogJyd9IiBwbGFjZWhvbGRlcj0iRmFjdWx0YXRpZiI+PC9sYWJlbD4KICAgICAgICAgIDxsYWJlbD5TS1UgLyBSw6lmw6lyZW5jZSA8aW5wdXQgdHlwZT0idGV4dCIgaWQ9ImFmLXNrdSIgdmFsdWU9IiR7YSA/IGVzYyhhLnNrdSB8fCAnJykgOiAnJ30iIHBsYWNlaG9sZGVyPSJleC4gQ0ItMDAxIj48L2xhYmVsPgogICAgICAgICAgPGxhYmVsPkNhdMOpZ29yaWUgPGlucHV0IHR5cGU9InRleHQiIGlkPSJhZi1jYXQiIHZhbHVlPSIke2EgPyBlc2MoYS5jYXRlZ29yeSB8fCAnJykgOiAnJ30iIHBsYWNlaG9sZGVyPSJleC4gQXVkaW8iPjwvbGFiZWw+CiAgICAgICAgICA8bGFiZWw+U3RvY2sgZGUgZMOpcGFydCA8aW5wdXQgdHlwZT0ibnVtYmVyIiBpZD0iYWYtc3RvY2siIG1pbj0iMCIgc3RlcD0iMSIgdmFsdWU9IiR7YSA/IGEuc3RvY2sgOiAwfSI+PC9sYWJlbD4KICAgICAgICAgIDxsYWJlbD5TZXVpbCBk4oCZYWxlcnRlIHN0b2NrIGJhcyA8aW5wdXQgdHlwZT0ibnVtYmVyIiBpZD0iYWYtdGhyZXNob2xkIiBtaW49IjAiIHN0ZXA9IjEiIHZhbHVlPSIke2EgPyBhLmxvd190aHJlc2hvbGQgOiA1fSI+PC9sYWJlbD4KICAgICAgICA8L2Rpdj4KICAgICAgICA8cCBpZD0iYWYtZXJyb3IiIGNsYXNzPSJlcnJvciIgaGlkZGVuPjwvcD4KICAgICAgPC9kaXY+CiAgICAgIDxkaXYgc3R5bGU9ImRpc3BsYXk6ZmxleDtnYXA6OHB4O2p1c3RpZnktY29udGVudDpzcGFjZS1iZXR3ZWVuO21hcmdpbi10b3A6MTRweCI+CiAgICAgICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJidG4iIGlkPSJhZi1iYWNrIiBoaWRkZW4+4oaQIFJldG91cjwvYnV0dG9uPgogICAgICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0iYnRuIHByaW1hcnkiIGlkPSJhZi1uZXh0Ij5TdWl2YW50IOKGkjwvYnV0dG9uPgogICAgICAgIDxidXR0b24gdHlwZT0ic3VibWl0IiBjbGFzcz0iYnRuIHByaW1hcnkiIGlkPSJhZi1zdWJtaXQiIGhpZGRlbj4ke2EgPyAnRW5yZWdpc3RyZXInIDogJ0Fqb3V0ZXIgbOKAmWFydGljbGUnfTwvYnV0dG9uPgogICAgICA8L2Rpdj4KICAgIDwvZm9ybT5gKTsKCiAgJCgnI2FmLXBob3RvJykuYWRkRXZlbnRMaXN0ZW5lcignY2hhbmdlJywgYXN5bmMgKGUpID0+IHsKICAgIGNvbnN0IGZpbGUgPSBlLnRhcmdldC5maWxlc1swXTsKICAgIGlmICghZmlsZSkgcmV0dXJuOwogICAgdHJ5IHsKICAgICAgYXJ0aWNsZUZvcm1QaG90byA9IGF3YWl0IHJlYWRQaG90b0ZpbGUoZmlsZSk7CiAgICAgIGNvbnN0IGltZyA9ICQoJyNhZi1wcmV2aWV3Jyk7CiAgICAgIGltZy5zcmMgPSBhcnRpY2xlRm9ybVBob3RvOwogICAgICBpbWcuaGlkZGVuID0gZmFsc2U7CiAgICB9IGNhdGNoIChfKSB7IHRvYXN0KCdJbXBvc3NpYmxlIGRlIGxpcmUgY2V0dGUgcGhvdG8uJyk7IH0KICB9KTsKCiAgY29uc3Qgc2hvd1N0ZXAgPSAobikgPT4gewogICAgYXJ0aWNsZVN0ZXAgPSBuOwogICAgJCQoJy5zdGVwLXBhbmUnKS5mb3JFYWNoKChwKSA9PiB7IHAuaGlkZGVuID0gTnVtYmVyKHAuZGF0YXNldC5wYW5lKSAhPT0gbjsgfSk7CiAgICAkJCgnLnN0ZXBzIHNwYW4nKS5mb3JFYWNoKChzLCBpKSA9PiBzLmNsYXNzTGlzdC50b2dnbGUoJ29uJywgaSArIDEgPT09IG4pKTsKICAgICQoJyNhZi1iYWNrJykuaGlkZGVuID0gbiA9PT0gMTsKICAgICQoJyNhZi1uZXh0JykuaGlkZGVuID0gbiA9PT0gMzsKICAgICQoJyNhZi1zdWJtaXQnKS5oaWRkZW4gPSBuICE9PSAzOwogIH07CiAgJCgnI2FmLWJhY2snKS5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsICgpID0+IHNob3dTdGVwKGFydGljbGVTdGVwIC0gMSkpOwogICQoJyNhZi1uZXh0JykuYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCAoKSA9PiB7CiAgICBpZiAoYXJ0aWNsZVN0ZXAgPT09IDIgJiYgISQoJyNhZi1uYW1lJykudmFsdWUudHJpbSgpKSB7IHRvYXN0KCdEb25uZXogdW4gbm9tIMOgIGzigJlhcnRpY2xlLicpOyByZXR1cm47IH0KICAgIHNob3dTdGVwKGFydGljbGVTdGVwICsgMSk7CiAgfSk7CiAgJCgnI2FydGljbGUtZm9ybScpLmFkZEV2ZW50TGlzdGVuZXIoJ3N1Ym1pdCcsIGFzeW5jIChlKSA9PiB7CiAgICBlLnByZXZlbnREZWZhdWx0KCk7CiAgICBjb25zdCBlcnIgPSAkKCcjYWYtZXJyb3InKTsKICAgIGVyci5oaWRkZW4gPSB0cnVlOwogICAgY29uc3QgcGF5bG9hZCA9IHsKICAgICAgbmFtZTogJCgnI2FmLW5hbWUnKS52YWx1ZS50cmltKCksCiAgICAgIGRlc2NyaXB0aW9uOiAkKCcjYWYtZGVzYycpLnZhbHVlLnRyaW0oKSwKICAgICAgcGhvdG86IGFydGljbGVGb3JtUGhvdG8sCiAgICAgIHByaWNlOiBOdW1iZXIoJCgnI2FmLXByaWNlJykudmFsdWUpLAogICAgICBjb3N0X3ByaWNlOiAkKCcjYWYtY29zdCcpLnZhbHVlID09PSAnJyA/IG51bGwgOiBOdW1iZXIoJCgnI2FmLWNvc3QnKS52YWx1ZSksCiAgICAgIHNrdTogJCgnI2FmLXNrdScpLnZhbHVlLnRyaW0oKSwKICAgICAgY2F0ZWdvcnk6ICQoJyNhZi1jYXQnKS52YWx1ZS50cmltKCksCiAgICAgIHN0b2NrOiBOdW1iZXIoJCgnI2FmLXN0b2NrJykudmFsdWUpLAogICAgICBsb3dfdGhyZXNob2xkOiBOdW1iZXIoJCgnI2FmLXRocmVzaG9sZCcpLnZhbHVlKSwKICAgIH07CiAgICB0cnkgewogICAgICBpZiAoYSkgYXdhaXQgYXBpKCcvYXBpL2FydGljbGVzLycgKyBhLmlkLCB7IG1ldGhvZDogJ1BVVCcsIGJvZHk6IEpTT04uc3RyaW5naWZ5KHBheWxvYWQpIH0pOwogICAgICBlbHNlIGF3YWl0IGFwaSgnL2FwaS9hcnRpY2xlcycsIHsgbWV0aG9kOiAnUE9TVCcsIGJvZHk6IEpTT04uc3RyaW5naWZ5KHBheWxvYWQpIH0pOwogICAgICBjbG9zZU1vZGFsKCk7CiAgICAgIHRvYXN0KGEgPyAnQXJ0aWNsZSBtb2RpZmnDqS4nIDogJ0FydGljbGUgYWpvdXTDqSAhIPCfjoknKTsKICAgICAgbG9hZEFydGljbGVzKCk7CiAgICAgIGxvYWREYXNoYm9hcmQoKTsKICAgIH0gY2F0Y2ggKGV4KSB7IHNob3dFcnJvcihlcnIsIGV4Lm1lc3NhZ2UpOyB9CiAgfSk7Cn0KCmFzeW5jIGZ1bmN0aW9uIGRlbGV0ZUFydGljbGUoaWQsIG5hbWUpIHsKICBpZiAoIWNvbmZpcm0oYFN1cHByaW1lciBkw6lmaW5pdGl2ZW1lbnQgwqsgJHtuYW1lfSDCuyA/YCkpIHJldHVybjsKICB0cnkgewogICAgYXdhaXQgYXBpKCcvYXBpL2FydGljbGVzLycgKyBpZCwgeyBtZXRob2Q6ICdERUxFVEUnIH0pOwogICAgdG9hc3QoJ0FydGljbGUgc3VwcHJpbcOpLicpOwogICAgbG9hZEFydGljbGVzKCk7CiAgICBsb2FkRGFzaGJvYXJkKCk7CiAgfSBjYXRjaCAoZSkgeyB0b2FzdChlLm1lc3NhZ2UpOyB9Cn0KCi8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQovLyBNb3V2ZW1lbnRzIGRlIHN0b2NrCi8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQphc3luYyBmdW5jdGlvbiBxdWlja01vdmUoYXJ0aWNsZUlkLCB0eXBlLCBxdHkpIHsKICBpZiAodHlwZSA9PT0gJ3ZlbnRlJyB8fCB0eXBlID09PSAnc29ydGllJykgeyBvcGVuTW92ZU1vZGFsKGFydGljbGVJZCwgdHlwZSwgcXR5KTsgcmV0dXJuOyB9CiAgdHJ5IHsKICAgIGNvbnN0IHsgc3RvY2sgfSA9IGF3YWl0IGFwaSgnL2FwaS9tb3ZlbWVudHMnLCB7CiAgICAgIG1ldGhvZDogJ1BPU1QnLAogICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IGFydGljbGVfaWQ6IGFydGljbGVJZCwgdHlwZTogJ2VudHJlZScsIHF1YW50aXR5OiBxdHkgfSksCiAgICB9KTsKICAgIHRvYXN0KGBFbnRyw6llIGVucmVnaXN0csOpZS4gTm91dmVhdSBzdG9jayA6ICR7c3RvY2t9LmApOwogICAgbG9hZEFydGljbGVzKCk7IGxvYWREYXNoYm9hcmQoKTsgbG9hZEhpc3RvcnkoKTsKICB9IGNhdGNoIChlKSB7IHRvYXN0KGUubWVzc2FnZSk7IH0KfQoKZnVuY3Rpb24gb3Blbk1vdmVNb2RhbChhcnRpY2xlSWQsIHR5cGUsIHByZXNldFF0eSA9IDEpIHsKICBjb25zdCBhID0gc3RhdGUuYXJ0aWNsZXMuZmluZCgoeCkgPT4geC5pZCA9PT0gYXJ0aWNsZUlkKTsKICBpZiAoIWEpIHJldHVybjsKICBjb25zdCBpc1NhbGUgPSB0eXBlID09PSAndmVudGUnOwogIG9wZW5Nb2RhbChgCiAgICA8aDI+JHtpc1NhbGUgPyAn8J+bkiBWZW5kcmUnIDogdHlwZSA9PT0gJ2VudHJlZScgPyAn77yLIEVudHLDqWUgZGUgc3RvY2snIDogJ+KIkiBTb3J0aWUgZGUgc3RvY2snfSDigJQgJHtlc2MoYS5uYW1lKX08L2gyPgogICAgPHAgY2xhc3M9Im11dGVkIj5TdG9jayBhY3R1ZWwgOiA8Yj4ke2Euc3RvY2t9PC9iPiDCtyBQcml4IGRlIHZlbnRlIDogPGI+JHttb25leShhLnByaWNlKX08L2I+PC9wPgogICAgPGZvcm0gaWQ9Im1vdmUtZm9ybSI+CiAgICAgIDxsYWJlbD5RdWFudGl0w6kKICAgICAgICA8aW5wdXQgdHlwZT0ibnVtYmVyIiBpZD0ibXYtcXR5IiBtaW49IjEiIHN0ZXA9IjEiIHZhbHVlPSIke3ByZXNldFF0eX0iIHJlcXVpcmVkPgogICAgICA8L2xhYmVsPgogICAgICA8ZGl2IGNsYXNzPSJxdHktcm93IiBzdHlsZT0ibWFyZ2luLWJvdHRvbToxMnB4Ij4KICAgICAgICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgY2xhc3M9ImJ0biBzbWFsbCIgb25jbGljaz0iZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ212LXF0eScpLnZhbHVlPTUiPsOXNTwvYnV0dG9uPgogICAgICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0iYnRuIHNtYWxsIiBvbmNsaWNrPSJkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnbXYtcXR5JykudmFsdWU9MTAiPsOXMTA8L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgY2xhc3M9ImJ0biBzbWFsbCIgb25jbGljaz0iZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ212LXF0eScpLnZhbHVlPU1hdGgubWF4KDEsKGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdtdi1xdHknKS52YWx1ZXx8MSktMSkiPuKIkjE8L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgY2xhc3M9ImJ0biBzbWFsbCIgb25jbGljaz0iZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ212LXF0eScpLnZhbHVlPSgrZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ212LXF0eScpLnZhbHVlfHwwKSsxIj7vvIsxPC9idXR0b24+CiAgICAgIDwvZGl2PgogICAgICA8bGFiZWw+UHJpeCB1bml0YWlyZSAoJCkKICAgICAgICA8aW5wdXQgdHlwZT0ibnVtYmVyIiBpZD0ibXYtcHJpY2UiIG1pbj0iMCIgc3RlcD0iMC4wMSIgdmFsdWU9IiR7aXNTYWxlID8gYS5wcmljZSA6IChhLmNvc3RfcHJpY2UgPz8gYS5wcmljZSl9Ij4KICAgICAgPC9sYWJlbD4KICAgICAgPGxhYmVsPk5vdGUgPGlucHV0IHR5cGU9InRleHQiIGlkPSJtdi1ub3RlIiBwbGFjZWhvbGRlcj0iRmFjdWx0YXRpZiDigJQgZXguIGNsaWVudCByw6lndWxpZXIsIGNhc3Nl4oCmIj48L2xhYmVsPgogICAgICAke2lzU2FsZSA/IGAKICAgICAgPGxhYmVsIGNsYXNzPSJjaGVja2JveC1saW5lIj48aW5wdXQgdHlwZT0iY2hlY2tib3giIGlkPSJtdi1pbnZvaWNlIj4gR8OpbsOpcmVyIHVuZSBmYWN0dXJlIHBvdXIgY2V0dGUgdmVudGUgKGZhY3VsdGF0aWYpPC9sYWJlbD4KICAgICAgPGRpdiBpZD0ibXYtaW52b2ljZS1maWVsZHMiIGhpZGRlbj4KICAgICAgICA8bGFiZWw+Tm9tIGR1IGNsaWVudCA8aW5wdXQgdHlwZT0idGV4dCIgaWQ9Im12LWNsaWVudCIgcGxhY2Vob2xkZXI9ImV4LiBNYXJpZSBUcmVtYmxheSI+PC9sYWJlbD4KICAgICAgICA8bGFiZWw+VGF1eCBkZSB0YXhlcyAoJSkgPGlucHV0IHR5cGU9Im51bWJlciIgaWQ9Im12LXRheCIgbWluPSIwIiBzdGVwPSIwLjAxIiB2YWx1ZT0iMCI+PC9sYWJlbD4KICAgICAgPC9kaXY+YCA6ICcnfQogICAgICA8cCBpZD0ibXYtZXJyb3IiIGNsYXNzPSJlcnJvciIgaGlkZGVuPjwvcD4KICAgICAgPGJ1dHRvbiB0eXBlPSJzdWJtaXQiIGNsYXNzPSJidG4gcHJpbWFyeSBiaWciPkNvbmZpcm1lciAke2lzU2FsZSA/ICdsYSB2ZW50ZScgOiAnbGUgbW91dmVtZW50J308L2J1dHRvbj4KICAgIDwvZm9ybT5gKTsKICBjb25zdCBpbnZCb3ggPSAkKCcjbXYtaW52b2ljZScpOwogIGlmIChpbnZCb3gpIGludkJveC5hZGRFdmVudExpc3RlbmVyKCdjaGFuZ2UnLCAoKSA9PiB7ICQoJyNtdi1pbnZvaWNlLWZpZWxkcycpLmhpZGRlbiA9ICFpbnZCb3guY2hlY2tlZDsgfSk7CiAgJCgnI21vdmUtZm9ybScpLmFkZEV2ZW50TGlzdGVuZXIoJ3N1Ym1pdCcsIGFzeW5jIChlKSA9PiB7CiAgICBlLnByZXZlbnREZWZhdWx0KCk7CiAgICBjb25zdCBlcnIgPSAkKCcjbXYtZXJyb3InKTsKICAgIGVyci5oaWRkZW4gPSB0cnVlOwogICAgY29uc3QgYm9keSA9IHsKICAgICAgYXJ0aWNsZV9pZDogYXJ0aWNsZUlkLAogICAgICB0eXBlLAogICAgICBxdWFudGl0eTogTnVtYmVyKCQoJyNtdi1xdHknKS52YWx1ZSksCiAgICAgIHVuaXRfcHJpY2U6IE51bWJlcigkKCcjbXYtcHJpY2UnKS52YWx1ZSksCiAgICAgIG5vdGU6ICQoJyNtdi1ub3RlJykudmFsdWUudHJpbSgpLAogICAgfTsKICAgIGlmIChpc1NhbGUgJiYgaW52Qm94ICYmIGludkJveC5jaGVja2VkKSB7CiAgICAgIGJvZHkuZ2VuZXJhdGVfaW52b2ljZSA9IHRydWU7CiAgICAgIGJvZHkuY2xpZW50X25hbWUgPSAkKCcjbXYtY2xpZW50JykudmFsdWUudHJpbSgpOwogICAgICBib2R5LnRheF9yYXRlID0gTnVtYmVyKCQoJyNtdi10YXgnKS52YWx1ZSB8fCAwKTsKICAgIH0KICAgIHRyeSB7CiAgICAgIGNvbnN0IHsgc3RvY2ssIGludm9pY2UgfSA9IGF3YWl0IGFwaSgnL2FwaS9tb3ZlbWVudHMnLCB7IG1ldGhvZDogJ1BPU1QnLCBib2R5OiBKU09OLnN0cmluZ2lmeShib2R5KSB9KTsKICAgICAgY2xvc2VNb2RhbCgpOwogICAgICB0b2FzdChpbnZvaWNlID8gYFZlbnRlIGVucmVnaXN0csOpZSDigJQgZmFjdHVyZSAke2ludm9pY2UubnVtYmVyfSBjcsOpw6llLmAgOiBgTW91dmVtZW50IGVucmVnaXN0csOpLiBOb3V2ZWF1IHN0b2NrIDogJHtzdG9ja30uYCk7CiAgICAgIGxvYWRBcnRpY2xlcygpOyBsb2FkRGFzaGJvYXJkKCk7IGxvYWRIaXN0b3J5KCk7IGxvYWRJbnZvaWNlcygpOwogICAgfSBjYXRjaCAoZXgpIHsgc2hvd0Vycm9yKGVyciwgZXgubWVzc2FnZSk7IH0KICB9KTsKfQoKLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCi8vIEhpc3RvcmlxdWUgZGVzIG1vdXZlbWVudHMKLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCmFzeW5jIGZ1bmN0aW9uIGxvYWRIaXN0b3J5KCkgewogIGNvbnN0IHBhcmFtcyA9IG5ldyBVUkxTZWFyY2hQYXJhbXMoKTsKICBjb25zdCB0eXBlID0gJCgnI2hpc3QtdHlwZScpLnZhbHVlOwogIGNvbnN0IGZyb20gPSAkKCcjaGlzdC1mcm9tJykudmFsdWU7CiAgY29uc3QgdG8gPSAkKCcjaGlzdC10bycpLnZhbHVlOwogIGlmICh0eXBlKSBwYXJhbXMuc2V0KCd0eXBlJywgdHlwZSk7CiAgaWYgKGZyb20pIHBhcmFtcy5zZXQoJ2Zyb20nLCBmcm9tKTsKICBpZiAodG8pIHBhcmFtcy5zZXQoJ3RvJywgdG8pOwogIHRyeSB7CiAgICBjb25zdCBsaXN0ID0gYXdhaXQgYXBpKCcvYXBpL21vdmVtZW50cz8nICsgcGFyYW1zLnRvU3RyaW5nKCkpOwogICAgJCgnI2hpc3RvcnktYm9keScpLmlubmVySFRNTCA9IGxpc3QubWFwKChtKSA9PiBgCiAgICAgIDx0cj48dGQ+JHtlc2MobS5kYXkpfTwvdGQ+PHRkPiR7ZXNjKG0uYXJ0aWNsZV9uYW1lKX08L3RkPgogICAgICA8dGQ+PHNwYW4gY2xhc3M9InRhZyAke20udHlwZX0iPiR7VFlQRV9MQUJFTFttLnR5cGVdfTwvc3Bhbj48L3RkPgogICAgICA8dGQ+JHttLnF1YW50aXR5fTwvdGQ+PHRkPiR7bW9uZXkobS51bml0X3ByaWNlKX08L3RkPjx0ZD4ke21vbmV5KG0udG90YWwpfTwvdGQ+CiAgICAgIDx0ZD4ke2VzYyhtLnVzZXJuYW1lIHx8ICcnKX08L3RkPjx0ZD4ke2VzYyhtLm5vdGUgfHwgJycpfTwvdGQ+PC90cj5gKS5qb2luKCcnKQogICAgICB8fCAnPHRyPjx0ZCBjb2xzcGFuPSI4IiBjbGFzcz0ibXV0ZWQiPkF1Y3VuIG1vdXZlbWVudCBwb3VyIGNlcyBmaWx0cmVzLjwvdGQ+PC90cj4nOwogIH0gY2F0Y2ggKF8pIHt9Cn0KJCgnI2hpc3QtYXBwbHknKS5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsIGxvYWRIaXN0b3J5KTsKCi8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQovLyBGYWN0dXJlcwovLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KYXN5bmMgZnVuY3Rpb24gbG9hZEludm9pY2VzKCkgewogIHRyeSB7CiAgICBjb25zdCBsaXN0ID0gYXdhaXQgYXBpKCcvYXBpL2ludm9pY2VzJyk7CiAgICAkKCcjaW52b2ljZXMtbGlzdCcpLmlubmVySFRNTCA9IGxpc3QubGVuZ3RoID8gbGlzdC5tYXAoKGludikgPT4gYAogICAgICA8ZGl2IGNsYXNzPSJjYXJkIj4KICAgICAgICA8ZGl2IGNsYXNzPSJjYXJkLWhlYWQiPgogICAgICAgICAgPGgzPvCfp74gJHtlc2MoaW52Lm51bWJlcil9IOKAlCAke2VzYyhpbnYuY2xpZW50X25hbWUgfHwgJ0NsaWVudCBjb21wdGFudCcpfTwvaDM+CiAgICAgICAgICA8c3BhbiBjbGFzcz0ibXV0ZWQiPiR7ZXNjKGludi5kYXkpfSDCtyBwYXIgJHtlc2MoaW52LnVzZXJuYW1lIHx8ICcnKX08L3NwYW4+CiAgICAgICAgPC9kaXY+CiAgICAgICAgPHA+JHsoaW52Lml0ZW1zIHx8IFtdKS5tYXAoKGl0KSA9PiBgJHtlc2MoaXQubmFtZSl9IMOXICR7aXQucXVhbnRpdHl9YCkuam9pbignIMK3ICcpfTwvcD4KICAgICAgICA8cD48Yj5Ub3RhbCA6ICR7bW9uZXkoaW52LnRvdGFsKX08L2I+IChzb3VzLXRvdGFsICR7bW9uZXkoaW52LnN1YnRvdGFsKX0sIHRheGVzICR7bW9uZXkoaW52LnRheF9hbW91bnQpfSk8L3A+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIHNtYWxsIiBvbmNsaWNrPSJ3aW5kb3cub3BlbignL2FwaS9pbnZvaWNlcy8ke2ludi5pZH0vaHRtbCcsJ19ibGFuaycpIj7wn5ao77iPIFZvaXIgLyBJbXByaW1lcjwvYnV0dG9uPgogICAgICA8L2Rpdj5gKS5qb2luKCcnKQogICAgICA6ICc8cCBjbGFzcz0iZW1wdHkiPkF1Y3VuZSBmYWN0dXJlIHBvdXIgbGUgbW9tZW50LiBMZXMgdmVudGVzIGZvbmN0aW9ubmVudCB0csOocyBiaWVuIHNhbnMgZmFjdHVyZSAhPC9wPic7CiAgfSBjYXRjaCAoXykge30KfQoKJCgnI25ldy1pbnZvaWNlLWJ0bicpLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCkgPT4gewogIGlmIChzdGF0ZS51c2VyLnJvbGUgPT09ICdsZWN0dXJlJykgeyB0b2FzdCgnVm90cmUgcsO0bGUgbmUgcGVybWV0IHBhcyBkZSBjcsOpZXIgZGVzIGZhY3R1cmVzLicpOyByZXR1cm47IH0KICBvcGVuTW9kYWwoYAogICAgPGgyPk5vdXZlbGxlIGZhY3R1cmU8L2gyPgogICAgPHAgY2xhc3M9Im11dGVkIj5GYWN1bHRhdGl2ZSA6IGNvY2hleiDCqyBEw6lkdWlyZSBkdSBzdG9jayDCuyBwb3VyIGVucmVnaXN0cmVyIGF1c3NpIGxlcyB2ZW50ZXMuPC9wPgogICAgPGZvcm0gaWQ9Imludm9pY2UtZm9ybSI+CiAgICAgIDxsYWJlbD5Ob20gZHUgY2xpZW50IDxpbnB1dCB0eXBlPSJ0ZXh0IiBpZD0iaW52LWNsaWVudCIgcGxhY2Vob2xkZXI9ImV4LiBNYXJpZSBUcmVtYmxheSI+PC9sYWJlbD4KICAgICAgPGxhYmVsPkluZm9zIGNsaWVudCAoYWRyZXNzZSwgdMOpbMOpcGhvbmXigKYpIDxpbnB1dCB0eXBlPSJ0ZXh0IiBpZD0iaW52LWluZm8iIHBsYWNlaG9sZGVyPSJGYWN1bHRhdGlmIj48L2xhYmVsPgogICAgICA8bGFiZWw+VGF1eCBkZSB0YXhlcyAoJSkgPGlucHV0IHR5cGU9Im51bWJlciIgaWQ9Imludi10YXgiIG1pbj0iMCIgc3RlcD0iMC4wMSIgdmFsdWU9IjAiPjwvbGFiZWw+CiAgICAgIDxoMz5MaWduZXM8L2gzPgogICAgICA8ZGl2IGlkPSJpbnYtbGluZXMiPjwvZGl2PgogICAgICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgY2xhc3M9ImJ0biBzbWFsbCIgaWQ9Imludi1hZGQtbGluZSI+77yLIEFqb3V0ZXIgdW5lIGxpZ25lPC9idXR0b24+CiAgICAgIDxsYWJlbCBjbGFzcz0iY2hlY2tib3gtbGluZSI+PGlucHV0IHR5cGU9ImNoZWNrYm94IiBpZD0iaW52LWRlZHVjdCIgY2hlY2tlZD4gRMOpZHVpcmUgbGVzIHF1YW50aXTDqXMgZHUgc3RvY2sgKGNyw6llIGRlcyB2ZW50ZXMpPC9sYWJlbD4KICAgICAgPHAgaWQ9Imludi1lcnJvciIgY2xhc3M9ImVycm9yIiBoaWRkZW4+PC9wPgogICAgICA8YnV0dG9uIHR5cGU9InN1Ym1pdCIgY2xhc3M9ImJ0biBwcmltYXJ5IGJpZyI+Q3LDqWVyIGxhIGZhY3R1cmU8L2J1dHRvbj4KICAgIDwvZm9ybT5gKTsKICBjb25zdCBhZGRMaW5lID0gKCkgPT4gewogICAgY29uc3QgZGl2ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnZGl2Jyk7CiAgICBkaXYuY2xhc3NOYW1lID0gJ2ludm9pY2UtbGluZSc7CiAgICBkaXYuaW5uZXJIVE1MID0gYAogICAgICA8c2VsZWN0IGNsYXNzPSJpbC1hcnRpY2xlIj4ke3N0YXRlLmFydGljbGVzLm1hcCgoYSkgPT4gYDxvcHRpb24gdmFsdWU9IiR7YS5pZH0iPiR7ZXNjKGEubmFtZSl9IOKAlCAke21vbmV5KGEucHJpY2UpfTwvb3B0aW9uPmApLmpvaW4oJycpfTwvc2VsZWN0PgogICAgICA8aW5wdXQgdHlwZT0ibnVtYmVyIiBjbGFzcz0iaWwtcXR5IiBtaW49IjEiIHN0ZXA9IjEiIHZhbHVlPSIxIj4KICAgICAgPGlucHV0IHR5cGU9Im51bWJlciIgY2xhc3M9ImlsLXByaWNlIiBtaW49IjAiIHN0ZXA9IjAuMDEiIHZhbHVlPSIke3N0YXRlLmFydGljbGVzWzBdID8gc3RhdGUuYXJ0aWNsZXNbMF0ucHJpY2UgOiAwfSI+CiAgICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0iYnRuIHNtYWxsIGRhbmdlciBpbC1yZW1vdmUiPuKclTwvYnV0dG9uPmA7CiAgICBkaXYucXVlcnlTZWxlY3RvcignLmlsLWFydGljbGUnKS5hZGRFdmVudExpc3RlbmVyKCdjaGFuZ2UnLCAoZSkgPT4gewogICAgICBjb25zdCBhID0gc3RhdGUuYXJ0aWNsZXMuZmluZCgoeCkgPT4geC5pZCA9PT0gTnVtYmVyKGUudGFyZ2V0LnZhbHVlKSk7CiAgICAgIGlmIChhKSBkaXYucXVlcnlTZWxlY3RvcignLmlsLXByaWNlJykudmFsdWUgPSBhLnByaWNlOwogICAgfSk7CiAgICBkaXYucXVlcnlTZWxlY3RvcignLmlsLXJlbW92ZScpLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCkgPT4gZGl2LnJlbW92ZSgpKTsKICAgICQoJyNpbnYtbGluZXMnKS5hcHBlbmRDaGlsZChkaXYpOwogIH07CiAgJCgnI2ludi1hZGQtbGluZScpLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgYWRkTGluZSk7CiAgYWRkTGluZSgpOwogICQoJyNpbnZvaWNlLWZvcm0nKS5hZGRFdmVudExpc3RlbmVyKCdzdWJtaXQnLCBhc3luYyAoZSkgPT4gewogICAgZS5wcmV2ZW50RGVmYXVsdCgpOwogICAgY29uc3QgZXJyID0gJCgnI2ludi1lcnJvcicpOwogICAgZXJyLmhpZGRlbiA9IHRydWU7CiAgICBjb25zdCBsaW5lcyA9IFsuLi5kb2N1bWVudC5xdWVyeVNlbGVjdG9yQWxsKCcuaW52b2ljZS1saW5lJyldLm1hcCgocm93KSA9PiAoewogICAgICBhcnRpY2xlX2lkOiBOdW1iZXIocm93LnF1ZXJ5U2VsZWN0b3IoJy5pbC1hcnRpY2xlJykudmFsdWUpLAogICAgICBxdWFudGl0eTogTnVtYmVyKHJvdy5xdWVyeVNlbGVjdG9yKCcuaWwtcXR5JykudmFsdWUpLAogICAgICB1bml0X3ByaWNlOiBOdW1iZXIocm93LnF1ZXJ5U2VsZWN0b3IoJy5pbC1wcmljZScpLnZhbHVlKSwKICAgIH0pKTsKICAgIHRyeSB7CiAgICAgIGNvbnN0IGludiA9IGF3YWl0IGFwaSgnL2FwaS9pbnZvaWNlcycsIHsKICAgICAgICBtZXRob2Q6ICdQT1NUJywKICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7CiAgICAgICAgICBjbGllbnRfbmFtZTogJCgnI2ludi1jbGllbnQnKS52YWx1ZS50cmltKCksCiAgICAgICAgICBjbGllbnRfaW5mbzogJCgnI2ludi1pbmZvJykudmFsdWUudHJpbSgpLAogICAgICAgICAgdGF4X3JhdGU6IE51bWJlcigkKCcjaW52LXRheCcpLnZhbHVlIHx8IDApLAogICAgICAgICAgZGVkdWN0X3N0b2NrOiAkKCcjaW52LWRlZHVjdCcpLmNoZWNrZWQsCiAgICAgICAgICBsaW5lcywKICAgICAgICB9KSwKICAgICAgfSk7CiAgICAgIGNsb3NlTW9kYWwoKTsKICAgICAgdG9hc3QoYEZhY3R1cmUgJHtpbnYubnVtYmVyfSBjcsOpw6llLmApOwogICAgICBsb2FkSW52b2ljZXMoKTsgbG9hZEFydGljbGVzKCk7IGxvYWREYXNoYm9hcmQoKTsgbG9hZEhpc3RvcnkoKTsKICAgIH0gY2F0Y2ggKGV4KSB7IHNob3dFcnJvcihlcnIsIGV4Lm1lc3NhZ2UpOyB9CiAgfSk7Cn0pOwoKLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCi8vIMOJcXVpcGUgJiByw7RsZXMgKGFkbWluKQovLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KYXN5bmMgZnVuY3Rpb24gbG9hZFVzZXJzKCkgewogIHRyeSB7CiAgICBjb25zdCB1c2VycyA9IGF3YWl0IGFwaSgnL2FwaS91c2VycycpOwogICAgJCgnI3VzZXJzLWxpc3QnKS5pbm5lckhUTUwgPSB1c2Vycy5tYXAoKHUpID0+IGAKICAgICAgPGxpPjxzcGFuPjxiPiR7ZXNjKHUudXNlcm5hbWUpfTwvYj4g4oCUICR7Uk9MRV9MQUJFTFt1LnJvbGVdfTwvc3Bhbj4KICAgICAgPHNwYW4+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIHNtYWxsIiBvbmNsaWNrPSJyZXNldFVzZXJQYXNzd29yZCgke3UuaWR9LCcke2VzYyh1LnVzZXJuYW1lKX0nKSI+8J+UkSBOb3V2ZWF1IG1vdCBkZSBwYXNzZTwvYnV0dG9uPgogICAgICAgICR7dS5pZCAhPT0gc3RhdGUudXNlci5pZCA/IGA8YnV0dG9uIGNsYXNzPSJidG4gc21hbGwgZGFuZ2VyIiBvbmNsaWNrPSJkZWxldGVVc2VyKCR7dS5pZH0sJyR7ZXNjKHUudXNlcm5hbWUpfScpIj7wn5eR77iPPC9idXR0b24+YCA6ICcnfQogICAgICA8L3NwYW4+PC9saT5gKS5qb2luKCcnKTsKICB9IGNhdGNoIChfKSB7fQp9CgokKCcjdXNlci1mb3JtJykuYWRkRXZlbnRMaXN0ZW5lcignc3VibWl0JywgYXN5bmMgKGUpID0+IHsKICBlLnByZXZlbnREZWZhdWx0KCk7CiAgdHJ5IHsKICAgIGF3YWl0IGFwaSgnL2FwaS91c2VycycsIHsKICAgICAgbWV0aG9kOiAnUE9TVCcsCiAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsKICAgICAgICB1c2VybmFtZTogJCgnI3VzZXItbmFtZScpLnZhbHVlLnRyaW0oKSwKICAgICAgICBwYXNzd29yZDogJCgnI3VzZXItcGFzcycpLnZhbHVlLAogICAgICAgIHJvbGU6ICQoJyN1c2VyLXJvbGUnKS52YWx1ZSwKICAgICAgfSksCiAgICB9KTsKICAgIHRvYXN0KCdVdGlsaXNhdGV1ciBjcsOpw6kuJyk7CiAgICAkKCcjdXNlci1mb3JtJykucmVzZXQoKTsKICAgIGxvYWRVc2VycygpOwogIH0gY2F0Y2ggKGV4KSB7IHRvYXN0KGV4Lm1lc3NhZ2UpOyB9Cn0pOwoKYXN5bmMgZnVuY3Rpb24gZGVsZXRlVXNlcihpZCwgbmFtZSkgewogIGlmICghY29uZmlybShgU3VwcHJpbWVyIGwndXRpbGlzYXRldXIgwqsgJHtuYW1lfSDCuyA/YCkpIHJldHVybjsKICB0cnkgeyBhd2FpdCBhcGkoJy9hcGkvdXNlcnMvJyArIGlkLCB7IG1ldGhvZDogJ0RFTEVURScgfSk7IHRvYXN0KCdVdGlsaXNhdGV1ciBzdXBwcmltw6kuJyk7IGxvYWRVc2VycygpOyB9CiAgY2F0Y2ggKGUpIHsgdG9hc3QoZS5tZXNzYWdlKTsgfQp9Cgphc3luYyBmdW5jdGlvbiByZXNldFVzZXJQYXNzd29yZChpZCwgbmFtZSkgewogIGNvbnN0IHB3ID0gcHJvbXB0KGBOb3V2ZWF1IG1vdCBkZSBwYXNzZSBwb3VyIMKrICR7bmFtZX0gwrsgKDYgY2FyYWN0w6hyZXMgbWluLikgOmApOwogIGlmICghcHcpIHJldHVybjsKICB0cnkgewogICAgYXdhaXQgYXBpKCcvYXBpL3VzZXJzLycgKyBpZCwgeyBtZXRob2Q6ICdQVVQnLCBib2R5OiBKU09OLnN0cmluZ2lmeSh7IHBhc3N3b3JkOiBwdyB9KSB9KTsKICAgIHRvYXN0KCdNb3QgZGUgcGFzc2UgbWlzIMOgIGpvdXIuJyk7CiAgfSBjYXRjaCAoZSkgeyB0b2FzdChlLm1lc3NhZ2UpOyB9Cn0KCi8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQovLyBTYXV2ZWdhcmRlCi8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQokKCcjZXhwb3J0LWJ0bicpLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCkgPT4gewogIHdpbmRvdy5sb2NhdGlvbi5ocmVmID0gJy9hcGkvYmFja3VwL2V4cG9ydCc7CiAgdG9hc3QoJ0V4cG9ydCBlbiBjb3VycyBkZSB0w6lsw6ljaGFyZ2VtZW504oCmJyk7Cn0pOwoKJCgnI2ltcG9ydC1idG4nKS5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsIGFzeW5jICgpID0+IHsKICBjb25zdCBmaWxlID0gJCgnI2ltcG9ydC1maWxlJykuZmlsZXNbMF07CiAgaWYgKCFmaWxlKSB7ICQoJyNpbXBvcnQtbXNnJykudGV4dENvbnRlbnQgPSAnQ2hvaXNpc3NleiBk4oCZYWJvcmQgdW4gZmljaGllciBKU09OLic7IHJldHVybjsgfQogIGlmICghY29uZmlybSgnUmVzdGF1cmVyIGNldHRlIHNhdXZlZ2FyZGUgPyBMZXMgZG9ubsOpZXMgYWN0dWVsbGVzIHNlcm9udCByZW1wbGFjw6llcy4nKSkgcmV0dXJuOwogIHRyeSB7CiAgICBjb25zdCBkYXRhID0gSlNPTi5wYXJzZShhd2FpdCBmaWxlLnRleHQoKSk7CiAgICBjb25zdCByZXMgPSBhd2FpdCBhcGkoJy9hcGkvYmFja3VwL2ltcG9ydCcsIHsgbWV0aG9kOiAnUE9TVCcsIGJvZHk6IEpTT04uc3RyaW5naWZ5KGRhdGEpIH0pOwogICAgJCgnI2ltcG9ydC1tc2cnKS50ZXh0Q29udGVudCA9IHJlcy5yZXN0b3JlZEFkbWluCiAgICAgID8gJ1NhdXZlZ2FyZGUgcmVzdGF1csOpZS4gQXVjdW4gYWRtaW4gdHJvdXbDqSA6IGNvbXB0ZSBhZG1pbiAvIGFkbWluMTIzIHJlY3LDqcOpLicKICAgICAgOiAnU2F1dmVnYXJkZSByZXN0YXVyw6llIGF2ZWMgc3VjY8Oocy4nOwogICAgdG9hc3QoJ1NhdXZlZ2FyZGUgcmVzdGF1csOpZS4nKTsKICAgIGxvYWREYXNoYm9hcmQoKTsgbG9hZEFydGljbGVzKCk7IGxvYWRJbnZvaWNlcygpOwogIH0gY2F0Y2ggKGUpIHsKICAgICQoJyNpbXBvcnQtbXNnJykudGV4dENvbnRlbnQgPSAnRXJyZXVyIDogJyArIGUubWVzc2FnZTsKICB9Cn0pOwoKLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCi8vIETDqW1hcnJhZ2UKLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCmNoZWNrU2Vzc2lvbigpOwo=","style.css":"LyogR2VzdGlvbm5haXJlIGQnaW52ZW50YWlyZSDigJQgaW50ZXJmYWNlIGFjY3VlaWxsYW50ZSwgbW9kZXJuZSwgbW9iaWxlIGQnYWJvcmQgKi8KOnJvb3QgewogIC0tcHJpbWFyeTogIzRmNDZlNTsKICAtLXByaW1hcnktZGFyazogIzQzMzhjYTsKICAtLXByaW1hcnktc29mdDogI2VlZjJmZjsKICAtLXZpb2xldDogIzdjM2FlZDsKICAtLWdyZWVuOiAjMTZhMzRhOwogIC0tZ3JlZW4tc29mdDogI2RjZmNlNzsKICAtLXJlZDogI2RjMjYyNjsKICAtLXJlZC1zb2Z0OiAjZmVlMmUyOwogIC0tYW1iZXI6ICNkOTc3MDY7CiAgLS1hbWJlci1zb2Z0OiAjZmVmM2M3OwogIC0tY3lhbjogIzA4OTFiMjsKICAtLWJnOiAjZjNmNWZhOwogIC0tY2FyZDogI2ZmZmZmZjsKICAtLXRleHQ6ICMxZTI5M2I7CiAgLS1tdXRlZDogIzY0NzQ4YjsKICAtLWJvcmRlcjogI2UyZThmMDsKICAtLXJhZGl1czogMTZweDsKICAtLXNoYWRvdzogMCAxcHggM3B4IHJnYmEoMTUsIDIzLCA0MiwgLjA2KSwgMCA4cHggMjRweCByZ2JhKDE1LCAyMywgNDIsIC4wNik7CiAgLS1zaGFkb3ctbGc6IDAgMTZweCA0MHB4IHJnYmEoMTUsIDIzLCA0MiwgLjE2KTsKfQoqIHsgYm94LXNpemluZzogYm9yZGVyLWJveDsgfQovKiBMJ2F0dHJpYnV0IGhpZGRlbiBkb2l0IHRvdWpvdXJzIGNhY2hlciBsJ8OpbMOpbWVudCwgbcOqbWUgcXVhbmQgdW5lIGNsYXNzZQogICBkw6lmaW5pdCB1biBkaXNwbGF5IChleC4gLm1vZGFsLWJhY2tkcm9wIGVuIGRpc3BsYXk6ZmxleCkgOiBzYW5zIGNldHRlCiAgIHLDqGdsZSwgbGUgZm9uZCBzb21icmUgZGUgbGEgZmVuw6p0cmUgbW9kYWxlIHJlc3RlIGFmZmljaMOpIHBhci1kZXNzdXMKICAgdG91dGUgbGEgcGFnZSBldCBibG9xdWUgdG91cyBsZXMgY2xpY3MuICovCltoaWRkZW5dIHsgZGlzcGxheTogbm9uZSAhaW1wb3J0YW50OyB9CmJvZHkgeyBtYXJnaW46IDA7IGZvbnQtZmFtaWx5OiBzeXN0ZW0tdWksIC1hcHBsZS1zeXN0ZW0sICJTZWdvZSBVSSIsIFJvYm90bywgc2Fucy1zZXJpZjsgYmFja2dyb3VuZDogdmFyKC0tYmcpOyBjb2xvcjogdmFyKC0tdGV4dCk7IGxpbmUtaGVpZ2h0OiAxLjU7IH0KaDEgeyBmb250LXNpemU6IDEuNXJlbTsgbWFyZ2luOiAwIDAgOHB4OyBsZXR0ZXItc3BhY2luZzogLS4wMWVtOyB9CmgyIHsgZm9udC1zaXplOiAxLjM1cmVtOyBtYXJnaW46IDAgMCA0cHg7IGxldHRlci1zcGFjaW5nOiAtLjAxZW07IH0KaDMgeyBmb250LXNpemU6IDEuMDVyZW07IG1hcmdpbjogMCAwIDEwcHg7IH0KcCB7IG1hcmdpbjogNnB4IDA7IH0KLm11dGVkIHsgY29sb3I6IHZhcigtLW11dGVkKTsgZm9udC1zaXplOiAuOTJyZW07IH0KLmVycm9yIHsgY29sb3I6IHZhcigtLXJlZCk7IGZvbnQtc2l6ZTogLjkycmVtOyBmb250LXdlaWdodDogNjAwOyB9CmJ1dHRvbiB7IGZvbnQtZmFtaWx5OiBpbmhlcml0OyBjdXJzb3I6IHBvaW50ZXI7IH0KaW5wdXQsIHNlbGVjdCwgdGV4dGFyZWEgeyBmb250LWZhbWlseTogaW5oZXJpdDsgZm9udC1zaXplOiAxcmVtOyBwYWRkaW5nOiAxMXB4IDEycHg7IGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7IGJvcmRlci1yYWRpdXM6IDEycHg7IHdpZHRoOiAxMDAlOyBiYWNrZ3JvdW5kOiAjZmZmOyB0cmFuc2l0aW9uOiBib3JkZXItY29sb3IgLjEycywgYm94LXNoYWRvdyAuMTJzOyB9CmlucHV0OmZvY3VzLCBzZWxlY3Q6Zm9jdXMsIHRleHRhcmVhOmZvY3VzIHsgb3V0bGluZTogbm9uZTsgYm9yZGVyLWNvbG9yOiB2YXIoLS1wcmltYXJ5KTsgYm94LXNoYWRvdzogMCAwIDAgM3B4IHJnYmEoNzksIDcwLCAyMjksIC4xNSk7IH0KbGFiZWwgeyBkaXNwbGF5OiBibG9jazsgZm9udC1zaXplOiAuOTJyZW07IGZvbnQtd2VpZ2h0OiA2MDA7IG1hcmdpbi1ib3R0b206IDEycHg7IH0KbGFiZWwgaW5wdXQsIGxhYmVsIHNlbGVjdCwgbGFiZWwgdGV4dGFyZWEgeyBtYXJnaW4tdG9wOiA1cHg7IGZvbnQtd2VpZ2h0OiA0MDA7IH0KdGV4dGFyZWEgeyByZXNpemU6IHZlcnRpY2FsOyBtaW4taGVpZ2h0OiA3MHB4OyB9Cjpmb2N1cy12aXNpYmxlIHsgb3V0bGluZTogM3B4IHNvbGlkIHJnYmEoNzksIDcwLCAyMjksIC4zNSk7IG91dGxpbmUtb2Zmc2V0OiAycHg7IH0KCi8qIEJvdXRvbnMgKi8KLmJ0biB7IGJhY2tncm91bmQ6ICNmZmY7IGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7IGJvcmRlci1yYWRpdXM6IDEycHg7IHBhZGRpbmc6IDExcHggMThweDsgZm9udC1zaXplOiAuOTVyZW07IGZvbnQtd2VpZ2h0OiA2MDA7IGNvbG9yOiB2YXIoLS10ZXh0KTsgYm94LXNoYWRvdzogMCAxcHggMnB4IHJnYmEoMTUsIDIzLCA0MiwgLjA1KTsgdHJhbnNpdGlvbjogdHJhbnNmb3JtIC4xMnMsIGJveC1zaGFkb3cgLjEycywgYmFja2dyb3VuZCAuMTJzOyB9Ci5idG46aG92ZXIgeyBiYWNrZ3JvdW5kOiAjZjhmYWZjOyB0cmFuc2Zvcm06IHRyYW5zbGF0ZVkoLTFweCk7IH0KLmJ0bjphY3RpdmUgeyB0cmFuc2Zvcm06IHRyYW5zbGF0ZVkoMCk7IH0KLmJ0bi5wcmltYXJ5IHsgYmFja2dyb3VuZDogbGluZWFyLWdyYWRpZW50KDEzNWRlZywgIzRmNDZlNSwgIzdjM2FlZCk7IGJvcmRlci1jb2xvcjogdHJhbnNwYXJlbnQ7IGNvbG9yOiAjZmZmOyBib3gtc2hhZG93OiAwIDZweCAxNnB4IHJnYmEoNzksIDcwLCAyMjksIC4zNSk7IH0KLmJ0bi5wcmltYXJ5OmhvdmVyIHsgYmFja2dyb3VuZDogbGluZWFyLWdyYWRpZW50KDEzNWRlZywgIzQzMzhjYSwgIzZkMjhkOSk7IGJveC1zaGFkb3c6IDAgOHB4IDIwcHggcmdiYSg3OSwgNzAsIDIyOSwgLjQpOyB9Ci5idG4uZGFuZ2VyIHsgY29sb3I6IHZhcigtLXJlZCk7IGJvcmRlci1jb2xvcjogI2ZlY2FjYTsgfQouYnRuLmRhbmdlcjpob3ZlciB7IGJhY2tncm91bmQ6ICNmZWYyZjI7IH0KLmJ0bi5zbWFsbCB7IHBhZGRpbmc6IDdweCAxMXB4OyBmb250LXNpemU6IC44NXJlbTsgfQouYnRuLmJpZyB7IHdpZHRoOiAxMDAlOyBwYWRkaW5nOiAxNHB4OyBmb250LXNpemU6IDEuMDVyZW07IGJvcmRlci1yYWRpdXM6IDEycHg7IH0KLmJ0bjpkaXNhYmxlZCB7IG9wYWNpdHk6IC41OyBjdXJzb3I6IG5vdC1hbGxvd2VkOyB0cmFuc2Zvcm06IG5vbmU7IH0KCi8qIENvbm5leGlvbiAqLwoubG9naW4td3JhcCB7IG1pbi1oZWlnaHQ6IDEwMHZoOyBkaXNwbGF5OiBmbGV4OyBhbGlnbi1pdGVtczogY2VudGVyOyBqdXN0aWZ5LWNvbnRlbnQ6IGNlbnRlcjsgcGFkZGluZzogMjBweDsKICBiYWNrZ3JvdW5kOgogICAgcmFkaWFsLWdyYWRpZW50KDYwMHB4IDQyMHB4IGF0IDEyJSA4JSwgcmdiYSgxMjQsIDU4LCAyMzcsIC4zNSksIHRyYW5zcGFyZW50IDYwJSksCiAgICByYWRpYWwtZ3JhZGllbnQoNTIwcHggMzgwcHggYXQgODglIDkyJSwgcmdiYSgyNDUsIDE1OCwgMTEsIC4yOCksIHRyYW5zcGFyZW50IDYwJSksCiAgICBsaW5lYXItZ3JhZGllbnQoMTYwZGVnLCAjMzEyZTgxLCAjNGY0NmU1IDU1JSwgIzdjM2FlZCk7IH0KLmxvZ2luLWNhcmQgeyBiYWNrZ3JvdW5kOiAjZmZmOyBib3JkZXItcmFkaXVzOiAyNHB4OyBib3gtc2hhZG93OiB2YXIoLS1zaGFkb3ctbGcpOyBwYWRkaW5nOiAzNnB4IDMwcHggMjhweDsgd2lkdGg6IDEwMCU7IG1heC13aWR0aDogNDMwcHg7IHRleHQtYWxpZ246IGNlbnRlcjsgfQoubG9nbyB7IGZvbnQtc2l6ZTogMi42cmVtOyB3aWR0aDogNzhweDsgaGVpZ2h0OiA3OHB4OyBtYXJnaW46IDAgYXV0byAxNHB4OyBkaXNwbGF5OiBmbGV4OyBhbGlnbi1pdGVtczogY2VudGVyOyBqdXN0aWZ5LWNvbnRlbnQ6IGNlbnRlcjsgYmFja2dyb3VuZDogbGluZWFyLWdyYWRpZW50KDEzNWRlZywgI2VlZjJmZiwgI2RkZDZmZSk7IGJvcmRlci1yYWRpdXM6IDI0cHg7IGJveC1zaGFkb3c6IGluc2V0IDAgMCAwIDFweCByZ2JhKDc5LCA3MCwgMjI5LCAuMTIpOyB9Ci5zdWJ0aXRsZSB7IGNvbG9yOiB2YXIoLS1tdXRlZCk7IG1hcmdpbi1ib3R0b206IDI0cHg7IH0KLmxvZ2luLWNhcmQgZm9ybSB7IHRleHQtYWxpZ246IGxlZnQ7IH0KLmhpbnQgeyBmb250LXNpemU6IC44NXJlbTsgY29sb3I6IHZhcigtLW11dGVkKTsgbWFyZ2luLXRvcDogMThweDsgYmFja2dyb3VuZDogI2Y4ZmFmYzsgYm9yZGVyLXJhZGl1czogMTBweDsgcGFkZGluZzogMTBweCAxMnB4OyB9CgovKiBCYXJyZSBkdSBoYXV0ICsgb25nbGV0cyAqLwoudG9wYmFyIHsgZGlzcGxheTogZmxleDsganVzdGlmeS1jb250ZW50OiBzcGFjZS1iZXR3ZWVuOyBhbGlnbi1pdGVtczogY2VudGVyOyBnYXA6IDEwcHg7IHBhZGRpbmc6IDE0cHggMjBweDsgYmFja2dyb3VuZDogcmdiYSgyNTUsIDI1NSwgMjU1LCAuOTQpOyBiYWNrZHJvcC1maWx0ZXI6IGJsdXIoOHB4KTsgYm9yZGVyLWJvdHRvbTogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7IHBvc2l0aW9uOiBzdGlja3k7IHRvcDogMDsgei1pbmRleDogMTA7IGJveC1zaGFkb3c6IDAgMXB4IDEwcHggcmdiYSgxNSwgMjMsIDQyLCAuMDUpOyB9Ci5icmFuZCB7IGZvbnQtc2l6ZTogMS4yNXJlbTsgZm9udC13ZWlnaHQ6IDgwMDsgbGV0dGVyLXNwYWNpbmc6IC0uMDJlbTsgfQouYnJhbmQgc3BhbiB7IGJhY2tncm91bmQ6IGxpbmVhci1ncmFkaWVudCg5MGRlZywgIzRmNDZlNSwgIzdjM2FlZCk7IC13ZWJraXQtYmFja2dyb3VuZC1jbGlwOiB0ZXh0OyBiYWNrZ3JvdW5kLWNsaXA6IHRleHQ7IGNvbG9yOiB0cmFuc3BhcmVudDsgfQoudXNlcmJveCB7IGRpc3BsYXk6IGZsZXg7IGFsaWduLWl0ZW1zOiBjZW50ZXI7IGdhcDogOHB4OyB9Ci5jaGlwIHsgYmFja2dyb3VuZDogI2VlZjJmZjsgY29sb3I6ICM0MzM4Y2E7IGJvcmRlci1yYWRpdXM6IDk5OXB4OyBwYWRkaW5nOiA2cHggMTJweDsgZm9udC1zaXplOiAuODVyZW07IGZvbnQtd2VpZ2h0OiA3MDA7IH0KLnRhYnMgeyBkaXNwbGF5OiBmbGV4OyBnYXA6IDhweDsgcGFkZGluZzogMTJweCAxNnB4OyBvdmVyZmxvdy14OiBhdXRvOyBiYWNrZ3JvdW5kOiAjZmZmOyBib3JkZXItYm90dG9tOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsgfQoudGFicyBidXR0b24geyB3aGl0ZS1zcGFjZTogbm93cmFwOyBib3JkZXI6IDFweCBzb2xpZCB0cmFuc3BhcmVudDsgYmFja2dyb3VuZDogbm9uZTsgcGFkZGluZzogOXB4IDE0cHg7IGJvcmRlci1yYWRpdXM6IDk5OXB4OyBmb250LXNpemU6IC45NXJlbTsgZm9udC13ZWlnaHQ6IDYwMDsgY29sb3I6IHZhcigtLW11dGVkKTsgdHJhbnNpdGlvbjogYmFja2dyb3VuZCAuMTJzLCBjb2xvciAuMTJzLCBib3gtc2hhZG93IC4xMnM7IH0KLnRhYnMgYnV0dG9uOmhvdmVyIHsgYmFja2dyb3VuZDogI2YxZjVmOTsgY29sb3I6IHZhcigtLXRleHQpOyB9Ci50YWJzIGJ1dHRvbi5hY3RpdmUgeyBiYWNrZ3JvdW5kOiBsaW5lYXItZ3JhZGllbnQoMTM1ZGVnLCAjNGY0NmU1LCAjN2MzYWVkKTsgY29sb3I6ICNmZmY7IGJveC1zaGFkb3c6IDAgNHB4IDEycHggcmdiYSg3OSwgNzAsIDIyOSwgLjM1KTsgfQptYWluIHsgbWF4LXdpZHRoOiAxMTIwcHg7IG1hcmdpbjogMCBhdXRvOyBwYWRkaW5nOiAyNHB4IDIwcHggNjRweDsgfQoudGFiLXBhZ2UgeyBhbmltYXRpb246IGZhZGUgLjJzIGVhc2U7IH0KQGtleWZyYW1lcyBmYWRlIHsgZnJvbSB7IG9wYWNpdHk6IDA7IH0gdG8geyBvcGFjaXR5OiAxOyB9IH0KCi8qIEJhbm5pw6hyZSBkJ2FjY3VlaWwgKyBhY3Rpb25zIHJhcGlkZXMgKi8KLmhlcm8geyBiYWNrZ3JvdW5kOiBsaW5lYXItZ3JhZGllbnQoMTIwZGVnLCAjMzEyZTgxIDAlLCAjNGY0NmU1IDU1JSwgIzdjM2FlZCAxMDAlKTsgYm9yZGVyLXJhZGl1czogMjBweDsgY29sb3I6ICNmZmY7IHBhZGRpbmc6IDI2cHggMjRweDsgbWFyZ2luLWJvdHRvbTogMThweDsgZGlzcGxheTogZmxleDsganVzdGlmeS1jb250ZW50OiBzcGFjZS1iZXR3ZWVuOyBhbGlnbi1pdGVtczogY2VudGVyOyBnYXA6IDE4cHg7IGZsZXgtd3JhcDogd3JhcDsgYm94LXNoYWRvdzogMCAxNHB4IDMycHggcmdiYSg3OSwgNzAsIDIyOSwgLjMpOyB9Ci5oZXJvIGgyIHsgY29sb3I6ICNmZmY7IGZvbnQtc2l6ZTogMS42cmVtOyBtYXJnaW46IDAgMCA0cHg7IH0KLmhlcm8gLm11dGVkIHsgY29sb3I6IHJnYmEoMjU1LCAyNTUsIDI1NSwgLjg1KTsgbWFyZ2luOiAwOyB9Ci5xdWljay1hY3Rpb25zIHsgZGlzcGxheTogZmxleDsgZ2FwOiAxMHB4OyBmbGV4LXdyYXA6IHdyYXA7IH0KLnF1aWNrLWFjdGlvbnMgLmJ0biB7IGJvcmRlci1yYWRpdXM6IDk5OXB4OyBwYWRkaW5nOiAxMHB4IDE2cHg7IHdoaXRlLXNwYWNlOiBub3dyYXA7IH0KLnF1aWNrLWFjdGlvbnMgLmJ0bi5wcmltYXJ5IHsgYmFja2dyb3VuZDogI2ZmZjsgY29sb3I6ICM0MzM4Y2E7IGJvcmRlci1jb2xvcjogdHJhbnNwYXJlbnQ7IGJveC1zaGFkb3c6IDAgNHB4IDE0cHggcmdiYSgwLCAwLCAwLCAuMTgpOyB9Ci5xdWljay1hY3Rpb25zIC5idG4ucHJpbWFyeTpob3ZlciB7IGJhY2tncm91bmQ6ICNlZWYyZmY7IH0KLnF1aWNrLWFjdGlvbnMgLmJ0bjpub3QoLnByaW1hcnkpIHsgYmFja2dyb3VuZDogcmdiYSgyNTUsIDI1NSwgMjU1LCAuMTQpOyBjb2xvcjogI2ZmZjsgYm9yZGVyLWNvbG9yOiByZ2JhKDI1NSwgMjU1LCAyNTUsIC40KTsgYm94LXNoYWRvdzogbm9uZTsgfQoucXVpY2stYWN0aW9ucyAuYnRuOm5vdCgucHJpbWFyeSk6aG92ZXIgeyBiYWNrZ3JvdW5kOiByZ2JhKDI1NSwgMjU1LCAyNTUsIC4yNik7IH0KCi8qIENhcnRlcyBldCBpbmRpY2F0ZXVycyAqLwouY2FyZCB7IGJhY2tncm91bmQ6IHZhcigtLWNhcmQpOyBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOyBib3JkZXItcmFkaXVzOiAxOHB4OyBwYWRkaW5nOiAyMHB4OyBtYXJnaW4tYm90dG9tOiAxOHB4OyBib3gtc2hhZG93OiB2YXIoLS1zaGFkb3cpOyB9Ci5jYXJkLWhlYWQgeyBkaXNwbGF5OiBmbGV4OyBqdXN0aWZ5LWNvbnRlbnQ6IHNwYWNlLWJldHdlZW47IGFsaWduLWl0ZW1zOiBjZW50ZXI7IGZsZXgtd3JhcDogd3JhcDsgZ2FwOiA4cHg7IH0KLmtwaXMgeyBkaXNwbGF5OiBncmlkOyBncmlkLXRlbXBsYXRlLWNvbHVtbnM6IHJlcGVhdCg0LCAxZnIpOyBnYXA6IDE0cHg7IG1hcmdpbjogMThweCAwOyB9Ci5rcGkgeyBiYWNrZ3JvdW5kOiAjZmZmOyBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOyBib3JkZXItcmFkaXVzOiAxOHB4OyBwYWRkaW5nOiAxOHB4OyBkaXNwbGF5OiBmbGV4OyBmbGV4LWRpcmVjdGlvbjogY29sdW1uOyBnYXA6IDRweDsgYm94LXNoYWRvdzogdmFyKC0tc2hhZG93KTsgcG9zaXRpb246IHJlbGF0aXZlOyBvdmVyZmxvdzogaGlkZGVuOyB9Ci5rcGk6OmJlZm9yZSB7IGNvbnRlbnQ6ICIiOyBwb3NpdGlvbjogYWJzb2x1dGU7IGxlZnQ6IDA7IHRvcDogMDsgYm90dG9tOiAwOyB3aWR0aDogNHB4OyBiYWNrZ3JvdW5kOiB2YXIoLS1wcmltYXJ5KTsgfQoua3BpcyAua3BpOm50aC1jaGlsZCgxKTo6YmVmb3JlIHsgYmFja2dyb3VuZDogIzRmNDZlNTsgfQoua3BpcyAua3BpOm50aC1jaGlsZCgyKTo6YmVmb3JlIHsgYmFja2dyb3VuZDogIzA4OTFiMjsgfQoua3BpcyAua3BpOm50aC1jaGlsZCgzKTo6YmVmb3JlIHsgYmFja2dyb3VuZDogIzE2YTM0YTsgfQoua3BpcyAua3BpOm50aC1jaGlsZCg0KTo6YmVmb3JlIHsgYmFja2dyb3VuZDogI2Q5NzcwNjsgfQoua3BpLWxhYmVsIHsgZm9udC1zaXplOiAuNzhyZW07IGNvbG9yOiB2YXIoLS1tdXRlZCk7IGZvbnQtd2VpZ2h0OiA3MDA7IGxldHRlci1zcGFjaW5nOiAuMDVlbTsgdGV4dC10cmFuc2Zvcm06IHVwcGVyY2FzZTsgfQoua3BpLXZhbHVlIHsgZm9udC1zaXplOiAxLjVyZW07IGZvbnQtd2VpZ2h0OiA4MDA7IGxldHRlci1zcGFjaW5nOiAtLjAyZW07IH0KLmtwaXMgLmtwaTpudGgtY2hpbGQoMSkgLmtwaS12YWx1ZSB7IGNvbG9yOiAjNGY0NmU1OyB9Ci5rcGlzIC5rcGk6bnRoLWNoaWxkKDIpIC5rcGktdmFsdWUgeyBjb2xvcjogIzA4OTFiMjsgfQoua3BpcyAua3BpOm50aC1jaGlsZCgzKSAua3BpLXZhbHVlIHsgY29sb3I6ICMxNmEzNGE7IH0KLmtwaXMgLmtwaTpudGgtY2hpbGQoNCkgLmtwaS12YWx1ZSB7IGNvbG9yOiAjZDk3NzA2OyB9Ci5ncmlkMiB7IGRpc3BsYXk6IGdyaWQ7IGdyaWQtdGVtcGxhdGUtY29sdW1uczogMWZyIDFmcjsgZ2FwOiAxNnB4OyB9Ci5saXN0IHsgbGlzdC1zdHlsZTogbm9uZTsgbWFyZ2luOiAwOyBwYWRkaW5nOiAwOyB9Ci5saXN0IGxpIHsgcGFkZGluZzogMTFweCAwOyBib3JkZXItYm90dG9tOiAxcHggc29saWQgI2YxZjVmOTsgZGlzcGxheTogZmxleDsganVzdGlmeS1jb250ZW50OiBzcGFjZS1iZXR3ZWVuOyBnYXA6IDEwcHg7IGFsaWduLWl0ZW1zOiBjZW50ZXI7IH0KLmxpc3QgbGk6bGFzdC1jaGlsZCB7IGJvcmRlci1ib3R0b206IG5vbmU7IH0KLnNlZyB7IGRpc3BsYXk6IGlubGluZS1mbGV4OyBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOyBib3JkZXItcmFkaXVzOiA5OTlweDsgb3ZlcmZsb3c6IGhpZGRlbjsgYmFja2dyb3VuZDogI2YxZjVmOTsgcGFkZGluZzogM3B4OyB9Ci5zZWcgYnV0dG9uIHsgYm9yZGVyOiBub25lOyBiYWNrZ3JvdW5kOiB0cmFuc3BhcmVudDsgcGFkZGluZzogN3B4IDEycHg7IGZvbnQtc2l6ZTogLjg1cmVtOyBmb250LXdlaWdodDogNjAwOyBjb2xvcjogdmFyKC0tbXV0ZWQpOyBib3JkZXItcmFkaXVzOiA5OTlweDsgfQouc2VnIGJ1dHRvbi5hY3RpdmUgeyBiYWNrZ3JvdW5kOiBsaW5lYXItZ3JhZGllbnQoMTM1ZGVnLCAjNGY0NmU1LCAjN2MzYWVkKTsgY29sb3I6ICNmZmY7IGJveC1zaGFkb3c6IDAgM3B4IDhweCByZ2JhKDc5LCA3MCwgMjI5LCAuMyk7IH0KY2FudmFzI2NoYXJ0IHsgd2lkdGg6IDEwMCU7IG1heC1oZWlnaHQ6IDIyMHB4OyB9CgovKiBBbGVydGVzICovCi5hbGVydCB7IGJvcmRlci1yYWRpdXM6IDE0cHg7IHBhZGRpbmc6IDE0cHggMTZweDsgbWFyZ2luLWJvdHRvbTogMTRweDsgZm9udC1zaXplOiAuOTVyZW07IGRpc3BsYXk6IGZsZXg7IGdhcDogMTBweDsgYWxpZ24taXRlbXM6IGZsZXgtc3RhcnQ7IGJvcmRlcjogMXB4IHNvbGlkOyB9Ci5hbGVydC53YXJuIHsgYmFja2dyb3VuZDogI2ZlZjNjNzsgYm9yZGVyLWNvbG9yOiAjZmNkMzRkOyBib3JkZXItbGVmdDogNHB4IHNvbGlkICNkOTc3MDY7IH0KLmFsZXJ0LmRhbmdlciB7IGJhY2tncm91bmQ6ICNmZWUyZTI7IGJvcmRlci1jb2xvcjogI2ZjYTVhNTsgYm9yZGVyLWxlZnQ6IDRweCBzb2xpZCAjZGMyNjI2OyB9Ci5hbGVydC5vayB7IGJhY2tncm91bmQ6ICNkY2ZjZTc7IGJvcmRlci1jb2xvcjogIzg2ZWZhYzsgYm9yZGVyLWxlZnQ6IDRweCBzb2xpZCAjMTZhMzRhOyB9CgovKiBBcnRpY2xlcyAqLwoucGFnZS1oZWFkIHsgZGlzcGxheTogZmxleDsganVzdGlmeS1jb250ZW50OiBzcGFjZS1iZXR3ZWVuOyBhbGlnbi1pdGVtczogZmxleC1zdGFydDsgZ2FwOiAxMnB4OyBmbGV4LXdyYXA6IHdyYXA7IG1hcmdpbi1ib3R0b206IDE2cHg7IH0KLnNlYXJjaC1yb3cgeyBkaXNwbGF5OiBmbGV4OyBnYXA6IDEwcHg7IG1hcmdpbi1ib3R0b206IDE2cHg7IH0KLnNlYXJjaC1yb3cgaW5wdXQgeyBmbGV4OiAyOyB9Ci5zZWFyY2gtcm93IHNlbGVjdCB7IGZsZXg6IDE7IH0KLmFydGljbGVzLWdyaWQgeyBkaXNwbGF5OiBncmlkOyBncmlkLXRlbXBsYXRlLWNvbHVtbnM6IHJlcGVhdChhdXRvLWZpbGwsIG1pbm1heCgyNTBweCwgMWZyKSk7IGdhcDogMTZweDsgbWFyZ2luLWJvdHRvbTogMjBweDsgfQouYXJ0aWNsZS1jYXJkIHsgYmFja2dyb3VuZDogI2ZmZjsgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsgYm9yZGVyLXJhZGl1czogMThweDsgb3ZlcmZsb3c6IGhpZGRlbjsgZGlzcGxheTogZmxleDsgZmxleC1kaXJlY3Rpb246IGNvbHVtbjsgYm94LXNoYWRvdzogdmFyKC0tc2hhZG93KTsgdHJhbnNpdGlvbjogdHJhbnNmb3JtIC4xNXMsIGJveC1zaGFkb3cgLjE1czsgfQouYXJ0aWNsZS1jYXJkOmhvdmVyIHsgdHJhbnNmb3JtOiB0cmFuc2xhdGVZKC0zcHgpOyBib3gtc2hhZG93OiB2YXIoLS1zaGFkb3ctbGcpOyB9Ci5hcnRpY2xlLWNhcmQgaW1nIHsgd2lkdGg6IDEwMCU7IGhlaWdodDogMTYwcHg7IG9iamVjdC1maXQ6IGNvdmVyOyBiYWNrZ3JvdW5kOiBsaW5lYXItZ3JhZGllbnQoMTM1ZGVnLCAjZWVmMmZmLCAjZGRkNmZlKTsgfQouYXJ0aWNsZS1jYXJkIC5uby1waG90byB7IGhlaWdodDogMTYwcHg7IGRpc3BsYXk6IGZsZXg7IGFsaWduLWl0ZW1zOiBjZW50ZXI7IGp1c3RpZnktY29udGVudDogY2VudGVyOyBmb250LXNpemU6IDNyZW07IGJhY2tncm91bmQ6IGxpbmVhci1ncmFkaWVudCgxMzVkZWcsICNlZWYyZmYsICNkZGQ2ZmUpOyB9Ci5hcnRpY2xlLWJvZHkgeyBwYWRkaW5nOiAxNnB4OyBkaXNwbGF5OiBmbGV4OyBmbGV4LWRpcmVjdGlvbjogY29sdW1uOyBnYXA6IDhweDsgZmxleDogMTsgfQouYXJ0aWNsZS1ib2R5IGgzIHsgbWFyZ2luOiAwOyB9Ci5hcnRpY2xlLWJvZHkgLmRlc2MgeyBjb2xvcjogdmFyKC0tbXV0ZWQpOyBmb250LXNpemU6IC45cmVtOyBmbGV4OiAxOyB9Ci5wcmljZSB7IGZvbnQtd2VpZ2h0OiA4MDA7IGZvbnQtc2l6ZTogMS4ycmVtOyBjb2xvcjogdmFyKC0tcHJpbWFyeS1kYXJrKTsgfQouc3RvY2stbGluZSB7IGRpc3BsYXk6IGZsZXg7IGp1c3RpZnktY29udGVudDogc3BhY2UtYmV0d2VlbjsgYWxpZ24taXRlbXM6IGNlbnRlcjsgZ2FwOiA4cHg7IH0KLmJhZGdlIHsgZm9udC1zaXplOiAuNzhyZW07IGZvbnQtd2VpZ2h0OiA3MDA7IGJvcmRlci1yYWRpdXM6IDk5OXB4OyBwYWRkaW5nOiA0cHggMTBweDsgd2hpdGUtc3BhY2U6IG5vd3JhcDsgfQouYmFkZ2Uub2sgeyBiYWNrZ3JvdW5kOiAjZGNmY2U3OyBjb2xvcjogIzE2NjUzNDsgfQouYmFkZ2Uud2FybiB7IGJhY2tncm91bmQ6ICNmZWYzYzc7IGNvbG9yOiAjOTI0MDBlOyB9Ci5iYWRnZS5vdXQgeyBiYWNrZ3JvdW5kOiAjZmVlMmUyOyBjb2xvcjogIzk5MWIxYjsgfQoucXR5LXJvdyB7IGRpc3BsYXk6IGZsZXg7IGdhcDogNnB4OyBmbGV4LXdyYXA6IHdyYXA7IH0KLnF0eS1yb3cgLmJ0biB7IGZsZXg6IDE7IHBhZGRpbmc6IDlweCA0cHg7IGZvbnQtc2l6ZTogLjg1cmVtOyB9Ci5lbXB0eSB7IHRleHQtYWxpZ246IGNlbnRlcjsgY29sb3I6IHZhcigtLW11dGVkKTsgcGFkZGluZzogNDhweCAxMnB4OyBib3JkZXI6IDJweCBkYXNoZWQgdmFyKC0tYm9yZGVyKTsgYm9yZGVyLXJhZGl1czogMTZweDsgYmFja2dyb3VuZDogI2ZmZjsgfQoKLyogVGFibGVhdXggKi8KLnRhYmxlLXdyYXAgeyBvdmVyZmxvdy14OiBhdXRvOyBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOyBib3JkZXItcmFkaXVzOiAxNHB4OyBiYWNrZ3JvdW5kOiAjZmZmOyB9CnRhYmxlIHsgd2lkdGg6IDEwMCU7IGJvcmRlci1jb2xsYXBzZTogY29sbGFwc2U7IGZvbnQtc2l6ZTogLjkycmVtOyB9CnRoLCB0ZCB7IHBhZGRpbmc6IDEwcHg7IGJvcmRlci1ib3R0b206IDFweCBzb2xpZCAjZjFmNWY5OyB0ZXh0LWFsaWduOiBsZWZ0OyB3aGl0ZS1zcGFjZTogbm93cmFwOyB9CnRoIHsgY29sb3I6IHZhcigtLW11dGVkKTsgZm9udC1zaXplOiAuNzhyZW07IHRleHQtdHJhbnNmb3JtOiB1cHBlcmNhc2U7IGxldHRlci1zcGFjaW5nOiAuMDVlbTsgYmFja2dyb3VuZDogI2Y4ZmFmYzsgfQp0Ym9keSB0cjpob3ZlciB0ZCB7IGJhY2tncm91bmQ6ICNmOGZhZmM7IH0KdGJvZHkgdHI6bGFzdC1jaGlsZCB0ZCB7IGJvcmRlci1ib3R0b206IG5vbmU7IH0KLnRhZyB7IGZvbnQtc2l6ZTogLjc4cmVtOyBmb250LXdlaWdodDogNzAwOyBib3JkZXItcmFkaXVzOiA5OTlweDsgcGFkZGluZzogM3B4IDlweDsgfQoudGFnLmVudHJlZSB7IGJhY2tncm91bmQ6ICNkY2ZjZTc7IGNvbG9yOiAjMTY2NTM0OyB9Ci50YWcudmVudGUgeyBiYWNrZ3JvdW5kOiAjZGJlYWZlOyBjb2xvcjogIzFlNDBhZjsgfQoudGFnLnNvcnRpZSB7IGJhY2tncm91bmQ6ICNmZWUyZTI7IGNvbG9yOiAjOTkxYjFiOyB9Ci5maWx0ZXJzIHsgZGlzcGxheTogZmxleDsgZ2FwOiA4cHg7IGZsZXgtd3JhcDogd3JhcDsgbWFyZ2luLWJvdHRvbTogMTJweDsgfQouZmlsdGVycyBzZWxlY3QsIC5maWx0ZXJzIGlucHV0IHsgd2lkdGg6IGF1dG87IGZsZXg6IDE7IG1pbi13aWR0aDogMTIwcHg7IH0KCi8qIEZvcm11bGFpcmVzICovCi5mb3JtLWdyaWQgeyBkaXNwbGF5OiBncmlkOyBncmlkLXRlbXBsYXRlLWNvbHVtbnM6IDFmciAxZnI7IGdhcDogMCAxNnB4OyB9Ci5mb3JtLWdyaWQgbGFiZWwuZnVsbCB7IGdyaWQtY29sdW1uOiAxIC8gLTE7IH0KLnN0ZXBzIHsgZGlzcGxheTogZmxleDsgZ2FwOiA2cHg7IG1hcmdpbi1ib3R0b206IDE2cHg7IH0KLnN0ZXBzIHNwYW4geyBmbGV4OiAxOyB0ZXh0LWFsaWduOiBjZW50ZXI7IGZvbnQtc2l6ZTogLjhyZW07IGZvbnQtd2VpZ2h0OiA3MDA7IHBhZGRpbmc6IDhweCA0cHg7IGJvcmRlci1yYWRpdXM6IDk5OXB4OyBiYWNrZ3JvdW5kOiAjZjFmNWY5OyBjb2xvcjogdmFyKC0tbXV0ZWQpOyB9Ci5zdGVwcyBzcGFuLm9uIHsgYmFja2dyb3VuZDogbGluZWFyLWdyYWRpZW50KDEzNWRlZywgIzRmNDZlNSwgIzdjM2FlZCk7IGNvbG9yOiAjZmZmOyBib3gtc2hhZG93OiAwIDNweCAxMHB4IHJnYmEoNzksIDcwLCAyMjksIC4zKTsgfQoucGhvdG8tcHJldmlldyB7IHdpZHRoOiAxMDAlOyBtYXgtaGVpZ2h0OiAyMDBweDsgb2JqZWN0LWZpdDogY29udGFpbjsgYm9yZGVyOiAxcHggZGFzaGVkIHZhcigtLWJvcmRlcik7IGJvcmRlci1yYWRpdXM6IDEycHg7IG1hcmdpbi10b3A6IDhweDsgfQouY2hlY2tib3gtbGluZSB7IGRpc3BsYXk6IGZsZXg7IGFsaWduLWl0ZW1zOiBjZW50ZXI7IGdhcDogOHB4OyBmb250LXdlaWdodDogNjAwOyB9Ci5jaGVja2JveC1saW5lIGlucHV0IHsgd2lkdGg6IGF1dG87IH0KLmludm9pY2UtbGluZSB7IGRpc3BsYXk6IGdyaWQ7IGdyaWQtdGVtcGxhdGUtY29sdW1uczogMmZyIDFmciAxZnIgYXV0bzsgZ2FwOiA4cHg7IG1hcmdpbi1ib3R0b206IDhweDsgYWxpZ24taXRlbXM6IGNlbnRlcjsgfQouaW52b2ljZS1saW5lIHNlbGVjdCwgLmludm9pY2UtbGluZSBpbnB1dCB7IHdpZHRoOiAxMDAlOyB9CgovKiBNb2RhbGUgKyB0b2FzdCAqLwoubW9kYWwtYmFja2Ryb3AgeyBwb3NpdGlvbjogZml4ZWQ7IGluc2V0OiAwOyBiYWNrZ3JvdW5kOiByZ2JhKDE1LCAyMywgNDIsIC41NSk7IGJhY2tkcm9wLWZpbHRlcjogYmx1cigzcHgpOyBkaXNwbGF5OiBmbGV4OyBhbGlnbi1pdGVtczogZmxleC1zdGFydDsganVzdGlmeS1jb250ZW50OiBjZW50ZXI7IHBhZGRpbmc6IDI0cHggMTRweDsgei1pbmRleDogNTA7IG92ZXJmbG93LXk6IGF1dG87IH0KLm1vZGFsIHsgYmFja2dyb3VuZDogI2ZmZjsgYm9yZGVyLXJhZGl1czogMjBweDsgcGFkZGluZzogMjZweDsgd2lkdGg6IDEwMCU7IG1heC13aWR0aDogNTIwcHg7IHBvc2l0aW9uOiByZWxhdGl2ZTsgbWFyZ2luLXRvcDogMjBweDsgYm94LXNoYWRvdzogdmFyKC0tc2hhZG93LWxnKTsgYW5pbWF0aW9uOiBwb3AgLjE4cyBlYXNlOyB9CkBrZXlmcmFtZXMgcG9wIHsgZnJvbSB7IHRyYW5zZm9ybTogdHJhbnNsYXRlWSg4cHgpIHNjYWxlKC45OCk7IG9wYWNpdHk6IDA7IH0gfQoubW9kYWwtY2xvc2UgeyBwb3NpdGlvbjogYWJzb2x1dGU7IHRvcDogMTBweDsgcmlnaHQ6IDEycHg7IGJvcmRlcjogbm9uZTsgYmFja2dyb3VuZDogbm9uZTsgZm9udC1zaXplOiAxLjJyZW07IGNvbG9yOiB2YXIoLS1tdXRlZCk7IGJvcmRlci1yYWRpdXM6IDhweDsgcGFkZGluZzogNHB4IDEwcHg7IH0KLm1vZGFsLWNsb3NlOmhvdmVyIHsgYmFja2dyb3VuZDogI2YxZjVmOTsgY29sb3I6IHZhcigtLXRleHQpOyB9Ci50b2FzdCB7IHBvc2l0aW9uOiBmaXhlZDsgYm90dG9tOiAyMHB4OyBsZWZ0OiA1MCU7IHRyYW5zZm9ybTogdHJhbnNsYXRlWCgtNTAlKTsgYmFja2dyb3VuZDogIzExMTgyNzsgY29sb3I6ICNmZmY7IHBhZGRpbmc6IDEycHggMThweDsgYm9yZGVyLXJhZGl1czogOTk5cHg7IGZvbnQtc2l6ZTogLjk1cmVtOyB6LWluZGV4OiAxMDA7IGJveC1zaGFkb3c6IDAgNnB4IDIwcHggcmdiYSgwLDAsMCwuMyk7IG1heC13aWR0aDogOTB2dzsgdGV4dC1hbGlnbjogY2VudGVyOyB9CgovKiBQZXRpdCDDqWNyYW4gKi8KQG1lZGlhIChtYXgtd2lkdGg6IDcwMHB4KSB7CiAgLmtwaXMgeyBncmlkLXRlbXBsYXRlLWNvbHVtbnM6IDFmciAxZnI7IH0KICAuZ3JpZDIgeyBncmlkLXRlbXBsYXRlLWNvbHVtbnM6IDFmcjsgfQogIC5mb3JtLWdyaWQgeyBncmlkLXRlbXBsYXRlLWNvbHVtbnM6IDFmcjsgfQogIC5zZWFyY2gtcm93IHsgZmxleC1kaXJlY3Rpb246IGNvbHVtbjsgfQogIC5pbnZvaWNlLWxpbmUgeyBncmlkLXRlbXBsYXRlLWNvbHVtbnM6IDFmciAxZnI7IH0KICAuYnJhbmQgc3BhbiB7IGRpc3BsYXk6IG5vbmU7IH0KICAuaGVybyB7IHBhZGRpbmc6IDIwcHg7IGZsZXgtZGlyZWN0aW9uOiBjb2x1bW47IGFsaWduLWl0ZW1zOiBmbGV4LXN0YXJ0OyB9CiAgLmhlcm8gaDIgeyBmb250LXNpemU6IDEuNHJlbTsgfQogIC5xdWljay1hY3Rpb25zIHsgd2lkdGg6IDEwMCU7IH0KICAucXVpY2stYWN0aW9ucyAuYnRuIHsgZmxleDogMSAxIGF1dG87IHRleHQtYWxpZ246IGNlbnRlcjsgfQogIC5sb2dpbi1jYXJkIHsgcGFkZGluZzogMjhweCAyMnB4OyB9CiAgbWFpbiB7IHBhZGRpbmc6IDE4cHggMTRweCA1NnB4OyB9Cn0K"};
// EMBEDDED_FRONTEND_END
if (PUBLIC_DIR) {
  console.log(`Interface trouvée : ${PUBLIC_DIR}`);
  app.use(express.static(PUBLIC_DIR));
  app.get('/', (req, res) => res.sendFile(path.join(PUBLIC_DIR, 'index.html')));
} else if (EMBEDDED) {
  // Secours : le dossier public/ n'a pas été téléversé, on sert la copie
  // intégrée dans ce fichier. L'application fonctionne normalement.
  console.log('Interface intégrée utilisée (dossier public/ absent sur le serveur).');
  const sendEmbedded = (name, type) => (req, res) =>
    res.type(type).send(Buffer.from(EMBEDDED[name], 'base64').toString('utf8'));
  app.get('/', sendEmbedded('index.html', 'html'));
  app.get('/app.js', sendEmbedded('app.js', 'js'));
  app.get('/style.css', sendEmbedded('style.css', 'css'));
} else {
  console.log('ATTENTION : dossier public/ introuvable. Emplacements essayés : ' + PUBLIC_CANDIDATES.join(' | '));
  console.log('Vérifiez que le dossier public (avec index.html) a bien été téléversé sur l’hébergeur.');
  app.get('/', (req, res) => res.status(500).type('html').send(
    '<h1>Interface introuvable</h1><p>Le dossier <code>public/</code> (avec <code>index.html</code>) ' +
    'n’a pas été trouvé sur le serveur. Vérifiez que le dossier <code>public</code> a bien été téléversé ' +
    'avec le reste du projet, puis redéployez.</p>'
  ));
}

app.listen(PORT, HOST, () => {
  console.log(`Gestionnaire d'inventaire en ligne sur http://${HOST}:${PORT}`);
  console.log(`Base de données : ${DB_PATH}`);
});
