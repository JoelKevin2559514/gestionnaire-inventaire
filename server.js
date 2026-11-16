// ============================================================================
// Gestionnaire d'inventaire — serveur autonome
// Node.js + Express + SQLite intégré (node:sqlite, aucune compilation native)
// Démarrage : node server.js  (port via la variable PORT, écoute 0.0.0.0)
//Version1.3
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

const money = (n) => (Math.round((Number(n) || 0) * 100) / 100).toFixed(2) + ' $';

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
app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Identifiant et mot de passe requis.' });
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(String(username).trim());
  if (!user || !bcrypt.compareSync(String(password), user.password_hash)) {
    return res.status(401).json({ error: 'Identifiant ou mot de passe incorrect.' });
  }
  const token = crypto.randomBytes(32).toString('hex');
  const expires = new Date(Date.now() + SESSION_DAYS * 24 * 3600 * 1000).toISOString();
  db.prepare('INSERT INTO sessions (token, user_id, expires_at, created_at) VALUES (?,?,?,?)')
    .run(token, user.id, expires, nowIso());
  res.cookie('session', token, {
    httpOnly: true, path: '/', sameSite: 'lax',
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
const EMBEDDED = {"index.html":"PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9ImZyIj4KPGhlYWQ+CjxtZXRhIGNoYXJzZXQ9InV0Zi04Ij4KPG1ldGEgbmFtZT0idmlld3BvcnQiIGNvbnRlbnQ9IndpZHRoPWRldmljZS13aWR0aCwgaW5pdGlhbC1zY2FsZT0xIj4KPHRpdGxlPkdlc3Rpb25uYWlyZSBkJ2ludmVudGFpcmU8L3RpdGxlPgo8bGluayByZWw9InN0eWxlc2hlZXQiIGhyZWY9InN0eWxlLmNzcyI+CjwvaGVhZD4KPGJvZHk+Cgo8IS0tID09PT09PT09PT09PT09PT09PT09IMOJQ1JBTiBERSBDT05ORVhJT04gPT09PT09PT09PT09PT09PT09PT0gLS0+CjxkaXYgaWQ9ImxvZ2luLXZpZXciIGNsYXNzPSJsb2dpbi13cmFwIj4KICA8ZGl2IGNsYXNzPSJsb2dpbi1jYXJkIj4KICAgIDxkaXYgY2xhc3M9ImxvZ28iPvCfk6Y8L2Rpdj4KICAgIDxoMT5HZXN0aW9ubmFpcmUgZCdpbnZlbnRhaXJlPC9oMT4KICAgIDxwIGNsYXNzPSJzdWJ0aXRsZSI+Vm9zIGFydGljbGVzLCB2b3MgdmVudGVzIGV0IHZvdHJlIHN0b2NrIOKAlCBwYXJ0b3V0LCBlbiDDqXF1aXBlLjwvcD4KICAgIDxmb3JtIGlkPSJsb2dpbi1mb3JtIj4KICAgICAgPGxhYmVsPklkZW50aWZpYW50CiAgICAgICAgPGlucHV0IHR5cGU9InRleHQiIGlkPSJsb2dpbi11c2VybmFtZSIgYXV0b2NvbXBsZXRlPSJ1c2VybmFtZSIgcGxhY2Vob2xkZXI9ImV4LiBhZG1pbiIgcmVxdWlyZWQ+CiAgICAgIDwvbGFiZWw+CiAgICAgIDxsYWJlbD5Nb3QgZGUgcGFzc2UKICAgICAgICA8aW5wdXQgdHlwZT0icGFzc3dvcmQiIGlkPSJsb2dpbi1wYXNzd29yZCIgYXV0b2NvbXBsZXRlPSJjdXJyZW50LXBhc3N3b3JkIiBwbGFjZWhvbGRlcj0i4oCi4oCi4oCi4oCi4oCi4oCi4oCi4oCiIiByZXF1aXJlZD4KICAgICAgPC9sYWJlbD4KICAgICAgPHAgaWQ9ImxvZ2luLWVycm9yIiBjbGFzcz0iZXJyb3IiIGhpZGRlbj48L3A+CiAgICAgIDxidXR0b24gdHlwZT0ic3VibWl0IiBjbGFzcz0iYnRuIHByaW1hcnkgYmlnIj5TZSBjb25uZWN0ZXI8L2J1dHRvbj4KICAgIDwvZm9ybT4KICAgIDxwIGNsYXNzPSJoaW50Ij5QcmVtacOocmUgY29ubmV4aW9uIDogPGI+YWRtaW48L2I+IC8gPGI+YWRtaW4xMjM8L2I+IOKAlCBjaGFuZ2V6IGxlIG1vdCBkZSBwYXNzZSBlbnN1aXRlLjwvcD4KICA8L2Rpdj4KPC9kaXY+Cgo8IS0tIENoYW5nZW1lbnQgZGUgbW90IGRlIHBhc3NlIG9ibGlnYXRvaXJlIChwcmVtacOocmUgY29ubmV4aW9uKSAtLT4KPGRpdiBpZD0icGFzc3dvcmQtdmlldyIgY2xhc3M9ImxvZ2luLXdyYXAiIGhpZGRlbj4KICA8ZGl2IGNsYXNzPSJsb2dpbi1jYXJkIj4KICAgIDxkaXYgY2xhc3M9ImxvZ28iPvCflJE8L2Rpdj4KICAgIDxoMT5DaGFuZ2V6IHZvdHJlIG1vdCBkZSBwYXNzZTwvaDE+CiAgICA8cCBjbGFzcz0ic3VidGl0bGUiPkMnZXN0IHZvdHJlIHByZW1pw6hyZSBjb25uZXhpb24gOiBjaG9pc2lzc2V6IHVuIG1vdCBkZSBwYXNzZSBwZXJzb25uZWwuPC9wPgogICAgPGZvcm0gaWQ9InBhc3N3b3JkLWZvcm0iPgogICAgICA8bGFiZWw+TW90IGRlIHBhc3NlIGFjdHVlbAogICAgICAgIDxpbnB1dCB0eXBlPSJwYXNzd29yZCIgaWQ9InB3LWN1cnJlbnQiIGF1dG9jb21wbGV0ZT0iY3VycmVudC1wYXNzd29yZCIgcmVxdWlyZWQ+CiAgICAgIDwvbGFiZWw+CiAgICAgIDxsYWJlbD5Ob3V2ZWF1IG1vdCBkZSBwYXNzZSAoNiBjYXJhY3TDqHJlcyBtaW4uKQogICAgICAgIDxpbnB1dCB0eXBlPSJwYXNzd29yZCIgaWQ9InB3LW5ldyIgYXV0b2NvbXBsZXRlPSJuZXctcGFzc3dvcmQiIHJlcXVpcmVkIG1pbmxlbmd0aD0iNiI+CiAgICAgIDwvbGFiZWw+CiAgICAgIDxsYWJlbD5Db25maXJtZXIgbGUgbm91dmVhdSBtb3QgZGUgcGFzc2UKICAgICAgICA8aW5wdXQgdHlwZT0icGFzc3dvcmQiIGlkPSJwdy1jb25maXJtIiBhdXRvY29tcGxldGU9Im5ldy1wYXNzd29yZCIgcmVxdWlyZWQgbWlubGVuZ3RoPSI2Ij4KICAgICAgPC9sYWJlbD4KICAgICAgPHAgaWQ9InB3LWVycm9yIiBjbGFzcz0iZXJyb3IiIGhpZGRlbj48L3A+CiAgICAgIDxidXR0b24gdHlwZT0ic3VibWl0IiBjbGFzcz0iYnRuIHByaW1hcnkgYmlnIj5FbnJlZ2lzdHJlcjwvYnV0dG9uPgogICAgPC9mb3JtPgogIDwvZGl2Pgo8L2Rpdj4KCjwhLS0gPT09PT09PT09PT09PT09PT09PT0gQVBQTElDQVRJT04gPT09PT09PT09PT09PT09PT09PT0gLS0+CjxkaXYgaWQ9ImFwcC12aWV3IiBoaWRkZW4+CiAgPGhlYWRlciBjbGFzcz0idG9wYmFyIj4KICAgIDxkaXYgY2xhc3M9ImJyYW5kIj7wn5OmIDxzcGFuPkludmVudGFpcmU8L3NwYW4+PC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJ1c2VyYm94Ij4KICAgICAgPHNwYW4gaWQ9InVzZXItY2hpcCIgY2xhc3M9ImNoaXAiPjwvc3Bhbj4KICAgICAgPGJ1dHRvbiBpZD0ibG9nb3V0LWJ0biIgY2xhc3M9ImJ0biBzbWFsbCI+RMOpY29ubmV4aW9uPC9idXR0b24+CiAgICA8L2Rpdj4KICA8L2hlYWRlcj4KCiAgPG5hdiBjbGFzcz0idGFicyIgaWQ9InRhYnMiPgogICAgPGJ1dHRvbiBkYXRhLXRhYj0iZGFzaGJvYXJkIiBjbGFzcz0iYWN0aXZlIj7wn4+gIFRhYmxlYXUgZGUgYm9yZDwvYnV0dG9uPgogICAgPGJ1dHRvbiBkYXRhLXRhYj0iYXJ0aWNsZXMiPvCfk6YgQXJ0aWNsZXM8L2J1dHRvbj4KICAgIDxidXR0b24gZGF0YS10YWI9Imludm9pY2VzIj7wn6e+IEZhY3R1cmVzPC9idXR0b24+CiAgICA8YnV0dG9uIGRhdGEtdGFiPSJ0ZWFtIiBpZD0idGFiLXRlYW0iPvCfkaUgw4lxdWlwZSAmYW1wOyByw7RsZXM8L2J1dHRvbj4KICAgIDxidXR0b24gZGF0YS10YWI9ImJhY2t1cCI+8J+SviBTYXV2ZWdhcmRlPC9idXR0b24+CiAgPC9uYXY+CgogIDxtYWluPgogICAgPCEtLSAtLS0tLSBUYWJsZWF1IGRlIGJvcmQgLS0tLS0gLS0+CiAgICA8c2VjdGlvbiBpZD0idGFiLWRhc2hib2FyZCIgY2xhc3M9InRhYi1wYWdlIj4KICAgICAgPGgyIGlkPSJ3ZWxjb21lLXRpdGxlIj5Cb25qb3VyIPCfkYs8L2gyPgogICAgICA8cCBjbGFzcz0ibXV0ZWQiPlZvaWNpIGwnw6l0YXQgZGUgdm90cmUgaW52ZW50YWlyZSBhdWpvdXJkJ2h1aS48L3A+CgogICAgICA8ZGl2IGlkPSJhbGVydHMtYm94Ij48L2Rpdj4KCiAgICAgIDxkaXYgY2xhc3M9ImtwaXMiPgogICAgICAgIDxkaXYgY2xhc3M9ImtwaSI+PHNwYW4gY2xhc3M9ImtwaS1sYWJlbCI+VmVudGVzIGR1IGpvdXI8L3NwYW4+PHNwYW4gY2xhc3M9ImtwaS12YWx1ZSIgaWQ9ImtwaS10b2RheSI+4oCUPC9zcGFuPjwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9ImtwaSI+PHNwYW4gY2xhc3M9ImtwaS1sYWJlbCI+VmVudGVzIGR1IG1vaXM8L3NwYW4+PHNwYW4gY2xhc3M9ImtwaS12YWx1ZSIgaWQ9ImtwaS1tb250aCI+4oCUPC9zcGFuPjwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9ImtwaSI+PHNwYW4gY2xhc3M9ImtwaS1sYWJlbCI+VmFsZXVyIGR1IHN0b2NrPC9zcGFuPjxzcGFuIGNsYXNzPSJrcGktdmFsdWUiIGlkPSJrcGktc3RvY2siPuKAlDwvc3Bhbj48L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJrcGkiPjxzcGFuIGNsYXNzPSJrcGktbGFiZWwiPkFydGljbGVzPC9zcGFuPjxzcGFuIGNsYXNzPSJrcGktdmFsdWUiIGlkPSJrcGktY291bnQiPuKAlDwvc3Bhbj48L2Rpdj4KICAgICAgPC9kaXY+CgogICAgICA8ZGl2IGNsYXNzPSJjYXJkIj4KICAgICAgICA8ZGl2IGNsYXNzPSJjYXJkLWhlYWQiPgogICAgICAgICAgPGgzPvCfk4ogVmVudGVzPC9oMz4KICAgICAgICAgIDxkaXYgY2xhc3M9InNlZyI+CiAgICAgICAgICAgIDxidXR0b24gaWQ9ImNoYXJ0LWRhaWx5IiBjbGFzcz0iYWN0aXZlIj5Kb3VybmFsaWVyICgzMCBqKTwvYnV0dG9uPgogICAgICAgICAgICA8YnV0dG9uIGlkPSJjaGFydC1tb250aGx5Ij5NZW5zdWVsICgxMiBtb2lzKTwvYnV0dG9uPgogICAgICAgICAgPC9kaXY+CiAgICAgICAgPC9kaXY+CiAgICAgICAgPGNhbnZhcyBpZD0iY2hhcnQiIGhlaWdodD0iMTgwIj48L2NhbnZhcz4KICAgICAgPC9kaXY+CgogICAgICA8ZGl2IGNsYXNzPSJncmlkMiI+CiAgICAgICAgPGRpdiBjbGFzcz0iY2FyZCI+CiAgICAgICAgICA8aDM+8J+PhiBBcnRpY2xlcyBsZXMgcGx1cyB2ZW5kdXM8L2gzPgogICAgICAgICAgPHVsIGlkPSJ0b3Atc2VsbGVycyIgY2xhc3M9Imxpc3QiPjwvdWw+CiAgICAgICAgPC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0iY2FyZCI+CiAgICAgICAgICA8aDM+8J+VkSBEZXJuaWVycyBtb3V2ZW1lbnRzPC9oMz4KICAgICAgICAgIDx1bCBpZD0icmVjZW50LW1vdmVtZW50cyIgY2xhc3M9Imxpc3QiPjwvdWw+CiAgICAgICAgPC9kaXY+CiAgICAgIDwvZGl2PgogICAgPC9zZWN0aW9uPgoKICAgIDwhLS0gLS0tLS0gQXJ0aWNsZXMgLS0tLS0gLS0+CiAgICA8c2VjdGlvbiBpZD0idGFiLWFydGljbGVzIiBjbGFzcz0idGFiLXBhZ2UiIGhpZGRlbj4KICAgICAgPGRpdiBjbGFzcz0icGFnZS1oZWFkIj4KICAgICAgICA8ZGl2PgogICAgICAgICAgPGgyPkFydGljbGVzPC9oMj4KICAgICAgICAgIDxwIGNsYXNzPSJtdXRlZCI+QWpvdXRleiB1biBhcnRpY2xlIGVuIDMgw6l0YXBlcyA6IHBob3RvLCBub20gZXQgZGVzY3JpcHRpb24sIHB1aXMgcHJpeCBldCBzdG9jay48L3A+CiAgICAgICAgPC9kaXY+CiAgICAgICAgPGJ1dHRvbiBpZD0ibmV3LWFydGljbGUtYnRuIiBjbGFzcz0iYnRuIHByaW1hcnkiPu+8iyBOb3V2ZWwgYXJ0aWNsZTwvYnV0dG9uPgogICAgICA8L2Rpdj4KCiAgICAgIDxkaXYgY2xhc3M9InNlYXJjaC1yb3ciPgogICAgICAgIDxpbnB1dCB0eXBlPSJzZWFyY2giIGlkPSJhcnRpY2xlLXNlYXJjaCIgcGxhY2Vob2xkZXI9IvCflI0gUmVjaGVyY2hlciB1biBhcnRpY2xl4oCmIj4KICAgICAgICA8c2VsZWN0IGlkPSJhcnRpY2xlLWZpbHRlciI+CiAgICAgICAgICA8b3B0aW9uIHZhbHVlPSIiPlRvdXRlcyBsZXMgY2F0w6lnb3JpZXM8L29wdGlvbj4KICAgICAgICA8L3NlbGVjdD4KICAgICAgPC9kaXY+CgogICAgICA8ZGl2IGlkPSJhcnRpY2xlcy1ncmlkIiBjbGFzcz0iYXJ0aWNsZXMtZ3JpZCI+PC9kaXY+CgogICAgICA8ZGl2IGNsYXNzPSJjYXJkIj4KICAgICAgICA8aDM+8J+VkSBIaXN0b3JpcXVlIGRlcyBtb3V2ZW1lbnRzPC9oMz4KICAgICAgICA8ZGl2IGNsYXNzPSJmaWx0ZXJzIj4KICAgICAgICAgIDxzZWxlY3QgaWQ9Imhpc3QtdHlwZSI+CiAgICAgICAgICAgIDxvcHRpb24gdmFsdWU9IiI+VG91cyBsZXMgdHlwZXM8L29wdGlvbj4KICAgICAgICAgICAgPG9wdGlvbiB2YWx1ZT0iZW50cmVlIj5FbnRyw6llczwvb3B0aW9uPgogICAgICAgICAgICA8b3B0aW9uIHZhbHVlPSJ2ZW50ZSI+VmVudGVzPC9vcHRpb24+CiAgICAgICAgICAgIDxvcHRpb24gdmFsdWU9InNvcnRpZSI+U29ydGllczwvb3B0aW9uPgogICAgICAgICAgPC9zZWxlY3Q+CiAgICAgICAgICA8aW5wdXQgdHlwZT0iZGF0ZSIgaWQ9Imhpc3QtZnJvbSIgdGl0bGU9IkR1Ij4KICAgICAgICAgIDxpbnB1dCB0eXBlPSJkYXRlIiBpZD0iaGlzdC10byIgdGl0bGU9IkF1Ij4KICAgICAgICAgIDxidXR0b24gaWQ9Imhpc3QtYXBwbHkiIGNsYXNzPSJidG4gc21hbGwiPkZpbHRyZXI8L2J1dHRvbj4KICAgICAgICA8L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJ0YWJsZS13cmFwIj4KICAgICAgICAgIDx0YWJsZT4KICAgICAgICAgICAgPHRoZWFkPjx0cj48dGg+RGF0ZTwvdGg+PHRoPkFydGljbGU8L3RoPjx0aD5UeXBlPC90aD48dGg+UXTDqTwvdGg+PHRoPlByaXggdW5pdC48L3RoPjx0aD5Ub3RhbDwvdGg+PHRoPlBhcjwvdGg+PHRoPk5vdGU8L3RoPjwvdHI+PC90aGVhZD4KICAgICAgICAgICAgPHRib2R5IGlkPSJoaXN0b3J5LWJvZHkiPjwvdGJvZHk+CiAgICAgICAgICA8L3RhYmxlPgogICAgICAgIDwvZGl2PgogICAgICA8L2Rpdj4KICAgIDwvc2VjdGlvbj4KCiAgICA8IS0tIC0tLS0tIEZhY3R1cmVzIC0tLS0tIC0tPgogICAgPHNlY3Rpb24gaWQ9InRhYi1pbnZvaWNlcyIgY2xhc3M9InRhYi1wYWdlIiBoaWRkZW4+CiAgICAgIDxkaXYgY2xhc3M9InBhZ2UtaGVhZCI+CiAgICAgICAgPGRpdj4KICAgICAgICAgIDxoMj5GYWN0dXJlczwvaDI+CiAgICAgICAgICA8cCBjbGFzcz0ibXV0ZWQiPkxhIGZhY3R1cmUgZXN0IDxiPmZhY3VsdGF0aXZlPC9iPiA6IHZvdXMgcG91dmV6IHZlbmRyZSBzYW5zIGVuIGNyw6llci4gQ3LDqWV6LWVuIHVuZSBpY2kgcXVhbmQgdW4gY2xpZW50IGVuIGRlbWFuZGUgdW5lLjwvcD4KICAgICAgICA8L2Rpdj4KICAgICAgICA8YnV0dG9uIGlkPSJuZXctaW52b2ljZS1idG4iIGNsYXNzPSJidG4gcHJpbWFyeSI+77yLIE5vdXZlbGxlIGZhY3R1cmU8L2J1dHRvbj4KICAgICAgPC9kaXY+CiAgICAgIDxkaXYgaWQ9Imludm9pY2VzLWxpc3QiPjwvZGl2PgogICAgPC9zZWN0aW9uPgoKICAgIDwhLS0gLS0tLS0gw4lxdWlwZSAmIHLDtGxlcyAtLS0tLSAtLT4KICAgIDxzZWN0aW9uIGlkPSJ0YWItdGVhbSIgY2xhc3M9InRhYi1wYWdlIiBoaWRkZW4+CiAgICAgIDxoMj7DiXF1aXBlICZhbXA7IHLDtGxlczwvaDI+CiAgICAgIDxwIGNsYXNzPSJtdXRlZCI+U2V1bCBsJ2FkbWluaXN0cmF0ZXVyIGfDqHJlIGxlcyBjb21wdGVzLjwvcD4KICAgICAgPGRpdiBjbGFzcz0iY2FyZCI+CiAgICAgICAgPGgzPvCfkaQgQWpvdXRlciB1biB1dGlsaXNhdGV1cjwvaDM+CiAgICAgICAgPGZvcm0gaWQ9InVzZXItZm9ybSIgY2xhc3M9ImZvcm0tZ3JpZCI+CiAgICAgICAgICA8bGFiZWw+SWRlbnRpZmlhbnQgPGlucHV0IHR5cGU9InRleHQiIGlkPSJ1c2VyLW5hbWUiIHJlcXVpcmVkIHBsYWNlaG9sZGVyPSJleC4gbWFyaWUiPjwvbGFiZWw+CiAgICAgICAgICA8bGFiZWw+TW90IGRlIHBhc3NlIDxpbnB1dCB0eXBlPSJwYXNzd29yZCIgaWQ9InVzZXItcGFzcyIgcmVxdWlyZWQgbWlubGVuZ3RoPSI2IiBwbGFjZWhvbGRlcj0iNiBjYXJhY3TDqHJlcyBtaW4uIj48L2xhYmVsPgogICAgICAgICAgPGxhYmVsPlLDtGxlCiAgICAgICAgICAgIDxzZWxlY3QgaWQ9InVzZXItcm9sZSI+CiAgICAgICAgICAgICAgPG9wdGlvbiB2YWx1ZT0iZW1wbG95ZSI+RW1wbG95w6kg4oCUIHZlbmQsIGZhY3R1cmUsIGfDqHJlIGxlIHN0b2NrPC9vcHRpb24+CiAgICAgICAgICAgICAgPG9wdGlvbiB2YWx1ZT0iYWRtaW4iPkFkbWluIOKAlCB0b3V0LCB5IGNvbXByaXMgY2F0YWxvZ3VlIGV0IHV0aWxpc2F0ZXVyczwvb3B0aW9uPgogICAgICAgICAgICAgIDxvcHRpb24gdmFsdWU9ImxlY3R1cmUiPkxlY3R1cmUgc2V1bGUg4oCUIGNvbnN1bHRlIHNldWxlbWVudDwvb3B0aW9uPgogICAgICAgICAgICA8L3NlbGVjdD4KICAgICAgICAgIDwvbGFiZWw+CiAgICAgICAgICA8YnV0dG9uIHR5cGU9InN1Ym1pdCIgY2xhc3M9ImJ0biBwcmltYXJ5Ij5DcsOpZXIgbCd1dGlsaXNhdGV1cjwvYnV0dG9uPgogICAgICAgIDwvZm9ybT4KICAgICAgPC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9ImNhcmQiPgogICAgICAgIDxoMz7wn5GlIE1lbWJyZXMgZGUgbCfDqXF1aXBlPC9oMz4KICAgICAgICA8dWwgaWQ9InVzZXJzLWxpc3QiIGNsYXNzPSJsaXN0Ij48L3VsPgogICAgICA8L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0iY2FyZCI+CiAgICAgICAgPGgzPvCflJAgUsO0bGVzIGV4cGxpcXXDqXM8L2gzPgogICAgICAgIDx1bCBjbGFzcz0ibGlzdCI+CiAgICAgICAgICA8bGk+PGI+QWRtaW48L2I+IDogZ8OocmUgbGUgY2F0YWxvZ3VlLCBsZXMgcHJpeCwgbGVzIHBob3RvcyBldCBsZXMgdXRpbGlzYXRldXJzLjwvbGk+CiAgICAgICAgICA8bGk+PGI+RW1wbG95w6k8L2I+IDogZW5yZWdpc3RyZSBsZXMgdmVudGVzIGV0IGxlcyBlbnRyw6llcy9zb3J0aWVzLCBjcsOpZSBkZXMgZmFjdHVyZXMuPC9saT4KICAgICAgICAgIDxsaT48Yj5MZWN0dXJlIHNldWxlPC9iPiA6IGNvbnN1bHRlIGxlIHRhYmxlYXUgZGUgYm9yZCBldCBsZXMgYXJ0aWNsZXMsIG5lIG1vZGlmaWUgcmllbi48L2xpPgogICAgICAgIDwvdWw+CiAgICAgIDwvZGl2PgogICAgPC9zZWN0aW9uPgoKICAgIDwhLS0gLS0tLS0gU2F1dmVnYXJkZSAtLS0tLSAtLT4KICAgIDxzZWN0aW9uIGlkPSJ0YWItYmFja3VwIiBjbGFzcz0idGFiLXBhZ2UiIGhpZGRlbj4KICAgICAgPGgyPlNhdXZlZ2FyZGU8L2gyPgogICAgICA8cCBjbGFzcz0ibXV0ZWQiPlN1ciB1biBow6liZXJnZXVyIGdyYXR1aXQsIGxlcyBkb25uw6llcyBwZXV2ZW50IMOqdHJlIGVmZmFjw6llcyBzaSBsZSBzZXJ2aWNlIGRvcnQgdHJvcCBsb25ndGVtcHMuCiAgICAgIEV4cG9ydGV6IHLDqWd1bGnDqHJlbWVudCB1bmUgY29waWUgZGUgdm9zIGRvbm7DqWVzIGV0IGdhcmRlei1sYSBwcsOpY2lldXNlbWVudC48L3A+CiAgICAgIDxkaXYgY2xhc3M9ImNhcmQiPgogICAgICAgIDxoMz7wn5K+IEV4cG9ydGVyIG1lcyBkb25uw6llczwvaDM+CiAgICAgICAgPHA+VMOpbMOpY2hhcmdlIHVuIGZpY2hpZXIgSlNPTiBhdmVjIHRvdXMgdm9zIGFydGljbGVzLCBtb3V2ZW1lbnRzLCBmYWN0dXJlcyBldCB1dGlsaXNhdGV1cnMuPC9wPgogICAgICAgIDxidXR0b24gaWQ9ImV4cG9ydC1idG4iIGNsYXNzPSJidG4gcHJpbWFyeSI+4qyH77iPIEV4cG9ydGVyIGVuIEpTT048L2J1dHRvbj4KICAgICAgPC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9ImNhcmQiPgogICAgICAgIDxoMz7wn5OlIFJlc3RhdXJlciB1bmUgc2F1dmVnYXJkZTwvaDM+CiAgICAgICAgPHA+Q2hvaXNpc3NleiB1biBmaWNoaWVyIEpTT04gZXhwb3J0w6kgcHLDqWPDqWRlbW1lbnQuIDxiPkF0dGVudGlvbiA6PC9iPiBsZXMgZG9ubsOpZXMgYWN0dWVsbGVzIHNlcm9udCByZW1wbGFjw6llcy48L3A+CiAgICAgICAgPGlucHV0IHR5cGU9ImZpbGUiIGlkPSJpbXBvcnQtZmlsZSIgYWNjZXB0PSJhcHBsaWNhdGlvbi9qc29uIj4KICAgICAgICA8YnV0dG9uIGlkPSJpbXBvcnQtYnRuIiBjbGFzcz0iYnRuIj5SZXN0YXVyZXIgY2V0dGUgc2F1dmVnYXJkZTwvYnV0dG9uPgogICAgICAgIDxwIGlkPSJpbXBvcnQtbXNnIiBjbGFzcz0ibXV0ZWQiPjwvcD4KICAgICAgPC9kaXY+CiAgICA8L3NlY3Rpb24+CiAgPC9tYWluPgo8L2Rpdj4KCjwhLS0gPT09PT09PT09PT09PT09PT09PT0gRkVOw4pUUkVTIChtb2RhbGVzKSA9PT09PT09PT09PT09PT09PT09PSAtLT4KPGRpdiBpZD0ibW9kYWwtYmFja2Ryb3AiIGNsYXNzPSJtb2RhbC1iYWNrZHJvcCIgaGlkZGVuPgogIDxkaXYgY2xhc3M9Im1vZGFsIiByb2xlPSJkaWFsb2ciIGFyaWEtbW9kYWw9InRydWUiPgogICAgPGJ1dHRvbiBjbGFzcz0ibW9kYWwtY2xvc2UiIGlkPSJtb2RhbC1jbG9zZSI+4pyVPC9idXR0b24+CiAgICA8ZGl2IGlkPSJtb2RhbC1jb250ZW50Ij48L2Rpdj4KICA8L2Rpdj4KPC9kaXY+Cgo8ZGl2IGlkPSJ0b2FzdCIgY2xhc3M9InRvYXN0IiBoaWRkZW4+PC9kaXY+Cgo8c2NyaXB0IHNyYz0iYXBwLmpzIj48L3NjcmlwdD4KPC9ib2R5Pgo8L2h0bWw+Cg==","app.js":"Ly8gPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PQovLyBHZXN0aW9ubmFpcmUgZCdpbnZlbnRhaXJlIOKAlCBpbnRlcmZhY2UgKHZhbmlsbGEgSlMsIGF1Y3VuZSBkw6lwZW5kYW5jZSkKLy8gPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PQpjb25zdCAkID0gKHMpID0+IGRvY3VtZW50LnF1ZXJ5U2VsZWN0b3Iocyk7CmNvbnN0ICQkID0gKHMpID0+IGRvY3VtZW50LnF1ZXJ5U2VsZWN0b3JBbGwocyk7Cgpjb25zdCBzdGF0ZSA9IHsKICB1c2VyOiBudWxsLAogIGFydGljbGVzOiBbXSwKICBkYXNoYm9hcmQ6IG51bGwsCiAgY2hhcnRNb2RlOiAnZGFpbHknLAp9OwoKY29uc3QgUk9MRV9MQUJFTCA9IHsgYWRtaW46ICdBZG1pbicsIGVtcGxveWU6ICdFbXBsb3nDqScsIGxlY3R1cmU6ICdMZWN0dXJlIHNldWxlJyB9Owpjb25zdCBUWVBFX0xBQkVMID0geyBlbnRyZWU6ICdFbnRyw6llJywgdmVudGU6ICdWZW50ZScsIHNvcnRpZTogJ1NvcnRpZScgfTsKCmZ1bmN0aW9uIG1vbmV5KG4pIHsgcmV0dXJuIChNYXRoLnJvdW5kKChOdW1iZXIobikgfHwgMCkgKiAxMDApIC8gMTAwKS50b0ZpeGVkKDIpICsgJyAkJzsgfQpmdW5jdGlvbiBlc2MocykgewogIHJldHVybiBTdHJpbmcocyA/PyAnJykucmVwbGFjZSgvJi9nLCAnJmFtcDsnKS5yZXBsYWNlKC88L2csICcmbHQ7JykucmVwbGFjZSgvPi9nLCAnJmd0OycpCiAgICAucmVwbGFjZSgvIi9nLCAnJnF1b3Q7JykucmVwbGFjZSgvJy9nLCAnJiMzOTsnKTsKfQpmdW5jdGlvbiB0b2FzdChtc2cpIHsKICBjb25zdCB0ID0gJCgnI3RvYXN0Jyk7CiAgdC50ZXh0Q29udGVudCA9IG1zZzsKICB0LmhpZGRlbiA9IGZhbHNlOwogIGNsZWFyVGltZW91dCh0Ll90aW1lcik7CiAgdC5fdGltZXIgPSBzZXRUaW1lb3V0KCgpID0+IHsgdC5oaWRkZW4gPSB0cnVlOyB9LCAzNTAwKTsKfQpmdW5jdGlvbiBzaG93RXJyb3IoZWwsIG1zZykgeyBlbC50ZXh0Q29udGVudCA9IG1zZzsgZWwuaGlkZGVuID0gZmFsc2U7IH0KCmFzeW5jIGZ1bmN0aW9uIGFwaShwYXRoLCBvcHRzID0ge30pIHsKICBjb25zdCByZXMgPSBhd2FpdCBmZXRjaChwYXRoLCB7CiAgICAuLi5vcHRzLAogICAgaGVhZGVyczogeyAnQ29udGVudC1UeXBlJzogJ2FwcGxpY2F0aW9uL2pzb24nLCAuLi4ob3B0cy5oZWFkZXJzIHx8IHt9KSB9LAogIH0pOwogIGNvbnN0IGRhdGEgPSBhd2FpdCByZXMuanNvbigpLmNhdGNoKCgpID0+ICh7fSkpOwogIGlmICghcmVzLm9rKSB0aHJvdyBuZXcgRXJyb3IoZGF0YS5lcnJvciB8fCAnRXJyZXVyIHNlcnZldXIuJyk7CiAgcmV0dXJuIGRhdGE7Cn0KCi8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQovLyBNb2RhbGUKLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCmZ1bmN0aW9uIG9wZW5Nb2RhbChodG1sKSB7CiAgJCgnI21vZGFsLWNvbnRlbnQnKS5pbm5lckhUTUwgPSBodG1sOwogICQoJyNtb2RhbC1iYWNrZHJvcCcpLmhpZGRlbiA9IGZhbHNlOwp9CmZ1bmN0aW9uIGNsb3NlTW9kYWwoKSB7CiAgJCgnI21vZGFsLWJhY2tkcm9wJykuaGlkZGVuID0gdHJ1ZTsKICAkKCcjbW9kYWwtY29udGVudCcpLmlubmVySFRNTCA9ICcnOwp9CiQoJyNtb2RhbC1jbG9zZScpLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgY2xvc2VNb2RhbCk7CiQoJyNtb2RhbC1iYWNrZHJvcCcpLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKGUpID0+IHsgaWYgKGUudGFyZ2V0LmlkID09PSAnbW9kYWwtYmFja2Ryb3AnKSBjbG9zZU1vZGFsKCk7IH0pOwoKLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCi8vIEF1dGhlbnRpZmljYXRpb24KLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCmFzeW5jIGZ1bmN0aW9uIGNoZWNrU2Vzc2lvbigpIHsKICB0cnkgewogICAgY29uc3QgeyB1c2VyIH0gPSBhd2FpdCBhcGkoJy9hcGkvbWUnKTsKICAgIGVudGVyQXBwKHVzZXIpOwogIH0gY2F0Y2ggKF8pIHsKICAgIHNob3dWaWV3KCdsb2dpbicpOwogIH0KfQoKZnVuY3Rpb24gc2hvd1ZpZXcobmFtZSkgewogICQoJyNsb2dpbi12aWV3JykuaGlkZGVuID0gbmFtZSAhPT0gJ2xvZ2luJzsKICAkKCcjcGFzc3dvcmQtdmlldycpLmhpZGRlbiA9IG5hbWUgIT09ICdwYXNzd29yZCc7CiAgJCgnI2FwcC12aWV3JykuaGlkZGVuID0gbmFtZSAhPT0gJ2FwcCc7Cn0KCmZ1bmN0aW9uIGVudGVyQXBwKHVzZXIpIHsKICBzdGF0ZS51c2VyID0gdXNlcjsKICBpZiAodXNlci5tdXN0Q2hhbmdlUGFzc3dvcmQpIHsgc2hvd1ZpZXcoJ3Bhc3N3b3JkJyk7IHJldHVybjsgfQogIHNob3dWaWV3KCdhcHAnKTsKICAkKCcjdXNlci1jaGlwJykudGV4dENvbnRlbnQgPSBgJHt1c2VyLnVzZXJuYW1lfSDCtyAke1JPTEVfTEFCRUxbdXNlci5yb2xlXX1gOwogICQoJyN0YWItdGVhbScpLnN0eWxlLmRpc3BsYXkgPSB1c2VyLnJvbGUgPT09ICdhZG1pbicgPyAnJyA6ICdub25lJzsKICAkKCcjbmV3LWFydGljbGUtYnRuJykuc3R5bGUuZGlzcGxheSA9IHVzZXIucm9sZSA9PT0gJ2FkbWluJyA/ICcnIDogJ25vbmUnOwogICQoJyN3ZWxjb21lLXRpdGxlJykudGV4dENvbnRlbnQgPSBgQm9uam91ciAke3VzZXIudXNlcm5hbWV9IPCfkYtgOwogIGxvYWREYXNoYm9hcmQoKTsKICBsb2FkQXJ0aWNsZXMoKTsKICBsb2FkSW52b2ljZXMoKTsKICBpZiAodXNlci5yb2xlID09PSAnYWRtaW4nKSBsb2FkVXNlcnMoKTsKfQoKJCgnI2xvZ2luLWZvcm0nKS5hZGRFdmVudExpc3RlbmVyKCdzdWJtaXQnLCBhc3luYyAoZSkgPT4gewogIGUucHJldmVudERlZmF1bHQoKTsKICBjb25zdCBlcnIgPSAkKCcjbG9naW4tZXJyb3InKTsKICBlcnIuaGlkZGVuID0gdHJ1ZTsKICB0cnkgewogICAgY29uc3QgeyB1c2VyIH0gPSBhd2FpdCBhcGkoJy9hcGkvbG9naW4nLCB7CiAgICAgIG1ldGhvZDogJ1BPU1QnLAogICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7CiAgICAgICAgdXNlcm5hbWU6ICQoJyNsb2dpbi11c2VybmFtZScpLnZhbHVlLnRyaW0oKSwKICAgICAgICBwYXNzd29yZDogJCgnI2xvZ2luLXBhc3N3b3JkJykudmFsdWUsCiAgICAgIH0pLAogICAgfSk7CiAgICBlbnRlckFwcCh1c2VyKTsKICB9IGNhdGNoIChleCkgeyBzaG93RXJyb3IoZXJyLCBleC5tZXNzYWdlKTsgfQp9KTsKCiQoJyNwYXNzd29yZC1mb3JtJykuYWRkRXZlbnRMaXN0ZW5lcignc3VibWl0JywgYXN5bmMgKGUpID0+IHsKICBlLnByZXZlbnREZWZhdWx0KCk7CiAgY29uc3QgZXJyID0gJCgnI3B3LWVycm9yJyk7CiAgZXJyLmhpZGRlbiA9IHRydWU7CiAgY29uc3QgbncgPSAkKCcjcHctbmV3JykudmFsdWU7CiAgaWYgKG53ICE9PSAkKCcjcHctY29uZmlybScpLnZhbHVlKSByZXR1cm4gc2hvd0Vycm9yKGVyciwgJ0xlcyBkZXV4IG5vdXZlYXV4IG1vdHMgZGUgcGFzc2UgbmUgY29ycmVzcG9uZGVudCBwYXMuJyk7CiAgdHJ5IHsKICAgIGF3YWl0IGFwaSgnL2FwaS9jaGFuZ2UtcGFzc3dvcmQnLCB7CiAgICAgIG1ldGhvZDogJ1BPU1QnLAogICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IGN1cnJlbnRQYXNzd29yZDogJCgnI3B3LWN1cnJlbnQnKS52YWx1ZSwgbmV3UGFzc3dvcmQ6IG53IH0pLAogICAgfSk7CiAgICB0b2FzdCgnTW90IGRlIHBhc3NlIGNoYW5nw6kuIEJpZW52ZW51ZSAhJyk7CiAgICBzdGF0ZS51c2VyLm11c3RDaGFuZ2VQYXNzd29yZCA9IGZhbHNlOwogICAgZW50ZXJBcHAoc3RhdGUudXNlcik7CiAgfSBjYXRjaCAoZXgpIHsgc2hvd0Vycm9yKGVyciwgZXgubWVzc2FnZSk7IH0KfSk7CgokKCcjbG9nb3V0LWJ0bicpLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgYXN5bmMgKCkgPT4gewogIGF3YWl0IGFwaSgnL2FwaS9sb2dvdXQnLCB7IG1ldGhvZDogJ1BPU1QnIH0pLmNhdGNoKCgpID0+IHt9KTsKICBzdGF0ZS51c2VyID0gbnVsbDsKICBzaG93VmlldygnbG9naW4nKTsKfSk7CgovLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KLy8gTmF2aWdhdGlvbiBwYXIgb25nbGV0cwovLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KJCQoJyN0YWJzIGJ1dHRvbicpLmZvckVhY2goKGJ0bikgPT4gewogIGJ0bi5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsICgpID0+IHsKICAgICQkKCcjdGFicyBidXR0b24nKS5mb3JFYWNoKChiKSA9PiBiLmNsYXNzTGlzdC5yZW1vdmUoJ2FjdGl2ZScpKTsKICAgIGJ0bi5jbGFzc0xpc3QuYWRkKCdhY3RpdmUnKTsKICAgICQkKCcudGFiLXBhZ2UnKS5mb3JFYWNoKChwKSA9PiB7IHAuaGlkZGVuID0gdHJ1ZTsgfSk7CiAgICAkKCcjdGFiLScgKyBidG4uZGF0YXNldC50YWIpLmhpZGRlbiA9IGZhbHNlOwogICAgaWYgKGJ0bi5kYXRhc2V0LnRhYiA9PT0gJ2Rhc2hib2FyZCcpIGxvYWREYXNoYm9hcmQoKTsKICAgIGlmIChidG4uZGF0YXNldC50YWIgPT09ICdhcnRpY2xlcycpIHsgbG9hZEFydGljbGVzKCk7IGxvYWRIaXN0b3J5KCk7IH0KICAgIGlmIChidG4uZGF0YXNldC50YWIgPT09ICdpbnZvaWNlcycpIGxvYWRJbnZvaWNlcygpOwogICAgaWYgKGJ0bi5kYXRhc2V0LnRhYiA9PT0gJ3RlYW0nKSBsb2FkVXNlcnMoKTsKICB9KTsKfSk7CgovLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KLy8gVGFibGVhdSBkZSBib3JkICsgZ3JhcGhpcXVlcyAoY2FudmFzLCBzYW5zIGTDqXBlbmRhbmNlKQovLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KYXN5bmMgZnVuY3Rpb24gbG9hZERhc2hib2FyZCgpIHsKICB0cnkgewogICAgc3RhdGUuZGFzaGJvYXJkID0gYXdhaXQgYXBpKCcvYXBpL2Rhc2hib2FyZCcpOwogIH0gY2F0Y2ggKGUpIHsgcmV0dXJuOyB9CiAgY29uc3QgZCA9IHN0YXRlLmRhc2hib2FyZDsKICAkKCcja3BpLXRvZGF5JykudGV4dENvbnRlbnQgPSBtb25leShkLnNhbGVzVG9kYXkpOwogICQoJyNrcGktbW9udGgnKS50ZXh0Q29udGVudCA9IG1vbmV5KGQuc2FsZXNNb250aCk7CiAgJCgnI2twaS1zdG9jaycpLnRleHRDb250ZW50ID0gbW9uZXkoZC5zdG9ja1ZhbHVlKTsKICAkKCcja3BpLWNvdW50JykudGV4dENvbnRlbnQgPSBkLmFydGljbGVzQ291bnQ7CgogIGNvbnN0IGJveCA9ICQoJyNhbGVydHMtYm94Jyk7CiAgbGV0IGh0bWwgPSAnJzsKICBpZiAoZC5vdXRPZlN0b2NrLmxlbmd0aCkgewogICAgaHRtbCArPSBgPGRpdiBjbGFzcz0iYWxlcnQgZGFuZ2VyIj7im5QgPGI+UnVwdHVyZSBkZSBzdG9jayA6PC9iPiAke2Qub3V0T2ZTdG9jay5tYXAoKGEpID0+IGVzYyhhLm5hbWUpKS5qb2luKCcsICcpfTwvZGl2PmA7CiAgfQogIGlmIChkLmxvd1N0b2NrLmxlbmd0aCkgewogICAgaHRtbCArPSBgPGRpdiBjbGFzcz0iYWxlcnQgd2FybiI+4pqg77iPIDxiPlN0b2NrIGJhcyA6PC9iPiAke2QubG93U3RvY2subWFwKChhKSA9PiBgJHtlc2MoYS5uYW1lKX0gKHBsdXMgcXVlICR7YS5zdG9ja30sIHNldWlsIDogJHthLmxvd190aHJlc2hvbGR9KWApLmpvaW4oJyDCtyAnKX08L2Rpdj5gOwogIH0KICBpZiAoIWQub3V0T2ZTdG9jay5sZW5ndGggJiYgIWQubG93U3RvY2subGVuZ3RoKSB7CiAgICBodG1sICs9IGA8ZGl2IGNsYXNzPSJhbGVydCBvayI+4pyFIFRvdXQgdmEgYmllbiA6IGF1Y3VuIGFydGljbGUgZW4gc3RvY2sgYmFzIG91IGVuIHJ1cHR1cmUuPC9kaXY+YDsKICB9CiAgYm94LmlubmVySFRNTCA9IGh0bWw7CgogICQoJyN0b3Atc2VsbGVycycpLmlubmVySFRNTCA9IGQudG9wU2VsbGVycy5sZW5ndGgKICAgID8gZC50b3BTZWxsZXJzLm1hcCgodCkgPT4gYDxsaT48c3Bhbj4ke2VzYyh0LmFydGljbGVfbmFtZSl9PC9zcGFuPjxiPiR7dC5xdHl9IHZlbmR1KHMpIMK3ICR7bW9uZXkodC5yZXZlbnVlKX08L2I+PC9saT5gKS5qb2luKCcnKQogICAgOiAnPGxpIGNsYXNzPSJtdXRlZCI+QXVjdW5lIHZlbnRlIGVucmVnaXN0csOpZSBwb3VyIGxlIG1vbWVudC48L2xpPic7CgogIGRyYXdDaGFydCgpOwogIGxvYWRSZWNlbnRNb3ZlbWVudHMoKTsKfQoKYXN5bmMgZnVuY3Rpb24gbG9hZFJlY2VudE1vdmVtZW50cygpIHsKICB0cnkgewogICAgY29uc3QgbGlzdCA9IGF3YWl0IGFwaSgnL2FwaS9tb3ZlbWVudHMnKTsKICAgICQoJyNyZWNlbnQtbW92ZW1lbnRzJykuaW5uZXJIVE1MID0gbGlzdC5zbGljZSgwLCA4KS5tYXAoKG0pID0+IGAKICAgICAgPGxpPjxzcGFuPjxzcGFuIGNsYXNzPSJ0YWcgJHttLnR5cGV9Ij4ke1RZUEVfTEFCRUxbbS50eXBlXX08L3NwYW4+ICR7ZXNjKG0uYXJ0aWNsZV9uYW1lKX0gw5cgJHttLnF1YW50aXR5fTwvc3Bhbj4KICAgICAgPGI+JHttb25leShtLnRvdGFsKX08L2I+PC9saT5gKS5qb2luKCcnKSB8fCAnPGxpIGNsYXNzPSJtdXRlZCI+QXVjdW4gbW91dmVtZW50LjwvbGk+JzsKICB9IGNhdGNoIChfKSB7fQp9CgokKCcjY2hhcnQtZGFpbHknKS5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsICgpID0+IHsgc3RhdGUuY2hhcnRNb2RlID0gJ2RhaWx5Jzsgc3luY0NoYXJ0U2VnKCk7IGRyYXdDaGFydCgpOyB9KTsKJCgnI2NoYXJ0LW1vbnRobHknKS5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsICgpID0+IHsgc3RhdGUuY2hhcnRNb2RlID0gJ21vbnRobHknOyBzeW5jQ2hhcnRTZWcoKTsgZHJhd0NoYXJ0KCk7IH0pOwpmdW5jdGlvbiBzeW5jQ2hhcnRTZWcoKSB7CiAgJCgnI2NoYXJ0LWRhaWx5JykuY2xhc3NMaXN0LnRvZ2dsZSgnYWN0aXZlJywgc3RhdGUuY2hhcnRNb2RlID09PSAnZGFpbHknKTsKICAkKCcjY2hhcnQtbW9udGhseScpLmNsYXNzTGlzdC50b2dnbGUoJ2FjdGl2ZScsIHN0YXRlLmNoYXJ0TW9kZSA9PT0gJ21vbnRobHknKTsKfQoKZnVuY3Rpb24gZHJhd0NoYXJ0KCkgewogIGNvbnN0IGNhbnZhcyA9ICQoJyNjaGFydCcpOwogIGlmICghc3RhdGUuZGFzaGJvYXJkKSByZXR1cm47CiAgY29uc3QgZGF0YSA9IHN0YXRlLmNoYXJ0TW9kZSA9PT0gJ2RhaWx5JyA/IHN0YXRlLmRhc2hib2FyZC5kYWlseSA6IHN0YXRlLmRhc2hib2FyZC5tb250aGx5OwogIGNvbnN0IGN0eCA9IGNhbnZhcy5nZXRDb250ZXh0KCcyZCcpOwogIGNvbnN0IGRwciA9IHdpbmRvdy5kZXZpY2VQaXhlbFJhdGlvIHx8IDE7CiAgY29uc3QgdyA9IGNhbnZhcy5jbGllbnRXaWR0aCB8fCA2MDA7CiAgY29uc3QgaCA9IDE4MDsKICBjYW52YXMud2lkdGggPSB3ICogZHByOwogIGNhbnZhcy5oZWlnaHQgPSBoICogZHByOwogIGN0eC5zY2FsZShkcHIsIGRwcik7CiAgY3R4LmNsZWFyUmVjdCgwLCAwLCB3LCBoKTsKICBjb25zdCBtYXggPSBNYXRoLm1heCguLi5kYXRhLm1hcCgocCkgPT4gcC50b3RhbCksIDEpOwogIGNvbnN0IGJhclcgPSBNYXRoLm1heCg0LCAodyAtIDEwKSAvIGRhdGEubGVuZ3RoIC0gNCk7CiAgZGF0YS5mb3JFYWNoKChwLCBpKSA9PiB7CiAgICBjb25zdCBiaCA9IChwLnRvdGFsIC8gbWF4KSAqIChoIC0gNDApOwogICAgY29uc3QgeCA9IDUgKyBpICogKCh3IC0gMTApIC8gZGF0YS5sZW5ndGgpOwogICAgY3R4LmZpbGxTdHlsZSA9ICcjMjU2M2ViJzsKICAgIGN0eC5maWxsUmVjdCh4LCBoIC0gMjQgLSBiaCwgYmFyVywgYmgpOwogICAgaWYgKGkgJSBNYXRoLmNlaWwoZGF0YS5sZW5ndGggLyA4KSA9PT0gMCkgewogICAgICBjdHguZmlsbFN0eWxlID0gJyM2YjcyODAnOwogICAgICBjdHguZm9udCA9ICcxMHB4IHNhbnMtc2VyaWYnOwogICAgICBjdHguZmlsbFRleHQocC5sYWJlbCwgeCwgaCAtIDgpOwogICAgfQogIH0pOwp9CndpbmRvdy5hZGRFdmVudExpc3RlbmVyKCdyZXNpemUnLCBkcmF3Q2hhcnQpOwoKLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCi8vIEFydGljbGVzCi8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQphc3luYyBmdW5jdGlvbiBsb2FkQXJ0aWNsZXMoKSB7CiAgdHJ5IHsKICAgIHN0YXRlLmFydGljbGVzID0gYXdhaXQgYXBpKCcvYXBpL2FydGljbGVzJyk7CiAgfSBjYXRjaCAoZSkgeyByZXR1cm47IH0KICBjb25zdCBxID0gKCQoJyNhcnRpY2xlLXNlYXJjaCcpLnZhbHVlIHx8ICcnKS50b0xvd2VyQ2FzZSgpOwogIGNvbnN0IGNhdCA9ICQoJyNhcnRpY2xlLWZpbHRlcicpLnZhbHVlOwogIGNvbnN0IGNhdHMgPSBbLi4ubmV3IFNldChzdGF0ZS5hcnRpY2xlcy5tYXAoKGEpID0+IGEuY2F0ZWdvcnkpLmZpbHRlcihCb29sZWFuKSldOwogICQoJyNhcnRpY2xlLWZpbHRlcicpLmlubmVySFRNTCA9ICc8b3B0aW9uIHZhbHVlPSIiPlRvdXRlcyBsZXMgY2F0w6lnb3JpZXM8L29wdGlvbj4nICsKICAgIGNhdHMubWFwKChjKSA9PiBgPG9wdGlvbiAke2MgPT09IGNhdCA/ICdzZWxlY3RlZCcgOiAnJ30+JHtlc2MoYyl9PC9vcHRpb24+YCkuam9pbignJyk7CiAgY29uc3QgbGlzdCA9IHN0YXRlLmFydGljbGVzLmZpbHRlcigoYSkgPT4KICAgICghcSB8fCAoYS5uYW1lICsgJyAnICsgKGEuZGVzY3JpcHRpb24gfHwgJycpICsgJyAnICsgKGEuc2t1IHx8ICcnKSkudG9Mb3dlckNhc2UoKS5pbmNsdWRlcyhxKSkgJiYKICAgICghY2F0IHx8IGEuY2F0ZWdvcnkgPT09IGNhdCkpOwogIGNvbnN0IGdyaWQgPSAkKCcjYXJ0aWNsZXMtZ3JpZCcpOwogIGlmICghbGlzdC5sZW5ndGgpIHsKICAgIGdyaWQuaW5uZXJIVE1MID0gJzxwIGNsYXNzPSJlbXB0eSI+QXVjdW4gYXJ0aWNsZSBwb3VyIGxlIG1vbWVudC48YnI+Q2xpcXVleiBzdXIgwqsg77yLIE5vdXZlbCBhcnRpY2xlIMK7IHBvdXIgYWpvdXRlciBsZSBwcmVtaWVyICE8L3A+JzsKICAgIHJldHVybjsKICB9CiAgZ3JpZC5pbm5lckhUTUwgPSBsaXN0Lm1hcCgoYSkgPT4gewogICAgY29uc3QgYmFkZ2UgPSBhLnN0b2NrID09PSAwCiAgICAgID8gJzxzcGFuIGNsYXNzPSJiYWRnZSBvdXQiPlJ1cHR1cmU8L3NwYW4+JwogICAgICA6IGEuc3RvY2sgPD0gYS5sb3dfdGhyZXNob2xkCiAgICAgICAgPyBgPHNwYW4gY2xhc3M9ImJhZGdlIHdhcm4iPlN0b2NrIGJhcyDCtyAke2Euc3RvY2t9PC9zcGFuPmAKICAgICAgICA6IGA8c3BhbiBjbGFzcz0iYmFkZ2Ugb2siPkVuIHN0b2NrIMK3ICR7YS5zdG9ja308L3NwYW4+YDsKICAgIGNvbnN0IGNhbk1vdmUgPSBzdGF0ZS51c2VyLnJvbGUgIT09ICdsZWN0dXJlJzsKICAgIGNvbnN0IHBob3RvID0gYS5waG90bwogICAgICA/IGA8aW1nIHNyYz0iJHtlc2MoYS5waG90byl9IiBhbHQ9IiI+YAogICAgICA6ICc8ZGl2IGNsYXNzPSJuby1waG90byI+8J+TpjwvZGl2Pic7CiAgICByZXR1cm4gYDxkaXYgY2xhc3M9ImFydGljbGUtY2FyZCI+JHtwaG90b30KICAgICAgPGRpdiBjbGFzcz0iYXJ0aWNsZS1ib2R5Ij4KICAgICAgICA8aDM+JHtlc2MoYS5uYW1lKX08L2gzPgogICAgICAgIDxwIGNsYXNzPSJkZXNjIj4ke2VzYyhhLmRlc2NyaXB0aW9uIHx8ICcnKX08L3A+CiAgICAgICAgPGRpdiBjbGFzcz0icHJpY2UiPiR7bW9uZXkoYS5wcmljZSl9PC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0ic3RvY2stbGluZSI+PHNwYW4gY2xhc3M9Im11dGVkIj4ke2VzYyhhLnNrdSB8fCAnJyl9ICR7YS5jYXRlZ29yeSA/ICfCtyAnICsgZXNjKGEuY2F0ZWdvcnkpIDogJyd9PC9zcGFuPiR7YmFkZ2V9PC9kaXY+CiAgICAgICAgJHtjYW5Nb3ZlID8gYAogICAgICAgIDxkaXYgY2xhc3M9InF0eS1yb3ciPgogICAgICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIiBvbmNsaWNrPSJxdWlja01vdmUoJHthLmlkfSwnZW50cmVlJywxKSI+77yLIEVudHLDqWU8L2J1dHRvbj4KICAgICAgICAgIDxidXR0b24gY2xhc3M9ImJ0biIgb25jbGljaz0icXVpY2tNb3ZlKCR7YS5pZH0sJ3ZlbnRlJywxKSI+8J+bkiBWZW5kcmU8L2J1dHRvbj4KICAgICAgICAgIDxidXR0b24gY2xhc3M9ImJ0biIgb25jbGljaz0ib3Blbk1vdmVNb2RhbCgke2EuaWR9LCdzb3J0aWUnKSI+4oiSIFNvcnRpZTwvYnV0dG9uPgogICAgICAgIDwvZGl2PmAgOiAnJ30KICAgICAgICAke3N0YXRlLnVzZXIucm9sZSA9PT0gJ2FkbWluJyA/IGAKICAgICAgICA8ZGl2IGNsYXNzPSJxdHktcm93Ij4KICAgICAgICAgIDxidXR0b24gY2xhc3M9ImJ0biBzbWFsbCIgb25jbGljaz0ib3BlbkFydGljbGVGb3JtKCR7YS5pZH0pIj7inI/vuI8gTW9kaWZpZXI8L2J1dHRvbj4KICAgICAgICAgIDxidXR0b24gY2xhc3M9ImJ0biBzbWFsbCBkYW5nZXIiIG9uY2xpY2s9ImRlbGV0ZUFydGljbGUoJHthLmlkfSwnJHtlc2MoYS5uYW1lLnJlcGxhY2UoLycvZywgJycpKX0nKSI+8J+Xke+4jyBTdXBwcmltZXI8L2J1dHRvbj4KICAgICAgICA8L2Rpdj5gIDogJyd9CiAgICAgIDwvZGl2PjwvZGl2PmA7CiAgfSkuam9pbignJyk7Cn0KCiQoJyNhcnRpY2xlLXNlYXJjaCcpLmFkZEV2ZW50TGlzdGVuZXIoJ2lucHV0JywgbG9hZEFydGljbGVzKTsKJCgnI2FydGljbGUtZmlsdGVyJykuYWRkRXZlbnRMaXN0ZW5lcignY2hhbmdlJywgbG9hZEFydGljbGVzKTsKJCgnI25ldy1hcnRpY2xlLWJ0bicpLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCkgPT4gb3BlbkFydGljbGVGb3JtKG51bGwpKTsKCi8vIFLDqWR1aXQgbGEgcGhvdG8gKG1heCA4MDAgcHgsIEpQRUcpIHBvdXIgZ2FyZGVyIGxhIGJhc2UgcGV0aXRlLgpmdW5jdGlvbiByZWFkUGhvdG9GaWxlKGZpbGUpIHsKICByZXR1cm4gbmV3IFByb21pc2UoKHJlc29sdmUsIHJlamVjdCkgPT4gewogICAgY29uc3QgcmVhZGVyID0gbmV3IEZpbGVSZWFkZXIoKTsKICAgIHJlYWRlci5vbmxvYWQgPSAoKSA9PiB7CiAgICAgIGNvbnN0IGltZyA9IG5ldyBJbWFnZSgpOwogICAgICBpbWcub25sb2FkID0gKCkgPT4gewogICAgICAgIGNvbnN0IG1heCA9IDgwMDsKICAgICAgICBjb25zdCBzY2FsZSA9IE1hdGgubWluKDEsIG1heCAvIE1hdGgubWF4KGltZy53aWR0aCwgaW1nLmhlaWdodCkpOwogICAgICAgIGNvbnN0IGNhbnZhcyA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2NhbnZhcycpOwogICAgICAgIGNhbnZhcy53aWR0aCA9IE1hdGgucm91bmQoaW1nLndpZHRoICogc2NhbGUpOwogICAgICAgIGNhbnZhcy5oZWlnaHQgPSBNYXRoLnJvdW5kKGltZy5oZWlnaHQgKiBzY2FsZSk7CiAgICAgICAgY2FudmFzLmdldENvbnRleHQoJzJkJykuZHJhd0ltYWdlKGltZywgMCwgMCwgY2FudmFzLndpZHRoLCBjYW52YXMuaGVpZ2h0KTsKICAgICAgICByZXNvbHZlKGNhbnZhcy50b0RhdGFVUkwoJ2ltYWdlL2pwZWcnLCAwLjgpKTsKICAgICAgfTsKICAgICAgaW1nLm9uZXJyb3IgPSByZWplY3Q7CiAgICAgIGltZy5zcmMgPSByZWFkZXIucmVzdWx0OwogICAgfTsKICAgIHJlYWRlci5vbmVycm9yID0gcmVqZWN0OwogICAgcmVhZGVyLnJlYWRBc0RhdGFVUkwoZmlsZSk7CiAgfSk7Cn0KCmxldCBhcnRpY2xlRm9ybVBob3RvID0gJyc7CmxldCBhcnRpY2xlU3RlcCA9IDE7CgpmdW5jdGlvbiBvcGVuQXJ0aWNsZUZvcm0oaWQpIHsKICBjb25zdCBhID0gaWQgPyBzdGF0ZS5hcnRpY2xlcy5maW5kKCh4KSA9PiB4LmlkID09PSBpZCkgOiBudWxsOwogIGFydGljbGVGb3JtUGhvdG8gPSBhID8gYS5waG90byA6ICcnOwogIGFydGljbGVTdGVwID0gMTsKICBvcGVuTW9kYWwoYAogICAgPGgyPiR7YSA/ICdNb2RpZmllciBs4oCZYXJ0aWNsZScgOiAnTm91dmVsIGFydGljbGUnfTwvaDI+CiAgICA8ZGl2IGNsYXNzPSJzdGVwcyI+PHNwYW4gaWQ9InN0ZXAtMSIgY2xhc3M9Im9uIj4xIMK3IFBob3RvPC9zcGFuPjxzcGFuIGlkPSJzdGVwLTIiPjIgwrcgTm9tICZhbXA7IGRlc2NyaXB0aW9uPC9zcGFuPjxzcGFuIGlkPSJzdGVwLTMiPjMgwrcgUHJpeCAmYW1wOyBzdG9jazwvc3Bhbj48L2Rpdj4KICAgIDxmb3JtIGlkPSJhcnRpY2xlLWZvcm0iPgogICAgICA8ZGl2IGNsYXNzPSJzdGVwLXBhbmUiIGRhdGEtcGFuZT0iMSI+CiAgICAgICAgPGxhYmVsPlBob3RvIGRlIGzigJlhcnRpY2xlIChmYWN1bHRhdGlmKQogICAgICAgICAgPGlucHV0IHR5cGU9ImZpbGUiIGlkPSJhZi1waG90byIgYWNjZXB0PSJpbWFnZS8qIiBjYXB0dXJlPSJlbnZpcm9ubWVudCI+CiAgICAgICAgPC9sYWJlbD4KICAgICAgICA8aW1nIGlkPSJhZi1wcmV2aWV3IiBjbGFzcz0icGhvdG8tcHJldmlldyIgJHthcnRpY2xlRm9ybVBob3RvID8gYHNyYz0iJHtlc2MoYXJ0aWNsZUZvcm1QaG90byl9ImAgOiAnaGlkZGVuJ30+CiAgICAgICAgPHAgY2xhc3M9Im11dGVkIj5VbmUgcGhvdG8gYWlkZSB0b3V0ZSBsJ8OpcXVpcGUgw6AgcmVjb25uYcOudHJlIGwnYXJ0aWNsZSBlbiB1biBjb3VwIGQnxZNpbC48L3A+CiAgICAgIDwvZGl2PgogICAgICA8ZGl2IGNsYXNzPSJzdGVwLXBhbmUiIGRhdGEtcGFuZT0iMiIgaGlkZGVuPgogICAgICAgIDxsYWJlbD5Ob20gZGUgbOKAmWFydGljbGUgKiA8aW5wdXQgdHlwZT0idGV4dCIgaWQ9ImFmLW5hbWUiIHJlcXVpcmVkIHZhbHVlPSIke2EgPyBlc2MoYS5uYW1lKSA6ICcnfSIgcGxhY2Vob2xkZXI9ImV4LiBDYXNxdWUgQmx1ZXRvb3RoIFgyMDAiPjwvbGFiZWw+CiAgICAgICAgPGxhYmVsPkRlc2NyaXB0aW9uIDx0ZXh0YXJlYSBpZD0iYWYtZGVzYyIgcGxhY2Vob2xkZXI9IkNvdWxldXIsIHRhaWxsZSwgcGFydGljdWxhcml0w6lz4oCmIj4ke2EgPyBlc2MoYS5kZXNjcmlwdGlvbiB8fCAnJykgOiAnJ308L3RleHRhcmVhPjwvbGFiZWw+CiAgICAgIDwvZGl2PgogICAgICA8ZGl2IGNsYXNzPSJzdGVwLXBhbmUiIGRhdGEtcGFuZT0iMyIgaGlkZGVuPgogICAgICAgIDxkaXYgY2xhc3M9ImZvcm0tZ3JpZCI+CiAgICAgICAgICA8bGFiZWw+UHJpeCBkZSB2ZW50ZSAoJCkgKiA8aW5wdXQgdHlwZT0ibnVtYmVyIiBpZD0iYWYtcHJpY2UiIHJlcXVpcmVkIG1pbj0iMCIgc3RlcD0iMC4wMSIgdmFsdWU9IiR7YSA/IGEucHJpY2UgOiAnJ30iIHBsYWNlaG9sZGVyPSIxOS45OSI+PC9sYWJlbD4KICAgICAgICAgIDxsYWJlbD5Qcml4IGNvw7t0YW50ICgkKSA8aW5wdXQgdHlwZT0ibnVtYmVyIiBpZD0iYWYtY29zdCIgbWluPSIwIiBzdGVwPSIwLjAxIiB2YWx1ZT0iJHthICYmIGEuY29zdF9wcmljZSAhPSBudWxsID8gYS5jb3N0X3ByaWNlIDogJyd9IiBwbGFjZWhvbGRlcj0iRmFjdWx0YXRpZiI+PC9sYWJlbD4KICAgICAgICAgIDxsYWJlbD5TS1UgLyBSw6lmw6lyZW5jZSA8aW5wdXQgdHlwZT0idGV4dCIgaWQ9ImFmLXNrdSIgdmFsdWU9IiR7YSA/IGVzYyhhLnNrdSB8fCAnJykgOiAnJ30iIHBsYWNlaG9sZGVyPSJleC4gQ0ItMDAxIj48L2xhYmVsPgogICAgICAgICAgPGxhYmVsPkNhdMOpZ29yaWUgPGlucHV0IHR5cGU9InRleHQiIGlkPSJhZi1jYXQiIHZhbHVlPSIke2EgPyBlc2MoYS5jYXRlZ29yeSB8fCAnJykgOiAnJ30iIHBsYWNlaG9sZGVyPSJleC4gQXVkaW8iPjwvbGFiZWw+CiAgICAgICAgICA8bGFiZWw+U3RvY2sgZGUgZMOpcGFydCA8aW5wdXQgdHlwZT0ibnVtYmVyIiBpZD0iYWYtc3RvY2siIG1pbj0iMCIgc3RlcD0iMSIgdmFsdWU9IiR7YSA/IGEuc3RvY2sgOiAwfSI+PC9sYWJlbD4KICAgICAgICAgIDxsYWJlbD5TZXVpbCBk4oCZYWxlcnRlIHN0b2NrIGJhcyA8aW5wdXQgdHlwZT0ibnVtYmVyIiBpZD0iYWYtdGhyZXNob2xkIiBtaW49IjAiIHN0ZXA9IjEiIHZhbHVlPSIke2EgPyBhLmxvd190aHJlc2hvbGQgOiA1fSI+PC9sYWJlbD4KICAgICAgICA8L2Rpdj4KICAgICAgICA8cCBpZD0iYWYtZXJyb3IiIGNsYXNzPSJlcnJvciIgaGlkZGVuPjwvcD4KICAgICAgPC9kaXY+CiAgICAgIDxkaXYgc3R5bGU9ImRpc3BsYXk6ZmxleDtnYXA6OHB4O2p1c3RpZnktY29udGVudDpzcGFjZS1iZXR3ZWVuO21hcmdpbi10b3A6MTRweCI+CiAgICAgICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJidG4iIGlkPSJhZi1iYWNrIiBoaWRkZW4+4oaQIFJldG91cjwvYnV0dG9uPgogICAgICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0iYnRuIHByaW1hcnkiIGlkPSJhZi1uZXh0Ij5TdWl2YW50IOKGkjwvYnV0dG9uPgogICAgICAgIDxidXR0b24gdHlwZT0ic3VibWl0IiBjbGFzcz0iYnRuIHByaW1hcnkiIGlkPSJhZi1zdWJtaXQiIGhpZGRlbj4ke2EgPyAnRW5yZWdpc3RyZXInIDogJ0Fqb3V0ZXIgbOKAmWFydGljbGUnfTwvYnV0dG9uPgogICAgICA8L2Rpdj4KICAgIDwvZm9ybT5gKTsKCiAgJCgnI2FmLXBob3RvJykuYWRkRXZlbnRMaXN0ZW5lcignY2hhbmdlJywgYXN5bmMgKGUpID0+IHsKICAgIGNvbnN0IGZpbGUgPSBlLnRhcmdldC5maWxlc1swXTsKICAgIGlmICghZmlsZSkgcmV0dXJuOwogICAgdHJ5IHsKICAgICAgYXJ0aWNsZUZvcm1QaG90byA9IGF3YWl0IHJlYWRQaG90b0ZpbGUoZmlsZSk7CiAgICAgIGNvbnN0IGltZyA9ICQoJyNhZi1wcmV2aWV3Jyk7CiAgICAgIGltZy5zcmMgPSBhcnRpY2xlRm9ybVBob3RvOwogICAgICBpbWcuaGlkZGVuID0gZmFsc2U7CiAgICB9IGNhdGNoIChfKSB7IHRvYXN0KCdJbXBvc3NpYmxlIGRlIGxpcmUgY2V0dGUgcGhvdG8uJyk7IH0KICB9KTsKCiAgY29uc3Qgc2hvd1N0ZXAgPSAobikgPT4gewogICAgYXJ0aWNsZVN0ZXAgPSBuOwogICAgJCQoJy5zdGVwLXBhbmUnKS5mb3JFYWNoKChwKSA9PiB7IHAuaGlkZGVuID0gTnVtYmVyKHAuZGF0YXNldC5wYW5lKSAhPT0gbjsgfSk7CiAgICAkJCgnLnN0ZXBzIHNwYW4nKS5mb3JFYWNoKChzLCBpKSA9PiBzLmNsYXNzTGlzdC50b2dnbGUoJ29uJywgaSArIDEgPT09IG4pKTsKICAgICQoJyNhZi1iYWNrJykuaGlkZGVuID0gbiA9PT0gMTsKICAgICQoJyNhZi1uZXh0JykuaGlkZGVuID0gbiA9PT0gMzsKICAgICQoJyNhZi1zdWJtaXQnKS5oaWRkZW4gPSBuICE9PSAzOwogIH07CiAgJCgnI2FmLWJhY2snKS5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsICgpID0+IHNob3dTdGVwKGFydGljbGVTdGVwIC0gMSkpOwogICQoJyNhZi1uZXh0JykuYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCAoKSA9PiB7CiAgICBpZiAoYXJ0aWNsZVN0ZXAgPT09IDIgJiYgISQoJyNhZi1uYW1lJykudmFsdWUudHJpbSgpKSB7IHRvYXN0KCdEb25uZXogdW4gbm9tIMOgIGzigJlhcnRpY2xlLicpOyByZXR1cm47IH0KICAgIHNob3dTdGVwKGFydGljbGVTdGVwICsgMSk7CiAgfSk7CiAgJCgnI2FydGljbGUtZm9ybScpLmFkZEV2ZW50TGlzdGVuZXIoJ3N1Ym1pdCcsIGFzeW5jIChlKSA9PiB7CiAgICBlLnByZXZlbnREZWZhdWx0KCk7CiAgICBjb25zdCBlcnIgPSAkKCcjYWYtZXJyb3InKTsKICAgIGVyci5oaWRkZW4gPSB0cnVlOwogICAgY29uc3QgcGF5bG9hZCA9IHsKICAgICAgbmFtZTogJCgnI2FmLW5hbWUnKS52YWx1ZS50cmltKCksCiAgICAgIGRlc2NyaXB0aW9uOiAkKCcjYWYtZGVzYycpLnZhbHVlLnRyaW0oKSwKICAgICAgcGhvdG86IGFydGljbGVGb3JtUGhvdG8sCiAgICAgIHByaWNlOiBOdW1iZXIoJCgnI2FmLXByaWNlJykudmFsdWUpLAogICAgICBjb3N0X3ByaWNlOiAkKCcjYWYtY29zdCcpLnZhbHVlID09PSAnJyA/IG51bGwgOiBOdW1iZXIoJCgnI2FmLWNvc3QnKS52YWx1ZSksCiAgICAgIHNrdTogJCgnI2FmLXNrdScpLnZhbHVlLnRyaW0oKSwKICAgICAgY2F0ZWdvcnk6ICQoJyNhZi1jYXQnKS52YWx1ZS50cmltKCksCiAgICAgIHN0b2NrOiBOdW1iZXIoJCgnI2FmLXN0b2NrJykudmFsdWUpLAogICAgICBsb3dfdGhyZXNob2xkOiBOdW1iZXIoJCgnI2FmLXRocmVzaG9sZCcpLnZhbHVlKSwKICAgIH07CiAgICB0cnkgewogICAgICBpZiAoYSkgYXdhaXQgYXBpKCcvYXBpL2FydGljbGVzLycgKyBhLmlkLCB7IG1ldGhvZDogJ1BVVCcsIGJvZHk6IEpTT04uc3RyaW5naWZ5KHBheWxvYWQpIH0pOwogICAgICBlbHNlIGF3YWl0IGFwaSgnL2FwaS9hcnRpY2xlcycsIHsgbWV0aG9kOiAnUE9TVCcsIGJvZHk6IEpTT04uc3RyaW5naWZ5KHBheWxvYWQpIH0pOwogICAgICBjbG9zZU1vZGFsKCk7CiAgICAgIHRvYXN0KGEgPyAnQXJ0aWNsZSBtb2RpZmnDqS4nIDogJ0FydGljbGUgYWpvdXTDqSAhIPCfjoknKTsKICAgICAgbG9hZEFydGljbGVzKCk7CiAgICAgIGxvYWREYXNoYm9hcmQoKTsKICAgIH0gY2F0Y2ggKGV4KSB7IHNob3dFcnJvcihlcnIsIGV4Lm1lc3NhZ2UpOyB9CiAgfSk7Cn0KCmFzeW5jIGZ1bmN0aW9uIGRlbGV0ZUFydGljbGUoaWQsIG5hbWUpIHsKICBpZiAoIWNvbmZpcm0oYFN1cHByaW1lciBkw6lmaW5pdGl2ZW1lbnQgwqsgJHtuYW1lfSDCuyA/YCkpIHJldHVybjsKICB0cnkgewogICAgYXdhaXQgYXBpKCcvYXBpL2FydGljbGVzLycgKyBpZCwgeyBtZXRob2Q6ICdERUxFVEUnIH0pOwogICAgdG9hc3QoJ0FydGljbGUgc3VwcHJpbcOpLicpOwogICAgbG9hZEFydGljbGVzKCk7CiAgICBsb2FkRGFzaGJvYXJkKCk7CiAgfSBjYXRjaCAoZSkgeyB0b2FzdChlLm1lc3NhZ2UpOyB9Cn0KCi8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQovLyBNb3V2ZW1lbnRzIGRlIHN0b2NrCi8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQphc3luYyBmdW5jdGlvbiBxdWlja01vdmUoYXJ0aWNsZUlkLCB0eXBlLCBxdHkpIHsKICBpZiAodHlwZSA9PT0gJ3ZlbnRlJyB8fCB0eXBlID09PSAnc29ydGllJykgeyBvcGVuTW92ZU1vZGFsKGFydGljbGVJZCwgdHlwZSwgcXR5KTsgcmV0dXJuOyB9CiAgdHJ5IHsKICAgIGNvbnN0IHsgc3RvY2sgfSA9IGF3YWl0IGFwaSgnL2FwaS9tb3ZlbWVudHMnLCB7CiAgICAgIG1ldGhvZDogJ1BPU1QnLAogICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IGFydGljbGVfaWQ6IGFydGljbGVJZCwgdHlwZTogJ2VudHJlZScsIHF1YW50aXR5OiBxdHkgfSksCiAgICB9KTsKICAgIHRvYXN0KGBFbnRyw6llIGVucmVnaXN0csOpZS4gTm91dmVhdSBzdG9jayA6ICR7c3RvY2t9LmApOwogICAgbG9hZEFydGljbGVzKCk7IGxvYWREYXNoYm9hcmQoKTsgbG9hZEhpc3RvcnkoKTsKICB9IGNhdGNoIChlKSB7IHRvYXN0KGUubWVzc2FnZSk7IH0KfQoKZnVuY3Rpb24gb3Blbk1vdmVNb2RhbChhcnRpY2xlSWQsIHR5cGUsIHByZXNldFF0eSA9IDEpIHsKICBjb25zdCBhID0gc3RhdGUuYXJ0aWNsZXMuZmluZCgoeCkgPT4geC5pZCA9PT0gYXJ0aWNsZUlkKTsKICBpZiAoIWEpIHJldHVybjsKICBjb25zdCBpc1NhbGUgPSB0eXBlID09PSAndmVudGUnOwogIG9wZW5Nb2RhbChgCiAgICA8aDI+JHtpc1NhbGUgPyAn8J+bkiBWZW5kcmUnIDogdHlwZSA9PT0gJ2VudHJlZScgPyAn77yLIEVudHLDqWUgZGUgc3RvY2snIDogJ+KIkiBTb3J0aWUgZGUgc3RvY2snfSDigJQgJHtlc2MoYS5uYW1lKX08L2gyPgogICAgPHAgY2xhc3M9Im11dGVkIj5TdG9jayBhY3R1ZWwgOiA8Yj4ke2Euc3RvY2t9PC9iPiDCtyBQcml4IGRlIHZlbnRlIDogPGI+JHttb25leShhLnByaWNlKX08L2I+PC9wPgogICAgPGZvcm0gaWQ9Im1vdmUtZm9ybSI+CiAgICAgIDxsYWJlbD5RdWFudGl0w6kKICAgICAgICA8aW5wdXQgdHlwZT0ibnVtYmVyIiBpZD0ibXYtcXR5IiBtaW49IjEiIHN0ZXA9IjEiIHZhbHVlPSIke3ByZXNldFF0eX0iIHJlcXVpcmVkPgogICAgICA8L2xhYmVsPgogICAgICA8ZGl2IGNsYXNzPSJxdHktcm93IiBzdHlsZT0ibWFyZ2luLWJvdHRvbToxMnB4Ij4KICAgICAgICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgY2xhc3M9ImJ0biBzbWFsbCIgb25jbGljaz0iZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ212LXF0eScpLnZhbHVlPTUiPsOXNTwvYnV0dG9uPgogICAgICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0iYnRuIHNtYWxsIiBvbmNsaWNrPSJkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnbXYtcXR5JykudmFsdWU9MTAiPsOXMTA8L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgY2xhc3M9ImJ0biBzbWFsbCIgb25jbGljaz0iZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ212LXF0eScpLnZhbHVlPU1hdGgubWF4KDEsKGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdtdi1xdHknKS52YWx1ZXx8MSktMSkiPuKIkjE8L2J1dHRvbj4KICAgICAgICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgY2xhc3M9ImJ0biBzbWFsbCIgb25jbGljaz0iZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ212LXF0eScpLnZhbHVlPSgrZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ212LXF0eScpLnZhbHVlfHwwKSsxIj7vvIsxPC9idXR0b24+CiAgICAgIDwvZGl2PgogICAgICA8bGFiZWw+UHJpeCB1bml0YWlyZSAoJCkKICAgICAgICA8aW5wdXQgdHlwZT0ibnVtYmVyIiBpZD0ibXYtcHJpY2UiIG1pbj0iMCIgc3RlcD0iMC4wMSIgdmFsdWU9IiR7aXNTYWxlID8gYS5wcmljZSA6IChhLmNvc3RfcHJpY2UgPz8gYS5wcmljZSl9Ij4KICAgICAgPC9sYWJlbD4KICAgICAgPGxhYmVsPk5vdGUgPGlucHV0IHR5cGU9InRleHQiIGlkPSJtdi1ub3RlIiBwbGFjZWhvbGRlcj0iRmFjdWx0YXRpZiDigJQgZXguIGNsaWVudCByw6lndWxpZXIsIGNhc3Nl4oCmIj48L2xhYmVsPgogICAgICAke2lzU2FsZSA/IGAKICAgICAgPGxhYmVsIGNsYXNzPSJjaGVja2JveC1saW5lIj48aW5wdXQgdHlwZT0iY2hlY2tib3giIGlkPSJtdi1pbnZvaWNlIj4gR8OpbsOpcmVyIHVuZSBmYWN0dXJlIHBvdXIgY2V0dGUgdmVudGUgKGZhY3VsdGF0aWYpPC9sYWJlbD4KICAgICAgPGRpdiBpZD0ibXYtaW52b2ljZS1maWVsZHMiIGhpZGRlbj4KICAgICAgICA8bGFiZWw+Tm9tIGR1IGNsaWVudCA8aW5wdXQgdHlwZT0idGV4dCIgaWQ9Im12LWNsaWVudCIgcGxhY2Vob2xkZXI9ImV4LiBNYXJpZSBUcmVtYmxheSI+PC9sYWJlbD4KICAgICAgICA8bGFiZWw+VGF1eCBkZSB0YXhlcyAoJSkgPGlucHV0IHR5cGU9Im51bWJlciIgaWQ9Im12LXRheCIgbWluPSIwIiBzdGVwPSIwLjAxIiB2YWx1ZT0iMCI+PC9sYWJlbD4KICAgICAgPC9kaXY+YCA6ICcnfQogICAgICA8cCBpZD0ibXYtZXJyb3IiIGNsYXNzPSJlcnJvciIgaGlkZGVuPjwvcD4KICAgICAgPGJ1dHRvbiB0eXBlPSJzdWJtaXQiIGNsYXNzPSJidG4gcHJpbWFyeSBiaWciPkNvbmZpcm1lciAke2lzU2FsZSA/ICdsYSB2ZW50ZScgOiAnbGUgbW91dmVtZW50J308L2J1dHRvbj4KICAgIDwvZm9ybT5gKTsKICBjb25zdCBpbnZCb3ggPSAkKCcjbXYtaW52b2ljZScpOwogIGlmIChpbnZCb3gpIGludkJveC5hZGRFdmVudExpc3RlbmVyKCdjaGFuZ2UnLCAoKSA9PiB7ICQoJyNtdi1pbnZvaWNlLWZpZWxkcycpLmhpZGRlbiA9ICFpbnZCb3guY2hlY2tlZDsgfSk7CiAgJCgnI21vdmUtZm9ybScpLmFkZEV2ZW50TGlzdGVuZXIoJ3N1Ym1pdCcsIGFzeW5jIChlKSA9PiB7CiAgICBlLnByZXZlbnREZWZhdWx0KCk7CiAgICBjb25zdCBlcnIgPSAkKCcjbXYtZXJyb3InKTsKICAgIGVyci5oaWRkZW4gPSB0cnVlOwogICAgY29uc3QgYm9keSA9IHsKICAgICAgYXJ0aWNsZV9pZDogYXJ0aWNsZUlkLAogICAgICB0eXBlLAogICAgICBxdWFudGl0eTogTnVtYmVyKCQoJyNtdi1xdHknKS52YWx1ZSksCiAgICAgIHVuaXRfcHJpY2U6IE51bWJlcigkKCcjbXYtcHJpY2UnKS52YWx1ZSksCiAgICAgIG5vdGU6ICQoJyNtdi1ub3RlJykudmFsdWUudHJpbSgpLAogICAgfTsKICAgIGlmIChpc1NhbGUgJiYgaW52Qm94ICYmIGludkJveC5jaGVja2VkKSB7CiAgICAgIGJvZHkuZ2VuZXJhdGVfaW52b2ljZSA9IHRydWU7CiAgICAgIGJvZHkuY2xpZW50X25hbWUgPSAkKCcjbXYtY2xpZW50JykudmFsdWUudHJpbSgpOwogICAgICBib2R5LnRheF9yYXRlID0gTnVtYmVyKCQoJyNtdi10YXgnKS52YWx1ZSB8fCAwKTsKICAgIH0KICAgIHRyeSB7CiAgICAgIGNvbnN0IHsgc3RvY2ssIGludm9pY2UgfSA9IGF3YWl0IGFwaSgnL2FwaS9tb3ZlbWVudHMnLCB7IG1ldGhvZDogJ1BPU1QnLCBib2R5OiBKU09OLnN0cmluZ2lmeShib2R5KSB9KTsKICAgICAgY2xvc2VNb2RhbCgpOwogICAgICB0b2FzdChpbnZvaWNlID8gYFZlbnRlIGVucmVnaXN0csOpZSDigJQgZmFjdHVyZSAke2ludm9pY2UubnVtYmVyfSBjcsOpw6llLmAgOiBgTW91dmVtZW50IGVucmVnaXN0csOpLiBOb3V2ZWF1IHN0b2NrIDogJHtzdG9ja30uYCk7CiAgICAgIGxvYWRBcnRpY2xlcygpOyBsb2FkRGFzaGJvYXJkKCk7IGxvYWRIaXN0b3J5KCk7IGxvYWRJbnZvaWNlcygpOwogICAgfSBjYXRjaCAoZXgpIHsgc2hvd0Vycm9yKGVyciwgZXgubWVzc2FnZSk7IH0KICB9KTsKfQoKLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCi8vIEhpc3RvcmlxdWUgZGVzIG1vdXZlbWVudHMKLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCmFzeW5jIGZ1bmN0aW9uIGxvYWRIaXN0b3J5KCkgewogIGNvbnN0IHBhcmFtcyA9IG5ldyBVUkxTZWFyY2hQYXJhbXMoKTsKICBjb25zdCB0eXBlID0gJCgnI2hpc3QtdHlwZScpLnZhbHVlOwogIGNvbnN0IGZyb20gPSAkKCcjaGlzdC1mcm9tJykudmFsdWU7CiAgY29uc3QgdG8gPSAkKCcjaGlzdC10bycpLnZhbHVlOwogIGlmICh0eXBlKSBwYXJhbXMuc2V0KCd0eXBlJywgdHlwZSk7CiAgaWYgKGZyb20pIHBhcmFtcy5zZXQoJ2Zyb20nLCBmcm9tKTsKICBpZiAodG8pIHBhcmFtcy5zZXQoJ3RvJywgdG8pOwogIHRyeSB7CiAgICBjb25zdCBsaXN0ID0gYXdhaXQgYXBpKCcvYXBpL21vdmVtZW50cz8nICsgcGFyYW1zLnRvU3RyaW5nKCkpOwogICAgJCgnI2hpc3RvcnktYm9keScpLmlubmVySFRNTCA9IGxpc3QubWFwKChtKSA9PiBgCiAgICAgIDx0cj48dGQ+JHtlc2MobS5kYXkpfTwvdGQ+PHRkPiR7ZXNjKG0uYXJ0aWNsZV9uYW1lKX08L3RkPgogICAgICA8dGQ+PHNwYW4gY2xhc3M9InRhZyAke20udHlwZX0iPiR7VFlQRV9MQUJFTFttLnR5cGVdfTwvc3Bhbj48L3RkPgogICAgICA8dGQ+JHttLnF1YW50aXR5fTwvdGQ+PHRkPiR7bW9uZXkobS51bml0X3ByaWNlKX08L3RkPjx0ZD4ke21vbmV5KG0udG90YWwpfTwvdGQ+CiAgICAgIDx0ZD4ke2VzYyhtLnVzZXJuYW1lIHx8ICcnKX08L3RkPjx0ZD4ke2VzYyhtLm5vdGUgfHwgJycpfTwvdGQ+PC90cj5gKS5qb2luKCcnKQogICAgICB8fCAnPHRyPjx0ZCBjb2xzcGFuPSI4IiBjbGFzcz0ibXV0ZWQiPkF1Y3VuIG1vdXZlbWVudCBwb3VyIGNlcyBmaWx0cmVzLjwvdGQ+PC90cj4nOwogIH0gY2F0Y2ggKF8pIHt9Cn0KJCgnI2hpc3QtYXBwbHknKS5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsIGxvYWRIaXN0b3J5KTsKCi8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQovLyBGYWN0dXJlcwovLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KYXN5bmMgZnVuY3Rpb24gbG9hZEludm9pY2VzKCkgewogIHRyeSB7CiAgICBjb25zdCBsaXN0ID0gYXdhaXQgYXBpKCcvYXBpL2ludm9pY2VzJyk7CiAgICAkKCcjaW52b2ljZXMtbGlzdCcpLmlubmVySFRNTCA9IGxpc3QubGVuZ3RoID8gbGlzdC5tYXAoKGludikgPT4gYAogICAgICA8ZGl2IGNsYXNzPSJjYXJkIj4KICAgICAgICA8ZGl2IGNsYXNzPSJjYXJkLWhlYWQiPgogICAgICAgICAgPGgzPvCfp74gJHtlc2MoaW52Lm51bWJlcil9IOKAlCAke2VzYyhpbnYuY2xpZW50X25hbWUgfHwgJ0NsaWVudCBjb21wdGFudCcpfTwvaDM+CiAgICAgICAgICA8c3BhbiBjbGFzcz0ibXV0ZWQiPiR7ZXNjKGludi5kYXkpfSDCtyBwYXIgJHtlc2MoaW52LnVzZXJuYW1lIHx8ICcnKX08L3NwYW4+CiAgICAgICAgPC9kaXY+CiAgICAgICAgPHA+JHsoaW52Lml0ZW1zIHx8IFtdKS5tYXAoKGl0KSA9PiBgJHtlc2MoaXQubmFtZSl9IMOXICR7aXQucXVhbnRpdHl9YCkuam9pbignIMK3ICcpfTwvcD4KICAgICAgICA8cD48Yj5Ub3RhbCA6ICR7bW9uZXkoaW52LnRvdGFsKX08L2I+IChzb3VzLXRvdGFsICR7bW9uZXkoaW52LnN1YnRvdGFsKX0sIHRheGVzICR7bW9uZXkoaW52LnRheF9hbW91bnQpfSk8L3A+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIHNtYWxsIiBvbmNsaWNrPSJ3aW5kb3cub3BlbignL2FwaS9pbnZvaWNlcy8ke2ludi5pZH0vaHRtbCcsJ19ibGFuaycpIj7wn5ao77iPIFZvaXIgLyBJbXByaW1lcjwvYnV0dG9uPgogICAgICA8L2Rpdj5gKS5qb2luKCcnKQogICAgICA6ICc8cCBjbGFzcz0iZW1wdHkiPkF1Y3VuZSBmYWN0dXJlIHBvdXIgbGUgbW9tZW50LiBMZXMgdmVudGVzIGZvbmN0aW9ubmVudCB0csOocyBiaWVuIHNhbnMgZmFjdHVyZSAhPC9wPic7CiAgfSBjYXRjaCAoXykge30KfQoKJCgnI25ldy1pbnZvaWNlLWJ0bicpLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCkgPT4gewogIGlmIChzdGF0ZS51c2VyLnJvbGUgPT09ICdsZWN0dXJlJykgeyB0b2FzdCgnVm90cmUgcsO0bGUgbmUgcGVybWV0IHBhcyBkZSBjcsOpZXIgZGVzIGZhY3R1cmVzLicpOyByZXR1cm47IH0KICBvcGVuTW9kYWwoYAogICAgPGgyPk5vdXZlbGxlIGZhY3R1cmU8L2gyPgogICAgPHAgY2xhc3M9Im11dGVkIj5GYWN1bHRhdGl2ZSA6IGNvY2hleiDCqyBEw6lkdWlyZSBkdSBzdG9jayDCuyBwb3VyIGVucmVnaXN0cmVyIGF1c3NpIGxlcyB2ZW50ZXMuPC9wPgogICAgPGZvcm0gaWQ9Imludm9pY2UtZm9ybSI+CiAgICAgIDxsYWJlbD5Ob20gZHUgY2xpZW50IDxpbnB1dCB0eXBlPSJ0ZXh0IiBpZD0iaW52LWNsaWVudCIgcGxhY2Vob2xkZXI9ImV4LiBNYXJpZSBUcmVtYmxheSI+PC9sYWJlbD4KICAgICAgPGxhYmVsPkluZm9zIGNsaWVudCAoYWRyZXNzZSwgdMOpbMOpcGhvbmXigKYpIDxpbnB1dCB0eXBlPSJ0ZXh0IiBpZD0iaW52LWluZm8iIHBsYWNlaG9sZGVyPSJGYWN1bHRhdGlmIj48L2xhYmVsPgogICAgICA8bGFiZWw+VGF1eCBkZSB0YXhlcyAoJSkgPGlucHV0IHR5cGU9Im51bWJlciIgaWQ9Imludi10YXgiIG1pbj0iMCIgc3RlcD0iMC4wMSIgdmFsdWU9IjAiPjwvbGFiZWw+CiAgICAgIDxoMz5MaWduZXM8L2gzPgogICAgICA8ZGl2IGlkPSJpbnYtbGluZXMiPjwvZGl2PgogICAgICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgY2xhc3M9ImJ0biBzbWFsbCIgaWQ9Imludi1hZGQtbGluZSI+77yLIEFqb3V0ZXIgdW5lIGxpZ25lPC9idXR0b24+CiAgICAgIDxsYWJlbCBjbGFzcz0iY2hlY2tib3gtbGluZSI+PGlucHV0IHR5cGU9ImNoZWNrYm94IiBpZD0iaW52LWRlZHVjdCIgY2hlY2tlZD4gRMOpZHVpcmUgbGVzIHF1YW50aXTDqXMgZHUgc3RvY2sgKGNyw6llIGRlcyB2ZW50ZXMpPC9sYWJlbD4KICAgICAgPHAgaWQ9Imludi1lcnJvciIgY2xhc3M9ImVycm9yIiBoaWRkZW4+PC9wPgogICAgICA8YnV0dG9uIHR5cGU9InN1Ym1pdCIgY2xhc3M9ImJ0biBwcmltYXJ5IGJpZyI+Q3LDqWVyIGxhIGZhY3R1cmU8L2J1dHRvbj4KICAgIDwvZm9ybT5gKTsKICBjb25zdCBhZGRMaW5lID0gKCkgPT4gewogICAgY29uc3QgZGl2ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnZGl2Jyk7CiAgICBkaXYuY2xhc3NOYW1lID0gJ2ludm9pY2UtbGluZSc7CiAgICBkaXYuaW5uZXJIVE1MID0gYAogICAgICA8c2VsZWN0IGNsYXNzPSJpbC1hcnRpY2xlIj4ke3N0YXRlLmFydGljbGVzLm1hcCgoYSkgPT4gYDxvcHRpb24gdmFsdWU9IiR7YS5pZH0iPiR7ZXNjKGEubmFtZSl9IOKAlCAke21vbmV5KGEucHJpY2UpfTwvb3B0aW9uPmApLmpvaW4oJycpfTwvc2VsZWN0PgogICAgICA8aW5wdXQgdHlwZT0ibnVtYmVyIiBjbGFzcz0iaWwtcXR5IiBtaW49IjEiIHN0ZXA9IjEiIHZhbHVlPSIxIj4KICAgICAgPGlucHV0IHR5cGU9Im51bWJlciIgY2xhc3M9ImlsLXByaWNlIiBtaW49IjAiIHN0ZXA9IjAuMDEiIHZhbHVlPSIke3N0YXRlLmFydGljbGVzWzBdID8gc3RhdGUuYXJ0aWNsZXNbMF0ucHJpY2UgOiAwfSI+CiAgICAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0iYnRuIHNtYWxsIGRhbmdlciBpbC1yZW1vdmUiPuKclTwvYnV0dG9uPmA7CiAgICBkaXYucXVlcnlTZWxlY3RvcignLmlsLWFydGljbGUnKS5hZGRFdmVudExpc3RlbmVyKCdjaGFuZ2UnLCAoZSkgPT4gewogICAgICBjb25zdCBhID0gc3RhdGUuYXJ0aWNsZXMuZmluZCgoeCkgPT4geC5pZCA9PT0gTnVtYmVyKGUudGFyZ2V0LnZhbHVlKSk7CiAgICAgIGlmIChhKSBkaXYucXVlcnlTZWxlY3RvcignLmlsLXByaWNlJykudmFsdWUgPSBhLnByaWNlOwogICAgfSk7CiAgICBkaXYucXVlcnlTZWxlY3RvcignLmlsLXJlbW92ZScpLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCkgPT4gZGl2LnJlbW92ZSgpKTsKICAgICQoJyNpbnYtbGluZXMnKS5hcHBlbmRDaGlsZChkaXYpOwogIH07CiAgJCgnI2ludi1hZGQtbGluZScpLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgYWRkTGluZSk7CiAgYWRkTGluZSgpOwogICQoJyNpbnZvaWNlLWZvcm0nKS5hZGRFdmVudExpc3RlbmVyKCdzdWJtaXQnLCBhc3luYyAoZSkgPT4gewogICAgZS5wcmV2ZW50RGVmYXVsdCgpOwogICAgY29uc3QgZXJyID0gJCgnI2ludi1lcnJvcicpOwogICAgZXJyLmhpZGRlbiA9IHRydWU7CiAgICBjb25zdCBsaW5lcyA9IFsuLi5kb2N1bWVudC5xdWVyeVNlbGVjdG9yQWxsKCcuaW52b2ljZS1saW5lJyldLm1hcCgocm93KSA9PiAoewogICAgICBhcnRpY2xlX2lkOiBOdW1iZXIocm93LnF1ZXJ5U2VsZWN0b3IoJy5pbC1hcnRpY2xlJykudmFsdWUpLAogICAgICBxdWFudGl0eTogTnVtYmVyKHJvdy5xdWVyeVNlbGVjdG9yKCcuaWwtcXR5JykudmFsdWUpLAogICAgICB1bml0X3ByaWNlOiBOdW1iZXIocm93LnF1ZXJ5U2VsZWN0b3IoJy5pbC1wcmljZScpLnZhbHVlKSwKICAgIH0pKTsKICAgIHRyeSB7CiAgICAgIGNvbnN0IGludiA9IGF3YWl0IGFwaSgnL2FwaS9pbnZvaWNlcycsIHsKICAgICAgICBtZXRob2Q6ICdQT1NUJywKICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7CiAgICAgICAgICBjbGllbnRfbmFtZTogJCgnI2ludi1jbGllbnQnKS52YWx1ZS50cmltKCksCiAgICAgICAgICBjbGllbnRfaW5mbzogJCgnI2ludi1pbmZvJykudmFsdWUudHJpbSgpLAogICAgICAgICAgdGF4X3JhdGU6IE51bWJlcigkKCcjaW52LXRheCcpLnZhbHVlIHx8IDApLAogICAgICAgICAgZGVkdWN0X3N0b2NrOiAkKCcjaW52LWRlZHVjdCcpLmNoZWNrZWQsCiAgICAgICAgICBsaW5lcywKICAgICAgICB9KSwKICAgICAgfSk7CiAgICAgIGNsb3NlTW9kYWwoKTsKICAgICAgdG9hc3QoYEZhY3R1cmUgJHtpbnYubnVtYmVyfSBjcsOpw6llLmApOwogICAgICBsb2FkSW52b2ljZXMoKTsgbG9hZEFydGljbGVzKCk7IGxvYWREYXNoYm9hcmQoKTsgbG9hZEhpc3RvcnkoKTsKICAgIH0gY2F0Y2ggKGV4KSB7IHNob3dFcnJvcihlcnIsIGV4Lm1lc3NhZ2UpOyB9CiAgfSk7Cn0pOwoKLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCi8vIMOJcXVpcGUgJiByw7RsZXMgKGFkbWluKQovLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KYXN5bmMgZnVuY3Rpb24gbG9hZFVzZXJzKCkgewogIHRyeSB7CiAgICBjb25zdCB1c2VycyA9IGF3YWl0IGFwaSgnL2FwaS91c2VycycpOwogICAgJCgnI3VzZXJzLWxpc3QnKS5pbm5lckhUTUwgPSB1c2Vycy5tYXAoKHUpID0+IGAKICAgICAgPGxpPjxzcGFuPjxiPiR7ZXNjKHUudXNlcm5hbWUpfTwvYj4g4oCUICR7Uk9MRV9MQUJFTFt1LnJvbGVdfTwvc3Bhbj4KICAgICAgPHNwYW4+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIHNtYWxsIiBvbmNsaWNrPSJyZXNldFVzZXJQYXNzd29yZCgke3UuaWR9LCcke2VzYyh1LnVzZXJuYW1lKX0nKSI+8J+UkSBOb3V2ZWF1IG1vdCBkZSBwYXNzZTwvYnV0dG9uPgogICAgICAgICR7dS5pZCAhPT0gc3RhdGUudXNlci5pZCA/IGA8YnV0dG9uIGNsYXNzPSJidG4gc21hbGwgZGFuZ2VyIiBvbmNsaWNrPSJkZWxldGVVc2VyKCR7dS5pZH0sJyR7ZXNjKHUudXNlcm5hbWUpfScpIj7wn5eR77iPPC9idXR0b24+YCA6ICcnfQogICAgICA8L3NwYW4+PC9saT5gKS5qb2luKCcnKTsKICB9IGNhdGNoIChfKSB7fQp9CgokKCcjdXNlci1mb3JtJykuYWRkRXZlbnRMaXN0ZW5lcignc3VibWl0JywgYXN5bmMgKGUpID0+IHsKICBlLnByZXZlbnREZWZhdWx0KCk7CiAgdHJ5IHsKICAgIGF3YWl0IGFwaSgnL2FwaS91c2VycycsIHsKICAgICAgbWV0aG9kOiAnUE9TVCcsCiAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsKICAgICAgICB1c2VybmFtZTogJCgnI3VzZXItbmFtZScpLnZhbHVlLnRyaW0oKSwKICAgICAgICBwYXNzd29yZDogJCgnI3VzZXItcGFzcycpLnZhbHVlLAogICAgICAgIHJvbGU6ICQoJyN1c2VyLXJvbGUnKS52YWx1ZSwKICAgICAgfSksCiAgICB9KTsKICAgIHRvYXN0KCdVdGlsaXNhdGV1ciBjcsOpw6kuJyk7CiAgICAkKCcjdXNlci1mb3JtJykucmVzZXQoKTsKICAgIGxvYWRVc2VycygpOwogIH0gY2F0Y2ggKGV4KSB7IHRvYXN0KGV4Lm1lc3NhZ2UpOyB9Cn0pOwoKYXN5bmMgZnVuY3Rpb24gZGVsZXRlVXNlcihpZCwgbmFtZSkgewogIGlmICghY29uZmlybShgU3VwcHJpbWVyIGwndXRpbGlzYXRldXIgwqsgJHtuYW1lfSDCuyA/YCkpIHJldHVybjsKICB0cnkgeyBhd2FpdCBhcGkoJy9hcGkvdXNlcnMvJyArIGlkLCB7IG1ldGhvZDogJ0RFTEVURScgfSk7IHRvYXN0KCdVdGlsaXNhdGV1ciBzdXBwcmltw6kuJyk7IGxvYWRVc2VycygpOyB9CiAgY2F0Y2ggKGUpIHsgdG9hc3QoZS5tZXNzYWdlKTsgfQp9Cgphc3luYyBmdW5jdGlvbiByZXNldFVzZXJQYXNzd29yZChpZCwgbmFtZSkgewogIGNvbnN0IHB3ID0gcHJvbXB0KGBOb3V2ZWF1IG1vdCBkZSBwYXNzZSBwb3VyIMKrICR7bmFtZX0gwrsgKDYgY2FyYWN0w6hyZXMgbWluLikgOmApOwogIGlmICghcHcpIHJldHVybjsKICB0cnkgewogICAgYXdhaXQgYXBpKCcvYXBpL3VzZXJzLycgKyBpZCwgeyBtZXRob2Q6ICdQVVQnLCBib2R5OiBKU09OLnN0cmluZ2lmeSh7IHBhc3N3b3JkOiBwdyB9KSB9KTsKICAgIHRvYXN0KCdNb3QgZGUgcGFzc2UgbWlzIMOgIGpvdXIuJyk7CiAgfSBjYXRjaCAoZSkgeyB0b2FzdChlLm1lc3NhZ2UpOyB9Cn0KCi8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQovLyBTYXV2ZWdhcmRlCi8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQokKCcjZXhwb3J0LWJ0bicpLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCkgPT4gewogIHdpbmRvdy5sb2NhdGlvbi5ocmVmID0gJy9hcGkvYmFja3VwL2V4cG9ydCc7CiAgdG9hc3QoJ0V4cG9ydCBlbiBjb3VycyBkZSB0w6lsw6ljaGFyZ2VtZW504oCmJyk7Cn0pOwoKJCgnI2ltcG9ydC1idG4nKS5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsIGFzeW5jICgpID0+IHsKICBjb25zdCBmaWxlID0gJCgnI2ltcG9ydC1maWxlJykuZmlsZXNbMF07CiAgaWYgKCFmaWxlKSB7ICQoJyNpbXBvcnQtbXNnJykudGV4dENvbnRlbnQgPSAnQ2hvaXNpc3NleiBk4oCZYWJvcmQgdW4gZmljaGllciBKU09OLic7IHJldHVybjsgfQogIGlmICghY29uZmlybSgnUmVzdGF1cmVyIGNldHRlIHNhdXZlZ2FyZGUgPyBMZXMgZG9ubsOpZXMgYWN0dWVsbGVzIHNlcm9udCByZW1wbGFjw6llcy4nKSkgcmV0dXJuOwogIHRyeSB7CiAgICBjb25zdCBkYXRhID0gSlNPTi5wYXJzZShhd2FpdCBmaWxlLnRleHQoKSk7CiAgICBjb25zdCByZXMgPSBhd2FpdCBhcGkoJy9hcGkvYmFja3VwL2ltcG9ydCcsIHsgbWV0aG9kOiAnUE9TVCcsIGJvZHk6IEpTT04uc3RyaW5naWZ5KGRhdGEpIH0pOwogICAgJCgnI2ltcG9ydC1tc2cnKS50ZXh0Q29udGVudCA9IHJlcy5yZXN0b3JlZEFkbWluCiAgICAgID8gJ1NhdXZlZ2FyZGUgcmVzdGF1csOpZS4gQXVjdW4gYWRtaW4gdHJvdXbDqSA6IGNvbXB0ZSBhZG1pbiAvIGFkbWluMTIzIHJlY3LDqcOpLicKICAgICAgOiAnU2F1dmVnYXJkZSByZXN0YXVyw6llIGF2ZWMgc3VjY8Oocy4nOwogICAgdG9hc3QoJ1NhdXZlZ2FyZGUgcmVzdGF1csOpZS4nKTsKICAgIGxvYWREYXNoYm9hcmQoKTsgbG9hZEFydGljbGVzKCk7IGxvYWRJbnZvaWNlcygpOwogIH0gY2F0Y2ggKGUpIHsKICAgICQoJyNpbXBvcnQtbXNnJykudGV4dENvbnRlbnQgPSAnRXJyZXVyIDogJyArIGUubWVzc2FnZTsKICB9Cn0pOwoKLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCi8vIETDqW1hcnJhZ2UKLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCmNoZWNrU2Vzc2lvbigpOwo=","style.css":"LyogR2VzdGlvbm5haXJlIGQnaW52ZW50YWlyZSDigJQgaW50ZXJmYWNlIGFjY3VlaWxsYW50ZSwgbW9iaWxlIGQnYWJvcmQgKi8KOnJvb3QgewogIC0tcHJpbWFyeTogIzI1NjNlYjsKICAtLXByaW1hcnktZGFyazogIzFkNGVkODsKICAtLWdyZWVuOiAjMTZhMzRhOwogIC0tcmVkOiAjZGMyNjI2OwogIC0tYW1iZXI6ICNkOTc3MDY7CiAgLS1iZzogI2Y2ZjhmYjsKICAtLWNhcmQ6ICNmZmZmZmY7CiAgLS10ZXh0OiAjMWYyOTM3OwogIC0tbXV0ZWQ6ICM2YjcyODA7CiAgLS1ib3JkZXI6ICNlNWU3ZWI7CiAgLS1yYWRpdXM6IDE0cHg7Cn0KKiB7IGJveC1zaXppbmc6IGJvcmRlci1ib3g7IH0KLyogTCdhdHRyaWJ1dCBoaWRkZW4gZG9pdCB0b3Vqb3VycyBjYWNoZXIgbCfDqWzDqW1lbnQsIG3Dqm1lIHF1YW5kIHVuZSBjbGFzc2UKICAgZMOpZmluaXQgdW4gZGlzcGxheSAoZXguIC5tb2RhbC1iYWNrZHJvcCBlbiBkaXNwbGF5OmZsZXgpIDogc2FucyBjZXR0ZQogICByw6hnbGUsIGxlIGZvbmQgc29tYnJlIGRlIGxhIGZlbsOqdHJlIG1vZGFsZSByZXN0ZSBhZmZpY2jDqSBwYXItZGVzc3VzCiAgIHRvdXRlIGxhIHBhZ2UgZXQgYmxvcXVlIHRvdXMgbGVzIGNsaWNzLiAqLwpbaGlkZGVuXSB7IGRpc3BsYXk6IG5vbmUgIWltcG9ydGFudDsgfQpib2R5IHsgbWFyZ2luOiAwOyBmb250LWZhbWlseTogc3lzdGVtLXVpLCAtYXBwbGUtc3lzdGVtLCAiU2Vnb2UgVUkiLCBSb2JvdG8sIHNhbnMtc2VyaWY7IGJhY2tncm91bmQ6IHZhcigtLWJnKTsgY29sb3I6IHZhcigtLXRleHQpOyB9CmgxIHsgZm9udC1zaXplOiAxLjVyZW07IG1hcmdpbjogMCAwIDhweDsgfQpoMiB7IGZvbnQtc2l6ZTogMS4zcmVtOyBtYXJnaW46IDAgMCA0cHg7IH0KaDMgeyBmb250LXNpemU6IDEuMDVyZW07IG1hcmdpbjogMCAwIDEwcHg7IH0KcCB7IG1hcmdpbjogNnB4IDA7IH0KLm11dGVkIHsgY29sb3I6IHZhcigtLW11dGVkKTsgZm9udC1zaXplOiAuOTJyZW07IH0KLmVycm9yIHsgY29sb3I6IHZhcigtLXJlZCk7IGZvbnQtc2l6ZTogLjkycmVtOyB9CmJ1dHRvbiB7IGZvbnQtZmFtaWx5OiBpbmhlcml0OyBjdXJzb3I6IHBvaW50ZXI7IH0KaW5wdXQsIHNlbGVjdCwgdGV4dGFyZWEgeyBmb250LWZhbWlseTogaW5oZXJpdDsgZm9udC1zaXplOiAxcmVtOyBwYWRkaW5nOiAxMHB4IDEycHg7IGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7IGJvcmRlci1yYWRpdXM6IDEwcHg7IHdpZHRoOiAxMDAlOyBiYWNrZ3JvdW5kOiAjZmZmOyB9CmxhYmVsIHsgZGlzcGxheTogYmxvY2s7IGZvbnQtc2l6ZTogLjkycmVtOyBmb250LXdlaWdodDogNjAwOyBtYXJnaW4tYm90dG9tOiAxMnB4OyB9CmxhYmVsIGlucHV0LCBsYWJlbCBzZWxlY3QsIGxhYmVsIHRleHRhcmVhIHsgbWFyZ2luLXRvcDogNXB4OyBmb250LXdlaWdodDogNDAwOyB9CnRleHRhcmVhIHsgcmVzaXplOiB2ZXJ0aWNhbDsgbWluLWhlaWdodDogNzBweDsgfQoKLyogQm91dG9ucyAqLwouYnRuIHsgYmFja2dyb3VuZDogI2ZmZjsgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsgYm9yZGVyLXJhZGl1czogMTBweDsgcGFkZGluZzogMTBweCAxNnB4OyBmb250LXNpemU6IC45NXJlbTsgZm9udC13ZWlnaHQ6IDYwMDsgY29sb3I6IHZhcigtLXRleHQpOyB9Ci5idG46aG92ZXIgeyBiYWNrZ3JvdW5kOiAjZjNmNGY2OyB9Ci5idG4ucHJpbWFyeSB7IGJhY2tncm91bmQ6IHZhcigtLXByaW1hcnkpOyBib3JkZXItY29sb3I6IHZhcigtLXByaW1hcnkpOyBjb2xvcjogI2ZmZjsgfQouYnRuLnByaW1hcnk6aG92ZXIgeyBiYWNrZ3JvdW5kOiB2YXIoLS1wcmltYXJ5LWRhcmspOyB9Ci5idG4uZGFuZ2VyIHsgY29sb3I6IHZhcigtLXJlZCk7IGJvcmRlci1jb2xvcjogI2ZlY2FjYTsgfQouYnRuLnNtYWxsIHsgcGFkZGluZzogNnB4IDEwcHg7IGZvbnQtc2l6ZTogLjg1cmVtOyB9Ci5idG4uYmlnIHsgd2lkdGg6IDEwMCU7IHBhZGRpbmc6IDEzcHg7IGZvbnQtc2l6ZTogMS4wNXJlbTsgfQouYnRuOmRpc2FibGVkIHsgb3BhY2l0eTogLjU7IGN1cnNvcjogbm90LWFsbG93ZWQ7IH0KCi8qIENvbm5leGlvbiAqLwoubG9naW4td3JhcCB7IG1pbi1oZWlnaHQ6IDEwMHZoOyBkaXNwbGF5OiBmbGV4OyBhbGlnbi1pdGVtczogY2VudGVyOyBqdXN0aWZ5LWNvbnRlbnQ6IGNlbnRlcjsgcGFkZGluZzogMjBweDsKICBiYWNrZ3JvdW5kOiBsaW5lYXItZ3JhZGllbnQoMTYwZGVnLCAjZGJlYWZlLCAjZWZmNmZmIDU1JSwgI2ZlZjNjNyk7IH0KLmxvZ2luLWNhcmQgeyBiYWNrZ3JvdW5kOiAjZmZmOyBib3JkZXItcmFkaXVzOiAyMHB4OyBib3gtc2hhZG93OiAwIDEwcHggMzBweCByZ2JhKDAsMCwwLC4xMik7IHBhZGRpbmc6IDMycHggMjhweDsgd2lkdGg6IDEwMCU7IG1heC13aWR0aDogNDIwcHg7IHRleHQtYWxpZ246IGNlbnRlcjsgfQoubG9nbyB7IGZvbnQtc2l6ZTogM3JlbTsgfQouc3VidGl0bGUgeyBjb2xvcjogdmFyKC0tbXV0ZWQpOyBtYXJnaW4tYm90dG9tOiAyMHB4OyB9Ci5sb2dpbi1jYXJkIGZvcm0geyB0ZXh0LWFsaWduOiBsZWZ0OyB9Ci5oaW50IHsgZm9udC1zaXplOiAuODVyZW07IGNvbG9yOiB2YXIoLS1tdXRlZCk7IG1hcmdpbi10b3A6IDE2cHg7IH0KCi8qIEJhcnJlIGR1IGhhdXQgKyBvbmdsZXRzICovCi50b3BiYXIgeyBkaXNwbGF5OiBmbGV4OyBqdXN0aWZ5LWNvbnRlbnQ6IHNwYWNlLWJldHdlZW47IGFsaWduLWl0ZW1zOiBjZW50ZXI7IGdhcDogMTBweDsgcGFkZGluZzogMTJweCAxNnB4OyBiYWNrZ3JvdW5kOiAjZmZmOyBib3JkZXItYm90dG9tOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsgcG9zaXRpb246IHN0aWNreTsgdG9wOiAwOyB6LWluZGV4OiAxMDsgfQouYnJhbmQgeyBmb250LXNpemU6IDEuMnJlbTsgZm9udC13ZWlnaHQ6IDgwMDsgfQouYnJhbmQgc3BhbiB7IGNvbG9yOiB2YXIoLS1wcmltYXJ5KTsgfQoudXNlcmJveCB7IGRpc3BsYXk6IGZsZXg7IGFsaWduLWl0ZW1zOiBjZW50ZXI7IGdhcDogOHB4OyB9Ci5jaGlwIHsgYmFja2dyb3VuZDogI2RiZWFmZTsgY29sb3I6ICMxZTQwYWY7IGJvcmRlci1yYWRpdXM6IDk5OXB4OyBwYWRkaW5nOiA1cHggMTJweDsgZm9udC1zaXplOiAuODVyZW07IGZvbnQtd2VpZ2h0OiA3MDA7IH0KLnRhYnMgeyBkaXNwbGF5OiBmbGV4OyBnYXA6IDZweDsgcGFkZGluZzogMTBweCAxNnB4OyBvdmVyZmxvdy14OiBhdXRvOyBiYWNrZ3JvdW5kOiAjZmZmOyBib3JkZXItYm90dG9tOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsgfQoudGFicyBidXR0b24geyB3aGl0ZS1zcGFjZTogbm93cmFwOyBib3JkZXI6IDFweCBzb2xpZCB0cmFuc3BhcmVudDsgYmFja2dyb3VuZDogbm9uZTsgcGFkZGluZzogOHB4IDEycHg7IGJvcmRlci1yYWRpdXM6IDk5OXB4OyBmb250LXNpemU6IC45NXJlbTsgZm9udC13ZWlnaHQ6IDYwMDsgY29sb3I6IHZhcigtLW11dGVkKTsgfQoudGFicyBidXR0b24uYWN0aXZlIHsgYmFja2dyb3VuZDogI2RiZWFmZTsgY29sb3I6ICMxZTQwYWY7IH0KbWFpbiB7IG1heC13aWR0aDogMTEwMHB4OyBtYXJnaW46IDAgYXV0bzsgcGFkZGluZzogMjBweCAxNnB4IDYwcHg7IH0KLnRhYi1wYWdlIHsgYW5pbWF0aW9uOiBmYWRlIC4ycyBlYXNlOyB9CkBrZXlmcmFtZXMgZmFkZSB7IGZyb20geyBvcGFjaXR5OiAwOyB9IHRvIHsgb3BhY2l0eTogMTsgfSB9CgovKiBDYXJ0ZXMgZXQgaW5kaWNhdGV1cnMgKi8KLmNhcmQgeyBiYWNrZ3JvdW5kOiB2YXIoLS1jYXJkKTsgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsgYm9yZGVyLXJhZGl1czogdmFyKC0tcmFkaXVzKTsgcGFkZGluZzogMThweDsgbWFyZ2luLWJvdHRvbTogMTZweDsgfQouY2FyZC1oZWFkIHsgZGlzcGxheTogZmxleDsganVzdGlmeS1jb250ZW50OiBzcGFjZS1iZXR3ZWVuOyBhbGlnbi1pdGVtczogY2VudGVyOyBmbGV4LXdyYXA6IHdyYXA7IGdhcDogOHB4OyB9Ci5rcGlzIHsgZGlzcGxheTogZ3JpZDsgZ3JpZC10ZW1wbGF0ZS1jb2x1bW5zOiByZXBlYXQoNCwgMWZyKTsgZ2FwOiAxMnB4OyBtYXJnaW46IDE2cHggMDsgfQoua3BpIHsgYmFja2dyb3VuZDogI2ZmZjsgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsgYm9yZGVyLXJhZGl1czogdmFyKC0tcmFkaXVzKTsgcGFkZGluZzogMTZweDsgZGlzcGxheTogZmxleDsgZmxleC1kaXJlY3Rpb246IGNvbHVtbjsgZ2FwOiA0cHg7IH0KLmtwaS1sYWJlbCB7IGZvbnQtc2l6ZTogLjg1cmVtOyBjb2xvcjogdmFyKC0tbXV0ZWQpOyB9Ci5rcGktdmFsdWUgeyBmb250LXNpemU6IDEuMzVyZW07IGZvbnQtd2VpZ2h0OiA4MDA7IH0KLmdyaWQyIHsgZGlzcGxheTogZ3JpZDsgZ3JpZC10ZW1wbGF0ZS1jb2x1bW5zOiAxZnIgMWZyOyBnYXA6IDE2cHg7IH0KLmxpc3QgeyBsaXN0LXN0eWxlOiBub25lOyBtYXJnaW46IDA7IHBhZGRpbmc6IDA7IH0KLmxpc3QgbGkgeyBwYWRkaW5nOiAxMHB4IDA7IGJvcmRlci1ib3R0b206IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOyBkaXNwbGF5OiBmbGV4OyBqdXN0aWZ5LWNvbnRlbnQ6IHNwYWNlLWJldHdlZW47IGdhcDogMTBweDsgYWxpZ24taXRlbXM6IGNlbnRlcjsgfQoubGlzdCBsaTpsYXN0LWNoaWxkIHsgYm9yZGVyLWJvdHRvbTogbm9uZTsgfQouc2VnIHsgZGlzcGxheTogaW5saW5lLWZsZXg7IGJvcmRlcjogMXB4IHNvbGlkIHZhcigtLWJvcmRlcik7IGJvcmRlci1yYWRpdXM6IDk5OXB4OyBvdmVyZmxvdzogaGlkZGVuOyB9Ci5zZWcgYnV0dG9uIHsgYm9yZGVyOiBub25lOyBiYWNrZ3JvdW5kOiAjZmZmOyBwYWRkaW5nOiA3cHggMTJweDsgZm9udC1zaXplOiAuODVyZW07IGZvbnQtd2VpZ2h0OiA2MDA7IGNvbG9yOiB2YXIoLS1tdXRlZCk7IH0KLnNlZyBidXR0b24uYWN0aXZlIHsgYmFja2dyb3VuZDogdmFyKC0tcHJpbWFyeSk7IGNvbG9yOiAjZmZmOyB9CmNhbnZhcyNjaGFydCB7IHdpZHRoOiAxMDAlOyBtYXgtaGVpZ2h0OiAyMjBweDsgfQoKLyogQWxlcnRlcyAqLwouYWxlcnQgeyBib3JkZXItcmFkaXVzOiAxMnB4OyBwYWRkaW5nOiAxMnB4IDE0cHg7IG1hcmdpbi1ib3R0b206IDEycHg7IGZvbnQtc2l6ZTogLjk1cmVtOyB9Ci5hbGVydC53YXJuIHsgYmFja2dyb3VuZDogI2ZlZjNjNzsgYm9yZGVyOiAxcHggc29saWQgI2ZjZDM0ZDsgfQouYWxlcnQuZGFuZ2VyIHsgYmFja2dyb3VuZDogI2ZlZTJlMjsgYm9yZGVyOiAxcHggc29saWQgI2ZjYTVhNTsgfQouYWxlcnQub2sgeyBiYWNrZ3JvdW5kOiAjZGNmY2U3OyBib3JkZXI6IDFweCBzb2xpZCAjODZlZmFjOyB9CgovKiBBcnRpY2xlcyAqLwoucGFnZS1oZWFkIHsgZGlzcGxheTogZmxleDsganVzdGlmeS1jb250ZW50OiBzcGFjZS1iZXR3ZWVuOyBhbGlnbi1pdGVtczogZmxleC1zdGFydDsgZ2FwOiAxMnB4OyBmbGV4LXdyYXA6IHdyYXA7IG1hcmdpbi1ib3R0b206IDE0cHg7IH0KLnNlYXJjaC1yb3cgeyBkaXNwbGF5OiBmbGV4OyBnYXA6IDEwcHg7IG1hcmdpbi1ib3R0b206IDE2cHg7IH0KLnNlYXJjaC1yb3cgaW5wdXQgeyBmbGV4OiAyOyB9Ci5zZWFyY2gtcm93IHNlbGVjdCB7IGZsZXg6IDE7IH0KLmFydGljbGVzLWdyaWQgeyBkaXNwbGF5OiBncmlkOyBncmlkLXRlbXBsYXRlLWNvbHVtbnM6IHJlcGVhdChhdXRvLWZpbGwsIG1pbm1heCgyNTBweCwgMWZyKSk7IGdhcDogMTRweDsgbWFyZ2luLWJvdHRvbTogMjBweDsgfQouYXJ0aWNsZS1jYXJkIHsgYmFja2dyb3VuZDogI2ZmZjsgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tYm9yZGVyKTsgYm9yZGVyLXJhZGl1czogdmFyKC0tcmFkaXVzKTsgb3ZlcmZsb3c6IGhpZGRlbjsgZGlzcGxheTogZmxleDsgZmxleC1kaXJlY3Rpb246IGNvbHVtbjsgfQouYXJ0aWNsZS1jYXJkIGltZyB7IHdpZHRoOiAxMDAlOyBoZWlnaHQ6IDE1MHB4OyBvYmplY3QtZml0OiBjb3ZlcjsgYmFja2dyb3VuZDogI2VlZjJmZjsgfQouYXJ0aWNsZS1jYXJkIC5uby1waG90byB7IGhlaWdodDogMTUwcHg7IGRpc3BsYXk6IGZsZXg7IGFsaWduLWl0ZW1zOiBjZW50ZXI7IGp1c3RpZnktY29udGVudDogY2VudGVyOyBmb250LXNpemU6IDNyZW07IGJhY2tncm91bmQ6ICNlZWYyZmY7IH0KLmFydGljbGUtYm9keSB7IHBhZGRpbmc6IDE0cHg7IGRpc3BsYXk6IGZsZXg7IGZsZXgtZGlyZWN0aW9uOiBjb2x1bW47IGdhcDogNnB4OyBmbGV4OiAxOyB9Ci5hcnRpY2xlLWJvZHkgaDMgeyBtYXJnaW46IDA7IH0KLmFydGljbGUtYm9keSAuZGVzYyB7IGNvbG9yOiB2YXIoLS1tdXRlZCk7IGZvbnQtc2l6ZTogLjlyZW07IGZsZXg6IDE7IH0KLnByaWNlIHsgZm9udC13ZWlnaHQ6IDgwMDsgZm9udC1zaXplOiAxLjFyZW07IH0KLnN0b2NrLWxpbmUgeyBkaXNwbGF5OiBmbGV4OyBqdXN0aWZ5LWNvbnRlbnQ6IHNwYWNlLWJldHdlZW47IGFsaWduLWl0ZW1zOiBjZW50ZXI7IH0KLmJhZGdlIHsgZm9udC1zaXplOiAuNzhyZW07IGZvbnQtd2VpZ2h0OiA3MDA7IGJvcmRlci1yYWRpdXM6IDk5OXB4OyBwYWRkaW5nOiAzcHggOXB4OyB9Ci5iYWRnZS5vayB7IGJhY2tncm91bmQ6ICNkY2ZjZTc7IGNvbG9yOiAjMTY2NTM0OyB9Ci5iYWRnZS53YXJuIHsgYmFja2dyb3VuZDogI2ZlZjNjNzsgY29sb3I6ICM5MjQwMGU7IH0KLmJhZGdlLm91dCB7IGJhY2tncm91bmQ6ICNmZWUyZTI7IGNvbG9yOiAjOTkxYjFiOyB9Ci5xdHktcm93IHsgZGlzcGxheTogZmxleDsgZ2FwOiA2cHg7IGZsZXgtd3JhcDogd3JhcDsgfQoucXR5LXJvdyAuYnRuIHsgZmxleDogMTsgcGFkZGluZzogOHB4IDRweDsgZm9udC1zaXplOiAuODVyZW07IH0KLmVtcHR5IHsgdGV4dC1hbGlnbjogY2VudGVyOyBjb2xvcjogdmFyKC0tbXV0ZWQpOyBwYWRkaW5nOiA0MHB4IDEwcHg7IH0KCi8qIFRhYmxlYXV4ICovCi50YWJsZS13cmFwIHsgb3ZlcmZsb3cteDogYXV0bzsgfQp0YWJsZSB7IHdpZHRoOiAxMDAlOyBib3JkZXItY29sbGFwc2U6IGNvbGxhcHNlOyBmb250LXNpemU6IC45cmVtOyB9CnRoLCB0ZCB7IHBhZGRpbmc6IDhweCA2cHg7IGJvcmRlci1ib3R0b206IDFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOyB0ZXh0LWFsaWduOiBsZWZ0OyB3aGl0ZS1zcGFjZTogbm93cmFwOyB9CnRoIHsgY29sb3I6IHZhcigtLW11dGVkKTsgZm9udC1zaXplOiAuOHJlbTsgdGV4dC10cmFuc2Zvcm06IHVwcGVyY2FzZTsgfQoudGFnIHsgZm9udC1zaXplOiAuNzhyZW07IGZvbnQtd2VpZ2h0OiA3MDA7IGJvcmRlci1yYWRpdXM6IDk5OXB4OyBwYWRkaW5nOiAycHggOHB4OyB9Ci50YWcuZW50cmVlIHsgYmFja2dyb3VuZDogI2RjZmNlNzsgY29sb3I6ICMxNjY1MzQ7IH0KLnRhZy52ZW50ZSB7IGJhY2tncm91bmQ6ICNkYmVhZmU7IGNvbG9yOiAjMWU0MGFmOyB9Ci50YWcuc29ydGllIHsgYmFja2dyb3VuZDogI2ZlZTJlMjsgY29sb3I6ICM5OTFiMWI7IH0KLmZpbHRlcnMgeyBkaXNwbGF5OiBmbGV4OyBnYXA6IDhweDsgZmxleC13cmFwOiB3cmFwOyBtYXJnaW4tYm90dG9tOiAxMnB4OyB9Ci5maWx0ZXJzIHNlbGVjdCwgLmZpbHRlcnMgaW5wdXQgeyB3aWR0aDogYXV0bzsgZmxleDogMTsgbWluLXdpZHRoOiAxMjBweDsgfQoKLyogRm9ybXVsYWlyZXMgKi8KLmZvcm0tZ3JpZCB7IGRpc3BsYXk6IGdyaWQ7IGdyaWQtdGVtcGxhdGUtY29sdW1uczogMWZyIDFmcjsgZ2FwOiAwIDE0cHg7IH0KLmZvcm0tZ3JpZCBsYWJlbC5mdWxsIHsgZ3JpZC1jb2x1bW46IDEgLyAtMTsgfQouc3RlcHMgeyBkaXNwbGF5OiBmbGV4OyBnYXA6IDZweDsgbWFyZ2luLWJvdHRvbTogMTZweDsgfQouc3RlcHMgc3BhbiB7IGZsZXg6IDE7IHRleHQtYWxpZ246IGNlbnRlcjsgZm9udC1zaXplOiAuOHJlbTsgZm9udC13ZWlnaHQ6IDcwMDsgcGFkZGluZzogN3B4IDRweDsgYm9yZGVyLXJhZGl1czogOTk5cHg7IGJhY2tncm91bmQ6ICNmM2Y0ZjY7IGNvbG9yOiB2YXIoLS1tdXRlZCk7IH0KLnN0ZXBzIHNwYW4ub24geyBiYWNrZ3JvdW5kOiAjZGJlYWZlOyBjb2xvcjogIzFlNDBhZjsgfQoucGhvdG8tcHJldmlldyB7IHdpZHRoOiAxMDAlOyBtYXgtaGVpZ2h0OiAyMDBweDsgb2JqZWN0LWZpdDogY29udGFpbjsgYm9yZGVyOiAxcHggZGFzaGVkIHZhcigtLWJvcmRlcik7IGJvcmRlci1yYWRpdXM6IDEwcHg7IG1hcmdpbi10b3A6IDhweDsgfQouY2hlY2tib3gtbGluZSB7IGRpc3BsYXk6IGZsZXg7IGFsaWduLWl0ZW1zOiBjZW50ZXI7IGdhcDogOHB4OyBmb250LXdlaWdodDogNjAwOyB9Ci5jaGVja2JveC1saW5lIGlucHV0IHsgd2lkdGg6IGF1dG87IH0KLmludm9pY2UtbGluZSB7IGRpc3BsYXk6IGdyaWQ7IGdyaWQtdGVtcGxhdGUtY29sdW1uczogMmZyIDFmciAxZnIgYXV0bzsgZ2FwOiA4cHg7IG1hcmdpbi1ib3R0b206IDhweDsgYWxpZ24taXRlbXM6IGNlbnRlcjsgfQouaW52b2ljZS1saW5lIHNlbGVjdCwgLmludm9pY2UtbGluZSBpbnB1dCB7IHdpZHRoOiAxMDAlOyB9CgovKiBNb2RhbGUgKyB0b2FzdCAqLwoubW9kYWwtYmFja2Ryb3AgeyBwb3NpdGlvbjogZml4ZWQ7IGluc2V0OiAwOyBiYWNrZ3JvdW5kOiByZ2JhKDAsMCwwLC40NSk7IGRpc3BsYXk6IGZsZXg7IGFsaWduLWl0ZW1zOiBmbGV4LXN0YXJ0OyBqdXN0aWZ5LWNvbnRlbnQ6IGNlbnRlcjsgcGFkZGluZzogMjBweCAxMnB4OyB6LWluZGV4OiA1MDsgb3ZlcmZsb3cteTogYXV0bzsgfQoubW9kYWwgeyBiYWNrZ3JvdW5kOiAjZmZmOyBib3JkZXItcmFkaXVzOiAxNnB4OyBwYWRkaW5nOiAyMnB4OyB3aWR0aDogMTAwJTsgbWF4LXdpZHRoOiA1MjBweDsgcG9zaXRpb246IHJlbGF0aXZlOyBtYXJnaW4tdG9wOiAyMHB4OyB9Ci5tb2RhbC1jbG9zZSB7IHBvc2l0aW9uOiBhYnNvbHV0ZTsgdG9wOiAxMHB4OyByaWdodDogMTJweDsgYm9yZGVyOiBub25lOyBiYWNrZ3JvdW5kOiBub25lOyBmb250LXNpemU6IDEuMnJlbTsgfQoudG9hc3QgeyBwb3NpdGlvbjogZml4ZWQ7IGJvdHRvbTogMjBweDsgbGVmdDogNTAlOyB0cmFuc2Zvcm06IHRyYW5zbGF0ZVgoLTUwJSk7IGJhY2tncm91bmQ6ICMxMTE4Mjc7IGNvbG9yOiAjZmZmOyBwYWRkaW5nOiAxMnB4IDE4cHg7IGJvcmRlci1yYWRpdXM6IDk5OXB4OyBmb250LXNpemU6IC45NXJlbTsgei1pbmRleDogMTAwOyBib3gtc2hhZG93OiAwIDZweCAyMHB4IHJnYmEoMCwwLDAsLjMpOyBtYXgtd2lkdGg6IDkwdnc7IHRleHQtYWxpZ246IGNlbnRlcjsgfQoKLyogUGV0aXQgw6ljcmFuICovCkBtZWRpYSAobWF4LXdpZHRoOiA3MDBweCkgewogIC5rcGlzIHsgZ3JpZC10ZW1wbGF0ZS1jb2x1bW5zOiAxZnIgMWZyOyB9CiAgLmdyaWQyIHsgZ3JpZC10ZW1wbGF0ZS1jb2x1bW5zOiAxZnI7IH0KICAuZm9ybS1ncmlkIHsgZ3JpZC10ZW1wbGF0ZS1jb2x1bW5zOiAxZnI7IH0KICAuc2VhcmNoLXJvdyB7IGZsZXgtZGlyZWN0aW9uOiBjb2x1bW47IH0KICAuaW52b2ljZS1saW5lIHsgZ3JpZC10ZW1wbGF0ZS1jb2x1bW5zOiAxZnIgMWZyOyB9CiAgLmJyYW5kIHNwYW4geyBkaXNwbGF5OiBub25lOyB9Cn0K"};
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
