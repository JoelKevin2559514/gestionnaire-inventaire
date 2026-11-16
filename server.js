// ============================================================================
// Gestionnaire d'inventaire — serveur autonome
// Node.js + Express + SQLite intégré (node:sqlite, aucune compilation native)
// Démarrage : node server.js  (port via la variable PORT, écoute 0.0.0.0)
// ============================================================================
const express = require('express');
const path = require('path');
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
// ---------------------------------------------------------------------------
app.use(express.static(path.join(__dirname, 'public')));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, HOST, () => {
  console.log(`Gestionnaire d'inventaire en ligne sur http://${HOST}:${PORT}`);
  console.log(`Base de données : ${DB_PATH}`);
});
