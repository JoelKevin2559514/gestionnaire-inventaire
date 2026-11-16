// ============================================================================
// Gestionnaire d'inventaire — interface (vanilla JS, aucune dépendance)
// ============================================================================
const $ = (s) => document.querySelector(s);
const $$ = (s) => document.querySelectorAll(s);

const state = {
  user: null,
  articles: [],
  dashboard: null,
  chartMode: 'daily',
};

const ROLE_LABEL = { admin: 'Admin', employe: 'Employé', lecture: 'Lecture seule' };
const TYPE_LABEL = { entree: 'Entrée', vente: 'Vente', sortie: 'Sortie' };

// Monnaie affichée dans toute l'application. Pour changer de monnaie,
// modifiez seulement ces deux lignes (ex. SYMBOL = '€' et DECIMALS = 2,
// ou SYMBOL = '$' et DECIMALS = 2). Le FCFA n'a pas de centimes : 0 décimale.
const CURRENCY_SYMBOL = 'FCFA';
const CURRENCY_DECIMALS = 0;

function money(n) {
  const v = Math.round((Number(n) || 0) * 100) / 100;
  return v.toLocaleString('fr-FR', { minimumFractionDigits: CURRENCY_DECIMALS, maximumFractionDigits: CURRENCY_DECIMALS }) + ' ' + CURRENCY_SYMBOL;
}
function esc(s) {
  return String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
function toast(msg) {
  const t = $('#toast');
  t.textContent = msg;
  t.hidden = false;
  clearTimeout(t._timer);
  t._timer = setTimeout(() => { t.hidden = true; }, 3500);
}
function showError(el, msg) { el.textContent = msg; el.hidden = false; }

async function api(path, opts = {}) {
  const res = await fetch(path, {
    ...opts,
    headers: { 'Content-Type': 'application/json', ...(opts.headers || {}) },
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || 'Erreur serveur.');
  return data;
}

// ---------------------------------------------------------------------------
// Modale
// ---------------------------------------------------------------------------
function openModal(html) {
  $('#modal-content').innerHTML = html;
  $('#modal-backdrop').hidden = false;
}
function closeModal() {
  $('#modal-backdrop').hidden = true;
  $('#modal-content').innerHTML = '';
}
$('#modal-close').addEventListener('click', closeModal);
$('#modal-backdrop').addEventListener('click', (e) => { if (e.target.id === 'modal-backdrop') closeModal(); });

// ---------------------------------------------------------------------------
// Authentification
// ---------------------------------------------------------------------------
async function checkSession() {
  try {
    const { user } = await api('/api/me');
    enterApp(user);
  } catch (_) {
    showView('login');
  }
}

function showView(name) {
  $('#login-view').hidden = name !== 'login';
  $('#password-view').hidden = name !== 'password';
  $('#app-view').hidden = name !== 'app';
}

function enterApp(user) {
  state.user = user;
  if (user.mustChangePassword) { showView('password'); return; }
  showView('app');
  $('#user-chip').textContent = `${user.username} · ${ROLE_LABEL[user.role]}`;
  $('#tab-team-btn').style.display = user.role === 'admin' ? '' : 'none';
  $('#new-article-btn').style.display = user.role === 'admin' ? '' : 'none';
  $('#qa-new-article').style.display = user.role === 'admin' ? '' : 'none';
  $('#welcome-title').textContent = `Bonjour ${user.username} 👋`;
  loadDashboard();
  loadArticles();
  loadInvoices();
  if (user.role === 'admin') loadUsers();
}

$('#login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const err = $('#login-error');
  err.hidden = true;
  try {
    const { user } = await api('/api/login', {
      method: 'POST',
      body: JSON.stringify({
        username: $('#login-username').value.trim(),
        password: $('#login-password').value,
      }),
    });
    enterApp(user);
  } catch (ex) { showError(err, ex.message); }
});

$('#password-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const err = $('#pw-error');
  err.hidden = true;
  const nw = $('#pw-new').value;
  if (nw !== $('#pw-confirm').value) return showError(err, 'Les deux nouveaux mots de passe ne correspondent pas.');
  try {
    await api('/api/change-password', {
      method: 'POST',
      body: JSON.stringify({ currentPassword: $('#pw-current').value, newPassword: nw }),
    });
    toast('Mot de passe changé. Bienvenue !');
    state.user.mustChangePassword = false;
    enterApp(state.user);
  } catch (ex) { showError(err, ex.message); }
});

$('#logout-btn').addEventListener('click', async () => {
  await api('/api/logout', { method: 'POST' }).catch(() => {});
  state.user = null;
  showView('login');
});

// ---------------------------------------------------------------------------
// Navigation par onglets
// ---------------------------------------------------------------------------
$$('#tabs button').forEach((btn) => {
  btn.addEventListener('click', () => {
    // Défense en profondeur : l'onglet Équipe & rôles est réservé à l'admin,
    // même si le bouton était atteint par un autre chemin.
    if (btn.dataset.tab === 'team' && (!state.user || state.user.role !== 'admin')) {
      toast('Seul l’administrateur peut gérer l’équipe et les rôles.');
      return;
    }
    $$('#tabs button').forEach((b) => b.classList.remove('active'));
    btn.classList.add('active');
    $$('.tab-page').forEach((p) => { p.hidden = true; });
    $('#tab-' + btn.dataset.tab).hidden = false;
    if (btn.dataset.tab === 'dashboard') loadDashboard();
    if (btn.dataset.tab === 'articles') loadArticles();
    if (btn.dataset.tab === 'history') loadHistory();
    if (btn.dataset.tab === 'invoices') loadInvoices();
    if (btn.dataset.tab === 'team') loadUsers();
  });
});

// ---------------------------------------------------------------------------
// Tableau de bord + graphiques (canvas, sans dépendance)
// ---------------------------------------------------------------------------
async function loadDashboard() {
  try {
    state.dashboard = await api('/api/dashboard');
  } catch (e) { return; }
  const d = state.dashboard;
  $('#kpi-today').textContent = money(d.salesToday);
  $('#kpi-month').textContent = money(d.salesMonth);
  $('#kpi-stock').textContent = money(d.stockValue);
  $('#kpi-count').textContent = d.articlesCount;

  const box = $('#alerts-box');
  let html = '';
  if (d.outOfStock.length) {
    html += `<div class="alert danger">⛔ <b>Rupture de stock :</b> ${d.outOfStock.map((a) => esc(a.name)).join(', ')}</div>`;
  }
  if (d.lowStock.length) {
    html += `<div class="alert warn">⚠️ <b>Stock bas :</b> ${d.lowStock.map((a) => `${esc(a.name)} (plus que ${a.stock}, seuil : ${a.low_threshold})`).join(' · ')}</div>`;
  }
  if (!d.outOfStock.length && !d.lowStock.length) {
    html += `<div class="alert ok">✅ Tout va bien : aucun article en stock bas ou en rupture.</div>`;
  }
  box.innerHTML = html;

  $('#top-sellers').innerHTML = d.topSellers.length
    ? d.topSellers.map((t) => `<li><span>${esc(t.article_name)}</span><b>${t.qty} vendu(s) · ${money(t.revenue)}</b></li>`).join('')
    : '<li class="muted">Aucune vente enregistrée pour le moment.</li>';

  drawChart();
  loadRecentMovements();
}

async function loadRecentMovements() {
  try {
    const list = await api('/api/movements');
    $('#recent-movements').innerHTML = list.slice(0, 8).map((m) => `
      <li><span><span class="tag ${m.type}">${TYPE_LABEL[m.type]}</span> ${esc(m.article_name)} × ${m.quantity}</span>
      <b>${money(m.total)}</b></li>`).join('') || '<li class="muted">Aucun mouvement.</li>';
  } catch (_) {}
}

$('#chart-daily').addEventListener('click', () => { state.chartMode = 'daily'; syncChartSeg(); drawChart(); });
$('#chart-monthly').addEventListener('click', () => { state.chartMode = 'monthly'; syncChartSeg(); drawChart(); });
function syncChartSeg() {
  $('#chart-daily').classList.toggle('active', state.chartMode === 'daily');
  $('#chart-monthly').classList.toggle('active', state.chartMode === 'monthly');
}

function drawChart() {
  const canvas = $('#chart');
  if (!state.dashboard) return;
  const data = state.chartMode === 'daily' ? state.dashboard.daily : state.dashboard.monthly;
  const ctx = canvas.getContext('2d');
  const dpr = window.devicePixelRatio || 1;
  const w = canvas.clientWidth || 600;
  const h = 180;
  canvas.width = w * dpr;
  canvas.height = h * dpr;
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, w, h);
  const max = Math.max(...data.map((p) => p.total), 1);
  const barW = Math.max(4, (w - 10) / data.length - 4);
  data.forEach((p, i) => {
    const bh = (p.total / max) * (h - 40);
    const x = 5 + i * ((w - 10) / data.length);
    ctx.fillStyle = '#2563eb';
    ctx.fillRect(x, h - 24 - bh, barW, bh);
    if (i % Math.ceil(data.length / 8) === 0) {
      ctx.fillStyle = '#6b7280';
      ctx.font = '10px sans-serif';
      ctx.fillText(p.label, x, h - 8);
    }
  });
}
window.addEventListener('resize', drawChart);

// ---------------------------------------------------------------------------
// Articles
// ---------------------------------------------------------------------------
async function loadArticles() {
  try {
    state.articles = await api('/api/articles');
  } catch (e) { return; }
  const q = ($('#article-search').value || '').toLowerCase();
  const cat = $('#article-filter').value;
  const cats = [...new Set(state.articles.map((a) => a.category).filter(Boolean))];
  $('#article-filter').innerHTML = '<option value="">Toutes les catégories</option>' +
    cats.map((c) => `<option ${c === cat ? 'selected' : ''}>${esc(c)}</option>`).join('');
  const list = state.articles.filter((a) =>
    (!q || (a.name + ' ' + (a.description || '') + ' ' + (a.sku || '')).toLowerCase().includes(q)) &&
    (!cat || a.category === cat));
  const grid = $('#articles-grid');
  if (!list.length) {
    grid.innerHTML = '<p class="empty">Aucun article pour le moment.<br>Cliquez sur « ＋ Nouvel article » pour ajouter le premier !</p>';
    return;
  }
  grid.innerHTML = list.map((a) => {
    const badge = a.stock === 0
      ? '<span class="badge out">Rupture</span>'
      : a.stock <= a.low_threshold
        ? `<span class="badge warn">Stock bas · ${a.stock}</span>`
        : `<span class="badge ok">En stock · ${a.stock}</span>`;
    const canMove = state.user.role !== 'lecture';
    const photo = a.photo
      ? `<img src="${esc(a.photo)}" alt="">`
      : '<div class="no-photo">📦</div>';
    return `<div class="article-card">${photo}
      <div class="article-body">
        <h3>${esc(a.name)}</h3>
        <p class="desc">${esc(a.description || '')}</p>
        <div class="price">${money(a.price)}</div>
        <div class="stock-line"><span class="muted">${esc(a.sku || '')} ${a.category ? '· ' + esc(a.category) : ''}</span>${badge}</div>
        ${canMove ? `
        <div class="qty-row">
          <button class="btn" onclick="quickMove(${a.id},'entree',1)">＋ Entrée</button>
          <button class="btn" onclick="quickMove(${a.id},'vente',1)">🛒 Vendre</button>
          <button class="btn" onclick="openMoveModal(${a.id},'sortie')">− Sortie</button>
        </div>` : ''}
        ${state.user.role === 'admin' ? `
        <div class="qty-row">
          <button class="btn small" onclick="openArticleForm(${a.id})">✏️ Modifier</button>
          <button class="btn small danger" onclick="deleteArticle(${a.id},'${esc(a.name.replace(/'/g, ''))}')">🗑️ Supprimer</button>
        </div>` : ''}
      </div></div>`;
  }).join('');
}

$('#article-search').addEventListener('input', loadArticles);
$('#article-filter').addEventListener('change', loadArticles);
$('#new-article-btn').addEventListener('click', () => openArticleForm(null));

// Réduit la photo (max 800 px, JPEG) pour garder la base petite.
function readPhotoFile(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const img = new Image();
      img.onload = () => {
        const max = 800;
        const scale = Math.min(1, max / Math.max(img.width, img.height));
        const canvas = document.createElement('canvas');
        canvas.width = Math.round(img.width * scale);
        canvas.height = Math.round(img.height * scale);
        canvas.getContext('2d').drawImage(img, 0, 0, canvas.width, canvas.height);
        resolve(canvas.toDataURL('image/jpeg', 0.8));
      };
      img.onerror = reject;
      img.src = reader.result;
    };
    reader.onerror = reject;
    reader.readAsDataURL(file);
  });
}

let articleFormPhoto = '';
let articleStep = 1;

function openArticleForm(id) {
  // Seul l'admin gère le catalogue (le serveur refuse aussi, mais on ne
  // laisse même pas ouvrir le formulaire aux autres rôles).
  if (!state.user || state.user.role !== 'admin') {
    toast('Seul l’administrateur peut gérer le catalogue.');
    return;
  }
  const a = id ? state.articles.find((x) => x.id === id) : null;
  articleFormPhoto = a ? a.photo : '';
  articleStep = 1;
  openModal(`
    <h2>${a ? 'Modifier l’article' : 'Nouvel article'}</h2>
    <div class="steps"><span id="step-1" class="on">1 · Photo</span><span id="step-2">2 · Nom &amp; description</span><span id="step-3">3 · Prix &amp; stock</span></div>
    <form id="article-form">
      <div class="step-pane" data-pane="1">
        <label>Photo de l’article (facultatif)
          <input type="file" id="af-photo" accept="image/*" capture="environment">
        </label>
        <img id="af-preview" class="photo-preview" ${articleFormPhoto ? `src="${esc(articleFormPhoto)}"` : 'hidden'}>
        <p class="muted">Une photo aide toute l'équipe à reconnaître l'article en un coup d'œil.</p>
      </div>
      <div class="step-pane" data-pane="2" hidden>
        <label>Nom de l’article * <input type="text" id="af-name" required value="${a ? esc(a.name) : ''}" placeholder="ex. Casque Bluetooth X200"></label>
        <label>Description <textarea id="af-desc" placeholder="Couleur, taille, particularités…">${a ? esc(a.description || '') : ''}</textarea></label>
      </div>
      <div class="step-pane" data-pane="3" hidden>
        <div class="form-grid">
          <label>Prix de vente (FCFA) * <input type="number" id="af-price" required min="0" step="0.01" value="${a ? a.price : ''}" placeholder="5000"></label>
          <label>Prix coûtant (FCFA) <input type="number" id="af-cost" min="0" step="0.01" value="${a && a.cost_price != null ? a.cost_price : ''}" placeholder="Facultatif"></label>
          <label>SKU / Référence <input type="text" id="af-sku" value="${a ? esc(a.sku || '') : ''}" placeholder="ex. CB-001"></label>
          <label>Catégorie <input type="text" id="af-cat" value="${a ? esc(a.category || '') : ''}" placeholder="ex. Audio"></label>
          <label>Stock de départ <input type="number" id="af-stock" min="0" step="1" value="${a ? a.stock : 0}"></label>
          <label>Seuil d’alerte stock bas <input type="number" id="af-threshold" min="0" step="1" value="${a ? a.low_threshold : 5}"></label>
        </div>
        <p id="af-error" class="error" hidden></p>
      </div>
      <div style="display:flex;gap:8px;justify-content:space-between;margin-top:14px">
        <button type="button" class="btn" id="af-back" hidden>← Retour</button>
        <button type="button" class="btn primary" id="af-next">Suivant →</button>
        <button type="submit" class="btn primary" id="af-submit" hidden>${a ? 'Enregistrer' : 'Ajouter l’article'}</button>
      </div>
    </form>`);

  $('#af-photo').addEventListener('change', async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    try {
      articleFormPhoto = await readPhotoFile(file);
      const img = $('#af-preview');
      img.src = articleFormPhoto;
      img.hidden = false;
    } catch (_) { toast('Impossible de lire cette photo.'); }
  });

  const showStep = (n) => {
    articleStep = n;
    $$('.step-pane').forEach((p) => { p.hidden = Number(p.dataset.pane) !== n; });
    $$('.steps span').forEach((s, i) => s.classList.toggle('on', i + 1 === n));
    $('#af-back').hidden = n === 1;
    $('#af-next').hidden = n === 3;
    $('#af-submit').hidden = n !== 3;
  };
  $('#af-back').addEventListener('click', () => showStep(articleStep - 1));
  $('#af-next').addEventListener('click', () => {
    if (articleStep === 2 && !$('#af-name').value.trim()) { toast('Donnez un nom à l’article.'); return; }
    showStep(articleStep + 1);
  });
  $('#article-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const err = $('#af-error');
    err.hidden = true;
    const payload = {
      name: $('#af-name').value.trim(),
      description: $('#af-desc').value.trim(),
      photo: articleFormPhoto,
      price: Number($('#af-price').value),
      cost_price: $('#af-cost').value === '' ? null : Number($('#af-cost').value),
      sku: $('#af-sku').value.trim(),
      category: $('#af-cat').value.trim(),
      stock: Number($('#af-stock').value),
      low_threshold: Number($('#af-threshold').value),
    };
    try {
      if (a) await api('/api/articles/' + a.id, { method: 'PUT', body: JSON.stringify(payload) });
      else await api('/api/articles', { method: 'POST', body: JSON.stringify(payload) });
      closeModal();
      toast(a ? 'Article modifié.' : 'Article ajouté ! 🎉');
      loadArticles();
      loadDashboard();
    } catch (ex) { showError(err, ex.message); }
  });
}

async function deleteArticle(id, name) {
  if (!confirm(`Supprimer définitivement « ${name} » ?`)) return;
  try {
    await api('/api/articles/' + id, { method: 'DELETE' });
    toast('Article supprimé.');
    loadArticles();
    loadDashboard();
  } catch (e) { toast(e.message); }
}

// ---------------------------------------------------------------------------
// Mouvements de stock
// ---------------------------------------------------------------------------
async function quickMove(articleId, type, qty) {
  if (type === 'vente' || type === 'sortie') { openMoveModal(articleId, type, qty); return; }
  try {
    const { stock } = await api('/api/movements', {
      method: 'POST',
      body: JSON.stringify({ article_id: articleId, type: 'entree', quantity: qty }),
    });
    toast(`Entrée enregistrée. Nouveau stock : ${stock}.`);
    loadArticles(); loadDashboard(); loadHistory();
  } catch (e) { toast(e.message); }
}

function openMoveModal(articleId, type, presetQty = 1) {
  const a = state.articles.find((x) => x.id === articleId);
  if (!a) return;
  const isSale = type === 'vente';
  openModal(`
    <h2>${isSale ? '🛒 Vendre' : type === 'entree' ? '＋ Entrée de stock' : '− Sortie de stock'} — ${esc(a.name)}</h2>
    <p class="muted">Stock actuel : <b>${a.stock}</b> · Prix de vente : <b>${money(a.price)}</b></p>
    <form id="move-form">
      <label>Quantité
        <input type="number" id="mv-qty" min="1" step="1" value="${presetQty}" required>
      </label>
      <div class="qty-row" style="margin-bottom:12px">
        <button type="button" class="btn small" onclick="document.getElementById('mv-qty').value=5">×5</button>
        <button type="button" class="btn small" onclick="document.getElementById('mv-qty').value=10">×10</button>
        <button type="button" class="btn small" onclick="document.getElementById('mv-qty').value=Math.max(1,(document.getElementById('mv-qty').value||1)-1)">−1</button>
        <button type="button" class="btn small" onclick="document.getElementById('mv-qty').value=(+document.getElementById('mv-qty').value||0)+1">＋1</button>
      </div>
      <label>Prix unitaire (FCFA)
        <input type="number" id="mv-price" min="0" step="0.01" value="${isSale ? a.price : (a.cost_price ?? a.price)}">
      </label>
      <label>Note <input type="text" id="mv-note" placeholder="Facultatif — ex. client régulier, casse…"></label>
      ${isSale ? `
      <label class="checkbox-line"><input type="checkbox" id="mv-invoice"> Générer une facture pour cette vente (facultatif)</label>
      <div id="mv-invoice-fields" hidden>
        <label>Nom du client <input type="text" id="mv-client" placeholder="ex. Marie Tremblay"></label>
        <label>Taux de taxes (%) <input type="number" id="mv-tax" min="0" step="0.01" value="0"></label>
      </div>` : ''}
      <p id="mv-error" class="error" hidden></p>
      <button type="submit" class="btn primary big">Confirmer ${isSale ? 'la vente' : 'le mouvement'}</button>
    </form>`);
  const invBox = $('#mv-invoice');
  if (invBox) invBox.addEventListener('change', () => { $('#mv-invoice-fields').hidden = !invBox.checked; });
  $('#move-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const err = $('#mv-error');
    err.hidden = true;
    const body = {
      article_id: articleId,
      type,
      quantity: Number($('#mv-qty').value),
      unit_price: Number($('#mv-price').value),
      note: $('#mv-note').value.trim(),
    };
    if (isSale && invBox && invBox.checked) {
      body.generate_invoice = true;
      body.client_name = $('#mv-client').value.trim();
      body.tax_rate = Number($('#mv-tax').value || 0);
    }
    try {
      const { stock, invoice } = await api('/api/movements', { method: 'POST', body: JSON.stringify(body) });
      closeModal();
      toast(invoice ? `Vente enregistrée — facture ${invoice.number} créée.` : `Mouvement enregistré. Nouveau stock : ${stock}.`);
      loadArticles(); loadDashboard(); loadHistory(); loadInvoices();
    } catch (ex) { showError(err, ex.message); }
  });
}

// ---------------------------------------------------------------------------
// Historique des mouvements
// ---------------------------------------------------------------------------
async function loadHistory() {
  const params = new URLSearchParams();
  const type = $('#hist-type').value;
  const from = $('#hist-from').value;
  const to = $('#hist-to').value;
  if (type) params.set('type', type);
  if (from) params.set('from', from);
  if (to) params.set('to', to);
  try {
    const list = await api('/api/movements?' + params.toString());
    $('#history-body').innerHTML = list.map((m) => `
      <tr><td>${esc(m.day)}</td><td>${esc(m.article_name)}</td>
      <td><span class="tag ${m.type}">${TYPE_LABEL[m.type]}</span></td>
      <td>${m.quantity}</td><td>${money(m.unit_price)}</td><td>${money(m.total)}</td>
      <td>${esc(m.username || '')}</td><td>${esc(m.note || '')}</td></tr>`).join('')
      || '<tr><td colspan="8" class="muted">Aucun mouvement pour ces filtres.</td></tr>';
  } catch (_) {}
}
$('#hist-apply').addEventListener('click', loadHistory);

// ---------------------------------------------------------------------------
// Factures
// ---------------------------------------------------------------------------
async function loadInvoices() {
  try {
    const list = await api('/api/invoices');
    $('#invoices-list').innerHTML = list.length ? list.map((inv) => `
      <div class="card">
        <div class="card-head">
          <h3>🧾 ${esc(inv.number)} — ${esc(inv.client_name || 'Client comptant')}</h3>
          <span class="muted">${esc(inv.day)} · par ${esc(inv.username || '')}</span>
        </div>
        <p>${(inv.items || []).map((it) => `${esc(it.name)} × ${it.quantity}`).join(' · ')}</p>
        <p><b>Total : ${money(inv.total)}</b> (sous-total ${money(inv.subtotal)}, taxes ${money(inv.tax_amount)})</p>
        <button class="btn small" onclick="window.open('/api/invoices/${inv.id}/html','_blank')">🖨️ Voir / Imprimer</button>
      </div>`).join('')
      : '<p class="empty">Aucune facture pour le moment. Les ventes fonctionnent très bien sans facture !</p>';
  } catch (_) {}
}

$('#new-invoice-btn').addEventListener('click', () => {
  if (state.user.role === 'lecture') { toast('Votre rôle ne permet pas de créer des factures.'); return; }
  openModal(`
    <h2>Nouvelle facture</h2>
    <p class="muted">Facultative : cochez « Déduire du stock » pour enregistrer aussi les ventes.</p>
    <form id="invoice-form">
      <label>Nom du client <input type="text" id="inv-client" placeholder="ex. Marie Tremblay"></label>
      <label>Infos client (adresse, téléphone…) <input type="text" id="inv-info" placeholder="Facultatif"></label>
      <label>Taux de taxes (%) <input type="number" id="inv-tax" min="0" step="0.01" value="0"></label>
      <h3>Lignes</h3>
      <div id="inv-lines"></div>
      <button type="button" class="btn small" id="inv-add-line">＋ Ajouter une ligne</button>
      <label class="checkbox-line"><input type="checkbox" id="inv-deduct" checked> Déduire les quantités du stock (crée des ventes)</label>
      <p id="inv-error" class="error" hidden></p>
      <button type="submit" class="btn primary big">Créer la facture</button>
    </form>`);
  const addLine = () => {
    const div = document.createElement('div');
    div.className = 'invoice-line';
    div.innerHTML = `
      <select class="il-article">${state.articles.map((a) => `<option value="${a.id}">${esc(a.name)} — ${money(a.price)}</option>`).join('')}</select>
      <input type="number" class="il-qty" min="1" step="1" value="1">
      <input type="number" class="il-price" min="0" step="0.01" value="${state.articles[0] ? state.articles[0].price : 0}">
      <button type="button" class="btn small danger il-remove">✕</button>`;
    div.querySelector('.il-article').addEventListener('change', (e) => {
      const a = state.articles.find((x) => x.id === Number(e.target.value));
      if (a) div.querySelector('.il-price').value = a.price;
    });
    div.querySelector('.il-remove').addEventListener('click', () => div.remove());
    $('#inv-lines').appendChild(div);
  };
  $('#inv-add-line').addEventListener('click', addLine);
  addLine();
  $('#invoice-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const err = $('#inv-error');
    err.hidden = true;
    const lines = [...document.querySelectorAll('.invoice-line')].map((row) => ({
      article_id: Number(row.querySelector('.il-article').value),
      quantity: Number(row.querySelector('.il-qty').value),
      unit_price: Number(row.querySelector('.il-price').value),
    }));
    try {
      const inv = await api('/api/invoices', {
        method: 'POST',
        body: JSON.stringify({
          client_name: $('#inv-client').value.trim(),
          client_info: $('#inv-info').value.trim(),
          tax_rate: Number($('#inv-tax').value || 0),
          deduct_stock: $('#inv-deduct').checked,
          lines,
        }),
      });
      closeModal();
      toast(`Facture ${inv.number} créée.`);
      loadInvoices(); loadArticles(); loadDashboard(); loadHistory();
    } catch (ex) { showError(err, ex.message); }
  });
});

// ---------------------------------------------------------------------------
// Équipe & rôles (admin)
// ---------------------------------------------------------------------------
async function loadUsers() {
  try {
    const users = await api('/api/users');
    $('#users-list').innerHTML = users.map((u) => `
      <li><span><b>${esc(u.username)}</b> — ${ROLE_LABEL[u.role]}</span>
      <span>
        <button class="btn small" onclick="resetUserPassword(${u.id},'${esc(u.username)}')">🔑 Nouveau mot de passe</button>
        ${u.id !== state.user.id ? `<button class="btn small danger" onclick="deleteUser(${u.id},'${esc(u.username)}')">🗑️</button>` : ''}
      </span></li>`).join('');
  } catch (_) {}
}

$('#user-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  if (!state.user || state.user.role !== 'admin') {
    toast('Seul l’administrateur peut créer des utilisateurs.');
    return;
  }
  try {
    await api('/api/users', {
      method: 'POST',
      body: JSON.stringify({
        username: $('#user-name').value.trim(),
        password: $('#user-pass').value,
        role: $('#user-role').value,
      }),
    });
    toast('Utilisateur créé.');
    $('#user-form').reset();
    loadUsers();
  } catch (ex) { toast(ex.message); }
});

async function deleteUser(id, name) {
  if (!confirm(`Supprimer l'utilisateur « ${name} » ?`)) return;
  try { await api('/api/users/' + id, { method: 'DELETE' }); toast('Utilisateur supprimé.'); loadUsers(); }
  catch (e) { toast(e.message); }
}

async function resetUserPassword(id, name) {
  const pw = prompt(`Nouveau mot de passe pour « ${name} » (6 caractères min.) :`);
  if (!pw) return;
  try {
    await api('/api/users/' + id, { method: 'PUT', body: JSON.stringify({ password: pw }) });
    toast('Mot de passe mis à jour.');
  } catch (e) { toast(e.message); }
}

// ---------------------------------------------------------------------------
// Sauvegarde
// ---------------------------------------------------------------------------
$('#export-btn').addEventListener('click', () => {
  window.location.href = '/api/backup/export';
  toast('Export en cours de téléchargement…');
});

$('#import-btn').addEventListener('click', async () => {
  const file = $('#import-file').files[0];
  if (!file) { $('#import-msg').textContent = 'Choisissez d’abord un fichier JSON.'; return; }
  if (!confirm('Restaurer cette sauvegarde ? Les données actuelles seront remplacées.')) return;
  try {
    const data = JSON.parse(await file.text());
    const res = await api('/api/backup/import', { method: 'POST', body: JSON.stringify(data) });
    $('#import-msg').textContent = res.restoredAdmin
      ? 'Sauvegarde restaurée. Aucun admin trouvé : compte admin / admin123 recréé.'
      : 'Sauvegarde restaurée avec succès.';
    toast('Sauvegarde restaurée.');
    loadDashboard(); loadArticles(); loadInvoices();
  } catch (e) {
    $('#import-msg').textContent = 'Erreur : ' + e.message;
  }
});

// ---------------------------------------------------------------------------
// Démarrage
// ---------------------------------------------------------------------------
checkSession();
