// ══════════════════════════════════════════════════
// LC79 KEY SERVER - Node.js
// Chạy: node server.js
// PORT: 3000 (có thể đổi)
// ══════════════════════════════════════════════════
const http = require('http');
const fs   = require('fs');
const path = require('path');
const crypto = require('crypto');
const url  = require('url');

const PORT     = process.env.PORT || 3000;
const DB_FILE  = path.join(__dirname, 'keys.json');
const ADMIN_USER = 'buivanhoan';
const ADMIN_PASS = 'hzetnz212';
const DAY      = 86400000;

// ── DB helpers ──
function loadDB() {
  try { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); }
  catch(e) { return { keys: {} }; }
}
function saveDB(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

// ── Gen key ──
function genKey() {
  const c = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const s = () => Array.from({length:4}, () => c[Math.floor(Math.random()*c.length)]).join('');
  return `LC79-${s()}-${s()}-${s()}`;
}

// ── Get real IP ──
function getIP(req) {
  const raw =
    req.headers['x-forwarded-for'] ||
    req.headers['x-real-ip']       ||
    req.socket.remoteAddress       || '';
  return raw.split(',')[0].trim().replace('::ffff:','');
}

// ── CORS headers ──
function cors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
}

// ── JSON response ──
function json(res, code, data) {
  cors(res);
  res.writeHead(code, {'Content-Type':'application/json'});
  res.end(JSON.stringify(data));
}

// ── Admin auth ──
function checkAdmin(req) {
  const auth = req.headers['authorization'] || '';
  const b64  = auth.replace('Basic ','');
  try {
    const [u,p] = Buffer.from(b64,'base64').toString().split(':');
    return u === ADMIN_USER && p === ADMIN_PASS;
  } catch(e) { return false; }
}

// ── Body parser ──
function body(req) {
  return new Promise(resolve => {
    let d = '';
    req.on('data', c => d += c);
    req.on('end', () => { try { resolve(JSON.parse(d)); } catch(e) { resolve({}); } });
  });
}

// ══════════════════════════════════════════════════
// HTTP SERVER
// ══════════════════════════════════════════════════
const server = http.createServer(async (req, res) => {
  const u   = url.parse(req.url, true);
  const pathname = u.pathname;
  const ip  = getIP(req);

  // Preflight
  if (req.method === 'OPTIONS') { cors(res); res.writeHead(204); res.end(); return; }

  // ── [GET] /validate?key=LC79-XXXX-XXXX-XXXX ──
  // Dùng bởi client Tampermonkey để xác thực key + bind IP
  if (req.method === 'GET' && pathname === '/validate') {
    const k = u.query.key || '';
    const db = loadDB();
    const entry = db.keys[k];

    if (!entry) return json(res, 200, { valid: false, reason: 'Key không tồn tại' });
    if (entry.revoked) return json(res, 200, { valid: false, reason: 'Key đã bị thu hồi' });
    if (Date.now() > entry.expireAt) return json(res, 200, { valid: false, reason: 'Key đã hết hạn' });

    // IP binding: nếu chưa có IP → gán IP này
    if (!entry.boundIP) {
      entry.boundIP = ip;
      entry.boundAt = Date.now();
      db.keys[k] = entry;
      saveDB(db);
      console.log(`[BIND] Key ${k} → IP ${ip}`);
    }
    // Nếu đã có IP → kiểm tra
    else if (entry.boundIP !== ip) {
      console.log(`[BLOCK] Key ${k} IP mismatch: bound=${entry.boundIP} req=${ip}`);
      return json(res, 200, {
        valid: false,
        reason: `Key này đã được đăng ký trên IP khác (${entry.boundIP.slice(0,-3)}***)`
      });
    }

    // Cập nhật last seen
    entry.lastSeen = Date.now();
    entry.lastIP   = ip;
    db.keys[k] = entry;
    saveDB(db);

    const diff = entry.expireAt - Date.now();
    const d    = Math.floor(diff / DAY);
    const h    = Math.floor((diff % DAY) / 3600000);
    return json(res, 200, {
      valid: true,
      expireAt: entry.expireAt,
      timeLeft: d > 0 ? `${d} ngày ${h} giờ` : `${h} giờ`,
      note: entry.note || ''
    });
  }

  // ════ ADMIN ROUTES (yêu cầu Basic Auth) ════

  if (!checkAdmin(req)) {
    if (pathname.startsWith('/admin')) {
      return json(res, 401, { error: 'Unauthorized' });
    }
  }

  // ── [POST] /admin/create ──
  if (req.method === 'POST' && pathname === '/admin/create') {
    if (!checkAdmin(req)) return json(res, 401, { error: 'Unauthorized' });
    const b = await body(req);
    const days = parseInt(b.days) || 1;
    const note = b.note || '';
    const db   = loadDB();
    const k    = genKey();
    db.keys[k] = {
      expireAt:  Date.now() + days * DAY,
      createdAt: Date.now(),
      note, revoked: false,
      boundIP: null, boundAt: null,
      lastSeen: null, lastIP: null
    };
    saveDB(db);
    console.log(`[CREATE] Key ${k} | ${days} ngày | ${note}`);
    return json(res, 200, { success: true, key: k, days, expireAt: db.keys[k].expireAt });
  }

  // ── [GET] /admin/list ──
  if (req.method === 'GET' && pathname === '/admin/list') {
    if (!checkAdmin(req)) return json(res, 401, { error: 'Unauthorized' });
    const db = loadDB();
    const now = Date.now();
    const list = Object.entries(db.keys).map(([k, e]) => ({
      key: k,
      note: e.note,
      expireAt: e.expireAt,
      revoked: e.revoked,
      expired: now > e.expireAt,
      boundIP: e.boundIP ? e.boundIP.slice(0,-3)+'***' : null,
      lastSeen: e.lastSeen,
      createdAt: e.createdAt
    })).sort((a,b) => b.createdAt - a.createdAt);
    return json(res, 200, { success: true, keys: list });
  }

  // ── [POST] /admin/modify ──
  // body: { key, action: 'add'|'sub'|'revoke'|'delete'|'unbind', days }
  if (req.method === 'POST' && pathname === '/admin/modify') {
    if (!checkAdmin(req)) return json(res, 401, { error: 'Unauthorized' });
    const b  = await body(req);
    const db = loadDB();
    const k  = b.key;
    if (!db.keys[k]) return json(res, 200, { success: false, reason: 'Key không tồn tại' });
    const e  = db.keys[k];
    const days = parseInt(b.days) || 1;

    if (b.action === 'add') {
      const base = Math.max(e.expireAt, Date.now());
      e.expireAt = base + days * DAY;
      e.revoked  = false;
    }
    else if (b.action === 'sub') {
      e.expireAt = Math.max(Date.now() - 1000, e.expireAt - days * DAY);
    }
    else if (b.action === 'revoke') {
      e.revoked = true;
    }
    else if (b.action === 'unbind') {
      // Reset IP binding → cho phép máy khác dùng
      e.boundIP = null; e.boundAt = null;
      console.log(`[UNBIND] Key ${k}`);
    }
    else if (b.action === 'delete') {
      delete db.keys[k];
      saveDB(db);
      return json(res, 200, { success: true });
    }

    db.keys[k] = e;
    saveDB(db);
    return json(res, 200, { success: true, key: k });
  }

  // ── [GET] / ── Health check
  if (pathname === '/') {
    cors(res); res.writeHead(200, {'Content-Type':'text/plain'});
    res.end('LC79 Key Server v1.0 - OK');
    return;
  }

  json(res, 404, { error: 'Not found' });
});

server.listen(PORT, () => {
  console.log(`\n✅ LC79 Key Server đang chạy tại http://localhost:${PORT}`);
  console.log(`   Admin: ${ADMIN_USER} / ${ADMIN_PASS}`);
  console.log(`   DB:    ${DB_FILE}\n`);
});
