// ══════════════════════════════════════════════════
// LC79 KEY SERVER v2.0 - Render Compatible
// Dùng in-memory storage - KHÔNG cần file/database
// ══════════════════════════════════════════════════
const http = require('http');
const url  = require('url');

const PORT       = process.env.PORT || 3000;
const ADMIN_USER = 'buivanhoan';
const ADMIN_PASS = 'hzetnz212';
const DAY        = 86400000;

// IN-MEMORY DB
let DB = { keys: {} };

function genKey() {
  const c = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const s = () => Array.from({length:4}, () => c[Math.floor(Math.random()*c.length)]).join('');
  return `LC79-${s()}-${s()}-${s()}`;
}

function getIP(req) {
  const raw = req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || req.socket.remoteAddress || '';
  return raw.split(',')[0].trim().replace('::ffff:', '');
}

function cors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
}

function json(res, code, data) {
  cors(res);
  res.writeHead(code, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

function checkAdmin(req) {
  const auth = req.headers['authorization'] || '';
  try {
    const [u, p] = Buffer.from(auth.replace('Basic ', ''), 'base64').toString().split(':');
    return u === ADMIN_USER && p === ADMIN_PASS;
  } catch(e) { return false; }
}

function getBody(req) {
  return new Promise(resolve => {
    let d = '';
    req.on('data', c => d += c);
    req.on('end', () => { try { resolve(JSON.parse(d)); } catch(e) { resolve({}); } });
  });
}

function fmtLeft(expireAt) {
  const diff = expireAt - Date.now();
  if (diff <= 0) return 'Hết hạn';
  const d = Math.floor(diff / DAY);
  const h = Math.floor((diff % DAY) / 3600000);
  const m = Math.floor((diff % 3600000) / 60000);
  return d > 0 ? `${d} ngày ${h} giờ` : `${h} giờ ${m} phút`;
}

function maskIP(ip) {
  if (!ip) return null;
  const parts = ip.split('.');
  if (parts.length === 4) return `${parts[0]}.${parts[1]}.*.*`;
  return ip.slice(0, 6) + '***';
}

// ══════════════════════════════════════════════════
// SERVER
// ══════════════════════════════════════════════════
const server = http.createServer(async (req, res) => {
  const u        = url.parse(req.url, true);
  const pathname = u.pathname;
  const ip       = getIP(req);

  if (req.method === 'OPTIONS') { cors(res); res.writeHead(204); res.end(); return; }

  // Health check
  if (pathname === '/') {
    cors(res);
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('LC79 Key Server v2.0 OK | Keys: ' + Object.keys(DB.keys).length);
    return;
  }

  // ── VALIDATE KEY ──
  if (req.method === 'GET' && pathname === '/validate') {
    const k     = (u.query.key || '').toUpperCase().trim();
    const entry = DB.keys[k];

    if (!entry)         return json(res, 200, { valid: false, reason: 'Key không tồn tại' });
    if (entry.revoked)  return json(res, 200, { valid: false, reason: 'Key đã bị thu hồi' });
    if (Date.now() > entry.expireAt) return json(res, 200, { valid: false, reason: 'Key đã hết hạn' });

    // IP Binding
    if (!entry.boundIP) {
      entry.boundIP = ip;
      entry.boundAt = Date.now();
      console.log(`[BIND] ${k} → ${ip}`);
    } else if (entry.boundIP !== ip) {
      console.log(`[BLOCK] ${k} bound=${entry.boundIP} req=${ip}`);
      return json(res, 200, {
        valid: false,
        reason: `Key đã đăng ký trên máy khác (${maskIP(entry.boundIP)})`
      });
    }

    entry.lastSeen = Date.now();
    entry.lastIP   = ip;

    return json(res, 200, {
      valid:    true,
      expireAt: entry.expireAt,
      timeLeft: fmtLeft(entry.expireAt),
      note:     entry.note || ''
    });
  }

  // ── ADMIN ROUTES ──
  if (!checkAdmin(req)) return json(res, 401, { error: 'Unauthorized' });

  // Tạo key
  if (req.method === 'POST' && pathname === '/admin/create') {
    const b    = await getBody(req);
    const days = parseInt(b.days) || 1;
    const note = (b.note || '').trim() || '—';
    const k    = genKey();
    DB.keys[k] = {
      expireAt:  Date.now() + days * DAY,
      createdAt: Date.now(),
      note, revoked: false,
      boundIP: null, boundAt: null, lastSeen: null, lastIP: null
    };
    console.log(`[CREATE] ${k} | ${days}d | ${note}`);
    return json(res, 200, { success: true, key: k, days, expireAt: DB.keys[k].expireAt, timeLeft: fmtLeft(DB.keys[k].expireAt) });
  }

  // Danh sách key
  if (req.method === 'GET' && pathname === '/admin/list') {
    const now  = Date.now();
    const list = Object.entries(DB.keys)
      .map(([k, e]) => ({
        key: k, note: e.note,
        expireAt: e.expireAt, timeLeft: fmtLeft(e.expireAt),
        revoked: e.revoked, expired: now > e.expireAt,
        boundIP: maskIP(e.boundIP),
        lastSeen: e.lastSeen, createdAt: e.createdAt
      }))
      .sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
    return json(res, 200, { success: true, total: list.length, keys: list });
  }

  // Sửa key (add/sub/revoke/unbind/delete)
  if (req.method === 'POST' && pathname === '/admin/modify') {
    const b      = await getBody(req);
    const k      = (b.key || '').toUpperCase().trim();
    const action = b.action;
    const days   = parseInt(b.days) || 1;

    if (!DB.keys[k]) return json(res, 200, { success: false, reason: 'Key không tồn tại' });

    const e = DB.keys[k];
    if      (action === 'add')    { e.expireAt = Math.max(e.expireAt, Date.now()) + days * DAY; e.revoked = false; }
    else if (action === 'sub')    { e.expireAt = Math.max(Date.now() - 1000, e.expireAt - days * DAY); }
    else if (action === 'revoke') { e.revoked = true; }
    else if (action === 'unbind') { e.boundIP = null; e.boundAt = null; console.log(`[UNBIND] ${k}`); }
    else if (action === 'delete') { delete DB.keys[k]; console.log(`[DELETE] ${k}`); return json(res, 200, { success: true }); }

    console.log(`[${action.toUpperCase()}] ${k}`);
    return json(res, 200, { success: true, key: k, timeLeft: fmtLeft(e.expireAt || 0) });
  }

  json(res, 404, { error: 'Not found' });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`\n✅ LC79 Key Server v2.0 | Port: ${PORT}`);
  console.log(`   Admin: ${ADMIN_USER} / ${ADMIN_PASS}`);
});

process.on('SIGTERM', () => server.close(() => process.exit(0)));
