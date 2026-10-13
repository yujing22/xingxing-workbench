'use strict';
/*
 * 星星工作台 · 账号与同步服务
 * ---------------------------------------------------------------
 * 单端口 HTTP 服务（监听 PORT / 绑定 0.0.0.0），零第三方依赖。
 *  - 提供账号注册 / 登录（scrypt 加盐哈希 + HMAC 签名会话令牌）
 *  - 提供数据读写 /api/state（服务端做并集合并 + 删除墓碑）
 *  - 同时把同目录下的前端页面按白名单当静态资源提供
 *  - 数据落库在私有仓库 xingxing-workbench-sync（也可用本地文件，见 STORE）
 *  - GitHub 令牌只存在于服务器文件 server-secret.json，绝不进入前端页面
 */
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DIR = __dirname;
const PORT = parseInt(process.env.PORT || '3000', 10);
const HOST = '0.0.0.0';

/* ============================ 配置 ============================ */
let cfg = {};
try { cfg = JSON.parse(fs.readFileSync(path.join(DIR, 'server-secret.json'), 'utf8')); }
catch (e) { cfg = {}; }

const GH = {
  owner: cfg.ghOwner || 'yujing22',
  repo: cfg.ghRepo || 'xingxing-workbench-sync',
  token: cfg.ghToken || '',
  branch: cfg.ghBranch || 'main'
};
const STORE = String(process.env.STORE || cfg.store || (GH.token ? 'github' : 'local')).toLowerCase();
const REGISTER_INVITE = String(cfg.registerInvite || '');
const LOCAL_DIR = path.join(DIR, 'data');
const ACCOUNTS_FILE = 'accounts.json';
const SPACE_DIR = 'spaces';
const TOKEN_TTL = 90 * 24 * 3600 * 1000;
const SIGN_KEY = crypto.createHash('sha256')
  .update('xingxing-sign-v1|' + (cfg.ghToken || 'local') + '|' + (cfg.signSalt || ''))
  .digest();

/* ============================ 存储层 ============================ */
function ghRequest(method, apiPath, body) {
  return new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : null;
    const req = https.request({
      hostname: 'api.github.com',
      path: apiPath,
      method,
      headers: Object.assign({
        'Authorization': 'token ' + GH.token,
        'Accept': 'application/vnd.github+json',
        'User-Agent': 'xingxing-workbench',
        'Content-Type': 'application/json'
      }, payload ? { 'Content-Length': Buffer.byteLength(payload) } : {})
    }, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        let json = null;
        try { json = JSON.parse(data); } catch (e) {}
        resolve({ status: res.statusCode, json });
      });
    });
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

function localPath(key) {
  const p = path.join(LOCAL_DIR, key);
  if (!p.startsWith(LOCAL_DIR)) throw new Error('bad key');
  return p;
}

// 读：返回 { text, sha } 或 null
async function storeGet(key) {
  if (STORE === 'github') {
    const r = await ghRequest('GET', `/repos/${GH.owner}/${GH.repo}/contents/${key}?ref=${GH.branch}`);
    if (r.status === 404) return null;
    if (r.status !== 200) throw new Error('storage read failed: HTTP ' + r.status);
    const j = r.json;
    if (j.content && j.encoding === 'base64') {
      return { text: Buffer.from(j.content, 'base64').toString('utf8'), sha: j.sha };
    }
    // 大文件走 raw
    const raw = await new Promise((resolve, reject) => {
      https.get({
        hostname: 'raw.githubusercontent.com',
        path: `/${GH.owner}/${GH.repo}/${GH.branch}/${key}`,
        headers: { 'Authorization': 'token ' + GH.token, 'User-Agent': 'xingxing-workbench' }
      }, res => {
        let d = ''; res.on('data', c => d += c); res.on('end', () => resolve(d));
      }).on('error', reject);
    });
    return { text: raw, sha: j.sha };
  }
  const p = localPath(key);
  if (!fs.existsSync(p)) return null;
  return { text: fs.readFileSync(p, 'utf8'), sha: hashKey(fs.readFileSync(p)) };
}

function hashKey(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex').slice(0, 12);
}

// 写：sha 用于 GitHub 乐观锁；本地存储时校验 sha 防止并发覆盖
async function storePut(key, text, sha, message) {
  if (STORE === 'github') {
    const body = { message, content: Buffer.from(text, 'utf8').toString('base64'), branch: GH.branch };
    if (sha) body.sha = sha;
    const r = await ghRequest('PUT', `/repos/${GH.owner}/${GH.repo}/contents/${key}`, body);
    if (r.status === 409 || r.status === 422) return { conflict: true };
    if (r.status !== 200 && r.status !== 201) {
      throw new Error('storage write failed: HTTP ' + r.status + ' ' + (r.json && r.json.message || ''));
    }
    return { sha: r.json.content && r.json.content.sha };
  }
  const p = localPath(key);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  if (fs.existsSync(p)) {
    const cur = hashKey(fs.readFileSync(p));
    if (!sha || sha !== cur) return { conflict: true };
  } else if (sha) {
    return { conflict: true };
  }
  fs.writeFileSync(p, text);
  return { sha: hashKey(Buffer.from(text)) };
}

/* ============================ 账号 ============================ */
function normUser(u) { return String(u || '').trim().toLowerCase(); }

function hashPassword(password, salt) {
  return crypto.scryptSync(String(password), salt, 64).toString('hex');
}

function verifyPassword(password, salt, expected) {
  const got = Buffer.from(hashPassword(password, salt), 'hex');
  const exp = Buffer.from(String(expected || ''), 'hex');
  if (got.length !== exp.length) return false;
  return crypto.timingSafeEqual(got, exp);
}

async function readAccounts() {
  const r = await storeGet(ACCOUNTS_FILE);
  if (!r) return { users: {}, sha: null };
  let j = null;
  try { j = JSON.parse(r.text); } catch (e) { j = null; }
  return { users: (j && j.users) || {}, sha: r.sha };
}

// 注册/改密走"读-改-写 + 冲突重试"，避免两台设备同时操作互相覆盖
async function mutateAccounts(fn) {
  for (let i = 0; i < 4; i++) {
    const { users, sha } = await readAccounts();
    const ret = fn(users);
    if (ret && ret.stop) return ret.result;
    const text = JSON.stringify({ version: 1, users, updatedAt: new Date().toISOString() });
    const w = await storePut(ACCOUNTS_FILE, text, sha, '账号变更');
    if (!w.conflict) return ret;
  }
  throw new Error('账号数据繁忙，请重试');
}

function newSpaceId() {
  const chars = 'abcdefghijkmnpqrstuvwxyz23456789';
  let s = '';
  for (let i = 0; i < 12; i++) s += chars[crypto.randomInt(chars.length)];
  return s;
}

/* ============================ 会话令牌 ============================ */
function signToken(username) {
  const exp = Date.now() + TOKEN_TTL;
  const body = Buffer.from(JSON.stringify({ u: username, e: Math.floor(exp / 1000) })).toString('base64url');
  const sig = crypto.createHmac('sha256', SIGN_KEY).update(body).digest('base64url');
  return body + '.' + sig;
}

function verifyToken(token) {
  const parts = String(token || '').split('.');
  if (parts.length !== 2) return null;
  const expect = crypto.createHmac('sha256', SIGN_KEY).update(parts[0]).digest('base64url');
  const a = Buffer.from(parts[1]);
  const b = Buffer.from(expect);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  let payload = null;
  try { payload = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8')); } catch (e) { return null; }
  if (!payload || !payload.u) return null;
  if (Math.floor(Date.now() / 1000) > payload.e) return null;
  return payload.u;
}

/* ============================ 数据合并（并集 + 墓碑） ============================ */
function taskStamp(t) {
  return (t && (t.updatedAt || t.createdAt || t.completedAt)) || '1970-01-01T00:00:00.000Z';
}

function mergeData(local, remote) {
  const L = local || {}, R = remote || {};
  const deleted = {};
  [R.deleted || {}, L.deleted || {}].forEach(src => {
    for (const k in src) if (!deleted[k] || src[k] > deleted[k]) deleted[k] = src[k];
  });
  const best = {};
  (R.tasks || []).concat(L.tasks || []).forEach(t => {
    if (!t || !t.id) return;
    const st = taskStamp(t);
    if (!best[t.id] || st > best[t.id].st) best[t.id] = { t, st };
  });
  const tasks = [];
  for (const id in best) {
    const del = deleted[id];
    if (del && del >= best[id].st) continue;
    tasks.push(best[id].t);
  }
  const total = Math.max(parseInt(L.completedTotal || 0, 10) || 0, parseInt(R.completedTotal || 0, 10) || 0);
  return { tasks, deleted, completedTotal: total };
}

async function withSpaceRetry(space, fn) {
  for (let i = 0; i < 4; i++) {
    const r = await storeGet(`${SPACE_DIR}/${space}.json`);
    let data = null;
    if (r) { try { data = JSON.parse(r.text); } catch (e) { data = null; } }
    const ret = fn(data, r ? r.sha : null);
    if (ret && ret.stop) return ret.result;
    const text = JSON.stringify(ret.payload);
    const w = await storePut(`${SPACE_DIR}/${space}.json`, text, r ? r.sha : null, '同步 ' + new Date().toISOString().slice(0, 16).replace('T', ' '));
    if (!w.conflict) return ret.result;
  }
  throw new Error('云端繁忙，请稍后重试');
}

/* ============================ HTTP 辅助 ============================ */
function send(res, status, obj, extraHeaders) {
  const body = JSON.stringify(obj);
  res.writeHead(status, Object.assign({
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store'
  }, extraHeaders || {}));
  res.end(body);
}

function cors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Xing-Token');
  res.setHeader('Access-Control-Max-Age', '86400');
}

function readBody(req, limit = 4 * 1024 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0, chunks = [];
    req.on('data', c => {
      size += c.length;
      if (size > limit) { reject(new Error('payload too large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      if (!raw) return resolve({});
      try { resolve(JSON.parse(raw)); } catch (e) { reject(new Error('bad json')); }
    });
    req.on('error', reject);
  });
}

// 令牌可以从三个地方来。顺序很重要：部署环境的反向代理会**自己注入**一个
// Authorization 头，所以必须优先读自定义头，否则会拿到代理的头而误判成未登录。
function bearer(req, urlQuery) {
  const x = req.headers['x-xing-token'];
  if (x && String(x).trim()) return String(x).trim();
  const q = (urlQuery || '').match(/(?:^|&)token=([^&]+)/);
  if (q) return decodeURIComponent(q[1]).trim();
  const h = String(req.headers['authorization'] || '');
  const m = h.match(/^Bearer\s+(.+)$/i);
  if (m) return m[1].trim();
  return '';
}

/* ============================ 频率限制 ============================ */
const attempts = new Map();
function tooMany(ip) {
  const now = Date.now();
  const rec = attempts.get(ip);
  if (!rec || now > rec.resetAt) { attempts.set(ip, { n: 0, resetAt: now + 10 * 60 * 1000 }); return false; }
  return rec.n >= 20;
}
function noteAttempt(ip) {
  const rec = attempts.get(ip) || { n: 0, resetAt: Date.now() + 10 * 60 * 1000 };
  rec.n++;
  attempts.set(ip, rec);
}

/* ============================ 静态资源 ============================ */
const STATIC_WHITELIST = new Set([
  'index.html', 'manifest.json', 'sw.js', 'apple-touch-icon.png',
  'favicon.ico', 'favicon.png', 'icon-192.png', 'icon-512.png'
]);
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.svg': 'image/svg+xml'
};

function serveStatic(req, res, urlPath) {
  let name = decodeURIComponent(urlPath.split('?')[0]);
  if (name === '/' || name === '') name = 'index.html';
  name = name.replace(/^\/+/, '');
  if (!STATIC_WHITELIST.has(name)) { send(res, 404, { error: 'not found' }); return; }
  const file = path.join(DIR, name);
  fs.readFile(file, (err, buf) => {
    if (err) { send(res, 404, { error: 'not found' }); return; }
    res.writeHead(200, {
      'Content-Type': MIME[path.extname(name)] || 'application/octet-stream',
      'Content-Length': buf.length,
      'Cache-Control': (name === 'index.html' || name === 'sw.js') ? 'no-cache' : 'public, max-age=86400'
    });
    res.end(buf);
  });
}

/* ============================ 路由 ============================ */
const server = http.createServer(async (req, res) => {
  cors(res);
  const urlPath = (req.url || '/').split('?')[0];
  const urlQuery = (req.url || '').split('?')[1] || '';

  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  if (!urlPath.startsWith('/api/')) { serveStatic(req, res, urlPath); return; }

  const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'x').toString().split(',')[0].trim();

  try {
    /* ---- 健康检查 ---- */
    if (urlPath === '/api/health' && req.method === 'GET') {
      const { users } = await readAccounts();
      return send(res, 200, {
        ok: true, store: STORE, hasToken: !!GH.token,
        sawAuthHeader: !!req.headers['authorization'], sawXingHeader: !!req.headers['x-xing-token'],
        users: Object.keys(users).length, time: new Date().toISOString()
      });
    }

    /* ---- 注册 ---- */
    if (urlPath === '/api/register' && req.method === 'POST') {
      if (tooMany(ip)) return send(res, 429, { error: '尝试过于频繁，请稍后再试' });
      const body = await readBody(req);
      const username = normUser(body.username);
      const password = String(body.password || '');
      if (!/^[a-z0-9_\-\u4e00-\u9fa5]{2,24}$/.test(username)) return send(res, 400, { error: '账号需为 2-24 位字母、数字、下划线或中文' });
      if (password.length < 6) return send(res, 400, { error: '密码至少 6 位' });
      // 邀请码（可选开关）：server-secret.json 里的 registerInvite 留空 = 完全关闭注册门槛。
      // 想重新开启，把 registerInvite 填成任意一串并重启即可。
      if (REGISTER_INVITE && String(body.invite || '').trim() !== REGISTER_INVITE) {
        return send(res, 403, { error: '邀请码不对' });
      }

      const salt = crypto.randomBytes(16).toString('hex');
      const space = newSpaceId();
      const result = await mutateAccounts(users => {
        if (users[username]) return { stop: true, result: { error: '这个账号已经被注册了' } };
        users[username] = {
          name: String(body.username).trim(), salt,
          hash: hashPassword(password, salt), space,
          createdAt: new Date().toISOString()
        };
        return { ok: true };
      });
      if (result.error) return send(res, 409, result);
      noteAttempt(ip);
      return send(res, 200, { token: signToken(username), username, created: true });
    }

    /* ---- 登录 ---- */
    if (urlPath === '/api/login' && req.method === 'POST') {
      if (tooMany(ip)) return send(res, 429, { error: '尝试过于频繁，请稍后再试' });
      const body = await readBody(req);
      const username = normUser(body.username);
      const password = String(body.password || '');
      const { users } = await readAccounts();
      const u = users[username];
      if (!u || !verifyPassword(password, u.salt, u.hash)) {
        noteAttempt(ip);
        return send(res, 401, { error: '账号或密码不对' });
      }
      return send(res, 200, { token: signToken(username), username });
    }

    /* ---- 以下需要登录 ---- */
    let username = null;
    if (urlPath === '/api/state') {
      username = verifyToken(bearer(req, urlQuery));
      if (!username) return send(res, 401, { error: '登录已过期，请重新登录' });
      const { users } = await readAccounts();
      const u = users[username];
      if (!u) return send(res, 401, { error: '账号不存在' });

      if (req.method === 'GET') {
        const out = await withSpaceRetry(u.space, (data) => ({
          stop: true,
          result: data || { version: 1, tasks: [], deleted: {}, completedTotal: 0, updatedAt: null }
        }));
        return send(res, 200, out);
      }

      if (req.method === 'PUT') {
        const body = await readBody(req);
        const out = await withSpaceRetry(u.space, (data) => {
          const merged = mergeData(
            { tasks: body.tasks, deleted: body.deleted, completedTotal: body.completedTotal },
            data || {}
          );
          merged.version = 1;
          merged.updatedAt = new Date().toISOString();
          return { payload: merged, result: merged };
        });
        return send(res, 200, out);
      }
      return send(res, 405, { error: 'method not allowed' });
    }

    /* ---- 改密码 ---- */
    if (urlPath === '/api/password' && req.method === 'POST') {
      username = verifyToken(bearer(req, urlQuery));
      if (!username) return send(res, 401, { error: '登录已过期，请重新登录' });
      const body = await readBody(req);
      const oldPwd = String(body.oldPassword || '');
      const newPwd = String(body.newPassword || '');
      if (newPwd.length < 6) return send(res, 400, { error: '新密码至少 6 位' });
      const { users } = await readAccounts();
      const u = users[username];
      if (!u || !verifyPassword(oldPwd, u.salt, u.hash)) return send(res, 401, { error: '原密码不对' });
      const salt = crypto.randomBytes(16).toString('hex');
      const result = await mutateAccounts(list => {
        if (!list[username]) return { stop: true, result: { error: '账号不存在' } };
        list[username].salt = salt;
        list[username].hash = hashPassword(newPwd, salt);
        return { ok: true };
      });
      if (result.error) return send(res, 404, result);
      return send(res, 200, { ok: true, token: signToken(username) });
    }

    return send(res, 404, { error: 'not found' });
  } catch (e) {
    console.error('[api error]', urlPath, e && e.message);
    return send(res, 500, { error: '服务器开小差了：' + (e && e.message || 'unknown') });
  }
});

server.listen(PORT, HOST, () => {
  console.log(`星星工作台账号服务已启动 http://${HOST}:${PORT}  存储=${STORE}  令牌=${GH.token ? '已配置' : '未配置'}  注册邀请码=${REGISTER_INVITE ? '已开启' : '未开启'}`);
});
