'use strict';
/*
 * filx サーバー（Node.js 18以上。外部ライブラリ不要）
 *   起動:  node server.js
 *   環境変数:
 *     PORT          待ち受けポート（既定 3000）
 *     DATA_DIR      データ保存先フォルダ（既定 ./data）
 *     EMAIL_KEYWORD 登録に必要なメールの文字（既定 fzk）
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');

const PORT = Number(process.env.PORT) || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'data.json');
const KEYWORD = (process.env.EMAIL_KEYWORD || 'fzk').toLowerCase();
const SESSION_DAYS = 30;

/* ========== データ保存（JSONファイル） ========== */
fs.mkdirSync(DATA_DIR, { recursive: true });
let db = { secret: crypto.randomBytes(32).toString('hex'), users: [], posts: [], notifs: [], dms: [], sessions: {} };
if (fs.existsSync(DATA_FILE)) {
  try {
    db = Object.assign(db, JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')));
  } catch (e) {
    const bak = DATA_FILE + '.broken-' + Date.now();
    fs.renameSync(DATA_FILE, bak);
    console.error('データファイルが壊れていたため退避しました:', bak);
  }
}
let saveTimer = null;
function save() {
  if (saveTimer) return;
  saveTimer = setTimeout(() => {
    saveTimer = null;
    const tmp = DATA_FILE + '.tmp';
    fs.writeFile(tmp, JSON.stringify(db), err => { if (!err) fs.rename(tmp, DATA_FILE, () => {}); });
  }, 200);
}
function flushSync() {
  try { fs.writeFileSync(DATA_FILE + '.tmp', JSON.stringify(db)); fs.renameSync(DATA_FILE + '.tmp', DATA_FILE); } catch (e) {}
}
process.on('SIGINT', () => { flushSync(); process.exit(0); });
process.on('SIGTERM', () => { flushSync(); process.exit(0); });
save();

/* ========== ユーティリティ ========== */
const uid = () => Date.now().toString(36) + crypto.randomBytes(4).toString('hex');
const getUser = id => db.users.find(u => u.id === id);
const NAME_RE = /^[A-Za-z0-9_぀-ヿ一-鿿]+$/;
const NG = ['死ね', 'しね', '殺す', 'ころす', '消えろ', 'きもい', 'キモい', 'うざい', 'ウザい', 'ブス', 'デブ'];
const findNG = t => NG.find(w => t.includes(w));

class HttpError extends Error { constructor(status, msg) { super(msg); this.status = status; } }
const bad = (msg, status = 400) => new HttpError(status, msg);

function hashPw(pw, salt) { return crypto.scryptSync(pw, salt, 32).toString('hex'); }
function checkPw(pw, u) {
  const a = Buffer.from(hashPw(pw, u.salt), 'hex'), b = Buffer.from(u.pass, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

/* ========== 匿名の名前（サーバー側で作る＝投稿者は誰にも漏れない） ========== */
const ADJ = ['眠そうな', 'ごきげんな', '食いしん坊な', 'はにかむ', 'のんびりした', '元気な', 'ひかえめな', '夢見がちな', 'ふわふわの', 'こっそり来た', 'おだやかな', 'くすっと笑う'];
const ANI = ['カピバラ', 'ペンギン', 'ネコ', 'コアラ', 'ハリネズミ', 'カワウソ', 'フクロウ', 'ウサギ', 'パンダ', 'リス', 'アルパカ', 'イルカ'];
const ICON = ['🐹', '🐧', '🐱', '🐨', '🦔', '🦦', '🦉', '🐰', '🐼', '🐿️', '🦙', '🐬'];
const COLORS = ['#6c5ce7', '#00b894', '#e17055', '#0984e3', '#e84393', '#d6a12e', '#00cec9', '#d63031'];
function anonInfo(userId, post) {
  const day = new Date(post.ts + 9 * 3600 * 1000).toISOString().slice(0, 10); // 日本時間の日付
  const h = crypto.createHash('sha256').update(`${db.secret}|${userId}|${post.id}|${day}`).digest();
  const a = h.readUInt32BE(0), b = h.readUInt32BE(4), c = h.readUInt32BE(8);
  return { anon: true, name: ADJ[a % ADJ.length] + ANI[b % ANI.length], icon: ICON[b % ICON.length], color: COLORS[c % COLORS.length] };
}

/* ========== 画面に返す形に整える ========== */
const publicUser = u => ({ id: u.id, name: u.name, bio: u.bio || '', avatar: u.avatar ? `/avatar/${u.id}?v=${u.avatarVer || 0}` : null });
const authorOf = (userId, anon, post) => anon ? anonInfo(userId, post) : Object.assign({ anon: false }, publicUser(getUser(userId) || { id: '', name: '?' }));
function postView(p, me) {
  return {
    id: p.id, ts: p.ts, text: p.text, anon: p.anon, mine: p.uid === me,
    author: authorOf(p.uid, p.anon, p),
    likes: p.likes.length, liked: p.likes.includes(me), reported: (p.reports || []).includes(me),
    comments: p.comments.map(c => ({ id: c.id, ts: c.ts, text: c.text, anon: c.anon, mine: c.uid === me, author: authorOf(c.uid, c.anon, p) }))
  };
}
const hidden = p => (p.reports || []).length >= 3;

/* ========== 認証 ========== */
const fails = {}; // ログイン失敗の回数制限
function newSession(userId) {
  const token = crypto.randomBytes(32).toString('hex');
  db.sessions[token] = { uid: userId, ts: Date.now() };
  save();
  return token;
}
function authUser(req) {
  const m = /^Bearer (\w+)$/.exec(req.headers.authorization || '');
  if (!m) return null;
  const s = db.sessions[m[1]];
  if (!s) return null;
  if (Date.now() - s.ts > SESSION_DAYS * 86400000) { delete db.sessions[m[1]]; save(); return null; }
  return getUser(s.uid) || null;
}

/* ========== リクエスト処理 ========== */
function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', c => { size += c.length; if (size > 400000) { reject(bad('データが大きすぎます', 413)); req.destroy(); } else chunks.push(c); });
    req.on('end', () => {
      if (!chunks.length) return resolve({});
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); } catch (e) { reject(bad('不正なデータです')); }
    });
    req.on('error', reject);
  });
}
function send(res, status, body, headers = {}) {
  const isBuf = Buffer.isBuffer(body);
  res.writeHead(status, Object.assign({ 'X-Content-Type-Options': 'nosniff' },
    isBuf ? {} : { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }, headers));
  res.end(isBuf ? body : JSON.stringify(body));
}
const str = (v, max) => (typeof v === 'string' ? v.trim().slice(0, max) : '');

async function api(req, res, url) {
  const method = req.method, p = url.pathname;
  let m;

  /* --- 登録・ログイン（ログイン不要） --- */
  if (method === 'POST' && p === '/api/signup') {
    const b = await readBody(req);
    const email = str(b.email, 100).toLowerCase(), name = str(b.name, 12), pw = typeof b.password === 'string' ? b.password : '';
    if (!/^[^@\s]+@[^@\s]+$/.test(email)) throw bad('メールアドレスを正しく入力してください');
    if (!email.includes(KEYWORD)) throw bad(`校内専用です。メールアドレスに「${KEYWORD}」を含む人だけ登録できます`, 403);
    if (pw.length < 6 || pw.length > 100) throw bad('パスワードは6文字以上にしてください');
    if (!name) throw bad('ユーザー名を入力してください');
    if (!NAME_RE.test(name)) throw bad('ユーザー名は文字・数字・_だけ使えます');
    if (db.users.some(u => u.email === email)) throw bad('このメールアドレスは登録済みです', 409);
    if (db.users.some(u => u.name.toLowerCase() === name.toLowerCase())) throw bad('そのユーザー名は使われています', 409);
    const salt = crypto.randomBytes(16).toString('hex');
    const u = { id: uid(), email, name, bio: '', salt, pass: hashPw(pw, salt), ts: Date.now() };
    db.users.push(u);
    return send(res, 200, { token: newSession(u.id), user: Object.assign(publicUser(u), { email }) });
  }
  if (method === 'POST' && p === '/api/login') {
    const b = await readBody(req);
    const email = str(b.email, 100).toLowerCase(), pw = typeof b.password === 'string' ? b.password : '';
    const f = fails[email] || { n: 0, until: 0 };
    if (f.until > Date.now()) throw bad('ログインに何回も失敗しました。少し待ってからやり直してください', 429);
    const u = db.users.find(x => x.email === email);
    if (!u || !checkPw(pw, u)) {
      f.n++; if (f.n >= 5) { f.n = 0; f.until = Date.now() + 60000; }
      fails[email] = f;
      throw bad('メールアドレスかパスワードが違います', 401);
    }
    delete fails[email];
    return send(res, 200, { token: newSession(u.id), user: Object.assign(publicUser(u), { email: u.email }) });
  }

  /* --- ここから先はログイン必須 --- */
  const me = authUser(req);
  if (!me) throw bad('ログインしてください', 401);

  if (method === 'POST' && p === '/api/logout') {
    const t = /^Bearer (\w+)$/.exec(req.headers.authorization)[1];
    delete db.sessions[t]; save();
    return send(res, 200, { ok: true });
  }
  if (method === 'GET' && p === '/api/me') return send(res, 200, { user: Object.assign(publicUser(me), { email: me.email }) });

  if (method === 'PUT' && p === '/api/me') {
    const b = await readBody(req);
    if (b.name !== undefined) {
      const name = str(b.name, 12);
      if (!name) throw bad('名前を入力してください');
      if (!NAME_RE.test(name)) throw bad('名前は文字・数字・_だけ使えます');
      if (db.users.some(u => u.id !== me.id && u.name.toLowerCase() === name.toLowerCase())) throw bad('その名前は使われています', 409);
      me.name = name;
    }
    if (b.bio !== undefined) me.bio = str(b.bio, 80);
    if (b.avatar !== undefined) {
      if (b.avatar === '') { delete me.avatar; me.avatarVer = Date.now(); }
      else if (typeof b.avatar === 'string' && /^data:image\/jpeg;base64,[A-Za-z0-9+/=]+$/.test(b.avatar) && b.avatar.length < 200000) {
        me.avatar = b.avatar; me.avatarVer = Date.now();
      } else throw bad('画像を読み込めませんでした');
    }
    save();
    return send(res, 200, { user: Object.assign(publicUser(me), { email: me.email }) });
  }

  /* --- 投稿 --- */
  if (method === 'GET' && p === '/api/posts') {
    const list = db.posts.filter(x => !hidden(x) || x.uid === me.id).sort((a, b) => b.ts - a.ts).slice(0, 150);
    return send(res, 200, { posts: list.map(x => postView(x, me.id)) });
  }
  if (method === 'POST' && p === '/api/posts') {
    const b = await readBody(req);
    const text = str(b.text, 200);
    if (!text) throw bad('内容を入力してください');
    const ng = findNG(text); if (ng) throw bad(`「${ng}」は使えません。言い方を変えてみてね`);
    const last = db.posts.filter(x => x.uid === me.id).reduce((t, x) => Math.max(t, x.ts), 0);
    if (Date.now() - last < 10000) throw bad('少し待ってから投稿してね', 429);
    const post = { id: uid(), uid: me.id, anon: !!b.anon, text, ts: Date.now(), likes: [], comments: [], reports: [] };
    db.posts.push(post); save();
    return send(res, 200, { post: postView(post, me.id) });
  }
  if ((m = /^\/api\/posts\/(\w+)(?:\/(like|comments|report))?$/.exec(p))) {
    const post = db.posts.find(x => x.id === m[1]);
    if (!post) throw bad('投稿が見つかりません', 404);
    const act = m[2];
    if (method === 'DELETE' && !act) {
      if (post.uid !== me.id) throw bad('削除できません', 403);
      db.posts = db.posts.filter(x => x.id !== post.id);
      db.notifs = db.notifs.filter(n => n.pid !== post.id);
      save(); return send(res, 200, { ok: true });
    }
    if (method === 'POST' && act === 'like') {
      const i = post.likes.indexOf(me.id);
      if (i >= 0) post.likes.splice(i, 1);
      else {
        post.likes.push(me.id);
        if (post.uid !== me.id && !db.notifs.some(n => n.type === 'like' && n.pid === post.id && n.from === me.id))
          db.notifs.push({ id: uid(), to: post.uid, from: me.id, type: 'like', pid: post.id, ts: Date.now(), read: false });
      }
      save(); return send(res, 200, { likes: post.likes.length, liked: i < 0 });
    }
    if (method === 'POST' && act === 'comments') {
      const b = await readBody(req);
      const text = str(b.text, 100);
      if (!text) throw bad('コメントを入力してください');
      const ng = findNG(text); if (ng) throw bad(`「${ng}」は使えません`);
      const anon = !!b.anon;
      post.comments.push({ id: uid(), uid: me.id, anon, text, ts: Date.now() });
      if (post.uid !== me.id)
        db.notifs.push({ id: uid(), to: post.uid, from: me.id, anon, text, type: 'comment', pid: post.id, ts: Date.now(), read: false });
      save(); return send(res, 200, { ok: true });
    }
    if (method === 'POST' && act === 'report') {
      post.reports = post.reports || [];
      if (!post.reports.includes(me.id)) post.reports.push(me.id);
      save(); return send(res, 200, { ok: true });
    }
  }

  /* --- ユーザー --- */
  if (method === 'GET' && (m = /^\/api\/users\/by-name\/(.+)$/.exec(p))) {
    const name = decodeURIComponent(m[1]).toLowerCase();
    const u = db.users.find(x => x.name.toLowerCase() === name);
    if (!u) throw bad('そのユーザーは見つかりません', 404);
    return send(res, 200, { user: publicUser(u) });
  }
  if (method === 'GET' && (m = /^\/api\/users\/(\w+)$/.exec(p))) {
    const u = getUser(m[1]);
    if (!u) throw bad('ユーザーが見つかりません', 404);
    const own = u.id === me.id;
    // 他の人のプロフィールには、匿名で投稿したものは出さない
    const list = db.posts.filter(x => x.uid === u.id && (own || (!x.anon && !hidden(x)))).sort((a, b) => b.ts - a.ts).slice(0, 100);
    return send(res, 200, {
      user: Object.assign(publicUser(u), own ? { email: u.email } : {}),
      own, likes: list.reduce((s, x) => s + x.likes.length, 0), posts: list.map(x => postView(x, me.id))
    });
  }

  /* --- 通知 --- */
  if (method === 'GET' && p === '/api/summary')
    return send(res, 200, { unread: db.notifs.filter(n => n.to === me.id && !n.read).length });
  if (method === 'GET' && p === '/api/notifs') {
    const list = db.notifs.filter(n => n.to === me.id).sort((a, b) => b.ts - a.ts).slice(0, 100).map(n => {
      const post = db.posts.find(x => x.id === n.pid);
      const from = !n.anon && n.from ? getUser(n.from) : null; // 匿名コメントは誰からか分からない
      return {
        id: n.id, type: n.type, pid: n.pid, ts: n.ts, read: n.read, text: n.text || '',
        actor: from ? publicUser(from) : null, exists: !!post,
        preview: post ? post.text.slice(0, 30) + (post.text.length > 30 ? '…' : '') : ''
      };
    });
    return send(res, 200, { notifs: list });
  }
  if (method === 'POST' && p === '/api/notifs/read') {
    db.notifs.forEach(n => { if (n.to === me.id) n.read = true; });
    save(); return send(res, 200, { ok: true });
  }

  /* --- DM --- */
  if (method === 'GET' && p === '/api/dm') {
    const last = {};
    db.dms.filter(d => d.from === me.id || d.to === me.id).forEach(d => {
      const o = d.from === me.id ? d.to : d.from;
      if (!last[o] || last[o].ts < d.ts) last[o] = d;
    });
    const convs = Object.entries(last).sort((a, b) => b[1].ts - a[1].ts)
      .map(([id, d]) => ({ user: publicUser(getUser(id) || { id, name: '?' }), text: d.text.slice(0, 30), ts: d.ts }));
    return send(res, 200, { convs });
  }
  if ((m = /^\/api\/dm\/(\w+)$/.exec(p))) {
    const other = getUser(m[1]);
    if (!other) throw bad('ユーザーが見つかりません', 404);
    if (method === 'GET') {
      const msgs = db.dms.filter(d => (d.from === me.id && d.to === other.id) || (d.from === other.id && d.to === me.id))
        .sort((a, b) => a.ts - b.ts).slice(-200).map(d => ({ id: d.id, mine: d.from === me.id, text: d.text, ts: d.ts }));
      return send(res, 200, { user: publicUser(other), messages: msgs });
    }
    if (method === 'POST') {
      if (other.id === me.id) throw bad('自分にはDMできません');
      const b = await readBody(req);
      const text = str(b.text, 300);
      if (!text) throw bad('メッセージを入力してください');
      const ng = findNG(text); if (ng) throw bad(`「${ng}」は使えません`);
      db.dms.push({ id: uid(), from: me.id, to: other.id, text, ts: Date.now() });
      save(); return send(res, 200, { ok: true });
    }
  }

  throw bad('見つかりません', 404);
}

/* ========== サーバー本体 ========== */
const HTML_FILE = path.join(__dirname, 'index.html');
const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://localhost');
    if (url.pathname.startsWith('/api/')) return await api(req, res, url);

    let m;
    if (req.method === 'GET' && (m = /^\/avatar\/(\w+)$/.exec(url.pathname))) {
      const u = getUser(m[1]);
      if (!u || !u.avatar) return send(res, 404, Buffer.from('not found'), { 'Content-Type': 'text/plain' });
      return send(res, 200, Buffer.from(u.avatar.split(',')[1], 'base64'),
        { 'Content-Type': 'image/jpeg', 'Cache-Control': 'public, max-age=31536000, immutable' });
    }
    if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html')) {
      return send(res, 200, fs.readFileSync(HTML_FILE), { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache' });
    }
    send(res, 404, Buffer.from('not found'), { 'Content-Type': 'text/plain' });
  } catch (e) {
    if (e instanceof HttpError) return send(res, e.status, { error: e.message });
    console.error(e);
    send(res, 500, { error: 'サーバーでエラーが起きました' });
  }
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`filx が起動しました  →  http://localhost:${PORT}`);
  for (const list of Object.values(os.networkInterfaces()))
    for (const i of list || []) if (i.family === 'IPv4' && !i.internal) console.log(`同じWi-Fiのスマホから      →  http://${i.address}:${PORT}`);
  console.log(`データ保存先: ${DATA_FILE}`);
});
