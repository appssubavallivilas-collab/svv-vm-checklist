// VM Checklist API – Cloudflare Worker (STARTER, not yet wired to index.html)
// Bindings: ASSETS, CACHE (KV), PHOTOS (R2, optional: without it photos are kept in KV). Secrets: GOOGLE_CLIENT_EMAIL, GOOGLE_PRIVATE_KEY,
// SHEET_ID, TOKEN_SECRET, OWNER_USERNAME, OWNER_PASSWORD. Var: ALLOWED_ORIGIN (optional).
const enc = new TextEncoder();
const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64u = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
const now = () => new Date().toISOString();
const json = (o, status = 200, env) => new Response(JSON.stringify(o), { status, headers: hdr(env) });
const hdr = (env) => ({
  'content-type': 'application/json',
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'same-origin',
  'cache-control': 'no-store',
  ...(env && env.ALLOWED_ORIGIN ? { 'access-control-allow-origin': env.ALLOWED_ORIGIN, 'access-control-allow-headers': 'authorization,content-type', 'access-control-allow-methods': 'GET,POST,PUT,PATCH,OPTIONS' } : {}),
});
class HttpError extends Error { constructor(s, m) { super(m); this.status = s; } }

// ---------- Google Sheets ----------
async function googleToken(env) {
  const cached = await env.CACHE.get('g_token');
  if (cached) return cached;
  const iat = Math.floor(Date.now() / 1000);
  const head = b64u(enc.encode(JSON.stringify({ alg: 'RS256', typ: 'JWT' })));
  const claim = b64u(enc.encode(JSON.stringify({ iss: env.GOOGLE_CLIENT_EMAIL, scope: 'https://www.googleapis.com/auth/spreadsheets', aud: 'https://oauth2.googleapis.com/token', iat, exp: iat + 3600 })));
  const pem = env.GOOGLE_PRIVATE_KEY.replace(/\\n/g, '\n').replace(/-----[A-Z ]+-----/g, '').replace(/\s+/g, '');
  const key = await crypto.subtle.importKey('pkcs8', Uint8Array.from(atob(pem), (c) => c.charCodeAt(0)), { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
  const sig = b64u(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, enc.encode(head + '.' + claim)));
  const r = await fetch('https://oauth2.googleapis.com/token', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: 'grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=' + head + '.' + claim + '.' + sig });
  if (!r.ok) throw new HttpError(502, 'Google sign-in failed');
  const { access_token } = await r.json();
  await env.CACHE.put('g_token', access_token, { expirationTtl: 3000 });
  return access_token;
}
async function sheets(env, path, opts = {}, tries = 3) {
  const url = `https://sheets.googleapis.com/v4/spreadsheets/${env.SHEET_ID}${path}`;
  for (let i = 0; i < tries; i++) {
    const r = await fetch(url, { ...opts, headers: { authorization: 'Bearer ' + (await googleToken(env)), 'content-type': 'application/json' } });
    if (r.status === 429 || r.status >= 500) { await new Promise((s) => setTimeout(s, 500 * 2 ** i)); continue; }
    if (!r.ok) throw new HttpError(502, 'Sheets error ' + r.status);
    return r.json();
  }
  throw new HttpError(429, 'Google is busy, try again');
}
// Read tabs -> { Tab: [ {col: value} ] } with row numbers in _row
async function readTabs(env, tabs, fresh = false) {
  const ck = 'snap:' + tabs.join(',');
  if (!fresh) { const c = await env.CACHE.get(ck, 'json'); if (c) return c; }
  const q = tabs.map((t) => 'ranges=' + encodeURIComponent(t)).join('&');
  const d = await sheets(env, `/values:batchGet?${q}&valueRenderOption=UNFORMATTED_VALUE`);
  const out = {};
  d.valueRanges.forEach((vr, i) => {
    const [h = [], ...rows] = vr.values || [];
    out[tabs[i]] = rows.map((r, n) => Object.fromEntries([['_row', n + 2], ...h.map((k, j) => [k, r[j] ?? ''])])).filter((o) => Object.values(o).some((v) => v !== '' && v !== o._row));
  });
  await env.CACHE.put(ck, JSON.stringify(out), { expirationTtl: 30 });
  return out;
}
async function headers(env, tab) {
  const d = await sheets(env, `/values/${encodeURIComponent(tab)}!1:1`);
  return d.values?.[0] || [];
}
async function appendRows(env, tab, objs) {
  const h = await headers(env, tab);
  const values = objs.map((o) => h.map((k) => (o[k] ?? '')));
  await sheets(env, `/values/${encodeURIComponent(tab)}:append?valueInputOption=RAW&insertDataOption=INSERT_ROWS`, { method: 'POST', body: JSON.stringify({ values }) });
}
async function upsert(env, tab, keyCols, obj) {
  const h = await headers(env, tab);
  const rows = (await readTabs(env, [tab], true))[tab];
  const hit = rows.find((r) => keyCols.every((k) => String(r[k]) === String(obj[k])));
  obj.UpdatedOn = now();
  if (!hit) return appendRows(env, tab, [obj]);
  if (obj._ifUpdated && hit.UpdatedOn && obj._ifUpdated !== hit.UpdatedOn) throw new HttpError(409, 'Row changed by someone else');
  const values = [h.map((k) => (k in obj ? obj[k] : hit[k] ?? ''))];
  await sheets(env, `/values/${encodeURIComponent(tab)}!A${hit._row}?valueInputOption=RAW`, { method: 'PUT', body: JSON.stringify({ values }) });
}
const log = (env, userId, action, details) => appendRows(env, 'Log', [{ Timestamp: now(), UserID: userId, Action: action, Details: details }]);

// ---------- Auth ----------
async function pbkdf2(pw, saltB64) {
  const k = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveBits']);
  return b64u(await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: unb64u(saltB64), iterations: 100000, hash: 'SHA-256' }, k, 256));
}
async function hmac(env, data) {
  const k = await crypto.subtle.importKey('raw', enc.encode(env.TOKEN_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return b64u(await crypto.subtle.sign('HMAC', k, enc.encode(data)));
}
async function makeToken(env, u) {
  const body = b64u(enc.encode(JSON.stringify({ id: u.UserID, role: u.Role, stores: String(u.StoreIDs || '').split(',').filter(Boolean), exp: Date.now() + 12 * 3600e3 })));
  return body + '.' + (await hmac(env, body));
}
async function auth(req, env) {
  const t = (req.headers.get('authorization') || '').replace('Bearer ', '');
  const [body, sig] = t.split('.');
  if (!body || !sig || (await hmac(env, body)) !== sig) throw new HttpError(401, 'Sign in again');
  const p = JSON.parse(new TextDecoder().decode(unb64u(body)));
  if (p.exp < Date.now()) throw new HttpError(401, 'Session expired');
  return p;
}
const RANK = { Auditor: 1, Manager: 2, Owner: 3 };
const need = (u, role) => { if (RANK[u.role] < RANK[role]) throw new HttpError(403, 'Not allowed'); };
const storeOk = (u, id) => { if (u.role !== 'Owner' && !u.stores.includes(id)) throw new HttpError(403, 'Store not allowed'); };

async function login(req, env) {
  const { username, password } = await req.json();
  const ip = req.headers.get('cf-connecting-ip') || 'x';
  const lk = `fail:${String(username).toLowerCase()}:${ip}`;
  const fails = Number((await env.CACHE.get(lk)) || 0);
  if (fails >= 5) throw new HttpError(429, 'Too many attempts. Try again in 15 minutes.');
  let users = (await readTabs(env, ['Users'], true)).Users;
  if (!users.length && username === env.OWNER_USERNAME) { // first run: create owner from secrets
    const salt = b64u(crypto.getRandomValues(new Uint8Array(16)));
    await appendRows(env, 'Users', [{ UserID: 'U001', Name: 'Owner', Username: env.OWNER_USERNAME, PasswordHash: await pbkdf2(env.OWNER_PASSWORD, salt), Salt: salt, Role: 'Owner', Active: 'Y', MustChangePassword: 'Y', StoreIDs: '', CreatedBy: 'system', CreatedOn: now(), UpdatedOn: now() }]);
    await log(env, 'system', 'SETUP', 'Created initial owner account from Worker secrets');
    users = (await readTabs(env, ['Users'], true)).Users;
  }
  const u = users.find((x) => String(x.Username).toLowerCase() === String(username).toLowerCase() && x.Active === 'Y');
  if (!u || (await pbkdf2(password, u.Salt)) !== u.PasswordHash) {
    await env.CACHE.put(lk, String(fails + 1), { expirationTtl: 900 });
    throw new HttpError(401, 'Wrong username or password');
  }
  await env.CACHE.delete(lk);
  await log(env, u.UserID, 'LOGIN', u.Username);
  return { token: await makeToken(env, u), user: { id: u.UserID, name: u.Name, role: u.Role, must: u.MustChangePassword === 'Y', stores: String(u.StoreIDs).split(',').filter(Boolean) } };
}

// ---------- Routes ----------
async function route(req, env, url) {
  const p = url.pathname, m = req.method;
  if (p === '/api/login' && m === 'POST') return login(req, env);
  const u = await auth(req, env);
  if (p === '/api/bootstrap' && m === 'GET') {
    const store = url.searchParams.get('store'); storeOk(u, store);
    const d = await readTabs(env, ['Stores', 'Floors', 'Sections', 'Themes', 'Checklist', 'Settings', 'Audits', 'Actions']);
    const mine = (r) => String(r.StoreID) === store;
    return { stores: d.Stores.filter((s) => u.role === 'Owner' || u.stores.includes(s.StoreID)), floors: d.Floors.filter(mine), sections: d.Sections.filter(mine), themes: d.Themes, checklist: d.Checklist, settings: d.Settings, audits: d.Audits.filter(mine), actions: d.Actions.filter(mine) };
  }
  if (p === '/api/audits' && m === 'POST') {
    need(u, 'Auditor'); const { audit, responses = [], notes = [], actions = [] } = await req.json(); storeOk(u, audit.StoreID);
    audit.UserID = u.id; audit.UpdatedOn = now();
    await appendRows(env, 'Audits', [audit]);
    if (responses.length) await appendRows(env, 'Responses', responses.map((r) => ({ ...r, AuditID: audit.AuditID })));
    if (notes.length) await appendRows(env, 'Notes', notes.map((n) => ({ ...n, AuditID: audit.AuditID })));
    if (actions.length) await appendRows(env, 'Actions', actions.map((a) => ({ ...a, AuditID: audit.AuditID, StoreID: audit.StoreID, UpdatedOn: now() })));
    await log(env, u.id, 'AUDIT', audit.AuditID);
    return { ok: true };
  }
  const rows = p.match(/^\/api\/rows\/(Stores|Floors|Sections|Themes|Checklist|Settings)$/);
  if (rows && m === 'PUT') {
    need(u, 'Manager'); const keys = { Stores: ['StoreID'], Floors: ['StoreID', 'FloorCode'], Sections: ['SectionID'], Themes: ['ThemeID'], Checklist: ['QuestionID'], Settings: ['Key'] }[rows[1]];
    for (const o of await req.json()) await upsert(env, rows[1], keys, o);
    await log(env, u.id, 'EDIT', rows[1]); return { ok: true };
  }
  const act = p.match(/^\/api\/actions\/(.+)$/);
  if (act && m === 'PATCH') { need(u, 'Manager'); await upsert(env, 'Actions', ['ActionID'], { ...(await req.json()), ActionID: decodeURIComponent(act[1]) }); return { ok: true }; }
  if (p === '/api/photos' && m === 'POST') {
    need(u, 'Auditor'); const q = url.searchParams; const id = 'PH' + Date.now().toString(36);
    const key = `${q.get('store')}/${q.get('audit')}/${id}.jpg`; storeOk(u, q.get('store'));
    const buf = await req.arrayBuffer(); if (buf.byteLength > 1.5e6) throw new HttpError(413, 'Photo too large');
    if (env.PHOTOS) await env.PHOTOS.put(key, buf, { httpMetadata: { contentType: 'image/jpeg' } });
    else await env.CACHE.put('photo:' + key, buf); // no R2 bound: keep photos in KV (free plan: 1 GB, 1,000 writes a day)
    await appendRows(env, 'Photos', [{ PhotoID: id, AuditID: q.get('audit'), SectionID: q.get('section'), QuestionID: q.get('question'), R2Key: key, Timestamp: now() }]);
    return { id };
  }
  const ph = p.match(/^\/api\/photos\/(.+)$/);
  if (ph && m === 'GET') {
    const row = (await readTabs(env, ['Photos'])).Photos.find((r) => r.PhotoID === ph[1]); if (!row) throw new HttpError(404, 'No photo');
    storeOk(u, row.R2Key.split('/')[0]);
    let body;
    if (env.PHOTOS) { const o = await env.PHOTOS.get(row.R2Key); body = o && o.body; }
    else body = await env.CACHE.get('photo:' + row.R2Key, 'arrayBuffer');
    if (!body) throw new HttpError(404, 'No photo');
    return new Response(body, { headers: { 'content-type': 'image/jpeg', 'cache-control': 'private, max-age=3600' } });
  }
  throw new HttpError(404, 'Unknown route');
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (!url.pathname.startsWith('/api/')) return env.ASSETS.fetch(req);
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: hdr(env) });
    try {
      const r = await route(req, env, url);
      return r instanceof Response ? r : json(r, 200, env);
    } catch (e) {
      return json({ error: e.message || 'Server error' }, e.status || 500, env);
    }
  },
};
