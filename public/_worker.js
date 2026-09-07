// Find Your Seat — photo sharing backend (Cloudflare Pages advanced-mode worker).
//
// Guests send photos privately to the couple; the couple reads them on the same
// page with a private token (#couple=TOKEN). Everything outside /api/* is served
// as a static asset (index.html).
//
// Storage: R2 bucket `PHOTOS` if bound, otherwise KV namespace `PHOTOS_KV`.
// Keys:
//   arrive/<guestIndex>        JSON {i,name,t,at}                 — "seats found"
//
// Abuse limits: sends are gated by Cloudflare Turnstile (TURNSTILE_SECRET), a photo
// is only accepted for an existing batch and index, arrivals are written once per
// guest, and /api/* is the only path routed to this worker (_routes.json).
//   batch/<id>                 JSON {id,i,name,t,note,count,at}   — one "send"
//   photo/<batchId>/<n>        original file  (meta: ct,size,name,at)
//   thumb/<batchId>/<n>        ~300px  WebP/JPEG made on the guest's phone (grid + strip)
//   display/<batchId>/<n>      ~1600px WebP/JPEG made on the guest's phone (viewer)

const MAX_BYTES = 15 * 1024 * 1024;            // per file (KV allows 25 MiB)
const MAX_GUEST_INDEX = 600;                   // guest list is ~500 rows; bounds arrival writes
const MAX_FILES = 30;                          // per batch
const TYPE_OK = /^(image\/(jpeg|jpg|png|heic|heif|webp|gif|avif)|video\/(mp4|quicktime))$/i;
const EXT_OK = /\.(jpe?g|png|heic|heif|webp|gif|avif|mp4|mov)$/i;
const ID_RE = /^[a-z0-9]{6,20}-[a-z0-9]{4,12}$/;

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (!url.pathname.startsWith('/api/')) return env.ASSETS.fetch(request);
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
    try {
      return await api(request, env, ctx, url);
    } catch (e) {
      return json({ error: String((e && e.message) || e) }, 500);
    }
  },
};

const CORS = { 'access-control-allow-origin': '*', 'access-control-allow-headers': 'authorization,content-type', 'access-control-allow-methods': 'GET,POST,OPTIONS' };
const json = (o, status = 200, extra = {}) =>
  new Response(JSON.stringify(o), { status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...CORS, ...extra } });

// ---------- storage adapters (same tiny interface for R2 and KV) ----------
function storage(env) {
  if (env.PHOTOS) return r2Store(env.PHOTOS);
  if (env.PHOTOS_KV) return kvStore(env.PHOTOS_KV);
  return null;
}
const strMeta = (m) => Object.fromEntries(Object.entries(m).filter(([, v]) => v != null).map(([k, v]) => [k, String(v)]));

function r2Store(b) {
  return {
    kind: 'r2',
    async put(key, body, meta) {
      await b.put(key, body, { httpMetadata: { contentType: meta.ct || 'application/octet-stream' }, customMetadata: strMeta(meta) });
    },
    async get(key) {
      const o = await b.get(key);
      if (!o) return null;
      return { body: o.body, size: o.size, meta: o.customMetadata || {} };
    },
    async list(prefix) {
      const out = []; let cursor;
      do {
        const r = await b.list({ prefix, cursor, include: ['customMetadata'] });
        for (const o of r.objects) out.push({ key: o.key, size: o.size, meta: o.customMetadata || {} });
        cursor = r.truncated ? r.cursor : null;
      } while (cursor);
      return out;
    },
    del: (key) => b.delete(key),
  };
}

function kvStore(kv) {
  return {
    kind: 'kv',
    async put(key, body, meta) { await kv.put(key, body, { metadata: strMeta(meta) }); },
    async get(key) {
      const r = await kv.getWithMetadata(key, { type: 'stream' });
      if (r.value == null) return null;
      const meta = r.metadata || {};
      return { body: r.value, size: Number(meta.size) || undefined, meta };
    },
    async list(prefix) {
      const out = []; let cursor;
      do {
        const r = await kv.list({ prefix, cursor });
        for (const k of r.keys) out.push({ key: k.name, size: Number((k.metadata || {}).size) || 0, meta: k.metadata || {} });
        cursor = r.list_complete ? null : r.cursor;
      } while (cursor);
      return out;
    },
    del: (key) => kv.delete(key),
  };
}

// ---------- helpers ----------
const clean = (s, n) => String(s == null ? '' : s).replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, n);
const newId = () => Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 8);
async function readJson(request) { try { return await request.json(); } catch { return {}; } }

async function sha256hex(s) {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join('');
}
async function authed(request, env, url) {
  const h = request.headers.get('authorization') || '';
  const token = h.startsWith('Bearer ') ? h.slice(7).trim() : (url.searchParams.get('token') || '');
  if (!token) return false;
  if (env.ADMIN_TOKEN) return (await sha256hex(token)) === (await sha256hex(env.ADMIN_TOKEN));
  if (env.ADMIN_TOKEN_SHA256 && !/^REPLACE/.test(env.ADMIN_TOKEN_SHA256)) return (await sha256hex(token)) === env.ADMIN_TOKEN_SHA256.toLowerCase();
  return false;
}

// Cloudflare Turnstile: the send button hands us a one-time token; verify it here.
const NOT_CONFIGURED = 'The security check is not set up on this deployment yet.';
async function verifyTurnstile(env, token, ip) {
  if (!env.TURNSTILE_SECRET) return NOT_CONFIGURED;
  if (!token || typeof token !== 'string' || token.length > 2048) return 'Security check missing — please try again.';
  try {
    const fd = new FormData(); fd.append('secret', env.TURNSTILE_SECRET); fd.append('response', token); if (ip) fd.append('remoteip', ip);
    const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', { method: 'POST', body: fd });
    const o = await r.json();
    return o.success === true ? true : 'Security check failed — please try again.';
  } catch { return 'Security check unavailable — please try again in a moment.'; }
}

// ---------- routes ----------
async function api(request, env, ctx, url) {
  const store = storage(env);
  if (!store) return json({ error: 'Photo storage is not configured on this deployment yet.' }, 503);
  const p = url.pathname.replace(/^\/api\//, '').split('/').filter(Boolean);
  const m = request.method;

  if (p[0] === 'health') return json({ ok: true, storage: store.kind });

  // A guest resolved their table — counts as an arrival.
  if (p[0] === 'arrive' && m === 'POST') {
    const b = await readJson(request);
    const i = parseInt(b.i, 10);
    if (!Number.isFinite(i) || i < 0 || i > MAX_GUEST_INDEX) return json({ error: 'bad guest' }, 400);
    if (await store.get('arrive/' + i)) return json({ ok: true, again: true });   // a read, not a write
    const rec = { i, name: clean(b.name, 80), t: clean(b.t, 4), at: Date.now() };
    await store.put('arrive/' + i, JSON.stringify(rec), { ct: 'application/json', kind: 'arrive', name: rec.name, t: rec.t, at: rec.at });
    return json({ ok: true });
  }

  // Start a send: returns a batch id the photo uploads attach to.
  if (p[0] === 'batch' && m === 'POST') {
    const b = await readJson(request);
    const ts = await verifyTurnstile(env, b.cf, request.headers.get('cf-connecting-ip'));
    if (ts !== true) return json({ error: ts }, ts === NOT_CONFIGURED ? 503 : 403);
    const count = Math.min(MAX_FILES, Math.max(1, parseInt(b.count, 10) || 1));
    const rec = { id: newId(), i: Number.isFinite(+b.i) ? +b.i : null, name: clean(b.name, 80) || 'A guest', t: clean(b.t, 4), note: clean(b.note, 280), count, at: Date.now() };
    await store.put('batch/' + rec.id, JSON.stringify(rec), {
      ct: 'application/json', kind: 'batch', i: rec.i, name: rec.name, t: rec.t, count, at: rec.at,
      note: rec.note.slice(0, 120), long: rec.note.length > 120 ? 1 : 0,
    });
    return json({ id: rec.id });
  }

  // One photo (multipart: file, optional thumb).
  if (p[0] === 'photo' && m === 'POST') {
    const id = p[1] || '', n = parseInt(p[2], 10);
    if (!ID_RE.test(id) || !(n >= 0 && n < MAX_FILES)) return json({ error: 'bad batch or index' }, 400);
    const batch = await store.get('batch/' + id);
    if (!batch) return json({ error: 'That send has expired — please start again.' }, 404);
    if (n >= (Number(batch.meta.count) || MAX_FILES)) return json({ error: 'bad index' }, 400);
    if (Date.now() - (Number(batch.meta.at) || 0) > 6 * 3600e3) return json({ error: 'That send has expired — please start again.' }, 410);
    const form = await request.formData();
    const file = form.get('file');
    if (!(file && typeof file === 'object' && 'arrayBuffer' in file)) return json({ error: 'no file' }, 400);
    if (file.size > MAX_BYTES) return json({ error: 'That file is too large (limit 15 MB).' }, 413);
    const name = clean(file.name, 80) || 'photo';
    const ct = (file.type || '').toLowerCase();
    if (!(TYPE_OK.test(ct) || (!ct && EXT_OK.test(name)))) return json({ error: 'Only photos and short videos, please.' }, 415);
    const at = Date.now();
    await store.put(`photo/${id}/${n}`, await file.arrayBuffer(), { ct: ct || 'application/octet-stream', size: file.size, name, at, kind: 'photo' });
    const variants = [];
    for (const [kind, max] of [['thumb', 256 * 1024], ['display', 1536 * 1024]]) {
      const v = form.get(kind);
      if (v && typeof v === 'object' && 'arrayBuffer' in v && v.size > 0 && v.size <= max && /^image\/(webp|jpeg|avif)$/.test(v.type || '')) {
        await store.put(`${kind}/${id}/${n}`, await v.arrayBuffer(), { ct: v.type, size: v.size, at, kind });
        variants.push(kind);
      }
    }
    return json({ ok: true, key: `photo/${id}/${n}`, variants });
  }

  // ----- couple's side (token required) -----
  if (p[0] === 'admin') {
    if (!(await authed(request, env, url))) return json({ error: 'Not for you, sorry.' }, 401);

    if (p[1] === 'summary' && m === 'GET') return json(await summary(store));

    if (p[1] === 'file' && m === 'GET') {
      const kind = p[2], id = p[3] || '', n = parseInt(p[4], 10);
      if (!/^(photo|thumb|display)$/.test(kind) || !ID_RE.test(id) || !(n >= 0)) return json({ error: 'bad key' }, 400);
      const o = await store.get(`${kind}/${id}/${n}`);
      if (!o) return json({ error: 'gone' }, 404);
      const fname = (o.meta.name || `${id}-${n}`).replace(/["\\\r\n]/g, '_');
      return new Response(o.body, {
        headers: {
          'content-type': o.meta.ct || 'application/octet-stream',
          ...(o.size ? { 'content-length': String(o.size) } : {}),
          'content-disposition': (url.searchParams.has('dl') ? 'attachment' : 'inline') + `; filename="${fname}"`,
          'cache-control': 'private, max-age=3600', ...CORS,
        },
      });
    }

    if (p[1] === 'download.zip' && m === 'GET') return zipAll(store, ctx);

    // Delete whole sends ({id}) or individual photos ({items:[{id,n}]}).
    if (p[1] === 'delete' && m === 'POST') {
      const b = await readJson(request);
      const keys = new Set();
      if (ID_RE.test(b.id || '')) {
        for (const pre of ['photo', 'thumb', 'display']) for (const k of await store.list(`${pre}/${b.id}/`)) keys.add(k.key);
        keys.add('batch/' + b.id);
      }
      for (const it of Array.isArray(b.items) ? b.items.slice(0, 200) : []) {
        const n = parseInt(it && it.n, 10);
        if (!(it && ID_RE.test(it.id || '')) || !(n >= 0 && n < MAX_FILES)) continue;
        for (const pre of ['photo', 'thumb', 'display']) keys.add(`${pre}/${it.id}/${n}`);
      }
      if (!keys.size) return json({ error: 'nothing to delete' }, 400);
      await Promise.all([...keys].map((k) => store.del(k)));
      return json({ ok: true, removed: keys.size });
    }
  }
  return json({ error: 'not found' }, 404);
}

async function summary(store) {
  const [arrivals, batches, photos, thumbs, displays] = await Promise.all([store.list('arrive/'), store.list('batch/'), store.list('photo/'), store.list('thumb/'), store.list('display/')]);
  const thumbSet = new Set(thumbs.map((t) => t.key.slice(6)));
  const displaySet = new Set(displays.map((t) => t.key.slice(8)));
  const byBatch = new Map();
  for (const f of photos) {
    const [, id, n] = f.key.split('/');
    if (!byBatch.has(id)) byBatch.set(id, []);
    byBatch.get(id).push({ n: +n, name: f.meta.name || '', ct: f.meta.ct || '', size: Number(f.meta.size) || f.size || 0, at: Number(f.meta.at) || 0, thumb: thumbSet.has(`${id}/${n}`), display: displaySet.has(`${id}/${n}`) });
  }
  const feed = [];
  for (const b of batches) {
    const id = b.key.slice(6);
    let note = b.meta.note || '';
    if (b.meta.long === '1') { try { const o = await store.get(b.key); note = (JSON.parse(await new Response(o.body).text())).note || note; } catch {} }
    const files = (byBatch.get(id) || []).sort((a, c) => a.n - c.n);
    feed.push({ kind: 'photos', id, i: b.meta.i == null || b.meta.i === 'null' ? null : +b.meta.i, name: b.meta.name || 'A guest', t: b.meta.t || '', note, at: +b.meta.at || 0, expected: +b.meta.count || files.length, files });
  }
  for (const a of arrivals) feed.push({ kind: 'arrival', i: +a.key.slice(7), name: a.meta.name || '', t: a.meta.t || '', at: +a.meta.at || 0 });
  feed.sort((a, b) => b.at - a.at);
  const senders = new Set(batches.filter((b) => (byBatch.get(b.key.slice(6)) || []).length).map((b) => (b.meta.i && b.meta.i !== 'null') ? 'i' + b.meta.i : 'n' + (b.meta.name || '').toLowerCase()));
  return { seats: arrivals.length, photos: photos.length, guests: senders.size, bytes: photos.reduce((s, f) => s + (Number(f.meta.size) || f.size || 0), 0), feed, at: Date.now() };
}

// ---------- zip of all originals (store-only, streamed) ----------
const CRC_TABLE = (() => { const t = new Uint32Array(256); for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; t[n] = c; } return t; })();
function crcUpdate(crc, buf) { let c = crc ^ 0xffffffff; for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; }
function dosDateTime(ms) {
  const d = new Date(ms);
  const time = (d.getUTCHours() << 11) | (d.getUTCMinutes() << 5) | (d.getUTCSeconds() >> 1);
  const date = ((Math.max(1980, d.getUTCFullYear()) - 1980) << 9) | ((d.getUTCMonth() + 1) << 5) | d.getUTCDate();
  return { time, date };
}
function le(parts) { // parts: [value, bytes]
  const len = parts.reduce((s, p) => s + p[1], 0);
  const b = new Uint8Array(len); const dv = new DataView(b.buffer); let o = 0;
  for (const [v, n] of parts) { if (n === 2) dv.setUint16(o, v, true); else dv.setUint32(o, v >>> 0, true); o += n; }
  return b;
}
const safeName = (s) => s.replace(/[\/\\:*?"<>|\u0000-\u001f]/g, '_').trim() || 'photo';

async function zipAll(store, ctx) {
  const batches = new Map((await store.list('batch/')).map((b) => [b.key.slice(6), b.meta]));
  const photos = (await store.list('photo/')).sort((a, b) => a.key.localeCompare(b.key));
  const enc = new TextEncoder();
  const { readable, writable } = new TransformStream();
  const run = async () => {
    const w = writable.getWriter();
    let offset = 0; const central = [];
    const write = async (u8) => { await w.write(u8); offset += u8.length; };
    const seen = new Set();
    for (const f of photos) {
      const [, id, n] = f.key.split('/');
      const b = batches.get(id) || {};
      const folder = safeName((b.t ? `Table ${b.t} - ` : '') + (b.name || 'A guest'));
      let fname = `${folder}/${String(+n + 1).padStart(2, '0')} ${safeName(f.meta.name || 'photo')}`;
      while (seen.has(fname)) fname = fname.replace(/(\.[^.]*)?$/, '_$1');
      seen.add(fname);
      const o = await store.get(f.key);
      if (!o) continue;
      const nameBytes = enc.encode(fname);
      const { time, date } = dosDateTime(+f.meta.at || Date.now());
      const local = offset;
      await write(le([[0x04034b50, 4], [20, 2], [0x0808, 2], [0, 2], [time, 2], [date, 2], [0, 4], [0, 4], [0, 4], [nameBytes.length, 2], [0, 2]]));
      await write(nameBytes);
      let crc = 0, size = 0;
      const reader = o.body.getReader();
      for (;;) { const { value, done } = await reader.read(); if (done) break; crc = crcUpdate(crc, value); size += value.length; await write(value); }
      await write(le([[0x08074b50, 4], [crc, 4], [size, 4], [size, 4]]));
      central.push({ nameBytes, time, date, crc, size, local });
    }
    const cdStart = offset;
    for (const c of central) {
      await write(le([[0x02014b50, 4], [20, 2], [20, 2], [0x0808, 2], [0, 2], [c.time, 2], [c.date, 2], [c.crc, 4], [c.size, 4], [c.size, 4], [c.nameBytes.length, 2], [0, 2], [0, 2], [0, 2], [0, 2], [0, 4], [c.local, 4]]));
      await write(c.nameBytes);
    }
    await write(le([[0x06054b50, 4], [0, 2], [0, 2], [central.length, 2], [central.length, 2], [offset - cdStart, 4], [cdStart, 4], [0, 2]]));
    await w.close();
  };
  ctx.waitUntil(run().catch((e) => writable.abort(e)));
  return new Response(readable, {
    headers: { 'content-type': 'application/zip', 'content-disposition': 'attachment; filename="Wedding photos.zip"', 'cache-control': 'no-store', ...CORS },
  });
}
