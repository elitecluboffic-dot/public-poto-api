/**
 * Public Poto — Cloudflare Worker backend
 *
 * Bindings dibutuhkan (set di wrangler.toml / dashboard):
 *  - PHOTOS_KV       : KV namespace (metadata + index)
 *  - PHOTOS_BUCKET   : R2 bucket (file gambar)
 *  - ADMIN_TOKEN     : secret string (buat proteksi endpoint admin)
 *  - ALLOWED_ORIGIN  : origin frontend kamu, mis. "https://situskamu.com"
 *  - SIGNING_SECRET  : secret string BARU, khusus buat tanda tangan signed URL
 *                      (jangan sama dengan ADMIN_TOKEN, generate random panjang)
 */

const MAX_BYTES = 5 * 1024 * 1024; // 5MB
const ALLOWED_TYPES = {
  'image/jpeg': 'jpg',
  'image/png': 'png',
  'image/webp': 'webp',
  'image/gif': 'gif',
};
const PAGE_SIZE_DEFAULT = 24;
const SIGNED_URL_TTL_SECONDS = 120; // link foto valid 2 menit sejak /api/photos dipanggil

function corsHeaders(env, request) {
  const origin = request.headers.get('Origin') || '';
  const allowed = (env.ALLOWED_ORIGIN || '').split(',').map(s => s.trim());
  const allowOrigin = allowed.includes(origin) ? origin : allowed[0] || '*';
  return {
    'Access-Control-Allow-Origin': allowOrigin,
    'Access-Control-Allow-Methods': 'GET,POST,DELETE,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, X-Admin-Token',
    'Vary': 'Origin',
  };
}

function json(data, status, extraHeaders) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...extraHeaders },
  });
}

function requireAdmin(request, env) {
  const token = request.headers.get('X-Admin-Token') || '';
  return token && env.ADMIN_TOKEN && token === env.ADMIN_TOKEN;
}

async function getIndex(env, status) {
  const raw = await env.PHOTOS_KV.get(`index:${status}`);
  return raw ? JSON.parse(raw) : [];
}

async function setIndex(env, status, arr) {
  await env.PHOTOS_KV.put(`index:${status}`, JSON.stringify(arr));
}

async function getPhoto(env, id) {
  const raw = await env.PHOTOS_KV.get(`photo:${id}`);
  return raw ? JSON.parse(raw) : null;
}

function newId() {
  return crypto.randomUUID().replace(/-/g, '');
}

// ---------- Signed URL helpers ----------

async function hmacKey(secret) {
  const enc = new TextEncoder();
  return crypto.subtle.importKey(
    'raw',
    enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify']
  );
}

function toHex(buf) {
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}

async function signFilename(env, filename, exp) {
  const key = await hmacKey(env.SIGNING_SECRET);
  const enc = new TextEncoder();
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(`${filename}:${exp}`));
  return toHex(sig);
}

async function verifyFilenameSig(env, filename, exp, sig) {
  if (!exp || !sig) return false;
  if (Date.now() / 1000 > Number(exp)) return false; // expired
  const expected = await signFilename(env, filename, exp);
  // perbandingan sederhana; panjang string tetap (hex sha256) jadi risiko timing attack rendah untuk kasus ini
  return expected === sig;
}

async function buildSignedUrl(env, requestUrl, filename) {
  const exp = Math.floor(Date.now() / 1000) + SIGNED_URL_TTL_SECONDS;
  const sig = await signFilename(env, filename, exp);
  const origin = new URL(requestUrl).origin;
  return `${origin}/photos/${filename}?exp=${exp}&sig=${sig}`;
}

async function attachSignedUrls(env, requestUrl, photos) {
  return Promise.all(photos.map(async p => ({
    ...p,
    url: await buildSignedUrl(env, requestUrl, p.filename),
  })));
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const cors = corsHeaders(env, request);

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: cors });
    }

    try {
      // ---- Public: list approved photos (paginated) ----
      if (path === '/api/photos' && request.method === 'GET') {
        const offset = Math.max(0, parseInt(url.searchParams.get('offset') || '0', 10));
        const limit = Math.min(48, Math.max(1, parseInt(url.searchParams.get('limit') || String(PAGE_SIZE_DEFAULT), 10)));
        const index = await getIndex(env, 'approved');
        const page = index.slice(offset, offset + limit);
        const signedPage = await attachSignedUrls(env, request.url, page);
        return json({ photos: signedPage, total: index.length }, 200, cors);
      }

      // ---- Public: upload a new photo (goes in as pending) ----
      if (path === '/api/upload' && request.method === 'POST') {
        const contentLength = parseInt(request.headers.get('Content-Length') || '0', 10);
        if (contentLength && contentLength > MAX_BYTES + 200_000) {
          return json({ ok: false, error: 'Ukuran file maksimal 5MB.' }, 413, cors);
        }

        const form = await request.formData();
        const file = form.get('photo');
        const title = (form.get('title') || '').toString().slice(0, 150).trim();
        const uploaderName = (form.get('uploader_name') || '').toString().slice(0, 100).trim();

        if (!file || typeof file === 'string') {
          return json({ ok: false, error: 'File foto tidak ditemukan.' }, 400, cors);
        }
        if (file.size > MAX_BYTES) {
          return json({ ok: false, error: 'Ukuran file maksimal 5MB.' }, 413, cors);
        }
        const ext = ALLOWED_TYPES[file.type];
        if (!ext) {
          return json({ ok: false, error: 'Format harus JPG, PNG, WEBP, atau GIF.' }, 400, cors);
        }

        const id = newId();
        const filename = `${id}.${ext}`;
        const bytes = await file.arrayBuffer();

        await env.PHOTOS_BUCKET.put(`photos/${filename}`, bytes, {
          httpMetadata: { contentType: file.type },
        });

        const now = new Date().toISOString();
        const record = {
          id,
          filename,
          title: title || null,
          uploader_name: uploaderName || null,
          status: 'pending',
          uploaded_at: now,
          approved_at: null,
          ip: request.headers.get('CF-Connecting-IP') || null,
        };
        await env.PHOTOS_KV.put(`photo:${id}`, JSON.stringify(record));

        const pending = await getIndex(env, 'pending');
        pending.unshift(record);
        await setIndex(env, 'pending', pending);

        return json({ ok: true }, 200, cors);
      }

      // ---- Public: serve an image from R2 (butuh signed sig+exp yang valid) ----
      const imgMatch = path.match(/^\/photos\/([a-f0-9]+\.(jpg|png|webp|gif))$/);
      if (imgMatch && request.method === 'GET') {
        const filename = imgMatch[1];
        const exp = url.searchParams.get('exp');
        const sig = url.searchParams.get('sig');

        const validSig = await verifyFilenameSig(env, filename, exp, sig);
        if (!validSig) {
          return json({ ok: false, error: 'Link foto tidak valid atau sudah kedaluwarsa.' }, 403, cors);
        }

        // Referer check tambahan: tolak kalau diakses langsung dari luar situs
        // (opsional, bisa dilonggarkan kalau perlu dibuka lewat WhatsApp preview dll)
        const referer = request.headers.get('Referer') || '';
        const allowedOrigins = (env.ALLOWED_ORIGIN || '').split(',').map(s => s.trim());
        const refererOk = allowedOrigins.some(o => o && referer.startsWith(o));
        if (!refererOk) {
          return json({ ok: false, error: 'Akses ditolak.' }, 403, cors);
        }

        const object = await env.PHOTOS_BUCKET.get(`photos/${filename}`);
        if (!object) return new Response('Not found', { status: 404, headers: cors });

        return new Response(object.body, {
          headers: {
            'Content-Type': object.httpMetadata?.contentType || 'application/octet-stream',
            'Content-Disposition': 'inline',
            // signed URL expire cepat, jadi jangan cache lama & jangan immutable
            'Cache-Control': `private, max-age=${SIGNED_URL_TTL_SECONDS}`,
            'X-Content-Type-Options': 'nosniff',
            ...cors,
          },
        });
      }

      // ---- Admin routes below require X-Admin-Token ----
      if (path.startsWith('/api/admin/')) {
        if (!requireAdmin(request, env)) {
          return json({ ok: false, error: 'Unauthorized' }, 401, cors);
        }

        // list by status
        if (path === '/api/admin/photos' && request.method === 'GET') {
          const status = url.searchParams.get('status') || 'pending';
          if (!['pending', 'approved', 'rejected'].includes(status)) {
            return json({ ok: false, error: 'Status tidak valid.' }, 400, cors);
          }
          const index = await getIndex(env, status);
          const signedIndex = await attachSignedUrls(env, request.url, index);
          return json({ ok: true, photos: signedIndex }, 200, cors);
        }

        // counts for tab badges
        if (path === '/api/admin/counts' && request.method === 'GET') {
          const [pending, approved, rejected] = await Promise.all([
            getIndex(env, 'pending'),
            getIndex(env, 'approved'),
            getIndex(env, 'rejected'),
          ]);
          return json({ ok: true, counts: { pending: pending.length, approved: approved.length, rejected: rejected.length } }, 200, cors);
        }

        // approve / reject / delete: /api/admin/photos/:id/:action
        const actionMatch = path.match(/^\/api\/admin\/photos\/([a-f0-9]+)\/(approve|reject|delete)$/);
        if (actionMatch && request.method === 'POST') {
          const [, id, action] = actionMatch;
          const record = await getPhoto(env, id);
          if (!record) return json({ ok: false, error: 'Foto tidak ditemukan.' }, 404, cors);

          // remove id from whatever index it's currently in
          for (const s of ['pending', 'approved', 'rejected']) {
            const idx = await getIndex(env, s);
            const filtered = idx.filter(p => p.id !== id);
            if (filtered.length !== idx.length) await setIndex(env, s, filtered);
          }

          if (action === 'delete') {
            await env.PHOTOS_BUCKET.delete(`photos/${record.filename}`);
            await env.PHOTOS_KV.delete(`photo:${id}`);
            return json({ ok: true }, 200, cors);
          }

          const newStatus = action === 'approve' ? 'approved' : 'rejected';
          record.status = newStatus;
          record.approved_at = newStatus === 'approved' ? new Date().toISOString() : null;
          await env.PHOTOS_KV.put(`photo:${id}`, JSON.stringify(record));

          const target = await getIndex(env, newStatus);
          target.unshift(record);
          await setIndex(env, newStatus, target);

          return json({ ok: true }, 200, cors);
        }
      }

      return json({ ok: false, error: 'Not found' }, 404, cors);
    } catch (err) {
      return json({ ok: false, error: 'Server error: ' + err.message }, 500, cors);
    }
  },
};
