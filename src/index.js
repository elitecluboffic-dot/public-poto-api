/**
 * Public Poto — Cloudflare Worker backend
 *
 * Bindings dibutuhkan (set di wrangler.toml / dashboard):
 *  - PHOTOS_KV     : KV namespace (metadata + index)
 *  - PHOTOS_BUCKET : R2 bucket (file gambar)
 *  - ADMIN_TOKEN    : secret string (buat proteksi endpoint admin)
 *  - ALLOWED_ORIGIN : origin frontend kamu, mis. "https://situskamu.com"
 */

const MAX_BYTES = 5 * 1024 * 1024; // 5MB
const ALLOWED_TYPES = {
  'image/jpeg': 'jpg',
  'image/png': 'png',
  'image/webp': 'webp',
  'image/gif': 'gif',
};
const PAGE_SIZE_DEFAULT = 24;

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
        return json({ photos: page, total: index.length }, 200, cors);
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

      // ---- Public: serve an image from R2 ----
      const imgMatch = path.match(/^\/photos\/([a-f0-9]+\.(jpg|png|webp|gif))$/);
      if (imgMatch && request.method === 'GET') {
        const object = await env.PHOTOS_BUCKET.get(`photos/${imgMatch[1]}`);
        if (!object) return new Response('Not found', { status: 404, headers: cors });
        return new Response(object.body, {
          headers: {
            'Content-Type': object.httpMetadata?.contentType || 'application/octet-stream',
            'Cache-Control': 'public, max-age=31536000, immutable',
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
          return json({ ok: true, photos: index }, 200, cors);
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
