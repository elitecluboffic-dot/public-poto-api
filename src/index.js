/**
 * Public Poto — Cloudflare Worker backend
 *
 * Bindings dibutuhkan (set di wrangler.toml / dashboard):
 *  - PHOTOS_KV           : KV namespace (metadata + index)
 *  - PHOTOS_BUCKET       : R2 bucket (file gambar)
 *  - AI                    : Workers AI binding (BARU! wajib buat auto-moderasi)
 *  - ADMIN_TOKEN          : secret string (buat proteksi endpoint admin)
 *  - ALLOWED_ORIGIN       : origin frontend kamu, mis. "https://situskamu.com"
 *  - RECAPTCHA_SECRET_KEY : secret string dari Google reCAPTCHA v2
 *  - AUTO_MODERATION       : "on" / "off" (var biasa, bukan secret). Kalau "off"
 *                            atau nggak di-set, semua upload tetap masuk "pending"
 *                            seperti sebelumnya (perilaku lama, aman sebagai default).
 *
 * Cara nambahin binding AI (Workers AI) di wrangler.toml:
 *   [ai]
 *   binding = "AI"
 *
 * Cara nambahin secret RECAPTCHA_SECRET_KEY:
 *   wrangler secret put RECAPTCHA_SECRET_KEY
 *
 * Cara nyalain auto-moderasi:
 *   wrangler.toml -> [vars] -> AUTO_MODERATION = "on"
 *   (atau di dashboard: Worker -> Settings -> Variables -> Text)
 *
 * PENTING: pakai secret key YANG BARU (di-regenerate), bukan yang lama yang
 * pernah kelihatan di screenshot config.php. Anggap yang lama itu bocor.
 *
 * ---- Cara kerja auto-moderasi ----
 * Setiap upload yang lolos captcha & validasi dasar (tipe file, ukuran) akan
 * dikirim ke model vision Moondream 3.1 (@cf/moondream/moondream3.1-9B-A2B) di
 * Workers AI dengan pertanyaan sederhana: apakah gambar ini aman buat galeri
 * foto publik yang family-friendly?
 *   - Kalau model jawab "SAFE"   -> foto langsung masuk status "approved"
 *   - Kalau model jawab "UNSAFE" -> foto langsung masuk status "rejected"
 *   - Kalau model error / jawaban ambigu -> foto FALLBACK ke "pending" (fail-safe,
 *     supaya kalau AI-nya lagi bermasalah, konten nggak lolos begitu aja tanpa
 *     ada yang cek)
 * Admin tetap bisa override manual kapan aja lewat endpoint /api/admin/photos/:id/:action,
 * apa pun status hasil auto-moderasinya.
 */

const MAX_BYTES = 5 * 1024 * 1024; // 5MB
const ALLOWED_TYPES = {
  'image/jpeg': 'jpg',
  'image/png': 'png',
  'image/webp': 'webp',
  'image/gif': 'gif',
};
const PAGE_SIZE_DEFAULT = 24;
const MODERATION_MODEL = '@cf/moondream/moondream3.1-9B-A2B';
const MODERATION_QUESTION =
  "Look at this image carefully. Would this image be considered inappropriate for a " +
  "public, family-friendly photo gallery website? Consider nudity, sexual content, " +
  "graphic violence, gore, hate symbols, or other clearly unsafe content. " +
  "Reply with exactly one word, either SAFE or UNSAFE. Do not explain.";

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

function bytesToBase64(bytes) {
  // Convert dalam chunk biar nggak kena limit argumen String.fromCharCode
  // buat file gambar yang cukup besar (sampai 5MB).
  let binary = '';
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunkSize));
  }
  return btoa(binary);
}

// ---- Verifikasi Google reCAPTCHA v2 ----
async function verifyRecaptcha(token, env, remoteIp) {
  if (!env.RECAPTCHA_SECRET_KEY) {
    // Kalau secret belum di-set di Worker, jangan diam-diam meloloskan request.
    // Ini bikin error jelas ketimbang "captcha ternyata nggak pernah dicek".
    return { success: false, error: 'server-misconfigured' };
  }
  if (!token || typeof token !== 'string') {
    return { success: false, error: 'missing-input-response' };
  }

  const params = new URLSearchParams();
  params.set('secret', env.RECAPTCHA_SECRET_KEY);
  params.set('response', token);
  if (remoteIp) params.set('remoteip', remoteIp);

  try {
    const res = await fetch('https://www.google.com/recaptcha/api/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params.toString(),
    });
    const data = await res.json();
    return data; // { success: bool, 'error-codes': [...] , ... }
  } catch (err) {
    return { success: false, error: 'verify-request-failed' };
  }
}

// ---- Auto-moderasi pakai Workers AI (Moondream 3.1) ----
// Return: { status: 'approved' | 'rejected' | 'pending', reason: string }
// 'pending' dipakai sebagai fallback aman kalau AI error / jawaban nggak jelas,
// atau kalau AUTO_MODERATION lagi dimatikan.
async function moderateImage(env, bytes, mimeType) {
  if ((env.AUTO_MODERATION || '').toLowerCase() !== 'on') {
    return { status: 'pending', reason: 'auto-moderation-disabled' };
  }
  if (!env.AI) {
    return { status: 'pending', reason: 'ai-binding-missing' };
  }

  try {
    const base64 = bytesToBase64(bytes);
    const dataUri = `data:${mimeType};base64,${base64}`;

    const result = await env.AI.run(MODERATION_MODEL, {
      task: 'query',
      image: dataUri,
      question: MODERATION_QUESTION,
      reasoning: false,
      max_tokens: 16,
      stream: false,
      temperature: 0,
    });

    const answer = (result && result.answer ? String(result.answer) : '').trim().toUpperCase();

    if (answer.includes('UNSAFE')) {
      return { status: 'rejected', reason: 'ai-flagged-unsafe' };
    }
    if (answer.includes('SAFE')) {
      return { status: 'approved', reason: 'ai-flagged-safe' };
    }
    // Jawaban ambigu -> jangan asal loloskan, kirim ke antrian manual.
    return { status: 'pending', reason: `ai-ambiguous-answer:${answer.slice(0, 40)}` };
  } catch (err) {
    return { status: 'pending', reason: 'ai-error:' + err.message };
  }
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

      // ---- Public: upload a new photo (auto-approve / auto-reject / pending) ----
      if (path === '/api/upload' && request.method === 'POST') {
        const contentLength = parseInt(request.headers.get('Content-Length') || '0', 10);
        if (contentLength && contentLength > MAX_BYTES + 200_000) {
          return json({ ok: false, error: 'Ukuran file maksimal 5MB.' }, 413, cors);
        }

        const form = await request.formData();
        const file = form.get('photo');
        const title = (form.get('title') || '').toString().slice(0, 150).trim();
        const uploaderName = (form.get('uploader_name') || '').toString().slice(0, 100).trim();
        const captchaToken = (form.get('g-recaptcha-response') || '').toString();

        // ---- Verifikasi captcha DULU, sebelum sentuh file / R2 / KV ----
        const remoteIp = request.headers.get('CF-Connecting-IP') || '';
        const captchaResult = await verifyRecaptcha(captchaToken, env, remoteIp);
        if (!captchaResult.success) {
          return json({ ok: false, error: 'Verifikasi captcha gagal. Silakan coba lagi.' }, 400, cors);
        }

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
        const bytes = new Uint8Array(await file.arrayBuffer());

        // ---- Auto-moderasi AI sebelum foto disimpan permanen ----
        const moderation = await moderateImage(env, bytes, file.type);

        // Kalau ditolak AI, jangan simpan sama sekali ke R2 -- cukup dicatat
        // statusnya "rejected" tanpa file fisik biar hemat storage & nggak
        // nyimpen konten yang udah jelas kena flag.
        const shouldStoreFile = moderation.status !== 'rejected';
        if (shouldStoreFile) {
          await env.PHOTOS_BUCKET.put(`photos/${filename}`, bytes, {
            httpMetadata: { contentType: file.type },
          });
        }

        const now = new Date().toISOString();
        const record = {
          id,
          filename,
          title: title || null,
          uploader_name: uploaderName || null,
          status: moderation.status, // 'approved' | 'rejected' | 'pending'
          uploaded_at: now,
          approved_at: moderation.status === 'approved' ? now : null,
          ip: remoteIp || null,
          moderation_reason: moderation.reason,
          has_file: shouldStoreFile,
        };
        await env.PHOTOS_KV.put(`photo:${id}`, JSON.stringify(record));

        const targetIndex = await getIndex(env, moderation.status);
        targetIndex.unshift(record);
        await setIndex(env, moderation.status, targetIndex);

        return json({ ok: true, status: moderation.status }, 200, cors);
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
            if (record.has_file !== false) {
              await env.PHOTOS_BUCKET.delete(`photos/${record.filename}`);
            }
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
