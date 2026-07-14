/**
 * Public Poto — Cloudflare Worker backend
 *
 * Bindings dibutuhkan (set di wrangler.toml / dashboard):
 *  - PHOTOS_KV           : KV namespace (metadata + index + rate limit counter + premium codes)
 *  - PHOTOS_BUCKET       : R2 bucket (file gambar)
 *  - AI                    : Workers AI binding (wajib buat auto-moderasi)
 *  - ADMIN_TOKEN          : secret string (buat proteksi endpoint admin)
 *  - ALLOWED_ORIGIN       : origin frontend kamu, mis. "https://situskamu.com"
 *  - RECAPTCHA_SECRET_KEY : secret string dari Google reCAPTCHA v2
 *  - AUTO_MODERATION       : "on" / "off"
 *
 * ---- FITUR BARU: Premium via Kode Redeem ----
 * User bisa beli premium (di luar sistem ini, lewat WhatsApp) lalu admin
 * generate kode unik dari panel admin dengan durasi tertentu (hari). User
 * masukin kode itu di halaman publik lewat endpoint POST /api/redeem.
 * Begitu kode valid & belum dipakai, IP yang redeem kode itu langsung
 * ditandai "premium aktif" sampai tanggal tertentu (expires_at), dan
 * SELAMA premium aktif, IP itu DIBEBASKAN dari rate limit upload harian
 * (MAX_UPLOADS_PER_DAY diabaikan sepenuhnya).
 *
 * Data disimpan di KV:
 *  - `premcode:{CODE}`   : { code, duration_days, created_at, revoked, used, used_at, used_ip }
 *  - `premcodes_index`   : array of code string (buat listing di admin panel)
 *  - `premium:{ip}`      : { code, activated_at, expires_at } dengan expirationTtl
 *                          sesuai duration_days, jadi otomatis "hangus" sendiri
 *                          di KV pas masa aktifnya abis.
 *
 * Catatan: sistem ini nge-tag premium ke IP address (bukan akun/login),
 * karena situs ini emang nggak punya sistem akun user. Konsekuensinya:
 * kalau IP publik user berubah (ganti wifi, ganti jaringan seluler, dll),
 * status premium-nya nggak keliatan lagi dari IP baru itu sampai dia
 * redeem ulang kodenya sendiri kalau belum "used". TAPI kode dibuat
 * SEKALI PAKAI (`used: true` setelah redeem pertama), jadi kalau IP
 * berubah, user PERLU kode baru dari admin -- ini limitasi yang harus
 * disadari dari desain "tanpa akun" ini.
 *
 * ---- Endpoint baru ----
 * Publik:
 *   POST /api/redeem            { code }             -> aktifkan premium utk IP pemanggil
 *   GET  /api/premium/status                          -> cek premium aktif utk IP pemanggil
 * Admin (butuh X-Admin-Token, sama seperti endpoint admin lain):
 *   POST /api/admin/codes/generate   { duration_days } -> generate kode baru
 *   GET  /api/admin/codes                              -> list semua kode + statusnya
 *   POST /api/admin/codes/:code/revoke                 -> nonaktifkan kode yang belum dipakai
 *   POST /api/admin/codes/:code/delete                 -> hapus kode dari histori
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
const MAX_UPLOADS_PER_DAY = 2; // batas upload per IP per hari (WIB) -- diabaikan kalau premium aktif
const MAX_ADMIN_ATTEMPTS = 5;
const ADMIN_LOCKOUT_WINDOW_SECONDS = 15 * 60;
const MODERATION_QUESTION =
  "Look at this image carefully. This gallery accepts digital/AI-generated art, including " +
  "fantasy, surreal, and ethereal styles that often feature stylized humanoid figures, " +
  "silhouettes, or non-explicit artistic nudity (e.g. a glowing spirit figure, a distant " +
  "silhouette, tasteful artistic nude poses without visible genitals or sexual acts). " +
  "That kind of stylized/artistic content is ALLOWED and should be marked SAFE. " +
  "Only mark UNSAFE if the image contains: explicit/pornographic sexual content, clearly " +
  "visible genitals or sexual acts, graphic violence or gore, hate symbols, or content " +
  "sexualizing minors. When in doubt between 'artistic' and 'explicit', lean toward SAFE " +
  "unless it is clearly explicit. " +
  "Respond in exactly this format on one line: VERDICT: SAFE or VERDICT: UNSAFE, " +
  "followed by a short reason in under 15 words. " +
  "Example: 'VERDICT: SAFE - stylized fantasy figure, no explicit content.' " +
  "Example: 'VERDICT: UNSAFE - explicit sexual content clearly visible.'";

function corsHeaders(env, request) {
  const origin = request.headers.get('Origin') || '';
  const allowed = (env.ALLOWED_ORIGIN || '').split(',').map(s => s.trim()).filter(Boolean);
  const allowOrigin = allowed.includes(origin) ? origin : (allowed[0] || 'null');
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

function timingSafeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

function requireAdmin(request, env) {
  const token = request.headers.get('X-Admin-Token') || '';
  if (!token || !env.ADMIN_TOKEN) return false;
  return timingSafeEqual(token, env.ADMIN_TOKEN);
}

async function checkAdminAttemptLimit(env, ip) {
  const key = `admin_fail:${ip || 'unknown'}`;
  const raw = await env.PHOTOS_KV.get(key);
  const count = raw ? (parseInt(raw, 10) || 0) : 0;
  return { blocked: count >= MAX_ADMIN_ATTEMPTS, count };
}

async function recordFailedAdminAttempt(env, ip) {
  const key = `admin_fail:${ip || 'unknown'}`;
  const raw = await env.PHOTOS_KV.get(key);
  const count = raw ? (parseInt(raw, 10) || 0) : 0;
  await env.PHOTOS_KV.put(key, String(count + 1), { expirationTtl: ADMIN_LOCKOUT_WINDOW_SECONDS });
}

async function clearAdminAttempts(env, ip) {
  await env.PHOTOS_KV.delete(`admin_fail:${ip || 'unknown'}`);
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
  let binary = '';
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunkSize));
  }
  return btoa(binary);
}

function detectRealImageType(bytes) {
  if (bytes.length < 12) return null;
  if (bytes[0] === 0xFF && bytes[1] === 0xD8) return 'image/jpeg';
  if (bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4E && bytes[3] === 0x47) {
    return 'image/png';
  }
  if (bytes[0] === 0x47 && bytes[1] === 0x49 && bytes[2] === 0x46) return 'image/gif';
  if (
    bytes[0] === 0x52 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x46 &&
    bytes[8] === 0x57 && bytes[9] === 0x45 && bytes[10] === 0x42 && bytes[11] === 0x50
  ) {
    return 'image/webp';
  }
  return null;
}

const WIB_OFFSET_MS = 7 * 60 * 60 * 1000;
function wibDateStr(date = new Date()) {
  return new Date(date.getTime() + WIB_OFFSET_MS).toISOString().slice(0, 10);
}

async function checkAndIncrementUploadRateLimit(env, ip) {
  const key = `ratelimit:${ip || 'unknown'}:${wibDateStr()}`;
  const raw = await env.PHOTOS_KV.get(key);
  const count = raw ? (parseInt(raw, 10) || 0) : 0;

  if (count >= MAX_UPLOADS_PER_DAY) {
    return { allowed: false, count, remaining: 0 };
  }

  const newCount = count + 1;
  await env.PHOTOS_KV.put(key, String(newCount), { expirationTtl: 60 * 60 * 24 * 2 });

  return { allowed: true, count: newCount, remaining: MAX_UPLOADS_PER_DAY - newCount };
}

// ==================================================================
// ==== PREMIUM: kode redeem & status aktif per IP =====
// ==================================================================

// Generate kode acak format XXXX-XXXX-XXXX, pakai charset yang buang
// karakter ambigu (0/O, 1/I/L) biar gampang diketik ulang user.
function generatePremiumCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  function group() {
    let s = '';
    for (let i = 0; i < 4; i++) s += chars[Math.floor(Math.random() * chars.length)];
    return s;
  }
  return `${group()}-${group()}-${group()}`;
}

// Cek status premium aktif buat suatu IP.
// Return: { active: boolean, expires_at?: string, code?: string }
async function checkPremiumStatus(env, ip) {
  if (!ip) return { active: false };
  const raw = await env.PHOTOS_KV.get(`premium:${ip}`);
  if (!raw) return { active: false };
  try {
    const data = JSON.parse(raw);
    if (data.expires_at && new Date(data.expires_at).getTime() > Date.now()) {
      return { active: true, expires_at: data.expires_at, code: data.code };
    }
    return { active: false };
  } catch (e) {
    return { active: false };
  }
}

async function getPremCodesIndex(env) {
  const raw = await env.PHOTOS_KV.get('premcodes_index');
  return raw ? JSON.parse(raw) : [];
}

async function setPremCodesIndex(env, arr) {
  await env.PHOTOS_KV.put('premcodes_index', JSON.stringify(arr));
}

// ---- Auto-moderasi pakai Workers AI (Moondream 3.1) ----
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
      max_tokens: 64,
      stream: false,
      temperature: 0,
    });

    const inner = (result && result.result) ? result.result : result;
    const rawAnswer = (inner && inner.answer ? String(inner.answer) : '').trim();
    const answer = rawAnswer.toUpperCase();

    if (!answer && inner && inner.finish_reason === 'length') {
      return { status: 'pending', reason: 'ai-truncated-max-tokens-too-low' };
    }

    function extractReasonText(text) {
      const dashIdx = text.indexOf('-');
      const reasonPart = dashIdx !== -1 ? text.slice(dashIdx + 1) : text;
      return reasonPart.trim().replace(/\s+/g, ' ').slice(0, 150);
    }

    if (answer.includes('UNSAFE')) {
      const why = extractReasonText(rawAnswer) || 'tidak ada alasan spesifik dari AI';
      return { status: 'rejected', reason: `ai-flagged-unsafe: ${why}` };
    }
    if (answer.includes('SAFE')) {
      const why = extractReasonText(rawAnswer) || 'tidak ada alasan spesifik dari AI';
      return { status: 'approved', reason: `ai-flagged-safe: ${why}` };
    }
    return { status: 'pending', reason: `ai-ambiguous-answer:${answer.slice(0, 80)}` };
  } catch (err) {
    return { status: 'pending', reason: 'ai-error:' + err.message };
  }
}

// ---- Verifikasi Google reCAPTCHA v2 ----
async function verifyRecaptcha(token, env, remoteIp) {
  if (!env.RECAPTCHA_SECRET_KEY) {
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
    return data;
  } catch (err) {
    return { success: false, error: 'verify-request-failed' };
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

      // ---- Public: cek status premium IP pemanggil ----
      if (path === '/api/premium/status' && request.method === 'GET') {
        const remoteIp = request.headers.get('CF-Connecting-IP') || '';
        const status = await checkPremiumStatus(env, remoteIp);
        return json({ ok: true, premium: status.active, expires_at: status.expires_at || null }, 200, cors);
      }

      // ---- Public: redeem kode premium ----
      if (path === '/api/redeem' && request.method === 'POST') {
        const remoteIp = request.headers.get('CF-Connecting-IP') || '';

        let body;
        try {
          body = await request.json();
        } catch (e) {
          return json({ ok: false, error: 'Data tidak valid.' }, 400, cors);
        }

        const code = (body && body.code ? String(body.code) : '').trim().toUpperCase();
        if (!code) return json({ ok: false, error: 'Kode wajib diisi.' }, 400, cors);

        const raw = await env.PHOTOS_KV.get(`premcode:${code}`);
        if (!raw) return json({ ok: false, error: 'Kode tidak ditemukan atau tidak valid.' }, 404, cors);

        const data = JSON.parse(raw);
        if (data.revoked) {
          return json({ ok: false, error: 'Kode ini sudah dinonaktifkan.' }, 400, cors);
        }
        if (data.used) {
          return json({ ok: false, error: 'Kode ini sudah pernah dipakai.' }, 400, cors);
        }

        const now = new Date();
        const durationDays = data.duration_days || 30;
        const expiresAt = new Date(now.getTime() + durationDays * 24 * 60 * 60 * 1000).toISOString();

        data.used = true;
        data.used_at = now.toISOString();
        data.used_ip = remoteIp;
        await env.PHOTOS_KV.put(`premcode:${code}`, JSON.stringify(data));

        await env.PHOTOS_KV.put(
          `premium:${remoteIp}`,
          JSON.stringify({ code, activated_at: now.toISOString(), expires_at: expiresAt }),
          { expirationTtl: durationDays * 24 * 60 * 60 }
        );

        return json({ ok: true, expires_at: expiresAt, duration_days: durationDays }, 200, cors);
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

        // ---- Cek premium DULU: kalau aktif, rate limit harian diabaikan ----
        const premiumStatus = await checkPremiumStatus(env, remoteIp);
        let rateLimit;
        if (premiumStatus.active) {
          rateLimit = { allowed: true, count: 0, remaining: 'unlimited' };
        } else {
          rateLimit = await checkAndIncrementUploadRateLimit(env, remoteIp);
          if (!rateLimit.allowed) {
            return json(
              {
                ok: false,
                error: `Batas upload harian tercapai (maksimal ${MAX_UPLOADS_PER_DAY} foto per hari). Upgrade ke Premium buat upload tanpa batas, atau coba lagi besok ya.`,
              },
              429,
              cors
            );
          }
        }

        const bytes = new Uint8Array(await file.arrayBuffer());

        const realType = detectRealImageType(bytes);
        if (!realType || realType !== file.type) {
          return json({ ok: false, error: 'Isi file tidak sesuai dengan format yang diklaim.' }, 400, cors);
        }

        const id = newId();
        const filename = `${id}.${ext}`;

        const moderation = await moderateImage(env, bytes, file.type);

        await env.PHOTOS_BUCKET.put(`photos/${filename}`, bytes, {
          httpMetadata: { contentType: file.type },
        });

        const now = new Date().toISOString();
        const record = {
          id,
          filename,
          title: title || null,
          uploader_name: uploaderName || null,
          status: moderation.status,
          uploaded_at: now,
          approved_at: moderation.status === 'approved' ? now : null,
          ip: remoteIp || null,
          moderation_reason: moderation.reason,
          has_file: true,
        };
        await env.PHOTOS_KV.put(`photo:${id}`, JSON.stringify(record));

        const targetIndex = await getIndex(env, moderation.status);
        targetIndex.unshift(record);
        await setIndex(env, moderation.status, targetIndex);

        return json(
          {
            ok: true,
            status: moderation.status,
            premium: premiumStatus.active,
            uploads_remaining_today: rateLimit.remaining,
          },
          200,
          cors
        );
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
            'X-Content-Type-Options': 'nosniff',
            ...cors,
          },
        });
      }

      // ---- Admin routes below require X-Admin-Token ----
      if (path.startsWith('/api/admin/')) {
        const remoteIp = request.headers.get('CF-Connecting-IP') || '';

        const attemptStatus = await checkAdminAttemptLimit(env, remoteIp);
        if (attemptStatus.blocked) {
          return json(
            { ok: false, error: 'Terlalu banyak percobaan gagal. Coba lagi dalam beberapa menit.' },
            429,
            cors
          );
        }

        if (!requireAdmin(request, env)) {
          await recordFailedAdminAttempt(env, remoteIp);
          return json({ ok: false, error: 'Unauthorized' }, 401, cors);
        }

        await clearAdminAttempts(env, remoteIp);

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

        // ---- PREMIUM: generate kode baru ----
        if (path === '/api/admin/codes/generate' && request.method === 'POST') {
          let body;
          try {
            body = await request.json();
          } catch (e) {
            body = {};
          }
          const durationDays = Math.max(1, parseInt(body && body.duration_days, 10) || 30);

          let code = null;
          for (let attempt = 0; attempt < 5; attempt++) {
            const candidate = generatePremiumCode();
            const exists = await env.PHOTOS_KV.get(`premcode:${candidate}`);
            if (!exists) { code = candidate; break; }
          }
          if (!code) return json({ ok: false, error: 'Gagal generate kode unik, coba lagi.' }, 500, cors);

          const record = {
            code,
            duration_days: durationDays,
            created_at: new Date().toISOString(),
            revoked: false,
            used: false,
            used_at: null,
            used_ip: null,
          };
          await env.PHOTOS_KV.put(`premcode:${code}`, JSON.stringify(record));

          const indexArr = await getPremCodesIndex(env);
          indexArr.unshift(code);
          await setPremCodesIndex(env, indexArr);

          return json({ ok: true, code: record }, 200, cors);
        }

        // ---- PREMIUM: list semua kode ----
        if (path === '/api/admin/codes' && request.method === 'GET') {
          const indexArr = await getPremCodesIndex(env);
          const codes = [];
          for (const c of indexArr) {
            const raw = await env.PHOTOS_KV.get(`premcode:${c}`);
            if (raw) codes.push(JSON.parse(raw));
          }
          return json({ ok: true, codes }, 200, cors);
        }

        // ---- PREMIUM: revoke kode yang belum dipakai ----
        const revokeMatch = path.match(/^\/api\/admin\/codes\/([A-Z0-9-]+)\/revoke$/);
        if (revokeMatch && request.method === 'POST') {
          const code = revokeMatch[1];
          const raw = await env.PHOTOS_KV.get(`premcode:${code}`);
          if (!raw) return json({ ok: false, error: 'Kode tidak ditemukan.' }, 404, cors);
          const data = JSON.parse(raw);
          data.revoked = true;
          await env.PHOTOS_KV.put(`premcode:${code}`, JSON.stringify(data));
          return json({ ok: true }, 200, cors);
        }

        // ---- PREMIUM: hapus kode dari histori ----
        const deleteCodeMatch = path.match(/^\/api\/admin\/codes\/([A-Z0-9-]+)\/delete$/);
        if (deleteCodeMatch && request.method === 'POST') {
          const code = deleteCodeMatch[1];
          await env.PHOTOS_KV.delete(`premcode:${code}`);
          const indexArr = await getPremCodesIndex(env);
          const filtered = indexArr.filter(c => c !== code);
          await setPremCodesIndex(env, filtered);
          return json({ ok: true }, 200, cors);
        }
      }

      return json({ ok: false, error: 'Not found' }, 404, cors);
    } catch (err) {
      return json({ ok: false, error: 'Server error: ' + err.message }, 500, cors);
    }
  },
};
