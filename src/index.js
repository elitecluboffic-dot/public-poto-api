/**
 * Public Poto — Cloudflare Worker backend
 *
 * Bindings dibutuhkan (set di wrangler.toml / dashboard):
 *  - PHOTOS_KV           : KV namespace (metadata + index + rate limit counter)
 *  - PHOTOS_BUCKET       : R2 bucket (file gambar)
 *  - AI                    : Workers AI binding (wajib buat auto-moderasi)
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
 * Workers AI dengan pertanyaan: apakah gambar ini aman buat galeri foto publik
 * yang family-friendly, plus minta alasan singkat (di bawah 15 kata).
 *   - Kalau model jawab "VERDICT: SAFE"   -> foto langsung masuk status "approved"
 *   - Kalau model jawab "VERDICT: UNSAFE" -> foto langsung masuk status "rejected"
 *   - Kalau model error / jawaban ambigu  -> foto FALLBACK ke "pending" (fail-safe,
 *     supaya kalau AI-nya lagi bermasalah, konten nggak lolos begitu aja tanpa
 *     ada yang cek)
 * Alasan singkat dari model disimpan di field `moderation_reason` tiap record,
 * jadi admin bisa lihat KENAPA suatu foto ditolak/disetujui, bukan cuma label.
 *
 * File foto SELALU disimpan ke R2, termasuk yang berstatus "rejected" -- ini
 * supaya admin bisa buka & lihat gambarnya sendiri buat verifikasi manual kalau
 * curiga AI-nya salah tebak (false positive). Foto berstatus "rejected" TIDAK
 * PERNAH otomatis tampil ke publik (endpoint /api/photos cuma nampilin yang
 * "approved"), jadi ini aman dari sisi publik. Kalau nanti storage jadi
 * perhatian, admin bisa hapus manual foto "rejected" yang numpuk lewat tombol
 * Hapus di panel admin.
 * Admin tetap bisa override manual kapan aja lewat endpoint /api/admin/photos/:id/:action,
 * apa pun status hasil auto-moderasinya.
 *
 * ---- Rate limit upload per IP ----
 * Setiap IP cuma boleh upload maksimal MAX_UPLOADS_PER_DAY foto per hari
 * (dihitung per hari WIB / UTC+7, reset jam 00:00 WIB, BUKAN jam 00:00 UTC
 * dan BUKAN rolling 24 jam dari upload pertama). Ini dihitung dari upload
 * yang LOLOS captcha & validasi file dasar -- terlepas dari hasil
 * auto-moderasi (approved/rejected/pending tetap makan jatah), karena tiap
 * percobaan upload tetap makan resource (Workers AI call + R2 storage).
 *
 * Catatan soal WIB: Worker jalan di server yang jamnya UTC, jadi buat dapetin
 * "hari ini menurut WIB" kita geser waktu +7 jam dulu sebelum diambil bagian
 * tanggalnya (fungsi `wibDateStr`). Ini cukup akurat buat kebutuhan rate
 * limit harian dan nggak butuh library timezone tambahan.
 *
 * Implementasi pakai counter simpel di PHOTOS_KV dengan key
 * `ratelimit:{ip}:{YYYY-MM-DD}` dan `expirationTtl` 2 hari (biar otomatis
 * kebersihan sendiri, nggak numpuk selamanya di KV).
 *
 * CATATAN JUJUR: pola read-modify-write ke KV di sini TIDAK atomic. Kalau ada
 * 2 request upload dari IP yang sama yang nyaris bersamaan banget (race
 * condition dalam hitungan milidetik), secara teori bisa lolos jadi 3x bukan
 * 2x. Untuk rate-limit anti-spam kasual ini cukup memadai; kalau butuh
 * presisi absolut (mis. buat billing), baru worth it pakai Durable Object
 * sebagai counter atomic.
 *
 * ---- Validasi tipe file "asli" (magic bytes) [BARU] ----
 * `file.type` yang dikirim browser gampang dipalsuin (orang bisa ubah header
 * request biar ngaku file-nya "image/png" padahal isinya bukan). Sebelum file
 * disimpan ke R2, kita cek beberapa byte pertama file itu sendiri buat mastiin
 * isinya BENERAN gambar sesuai tipe yang diklaim. Kalau nggak cocok, upload
 * ditolak sebelum sempat disimpan.
 *
 * ---- Perbandingan ADMIN_TOKEN pakai constant-time compare [BARU] ----
 * `===` biasa buat bandingin string berhenti di karakter pertama yang beda,
 * jadi secara teori waktu eksekusinya bisa dipakai buat nebak token karakter
 * demi karakter (timing attack). Diganti pakai perbandingan yang selalu
 * mengecek semua karakter meski udah ketemu beda dari karakter awal.
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
const MAX_UPLOADS_PER_DAY = 2; // batas upload per IP per hari (WIB)
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
  // Kalau ALLOWED_ORIGIN belum di-set sama sekali, jangan fallback ke "*"
  // (itu ngizinin semua origin akses API). Fallback ke "null" yang efeknya
  // browser tetap nolak cross-origin request.
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

// Constant-time string compare -- selalu ngecek semua karakter, nggak
// berhenti di awal begitu ketemu beda, biar waktu eksekusinya nggak bocorin
// informasi soal seberapa jauh tebakan token itu benar.
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

// ---- Deteksi tipe file "asli" dari isi byte-nya, bukan dari klaim browser ----
// Ngecek "magic bytes" -- beberapa byte pertama tiap format gambar yang khas
// dan konsisten -- biar file yang dipalsuin Content-Type-nya ketahuan.
// Return: mime type asli kalau dikenali, atau null kalau nggak cocok format apapun.
function detectRealImageType(bytes) {
  if (bytes.length < 12) return null;

  // JPEG: dimulai dengan FF D8
  if (bytes[0] === 0xFF && bytes[1] === 0xD8) return 'image/jpeg';

  // PNG: dimulai dengan 89 50 4E 47 (‰PNG)
  if (bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4E && bytes[3] === 0x47) {
    return 'image/png';
  }

  // GIF: dimulai dengan "GIF87a" atau "GIF89a"
  if (bytes[0] === 0x47 && bytes[1] === 0x49 && bytes[2] === 0x46) return 'image/gif';

  // WEBP: "RIFF"....'WEBP' -- 4 byte pertama RIFF, byte 8-11 WEBP
  if (
    bytes[0] === 0x52 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x46 &&
    bytes[8] === 0x57 && bytes[9] === 0x45 && bytes[10] === 0x42 && bytes[11] === 0x50
  ) {
    return 'image/webp';
  }

  return null;
}

// Ambil string tanggal "hari ini" menurut WIB (UTC+7), format YYYY-MM-DD.
// Worker jalan dengan jam sistem UTC, jadi kita geser +7 jam dulu sebelum
// ambil bagian tanggalnya lewat toISOString().
const WIB_OFFSET_MS = 7 * 60 * 60 * 1000;
function wibDateStr(date = new Date()) {
  return new Date(date.getTime() + WIB_OFFSET_MS).toISOString().slice(0, 10);
}

// ---- Rate limit upload per IP: maks MAX_UPLOADS_PER_DAY per hari (WIB) ----
// Return: { allowed: boolean, count: number, remaining: number }
async function checkAndIncrementUploadRateLimit(env, ip) {
  // Kalau karena suatu sebab IP nggak kebaca (jarang terjadi di Cloudflare,
  // tapi jaga-jaga), jangan diam-diam meloloskan tanpa batas -- treat semua
  // request tanpa IP sebagai satu grup 'unknown' yang tetap dibatasi.
  const key = `ratelimit:${ip || 'unknown'}:${wibDateStr()}`;

  const raw = await env.PHOTOS_KV.get(key);
  const count = raw ? (parseInt(raw, 10) || 0) : 0;

  if (count >= MAX_UPLOADS_PER_DAY) {
    return { allowed: false, count, remaining: 0 };
  }

  const newCount = count + 1;
  // TTL 2 hari: cukup buat nutupin hari berjalan + buffer, sekalian bikin
  // KV otomatis beres-beres sendiri (nggak numpuk key lama selamanya).
  await env.PHOTOS_KV.put(key, String(newCount), { expirationTtl: 60 * 60 * 24 * 2 });

  return { allowed: true, count: newCount, remaining: MAX_UPLOADS_PER_DAY - newCount };
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
      reasoning: false, // matikan reasoning trace, kita cuma butuh jawaban akhir
      max_tokens: 64,    // PENTING: jangan diset terlalu kecil (mis. 16) -- itu bikin
                          // jawaban kepotong sebelum sempat nulis SAFE/UNSAFE sama
                          // sekali, hasilnya field `answer` balik kosong. Default
                          // resmi model ini 8192; 64 udah lebih dari cukup buat
                          // satu kata jawaban + sedikit toleransi.
      stream: false,     // default true di API-nya, kita matikan biar respons langsung utuh
      temperature: 0,
    });

    // PENTING: struktur respons Workers AI buat model ini ternyata NESTED --
    // jawabannya ada di result.result.answer, bukan result.answer langsung.
    // Bentuk lengkapnya: { result: { answer, caption, finish_reason, ... }, usage: {...} }
    const inner = (result && result.result) ? result.result : result;
    const rawAnswer = (inner && inner.answer ? String(inner.answer) : '').trim();
    const answer = rawAnswer.toUpperCase();

    // Kalau jawabannya kosong DAN generation-nya kepotong karena kehabisan token,
    // catat itu spesifik di reason -- bukan cuma "ambiguous" -- biar ke-diagnosa
    // lebih cepat kalau ini kejadian lagi.
    if (!answer && inner && inner.finish_reason === 'length') {
      return { status: 'pending', reason: 'ai-truncated-max-tokens-too-low' };
    }

    // Ambil bagian alasan singkat yang ditulis model setelah "VERDICT: SAFE/UNSAFE"
    // (biasanya dipisah tanda "-"), biar bisa ditampilin ke admin -- bukan cuma
    // label "unsafe" doang tanpa konteks kenapa.
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
    // Jawaban ambigu -> jangan asal loloskan, kirim ke antrian manual.
    return { status: 'pending', reason: `ai-ambiguous-answer:${answer.slice(0, 80)}` };
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

        // ---- Rate limit per IP: maks MAX_UPLOADS_PER_DAY foto per hari ----
        // Ditaruh SETELAH validasi dasar (biar error "format salah" dll tetap
        // muncul duluan), tapi SEBELUM moderasi AI & simpan ke R2 (biar kalau
        // kena limit, kita nggak buang-buang panggilan Workers AI / storage).
        const rateLimit = await checkAndIncrementUploadRateLimit(env, remoteIp);
        if (!rateLimit.allowed) {
          return json(
            { ok: false, error: `Batas upload harian tercapai (maksimal ${MAX_UPLOADS_PER_DAY} foto per hari). Coba lagi besok ya.` },
            429,
            cors
          );
        }

        const bytes = new Uint8Array(await file.arrayBuffer());

        // ---- Validasi isi file yang SEBENARNYA, bukan cuma klaim browser ----
        // file.type dikirim dari sisi client dan gampang dipalsuin. Kita cek
        // beberapa byte pertama file itu sendiri buat mastiin isinya beneran
        // format gambar yang diklaim, sebelum disimpan ke R2.
        const realType = detectRealImageType(bytes);
        if (!realType || realType !== file.type) {
          return json({ ok: false, error: 'Isi file tidak sesuai dengan format yang diklaim.' }, 400, cors);
        }

        const id = newId();
        const filename = `${id}.${ext}`;

        // ---- Auto-moderasi AI sebelum foto ditampilin publik ----
        const moderation = await moderateImage(env, bytes, file.type);

        // File TETAP disimpan meskipun ditolak AI -- ini penting biar admin bisa
        // buka & lihat sendiri gambarnya di tab "Ditolak" buat verifikasi manual
        // (mengoreksi false positive). Foto yang ditolak TIDAK pernah otomatis
        // tampil ke publik (endpoint /api/photos cuma nampilin yang "approved"),
        // jadi menyimpannya sementara di sini aman dari sisi publik.
        // Catatan: ini nambah pemakaian storage R2 dibanding sebelumnya -- kalau
        // suatu saat mau balik ke perilaku "jangan simpan yang ditolak", admin
        // bisa hapus manual foto yang statusnya "rejected" lewat tombol Hapus.
        await env.PHOTOS_BUCKET.put(`photos/${filename}`, bytes, {
          httpMetadata: { contentType: file.type },
        });

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
          has_file: true,
        };
        await env.PHOTOS_KV.put(`photo:${id}`, JSON.stringify(record));

        const targetIndex = await getIndex(env, moderation.status);
        targetIndex.unshift(record);
        await setIndex(env, moderation.status, targetIndex);

        return json({ ok: true, status: moderation.status, uploads_remaining_today: rateLimit.remaining }, 200, cors);
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
            // Cegah browser lama "nyium" (sniff) isi file jadi beda dari
            // Content-Type yang di-declare -- pertahanan tambahan di atas
            // validasi magic bytes pas upload.
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
