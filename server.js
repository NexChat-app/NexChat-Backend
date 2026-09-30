'use strict';

const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const admin = require('firebase-admin');

/* ---------- Configuration ---------- */
const PORT = process.env.PORT || 3000;
const BREVO_API_KEY = process.env.BREVO_API_KEY;
const SENDER_EMAIL = process.env.BREVO_SENDER_EMAIL || 'nexchat52@gmail.com';
const SENDER_NAME = process.env.BREVO_SENDER_NAME || 'NexChat';
const CODE_SECRET = process.env.CODE_SECRET;
const CLOUD_NAME = process.env.CLOUDINARY_CLOUD_NAME || 'vxhmvyzh';
const CLD_KEY = process.env.CLOUDINARY_API_KEY;
const CLD_SECRET = process.env.CLOUDINARY_API_SECRET;
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || 'https://nexchat-app.github.io')
  .split(',').map(function (o) { return o.trim(); }).filter(Boolean);

const CODE_TTL_MS = 10 * 60 * 1000;   // validite du code : 10 minutes
const RESEND_COOLDOWN_MS = 60 * 1000; // delai entre deux envois : 60 secondes
const MAX_ATTEMPTS = 5;               // essais maximum par code

function requireEnv(name, value) {
  if (!value) { console.error('Variable d\'environnement manquante : ' + name); process.exit(1); }
}
requireEnv('BREVO_API_KEY', BREVO_API_KEY);
requireEnv('CODE_SECRET', CODE_SECRET);
requireEnv('CLOUDINARY_API_KEY', CLD_KEY);
requireEnv('CLOUDINARY_API_SECRET', CLD_SECRET);
requireEnv('FIREBASE_SERVICE_ACCOUNT', process.env.FIREBASE_SERVICE_ACCOUNT);

admin.initializeApp({
  credential: admin.credential.cert(JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT))
});
const auth = admin.auth();
const db = admin.firestore();
const codes = db.collection('emailCodes');

/* ---------- Utilitaires ---------- */
function normEmail(v) { return String(v || '').trim().toLowerCase(); }
function isEmail(v) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v) && v.length <= 254; }
function hmac(value) { return crypto.createHmac('sha256', CODE_SECRET).update(value).digest('hex'); }
function docId(email, purpose) { return hmac('doc:' + purpose + ':' + email); }
function safeEqual(a, b) {
  const x = Buffer.from(a, 'hex'); const y = Buffer.from(b, 'hex');
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}
function isPurpose(p) { return p === 'signup' || p === 'reset'; }

async function findUser(email) {
  try { return await auth.getUserByEmail(email); }
  catch (e) { if (e.code === 'auth/user-not-found') return null; throw e; }
}

async function sendCodeEmail(to, code, purpose) {
  const title = purpose === 'reset' ? 'Reinitialisation du mot de passe' : 'Confirmation de votre email';
  const intro = purpose === 'reset'
    ? 'Utilisez ce code pour choisir un nouveau mot de passe NexChat.'
    : 'Bienvenue sur NexChat. Utilisez ce code pour confirmer votre adresse email.';
  const html =
    '<div style="font-family:Arial,Helvetica,sans-serif;background:#f4f7fc;padding:32px 16px;">' +
    '<div style="max-width:440px;margin:0 auto;background:#ffffff;border-radius:18px;padding:32px 28px;">' +
    '<div style="font-size:22px;font-weight:800;color:#0b1b4d;">NexChat</div>' +
    '<h1 style="font-size:18px;color:#0b1b4d;margin:20px 0 8px;">' + title + '</h1>' +
    '<p style="font-size:14px;line-height:1.6;color:#4a5578;margin:0 0 20px;">' + intro + '</p>' +
    '<div style="font-size:34px;font-weight:800;letter-spacing:10px;text-align:center;color:#1f5eff;background:#eef3ff;border-radius:14px;padding:16px 0;">' + code + '</div>' +
    '<p style="font-size:13px;line-height:1.6;color:#7a86a8;margin:20px 0 0;">Ce code expire dans 10 minutes. Si vous n\'etes pas a l\'origine de cette demande, ignorez ce message.</p>' +
    '</div></div>';

  const res = await fetch('https://api.brevo.com/v3/smtp/email', {
    method: 'POST',
    headers: { 'accept': 'application/json', 'content-type': 'application/json', 'api-key': BREVO_API_KEY },
    body: JSON.stringify({
      sender: { name: SENDER_NAME, email: SENDER_EMAIL },
      to: [{ email: to }],
      subject: 'Votre code NexChat : ' + code,
      htmlContent: html
    })
  });
  if (!res.ok) {
    const detail = await res.text().catch(function () { return ''; });
    throw new Error('Brevo ' + res.status + ' ' + detail.slice(0, 200));
  }
}

/* ---------- Application ---------- */
const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '10kb' }));
app.use(cors({
  origin: function (origin, cb) {
    if (!origin || ALLOWED_ORIGINS.indexOf(origin) !== -1) return cb(null, true);
    return cb(new Error('Origine non autorisee'));
  },
  methods: ['GET', 'POST'],
  maxAge: 86400
}));

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 40, standardHeaders: true, legacyHeaders: false,
  message: { ok: false, error: 'Trop de requetes. Reessayez plus tard.' } });
app.use('/send-code', limiter);
app.use('/verify-code', limiter);
app.use('/reset-password', limiter);

app.get('/', function (req, res) { res.json({ ok: true, service: 'nexchat-backend' }); });
app.get('/health', function (req, res) { res.json({ ok: true }); });

/* POST /send-code  { email, purpose: 'signup' | 'reset' } */
app.post('/send-code', async function (req, res) {
  try {
    const email = normEmail(req.body.email);
    const purpose = req.body.purpose;
    if (!isEmail(email) || !isPurpose(purpose)) return res.status(400).json({ ok: false, error: 'Requete invalide.' });

    const user = await findUser(email);
    // Reponse identique dans tous les cas pour ne pas reveler quels emails existent
    const eligible = user && (purpose === 'reset' || !user.emailVerified);
    if (!eligible) return res.json({ ok: true });

    const ref = codes.doc(docId(email, purpose));
    const snap = await ref.get();
    const now = Date.now();
    if (snap.exists && now - snap.data().sentAt < RESEND_COOLDOWN_MS) {
      const wait = Math.ceil((RESEND_COOLDOWN_MS - (now - snap.data().sentAt)) / 1000);
      return res.status(429).json({ ok: false, error: 'Patientez ' + wait + ' secondes avant de renvoyer le code.' });
    }

    const code = String(crypto.randomInt(100000, 1000000));
    await ref.set({
      purpose: purpose,
      uid: user.uid,
      codeHash: hmac('code:' + email + ':' + purpose + ':' + code),
      attempts: 0,
      sentAt: now,
      expiresAt: now + CODE_TTL_MS,
      verified: false
    });
    await sendCodeEmail(email, code, purpose);
    return res.json({ ok: true });
  } catch (e) {
    console.error('send-code', e);
    return res.status(500).json({ ok: false, error: 'Impossible d\'envoyer le code pour le moment.' });
  }
});

/* POST /verify-code  { email, purpose, code }  ->  reset : renvoie resetToken */
app.post('/verify-code', async function (req, res) {
  try {
    const email = normEmail(req.body.email);
    const purpose = req.body.purpose;
    const code = String(req.body.code || '').trim();
    if (!isEmail(email) || !isPurpose(purpose) || !/^\d{6}$/.test(code)) {
      return res.status(400).json({ ok: false, error: 'Code invalide.' });
    }

    const ref = codes.doc(docId(email, purpose));
    const snap = await ref.get();
    const bad = { ok: false, error: 'Code incorrect ou expire.' };
    if (!snap.exists) return res.status(400).json(bad);
    const d = snap.data();
    if (Date.now() > d.expiresAt || d.attempts >= MAX_ATTEMPTS || d.verified) {
      await ref.delete();
      return res.status(400).json(bad);
    }

    const expected = hmac('code:' + email + ':' + purpose + ':' + code);
    if (!safeEqual(expected, d.codeHash)) {
      await ref.update({ attempts: admin.firestore.FieldValue.increment(1) });
      return res.status(400).json(bad);
    }

    if (purpose === 'signup') {
      await auth.updateUser(d.uid, { emailVerified: true });
      await db.collection('users').doc(d.uid).set({ emailVerified: true }, { merge: true });
      await ref.delete();
      return res.json({ ok: true });
    }

    // reset : on remet un jeton a usage unique, valable 10 minutes
    const resetToken = crypto.randomBytes(32).toString('hex');
    await ref.update({ verified: true, tokenHash: hmac('token:' + resetToken), expiresAt: Date.now() + CODE_TTL_MS });
    return res.json({ ok: true, resetToken: resetToken });
  } catch (e) {
    console.error('verify-code', e);
    return res.status(500).json({ ok: false, error: 'Verification impossible pour le moment.' });
  }
});

/* POST /reset-password  { email, resetToken, newPassword } */
app.post('/reset-password', async function (req, res) {
  try {
    const email = normEmail(req.body.email);
    const token = String(req.body.resetToken || '');
    const newPassword = String(req.body.newPassword || '');
    if (!isEmail(email) || !/^[0-9a-f]{64}$/.test(token)) return res.status(400).json({ ok: false, error: 'Requete invalide.' });
    if (newPassword.length < 8 || newPassword.length > 128) {
      return res.status(400).json({ ok: false, error: 'Le mot de passe doit contenir au moins 8 caracteres.' });
    }

    const ref = codes.doc(docId(email, 'reset'));
    const snap = await ref.get();
    const bad = { ok: false, error: 'Session expiree. Recommencez la reinitialisation.' };
    if (!snap.exists) return res.status(400).json(bad);
    const d = snap.data();
    if (!d.verified || !d.tokenHash || Date.now() > d.expiresAt || !safeEqual(hmac('token:' + token), d.tokenHash)) {
      return res.status(400).json(bad);
    }

    await auth.updateUser(d.uid, { password: newPassword });
    await auth.revokeRefreshTokens(d.uid); // deconnecte les anciens appareils
    await ref.delete();
    return res.json({ ok: true });
  } catch (e) {
    console.error('reset-password', e);
    return res.status(500).json({ ok: false, error: 'Reinitialisation impossible pour le moment.' });
  }
});


/* ---------- Cloudinary : suppression de fichiers ---------- */
function parseCloudinaryUrl(u) {
  if (typeof u !== 'string') return null;
  const m = /^https:\/\/res\.cloudinary\.com\/([^/]+)\/(image|video|raw)\/upload\/(?:v\d+\/)?(.+)$/.exec(u);
  if (!m || m[1] !== CLOUD_NAME) return null;
  let publicId = decodeURIComponent(m[3].split('?')[0]);
  if (m[2] !== 'raw') publicId = publicId.replace(/\.[A-Za-z0-9]+$/, '');
  return { type: m[2], publicId: publicId };
}

async function destroyFile(url) {
  const p = parseCloudinaryUrl(url);
  if (!p) return false;
  const ts = String(Math.floor(Date.now() / 1000));
  const signature = crypto.createHash('sha1')
    .update('invalidate=true&public_id=' + p.publicId + '&timestamp=' + ts + CLD_SECRET)
    .digest('hex');
  const body = new URLSearchParams({ public_id: p.publicId, timestamp: ts, api_key: CLD_KEY, signature: signature, invalidate: 'true' });
  const res = await fetch('https://api.cloudinary.com/v1_1/' + CLOUD_NAME + '/' + p.type + '/destroy', { method: 'POST', body: body });
  const data = await res.json().catch(function () { return {}; });
  if (!res.ok) throw new Error('Cloudinary ' + res.status + ' ' + JSON.stringify(data).slice(0, 160));
  return data.result === 'ok';
}

async function destroyMany(urls) {
  const list = urls.filter(Boolean);
  const out = await Promise.allSettled(list.map(destroyFile));
  out.forEach(function (r) { if (r.status === 'rejected') console.error('destroy', r.reason && r.reason.message); });
}

async function requireUser(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.indexOf('Bearer ') === 0 ? h.slice(7) : '';
  try {
    const dec = await auth.verifyIdToken(token);
    if (dec.email_verified !== true) return res.status(403).json({ ok: false, error: 'Email non confirme.' });
    req.uid = dec.uid;
    return next();
  } catch (e) {
    return res.status(401).json({ ok: false, error: 'Session invalide.' });
  }
}

const ITEMS = {
  status: { col: 'statuses', owner: function (d, uid) { return d.authorId === uid; }, urls: function (d) { return [d.url]; } },
  product: { col: 'products', owner: function (d, uid) { return d.shopId === uid; }, urls: function (d) { return d.photos || []; } },
  group: { col: 'groups', owner: function (d, uid) { return (d.admins || []).indexOf(uid) !== -1; }, urls: function (d) { return [d.photoURL]; } }
};

/* POST /delete-item  { type: 'status' | 'product' | 'group', id }  (jeton Firebase requis) */
app.post('/delete-item', limiter, requireUser, async function (req, res) {
  try {
    const cfg = ITEMS[req.body.type];
    const id = String(req.body.id || '');
    if (!cfg || !/^[A-Za-z0-9_-]{1,128}$/.test(id)) return res.status(400).json({ ok: false, error: 'Requete invalide.' });
    const ref = db.collection(cfg.col).doc(id);
    const snap = await ref.get();
    if (!snap.exists) return res.json({ ok: true });
    const data = snap.data();
    if (!cfg.owner(data, req.uid)) return res.status(403).json({ ok: false, error: 'Action non autorisee.' });
    let urls = cfg.urls(data);
    if (req.body.type === 'group') {
      const ms = await ref.collection('messages').get();
      ms.forEach(function (m) { urls.push(m.data().url); });
    }
    await destroyMany(urls);
    await db.recursiveDelete(ref);
    return res.json({ ok: true });
  } catch (e) {
    console.error('delete-item', e);
    return res.status(500).json({ ok: false, error: 'Suppression impossible pour le moment.' });
  }
});

/* Nettoyage des statuts expires (au demarrage puis toutes les heures tant que le serveur est actif) */
async function sweepExpired() {
  try {
    const snap = await db.collection('statuses').where('expiresAt', '<=', Date.now()).limit(50).get();
    for (const d of snap.docs) {
      await destroyMany([d.data().url]);
      await db.recursiveDelete(d.ref);
    }
    if (snap.size) console.log('Statuts expires supprimes :', snap.size);
  } catch (e) { console.error('sweepExpired', e.message); }
}
setTimeout(sweepExpired, 30 * 1000);
setInterval(sweepExpired, 60 * 60 * 1000);

app.use(function (err, req, res, next) { // eslint-disable-line no-unused-vars
  if (err && err.message === 'Origine non autorisee') return res.status(403).json({ ok: false, error: 'Origine non autorisee.' });
  console.error(err);
  return res.status(500).json({ ok: false, error: 'Erreur serveur.' });
});

app.listen(PORT, function () { console.log('NexChat backend sur le port ' + PORT); });
