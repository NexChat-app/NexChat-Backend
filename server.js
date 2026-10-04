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
const SUPPORT_EMAIL = process.env.SUPPORT_EMAIL || SENDER_EMAIL;
const CODE_SECRET = process.env.CODE_SECRET;
const CLOUD_NAME = process.env.CLOUDINARY_CLOUD_NAME || 'vxhmvyzh';
let APP_URL = process.env.APP_URL || 'https://nexchat-app.github.io/';
if (APP_URL.slice(-1) !== '/') APP_URL += '/';
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
  const title = purpose === 'reset' ? 'Reinitialisation du mot de passe'
    : purpose === '2fa' ? 'Verification en deux etapes'
    : purpose === 'change' ? 'Changement d\'adresse email' : 'Confirmation de votre email';
  const intro = purpose === 'reset'
    ? 'Utilisez ce code pour choisir un nouveau mot de passe NexChat.'
    : purpose === '2fa'
      ? 'Utilisez ce code pour confirmer votre identite. Si vous n\'etes pas a l\'origine de cette demande, changez votre mot de passe.'
    : purpose === 'change'
      ? 'Utilisez ce code pour confirmer que cette adresse sera desormais celle de votre compte NexChat.'
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
app.use('/email-change', limiter);
app.use('/support', limiter);
app.use('/delete-account', limiter);
app.use('/2fa', limiter);

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


/* Politique de mot de passe (identique a celle de l'appli) */
const COMMON_PW = ['password','motdepasse','azerty','qwerty','qwertyuiop','azertyuiop','nexchat','admin','administrateur','welcome','bienvenue','bonjour','soleil','iloveyou','jetaime','football','letmein','monkey','dragon','master','cotonou','benin','abcdef','abcdefgh','changeme','passw0rd','secret','azertyui'];
const LEET_PW = { '@': 'a', '4': 'a', '0': 'o', '1': 'i', '!': 'i', '3': 'e', '$': 's', '5': 's', '7': 't', '8': 'b' };
function passwordProblem(pw, email) {
  if (pw.length < 8) return 'Le mot de passe doit contenir au moins 8 caracteres.';
  if (pw.length > 128) return 'Le mot de passe ne doit pas depasser 128 caracteres.';
  if (!/\p{Lu}/u.test(pw) || !/\p{Ll}/u.test(pw) || !/\d/.test(pw) || !/[^\p{L}\p{N}\s]/u.test(pw)) {
    return 'Le mot de passe doit contenir une majuscule, une minuscule, un chiffre et un symbole.';
  }
  let n = '';
  for (const ch of pw.toLowerCase()) n += (LEET_PW[ch] || ch);
  n = n.replace(/[^a-z]/g, '');
  for (const w of COMMON_PW) {
    if (n === w || (w.length >= 6 && n.includes(w))) return 'Mot de passe trop courant. Choisissez-en un plus original.';
  }
  if (new Set(pw).size < 5) return 'Trop de caracteres repetes. Variez davantage.';
  const local = String(email || '').split('@')[0].toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '').replace(/[^a-z0-9]/g, '');
  const flat = pw.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '').replace(/[^a-z0-9]/g, '');
  if (local.length >= 4 && flat.includes(local)) return 'Le mot de passe ne doit pas contenir votre email.';
  return '';
}

/* POST /reset-password  { email, resetToken, newPassword } */
app.post('/reset-password', async function (req, res) {
  try {
    const email = normEmail(req.body.email);
    const token = String(req.body.resetToken || '');
    const newPassword = String(req.body.newPassword || '');
    if (!isEmail(email) || !/^[0-9a-f]{64}$/.test(token)) return res.status(400).json({ ok: false, error: 'Requete invalide.' });
    const pwProblem = passwordProblem(newPassword, email);
    if (pwProblem) return res.status(400).json({ ok: false, error: pwProblem });

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
    req.decoded = dec;
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


/* ---------- Changement d'adresse email (jeton Firebase requis) ---------- */
const RECENT_LOGIN_MS = 10 * 60 * 1000; // le client doit avoir reverifie son mot de passe il y a moins de 10 minutes

/* POST /email-change/send  { newEmail } */
app.post('/email-change/send', requireUser, async function (req, res) {
  try {
    const newEmail = normEmail(req.body.newEmail);
    if (!isEmail(newEmail)) return res.status(400).json({ ok: false, error: 'Adresse email invalide.' });
    const authTime = Number(req.decoded.auth_time || 0) * 1000;
    if (Date.now() - authTime > RECENT_LOGIN_MS) {
      return res.status(403).json({ ok: false, error: 'Pour votre securite, reconnectez-vous puis reessayez.' });
    }

    const current = await auth.getUser(req.uid);
    if (normEmail(current.email) === newEmail) {
      return res.status(400).json({ ok: false, error: 'C\'est deja l\'adresse de votre compte.' });
    }
    if (await findUser(newEmail)) {
      return res.status(400).json({ ok: false, error: 'Cette adresse email est deja utilisee.' });
    }

    const ref = codes.doc(docId(req.uid, 'change'));
    const snap = await ref.get();
    const now = Date.now();
    if (snap.exists && now - snap.data().sentAt < RESEND_COOLDOWN_MS) {
      const wait = Math.ceil((RESEND_COOLDOWN_MS - (now - snap.data().sentAt)) / 1000);
      return res.status(429).json({ ok: false, error: 'Patientez ' + wait + ' secondes avant de renvoyer le code.' });
    }

    const code = String(crypto.randomInt(100000, 1000000));
    await ref.set({
      purpose: 'change',
      uid: req.uid,
      newEmail: newEmail,
      codeHash: hmac('code:' + req.uid + ':' + newEmail + ':change:' + code),
      attempts: 0,
      sentAt: now,
      expiresAt: now + CODE_TTL_MS
    });
    await sendCodeEmail(newEmail, code, 'change');
    return res.json({ ok: true });
  } catch (e) {
    console.error('email-change/send', e);
    return res.status(500).json({ ok: false, error: 'Impossible d\'envoyer le code pour le moment.' });
  }
});

/* POST /email-change/confirm  { code } */
app.post('/email-change/confirm', requireUser, async function (req, res) {
  try {
    const code = String(req.body.code || '').trim();
    if (!/^\d{6}$/.test(code)) return res.status(400).json({ ok: false, error: 'Code invalide.' });

    const ref = codes.doc(docId(req.uid, 'change'));
    const snap = await ref.get();
    const bad = { ok: false, error: 'Code incorrect ou expire.' };
    if (!snap.exists) return res.status(400).json(bad);
    const d = snap.data();
    if (Date.now() > d.expiresAt || d.attempts >= MAX_ATTEMPTS) {
      await ref.delete();
      return res.status(400).json(bad);
    }
    const expected = hmac('code:' + req.uid + ':' + d.newEmail + ':change:' + code);
    if (!safeEqual(expected, d.codeHash)) {
      await ref.update({ attempts: admin.firestore.FieldValue.increment(1) });
      return res.status(400).json(bad);
    }

    try {
      await auth.updateUser(req.uid, { email: d.newEmail, emailVerified: true });
    } catch (e) {
      if (e.code === 'auth/email-already-exists') {
        await ref.delete();
        return res.status(400).json({ ok: false, error: 'Cette adresse email est deja utilisee.' });
      }
      throw e;
    }
    await db.collection('users').doc(req.uid).set({ email: d.newEmail, emailLower: d.newEmail, emailVerified: true }, { merge: true });
    await ref.delete();
    return res.json({ ok: true, email: d.newEmail });
  } catch (e) {
    console.error('email-change/confirm', e);
    return res.status(500).json({ ok: false, error: 'Changement impossible pour le moment.' });
  }
});


/* ---------- Remplacement d'une photo : le serveur enregistre la nouvelle et supprime l'ancienne ---------- */
const PHOTO_TARGETS = {
  profile: { ref: function (uid) { return db.collection('users').doc(uid); }, field: 'photoURL', can: function () { return true; } },
  group: { ref: function (uid, id) { return db.collection('groups').doc(id); }, field: 'photoURL', can: function (d, uid) { return (d.admins || []).indexOf(uid) !== -1; } },
  shopLogo: { ref: function (uid) { return db.collection('shops').doc(uid); }, field: 'logoURL', can: function () { return true; } },
  shopCover: { ref: function (uid) { return db.collection('shops').doc(uid); }, field: 'coverURL', can: function () { return true; } },
  productPhotos: { ref: function (uid, id) { return db.collection('products').doc(id); }, field: 'photos', list: true, can: function (d, uid) { return d.shopId === uid; } }
};
function ownCloudUrl(u) {
  return typeof u === 'string' && u.length < 600 && u.indexOf('https://res.cloudinary.com/' + CLOUD_NAME + '/') === 0;
}

/* POST /replace-photo  { kind, id?, value }  value : une URL (ou une liste d'URL pour productPhotos) */
app.post('/replace-photo', limiter, requireUser, async function (req, res) {
  try {
    const cfg = PHOTO_TARGETS[req.body.kind];
    const id = String(req.body.id || '');
    if (!cfg || (id && !/^[A-Za-z0-9_-]{1,128}$/.test(id))) return res.status(400).json({ ok: false, error: 'Requete invalide.' });
    if ((cfg.field === 'photoURL' && cfg.ref.length > 1 && !id) || (cfg.list && !id)) return res.status(400).json({ ok: false, error: 'Requete invalide.' });

    let next = req.body.value;
    if (cfg.list) {
      if (!Array.isArray(next) || next.length > 4 || !next.every(ownCloudUrl)) return res.status(400).json({ ok: false, error: 'Photos invalides.' });
    } else if (!ownCloudUrl(next)) {
      return res.status(400).json({ ok: false, error: 'Photo invalide.' });
    }

    const ref = cfg.ref(req.uid, id);
    const snap = await ref.get();
    const data = snap.exists ? snap.data() : {};
    if (snap.exists && !cfg.can(data, req.uid)) return res.status(403).json({ ok: false, error: 'Action non autorisee.' });
    if (!snap.exists && (cfg.list || cfg.ref.length > 1)) return res.status(404).json({ ok: false, error: 'Element introuvable.' });

    const old = cfg.list ? (data[cfg.field] || []) : [data[cfg.field]];
    const keep = cfg.list ? next : [next];
    const patch = {}; patch[cfg.field] = next;
    await ref.set(patch, { merge: true });
    if (req.body.kind === 'profile') await db.collection('profiles').doc(req.uid).set({ photoURL: next }, { merge: true });

    /* on compare les identifiants Cloudinary (et non les adresses) : un ancien fichier de meme identifiant que le nouveau ne doit jamais etre supprime */
    const keepIds = keep.map(function (u) { const q = parseCloudinaryUrl(u); return q ? q.type + '/' + q.publicId : u; });
    const gone = old.filter(function (u) {
      if (!u || keep.indexOf(u) !== -1) return false;
      const q = parseCloudinaryUrl(u);
      return !(q && keepIds.indexOf(q.type + '/' + q.publicId) !== -1);
    });
    await destroyMany(gone);
    return res.json({ ok: true, removed: gone.length });
  } catch (e) {
    console.error('replace-photo', e);
    return res.status(500).json({ ok: false, error: 'Enregistrement de la photo impossible pour le moment.' });
  }
});

/* ---------- Suppression de medias envoyes (jeton Firebase requis) ---------- */
/* POST /delete-media  { kind: 'private'|'group', chatId, ids: [messageId, ...] }
   Seul l'expediteur peut supprimer son media : le fichier Cloudinary est detruit et le message est remplace. */
app.post('/delete-media', limiter, requireUser, async function (req, res) {
  try {
    const kind = req.body.kind === 'group' ? 'group' : (req.body.kind === 'private' ? 'private' : '');
    const chatId = String(req.body.chatId || '');
    const ids = Array.isArray(req.body.ids) ? req.body.ids.map(String).slice(0, 50) : [];
    if (!kind || !/^[A-Za-z0-9_-]{1,200}$/.test(chatId) || !ids.length || ids.some(function (i) { return !/^[A-Za-z0-9_-]{1,128}$/.test(i); })) {
      return res.status(400).json({ ok: false, error: 'Requete invalide.' });
    }
    let msgs;
    if (kind === 'private') {
      if (chatId.split('_').indexOf(req.uid) === -1) return res.status(403).json({ ok: false, error: 'Action non autorisee.' });
      msgs = db.collection('conversations').doc(chatId).collection('messages');
    } else {
      const g = await db.collection('groups').doc(chatId).get();
      if (!g.exists || (g.data().members || []).indexOf(req.uid) === -1) return res.status(403).json({ ok: false, error: 'Action non autorisee.' });
      msgs = db.collection('groups').doc(chatId).collection('messages');
    }

    let deleted = 0;
    for (const id of ids) {
      const ref = msgs.doc(id);
      const snap = await ref.get();
      if (!snap.exists) continue;
      const m = snap.data();
      if (m.senderId !== req.uid || !m.url) continue; // uniquement ses propres medias
      await destroyMany([m.url]);
      await ref.update({
        type: 'deleted',
        text: 'Media supprime',
        url: admin.firestore.FieldValue.delete(),
        fileName: admin.firestore.FieldValue.delete(),
        size: admin.firestore.FieldValue.delete(),
        deletedAt: admin.firestore.FieldValue.serverTimestamp()
      });
      deleted++;
    }
    return res.json({ ok: true, deleted: deleted });
  } catch (e) {
    console.error('delete-media', e);
    return res.status(500).json({ ok: false, error: 'Suppression impossible pour le moment.' });
  }
});

/* ---------- Suppression du compte (jeton Firebase recent requis) ---------- */
/* POST /delete-account  {}  : efface les donnees et fichiers de l'utilisateur, puis son compte Firebase */
app.post('/delete-account', requireUser, async function (req, res) {
  const uid = req.uid;
  try {
    const authTime = Number(req.decoded.auth_time || 0) * 1000;
    if (Date.now() - authTime > RECENT_LOGIN_MS) {
      return res.status(403).json({ ok: false, error: 'Pour votre securite, reconnectez-vous puis reessayez.' });
    }
    const FV = admin.firestore.FieldValue;
    const MEDIA_GONE = { type: 'deleted', text: 'Media supprime', url: FV.delete(), fileName: FV.delete(), size: FV.delete(), deletedAt: FV.serverTimestamp() };

    // 1. Photo de profil
    const uSnap = await db.collection('users').doc(uid).get();
    if (uSnap.exists) await destroyMany([uSnap.data().photoURL]);

    // 2. Boutique et produits
    const prods = await db.collection('products').where('shopId', '==', uid).get();
    for (const d of prods.docs) { await destroyMany(d.data().photos || []); await db.recursiveDelete(d.ref); }
    const shop = await db.collection('shops').doc(uid).get();
    if (shop.exists) { await destroyMany([shop.data().logoURL, shop.data().coverURL]); await db.recursiveDelete(shop.ref); }

    // 3. Statuts
    const sts = await db.collection('statuses').where('authorId', '==', uid).get();
    for (const d of sts.docs) { await destroyMany([d.data().url]); await db.recursiveDelete(d.ref); }

    // 4. Discussions privees : medias envoyes retires, textes conserves pour l'autre personne
    const convs = await db.collection('conversations').where('members', 'array-contains', uid).get();
    for (const c of convs.docs) {
      const mine = await c.ref.collection('messages').where('senderId', '==', uid).get();
      for (const m of mine.docs) {
        if (m.data().url) { await destroyMany([m.data().url]); await m.ref.update(MEDIA_GONE); }
      }
    }

    // 5. Groupes : retrait du membre, suppression si plus personne
    const groups = await db.collection('groups').where('members', 'array-contains', uid).get();
    for (const g of groups.docs) {
      const data = g.data();
      const members = (data.members || []).filter(function (m) { return m !== uid; });
      if (!members.length) {
        const ms = await g.ref.collection('messages').get();
        await destroyMany([data.photoURL].concat(ms.docs.map(function (m) { return m.data().url; })));
        await db.recursiveDelete(g.ref);
        continue;
      }
      const mine = await g.ref.collection('messages').where('senderId', '==', uid).get();
      for (const m of mine.docs) {
        if (m.data().url) { await destroyMany([m.data().url]); await m.ref.update(MEDIA_GONE); }
      }
      let admins = (data.admins || []).filter(function (a) { return a !== uid; });
      if (!admins.length) admins = [members[0]];
      await g.ref.update({ members: members, admins: admins });
    }

    // 6. Codes en attente puis profil et sous-collections (contacts, panier, jetons, bloques, appareils)
    const codesSnap = await codes.where('uid', '==', uid).get();
    for (const d of codesSnap.docs) await d.ref.delete();
    await db.recursiveDelete(db.collection('users').doc(uid));
    await db.collection('profiles').doc(uid).delete().catch(function () {});

    // 7. Compte Firebase (en dernier : si une etape echoue, l'utilisateur peut recommencer)
    await auth.deleteUser(uid);
    return res.json({ ok: true });
  } catch (e) {
    console.error('delete-account', e);
    return res.status(500).json({ ok: false, error: 'Suppression impossible pour le moment. Reessayez.' });
  }
});

/* ---------- Verification en deux etapes (code par email, jeton Firebase requis) ---------- */
const TF_MODES = ['login', 'enable', 'disable'];

/* POST /2fa/send  { mode: 'login' | 'enable' | 'disable' } */
app.post('/2fa/send', requireUser, async function (req, res) {
  try {
    const mode = String(req.body.mode || '');
    if (TF_MODES.indexOf(mode) === -1) return res.status(400).json({ ok: false, error: 'Requete invalide.' });
    const uSnap = await db.collection('users').doc(req.uid).get();
    const enabled = uSnap.exists && uSnap.data().twoFactor === true;
    if (mode === 'enable' && enabled) return res.status(400).json({ ok: false, error: 'La verification en deux etapes est deja activee.' });
    if (mode !== 'enable' && !enabled) return res.status(400).json({ ok: false, error: 'La verification en deux etapes n\'est pas activee.' });

    const ref = codes.doc(docId(req.uid, '2fa'));
    const snap = await ref.get();
    const now = Date.now();
    if (snap.exists && now - snap.data().sentAt < RESEND_COOLDOWN_MS) {
      const wait = Math.ceil((RESEND_COOLDOWN_MS - (now - snap.data().sentAt)) / 1000);
      return res.status(429).json({ ok: false, error: 'Patientez ' + wait + ' secondes avant de renvoyer le code.' });
    }
    const user = await auth.getUser(req.uid);
    if (!user.email) return res.status(400).json({ ok: false, error: 'Aucune adresse email sur ce compte.' });

    const code = String(crypto.randomInt(100000, 1000000));
    await ref.set({
      purpose: '2fa', uid: req.uid, mode: mode,
      codeHash: hmac('code:' + req.uid + ':2fa:' + mode + ':' + code),
      attempts: 0, sentAt: now, expiresAt: now + CODE_TTL_MS
    });
    await sendCodeEmail(user.email, code, '2fa');
    return res.json({ ok: true });
  } catch (e) {
    console.error('2fa/send', e);
    return res.status(500).json({ ok: false, error: 'Impossible d\'envoyer le code pour le moment.' });
  }
});

/* POST /2fa/verify  { mode, code } */
app.post('/2fa/verify', requireUser, async function (req, res) {
  try {
    const mode = String(req.body.mode || '');
    const code = String(req.body.code || '').trim();
    if (TF_MODES.indexOf(mode) === -1 || !/^\d{6}$/.test(code)) return res.status(400).json({ ok: false, error: 'Code invalide.' });
    const ref = codes.doc(docId(req.uid, '2fa'));
    const snap = await ref.get();
    const bad = { ok: false, error: 'Code incorrect ou expire.' };
    if (!snap.exists) return res.status(400).json(bad);
    const d = snap.data();
    if (d.mode !== mode || Date.now() > d.expiresAt || d.attempts >= MAX_ATTEMPTS) {
      await ref.delete();
      return res.status(400).json(bad);
    }
    if (!safeEqual(hmac('code:' + req.uid + ':2fa:' + mode + ':' + code), d.codeHash)) {
      await ref.update({ attempts: admin.firestore.FieldValue.increment(1) });
      return res.status(400).json(bad);
    }
    await ref.delete();
    if (mode === 'enable') await db.collection('users').doc(req.uid).set({ twoFactor: true }, { merge: true });
    if (mode === 'disable') await db.collection('users').doc(req.uid).set({ twoFactor: false }, { merge: true });
    return res.json({ ok: true, enabled: mode === 'enable' ? true : (mode === 'disable' ? false : true) });
  } catch (e) {
    console.error('2fa/verify', e);
    return res.status(500).json({ ok: false, error: 'Verification impossible pour le moment.' });
  }
});

/* ---------- Recherche d'une personne par son nom ou prenom (jeton Firebase requis) ---------- */
const searchLog = new Map(); // uid -> horodatages des recherches recentes
function foldName(t) {
  return String(t || '').normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase().replace(/[^a-z0-9 ]+/g, ' ').replace(/\s+/g, ' ').trim();
}

/* POST /search-users  { q }  : renvoie au plus 20 personnes { uid, name, photo } */
app.post('/search-users', requireUser, async function (req, res) {
  try {
    const q = foldName(req.body.q).slice(0, 40);
    const tokens = q.split(' ').filter(Boolean).slice(0, 3);
    if (!tokens.length || tokens[0].length < 2) return res.status(400).json({ ok: false, error: 'Saisissez au moins 2 lettres.' });

    const now = Date.now();
    const recent = (searchLog.get(req.uid) || []).filter(function (t) { return now - t < 60000; });
    if (recent.length >= 30) return res.status(429).json({ ok: false, error: 'Trop de recherches. Patientez un instant.' });
    recent.push(now); searchLog.set(req.uid, recent);

    const key = tokens.slice().sort(function (a, b) { return b.length - a.length; })[0].slice(0, 10);
    const snap = await db.collection('users').where('searchKeys', 'array-contains', key).limit(60).get();

    let hits = snap.docs.filter(function (d) {
      if (d.id === req.uid) return false;
      const x = d.data();
      if (x.prefs && x.prefs.findable === false) return false;
      const words = foldName(x.displayName).split(' ');
      return tokens.every(function (t) { return words.some(function (w) { return w.indexOf(t) === 0; }); });
    });
    hits.sort(function (a, b) { return foldName(a.data().displayName).localeCompare(foldName(b.data().displayName)); });
    hits = hits.slice(0, 20);

    const out = await Promise.all(hits.map(async function (d) {
      const x = d.data();
      const ref = db.collection('users').doc(d.id);
      const blocked = await ref.collection('blocked').doc(req.uid).get().then(function (s) { return s.exists; }).catch(function () { return false; });
      if (blocked) return null;
      const vis = (x.prefs && x.prefs.privacy && x.prefs.privacy.photo) || 'Mes contacts';
      let photo = '';
      if (x.photoURL) {
        if (vis === 'Tout le monde') photo = x.photoURL;
        else if (vis === 'Mes contacts') {
          const isContact = await ref.collection('contacts').doc(req.uid).get().then(function (s) { return s.exists; }).catch(function () { return false; });
          if (isContact) photo = x.photoURL;
        }
      }
      return { uid: d.id, name: x.displayName || 'Utilisateur', photo: photo };
    }));
    return res.json({ ok: true, users: out.filter(Boolean) });
  } catch (e) {
    console.error('search-users', e);
    return res.status(500).json({ ok: false, error: 'Recherche impossible pour le moment.' });
  }
});

/* POST /find-user  { email } ou { phoneKey }  : renvoie { uid, name, photo } pour une correspondance exacte (les profils prives ne sont plus lisibles par les autres comptes) */
app.post('/find-user', requireUser, async function (req, res) {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const phoneKey = String(req.body.phoneKey || '').replace(/\D/g, '');
    let field, val;
    if (email) {
      if (email.length > 254 || email.indexOf('@') < 1) return res.status(400).json({ ok: false, error: 'Adresse email invalide.' });
      field = 'emailLower'; val = email;
    } else if (phoneKey) {
      if (phoneKey.length < 7 || phoneKey.length > 15) return res.status(400).json({ ok: false, error: 'Numero invalide.' });
      field = 'phoneKey'; val = phoneKey;
    } else {
      return res.status(400).json({ ok: false, error: 'Requete invalide.' });
    }

    const now = Date.now();
    const recent = (searchLog.get(req.uid) || []).filter(function (t) { return now - t < 60000; });
    if (recent.length >= 30) return res.status(429).json({ ok: false, error: 'Trop de recherches. Patientez un instant.' });
    recent.push(now); searchLog.set(req.uid, recent);

    const snap = await db.collection('users').where(field, '==', val).limit(1).get();
    if (snap.empty) return res.json({ ok: true, uid: null });
    const d = snap.docs[0];
    if (d.id === req.uid) return res.json({ ok: true, uid: d.id, name: '', photo: '' });
    const x = d.data();
    const ref = db.collection('users').doc(d.id);
    const blocked = await ref.collection('blocked').doc(req.uid).get().then(function (s2) { return s2.exists; }).catch(function () { return false; });
    if (blocked) return res.json({ ok: true, uid: null });
    const vis = (x.prefs && x.prefs.privacy && x.prefs.privacy.photo) || 'Mes contacts';
    let photo = '';
    if (x.photoURL) {
      if (vis === 'Tout le monde') photo = x.photoURL;
      else if (vis === 'Mes contacts') {
        const isContact = await ref.collection('contacts').doc(req.uid).get().then(function (s2) { return s2.exists; }).catch(function () { return false; });
        if (isContact) photo = x.photoURL;
      }
    }
    return res.json({ ok: true, uid: d.id, name: x.displayName || 'Utilisateur', photo: photo });
  } catch (e) {
    console.error('find-user', e);
    return res.status(500).json({ ok: false, error: 'Recherche impossible pour le moment.' });
  }
});

/* ---------- Support : message envoye par email a l'equipe (jeton Firebase requis) ---------- */
const supportLog = new Map(); // uid -> horodatages des envois recents
function escHtml(t) {
  return String(t).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

/* POST /support  { kind: 'question'|'bug', subject, message, context } */
app.post('/support', requireUser, async function (req, res) {
  try {
    const kind = req.body.kind === 'bug' ? 'bug' : 'question';
    const subject = String(req.body.subject || '').trim().slice(0, 100);
    const message = String(req.body.message || '').trim();
    const context = String(req.body.context || '').trim().slice(0, 300);
    if (message.length < 10) return res.status(400).json({ ok: false, error: 'Decrivez votre demande en 10 caracteres minimum.' });
    if (message.length > 2000) return res.status(400).json({ ok: false, error: 'Message trop long (2000 caracteres maximum).' });

    const now = Date.now();
    const recent = (supportLog.get(req.uid) || []).filter(function (t) { return now - t < 3600000; });
    if (recent.length && now - recent[recent.length - 1] < 60000) {
      return res.status(429).json({ ok: false, error: 'Patientez une minute avant un nouvel envoi.' });
    }
    if (recent.length >= 3) {
      return res.status(429).json({ ok: false, error: 'Limite atteinte : 3 messages par heure.' });
    }

    const user = await auth.getUser(req.uid);
    const profSnap = await db.collection('users').doc(req.uid).get();
    const prof = profSnap.exists ? profSnap.data() : {};
    const name = prof.displayName || user.displayName || 'Utilisateur';
    const label = kind === 'bug' ? 'Probleme signale' : 'Question';
    const mailSubject = '[NexChat ' + label + '] ' + (subject || message.slice(0, 60));

    const html =
      '<div style="font-family:Arial,Helvetica,sans-serif;font-size:14px;color:#0b1b4d;line-height:1.6;">' +
      '<p><strong>' + label + '</strong> de ' + escHtml(name) + ' (' + escHtml(user.email || '') + ')</p>' +
      (subject ? '<p><strong>Objet :</strong> ' + escHtml(subject) + '</p>' : '') +
      '<p style="white-space:pre-wrap;background:#f4f7fc;border-radius:10px;padding:14px;">' + escHtml(message) + '</p>' +
      '<p style="font-size:12px;color:#7a86a8;">Compte : ' + escHtml(req.uid) + '<br>Contexte : ' + escHtml(context || 'n/a') + '</p>' +
      '</div>';

    const r = await fetch('https://api.brevo.com/v3/smtp/email', {
      method: 'POST',
      headers: { 'accept': 'application/json', 'content-type': 'application/json', 'api-key': BREVO_API_KEY },
      body: JSON.stringify({
        sender: { name: SENDER_NAME, email: SENDER_EMAIL },
        to: [{ email: SUPPORT_EMAIL }],
        replyTo: user.email ? { email: user.email, name: name } : undefined,
        subject: mailSubject,
        htmlContent: html
      })
    });
    if (!r.ok) {
      const detail = await r.text().catch(function () { return ''; });
      throw new Error('Brevo ' + r.status + ' ' + detail.slice(0, 200));
    }

    recent.push(now);
    supportLog.set(req.uid, recent);
    // Copie de suivi (collection non listee dans les regles : accessible uniquement par le serveur)
    await db.collection('supportTickets').add({
      uid: req.uid, kind: kind, subject: subject, message: message, context: context,
      email: user.email || '', createdAt: admin.firestore.FieldValue.serverTimestamp()
    }).catch(function (e) { console.error('supportTickets', e); });
    return res.json({ ok: true });
  } catch (e) {
    console.error('support', e);
    return res.status(500).json({ ok: false, error: 'Envoi impossible pour le moment. Reessayez plus tard.' });
  }
});

/* ---------- Notifications push (Firebase Cloud Messaging) ---------- */
const notifyLimiter = rateLimit({
  windowMs: 60 * 1000, limit: 90, standardHeaders: true, legacyHeaders: false,
  keyGenerator: function (req) { return 'u:' + req.uid; },
  validate: { keyGeneratorIpFallback: false },
  message: { ok: false, error: 'Trop de notifications.' }
});

async function displayName(uid) {
  const sn = await db.collection('users').doc(uid).get();
  const d = sn.exists ? sn.data() : {};
  return d.displayName || ((d.firstName || '') + ' ' + (d.lastName || '')).trim() || 'NexChat';
}

async function pushTo(uids, msg) {
  const entries = [];
  for (const u of uids) {
    const sn = await db.collection('users').doc(u).collection('tokens').get();
    sn.forEach(function (d) { if (d.data().token) entries.push({ ref: d.ref, token: d.data().token }); });
  }
  if (!entries.length) return 0;
  const res = await admin.messaging().sendEachForMulticast({
    tokens: entries.map(function (e) { return e.token; }),
    notification: { title: msg.title, body: msg.body },
    data: msg.data || {},
    webpush: {
      fcmOptions: { link: msg.link || APP_URL },
      notification: Object.assign({ icon: APP_URL + 'icon-192.png', tag: msg.tag || 'nexchat' },
        msg.ring ? { requireInteraction: true, renotify: true, vibrate: [400, 200, 400, 200, 400, 200, 400],
          actions: [{ action: 'answer', title: 'Répondre' }, { action: 'ignore', title: 'Ignorer' }] } : {},
        msg.renotify ? { renotify: true } : {}),
      headers: { Urgency: msg.urgent ? 'high' : 'normal', TTL: msg.ring ? '30' : (msg.urgent ? '60' : '86400') }
    }
  });
  res.responses.forEach(function (r, i) {
    if (!r.success && r.error && /registration-token-not-registered|invalid-registration-token|invalid-argument/.test(r.error.code || '')) {
      entries[i].ref.delete().catch(function () {});
    }
  });
  return res.successCount;
}

/* Retire les destinataires qui ont bloque l'expediteur */
async function dropBlockers(uids, senderUid) {
  const flags = await Promise.all(uids.map(function (u) {
    return db.collection('users').doc(u).collection('blocked').doc(senderUid).get()
      .then(function (d) { return d.exists; }).catch(function () { return false; });
  }));
  return uids.filter(function (u, i) { return !flags[i]; });
}

/* ---------- Centre de notifications : collection ecrite uniquement par ce serveur ----------
   users/{uid}/notifications/{id} : les regles Firestore interdisent toute ecriture cote appli,
   le SDK admin (ce fichier) est le seul a creer ou modifier ces documents. */
const NOTIF_MAX = 100; // notifications gardees par personne (nettoyage de temps en temps)

async function writeNotif(uid, id, data, grouped) {
  const ref = db.collection('users').doc(uid).collection('notifications').doc(id);
  await db.runTransaction(async function (tx) {
    const snap = await tx.get(ref);
    const prev = snap.exists ? snap.data() : null;
    // Un message de plus dans une discussion non lue : on regroupe au lieu d'empiler
    const count = grouped && prev && prev.read === false ? (prev.count || 1) + 1 : 1;
    tx.set(ref, Object.assign({}, data, {
      read: false,
      count: count,
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    }));
  });
}

async function pruneNotifs(uid) {
  const old = await db.collection('users').doc(uid).collection('notifications')
    .orderBy('createdAt', 'desc').offset(NOTIF_MAX).limit(50).get();
  if (old.empty) return;
  const batch = db.batch();
  old.docs.forEach(function (d) { batch.delete(d.ref); });
  await batch.commit();
}

async function saveNotifs(uids, nf) {
  await Promise.all(uids.map(async function (u) {
    try {
      await writeNotif(u, nf.id, nf.data, nf.grouped);
      if (Math.random() < 0.1) pruneNotifs(u).catch(function () {}); // 1 fois sur 10 : limite le cout des lectures
    } catch (e) { console.error('notif', e.message); }
  }));
}

const ORDER_TEXT = { processing: 'a été acceptée', delivered: 'a été livrée', cancelled: 'a été annulée' };
function clip(v, n) { return String(v || '').slice(0, n); }

/* POST /notify  { kind: 'message'|'group'|'call'|'missedCall'|'order'|'orderStatus'|'joinRequest'|'joinDecision', ... }  (jeton Firebase requis) */
app.post('/notify', requireUser, notifyLimiter, async function (req, res) {
  try {
    const b = req.body || {}, uid = req.uid;
    const name = await displayName(uid);
    let uids = [], msg = null, nf = null;

    if (b.kind === 'message') {
      const parts = String(b.cid || '').split('_');
      if (parts.length !== 2 || parts.indexOf(uid) === -1) return res.status(403).json({ ok: false });
      uids = parts.filter(function (x) { return x !== uid; });
      msg = { title: name, body: clip(b.text, 140) || 'Nouveau message', tag: 'msg-' + b.cid, data: { type: 'message', cid: String(b.cid) }, link: APP_URL + '?open=message:' + encodeURIComponent(String(b.cid)) };
      nf = { id: 'msg_' + String(b.cid), grouped: true, data: { type: 'message', title: name, body: msg.body, fromUid: uid, fromName: name, cid: String(b.cid) } };
    } else if (b.kind === 'group') {
      const g = await db.collection('groups').doc(String(b.gid || '_')).get();
      if (!g.exists || g.data().members.indexOf(uid) === -1) return res.status(403).json({ ok: false });
      uids = g.data().members.filter(function (x) { return x !== uid; });
      msg = { title: g.data().name, body: name + ' : ' + (clip(b.text, 120) || 'Nouveau message'), tag: 'grp-' + g.id, data: { type: 'group', gid: String(g.id) }, link: APP_URL + '?open=group:' + encodeURIComponent(String(g.id)) };
      nf = { id: 'grp_' + g.id, grouped: true, data: { type: 'group', title: g.data().name, body: msg.body, fromUid: uid, fromName: name, gid: String(g.id), groupName: g.data().name } };
    } else if (b.kind === 'call') {
      const c = await db.collection('calls').doc(String(b.callId || '_')).get();
      if (!c.exists || c.data().callerId !== uid) return res.status(403).json({ ok: false });
      const d = c.data();
      uids = d.members.filter(function (x) { return x !== uid; });
      msg = { title: 'Appel ' + (d.video ? 'vidéo' : 'audio') + ' entrant', body: d.type === 'group' ? (d.groupName + ' · ' + name) : name, tag: 'call-' + c.id, urgent: true, ring: true, data: { type: 'call', callId: String(c.id) }, link: APP_URL + '?open=call:' + encodeURIComponent(String(c.id)) };
    } else if (b.kind === 'missedCall') {
      const c = await db.collection('calls').doc(String(b.callId || '_')).get();
      if (!c.exists || c.data().callerId !== uid) return res.status(403).json({ ok: false });
      const d = c.data();
      const joined = d.participants || [];
      uids = d.members.filter(function (x) { return x !== uid && joined.indexOf(x) === -1; });
      const grp = d.type === 'group';
      const cid = [uid, uids[0] || ''].sort().join('_');
      msg = { title: 'Appel manqué', body: grp ? (d.groupName + ' · ' + name) : name, tag: 'call-' + c.id, renotify: true,
        data: grp ? { type: 'group', gid: String(d.groupId || '') } : { type: 'message', cid: cid },
        link: grp ? (APP_URL + '?open=group:' + encodeURIComponent(String(d.groupId || ''))) : (APP_URL + '?open=message:' + encodeURIComponent(cid)) };
      nf = { id: 'call_' + c.id, grouped: false, data: Object.assign(
        { type: 'missedCall', title: 'Appel manqué', body: msg.body, fromUid: uid, fromName: name },
        grp ? { gid: String(d.groupId || ''), groupName: d.groupName || '' } : { cid: cid }) };
    } else if (b.kind === 'order') {
      const o = await db.collection('orders').doc(String(b.orderId || '_')).get();
      if (!o.exists || o.data().buyerId !== uid) return res.status(403).json({ ok: false });
      const d = o.data();
      uids = [d.sellerId];
      msg = { title: 'Nouvelle commande ' + d.ref, body: name + ' · ' + Number(d.total).toLocaleString('fr-FR') + ' FCFA', tag: 'ord-' + o.id, data: { type: 'order' } };
      nf = { id: 'ord_' + o.id, grouped: false, data: { type: 'order', title: msg.title, body: msg.body, fromUid: uid, fromName: name, orderId: o.id } };
    } else if (b.kind === 'orderStatus') {
      const o = await db.collection('orders').doc(String(b.orderId || '_')).get();
      if (!o.exists || o.data().sellerId !== uid || !ORDER_TEXT[o.data().status]) return res.status(403).json({ ok: false });
      const d = o.data();
      uids = [d.buyerId];
      msg = { title: d.shopName || 'Boutique', body: 'Votre commande ' + d.ref + ' ' + ORDER_TEXT[d.status] + '.', tag: 'ord-' + o.id, data: { type: 'orderStatus' } };
      nf = { id: 'ord_' + o.id + '_' + d.status, grouped: false, data: { type: 'orderStatus', title: msg.title, body: msg.body, fromUid: uid, fromName: name, orderId: o.id } };
    } else if (b.kind === 'joinRequest') {
      // Demande d'adhesion par lien : prevenir les administrateurs du groupe
      const gid = String(b.gid || '_');
      const g = await db.collection('groups').doc(gid).get();
      if (!g.exists || g.data().members.indexOf(uid) !== -1) return res.status(403).json({ ok: false });
      const rq = await db.collection('groups').doc(gid).collection('joinRequests').doc(uid).get();
      if (!rq.exists || rq.data().status !== 'pending') return res.status(403).json({ ok: false });
      uids = (g.data().admins || []).slice();
      msg = { title: g.data().name, body: name + ' demande à rejoindre le groupe', tag: 'join-' + gid, renotify: true, data: { type: 'group', gid: gid }, link: APP_URL + '?open=group:' + encodeURIComponent(gid) };
      nf = { id: 'join_' + gid + '_' + uid, grouped: false, data: { type: 'joinRequest', title: g.data().name, body: msg.body, fromUid: uid, fromName: name, gid: gid, groupName: g.data().name } };
    } else if (b.kind === 'joinDecision') {
      // Reponse d'un administrateur : prevenir la personne (acceptee ou refusee)
      const gid = String(b.gid || '_'), target = String(b.target || '');
      const g = await db.collection('groups').doc(gid).get();
      if (!g.exists || (g.data().admins || []).indexOf(uid) === -1 || !target) return res.status(403).json({ ok: false });
      const accepted = b.accepted === true;
      if (accepted) {
        if (g.data().members.indexOf(target) === -1 || !(g.data().joinedAt || {})[target]) return res.status(403).json({ ok: false });
      } else {
        const rq = await db.collection('groups').doc(gid).collection('joinRequests').doc(target).get();
        if (!rq.exists || rq.data().status !== 'refused') return res.status(403).json({ ok: false });
      }
      uids = [target];
      msg = accepted
        ? { title: g.data().name, body: 'Votre demande a été acceptée. Vous pouvez rejoindre la conversation.', tag: 'join-' + gid, data: { type: 'group', gid: gid }, link: APP_URL + '?open=group:' + encodeURIComponent(gid) }
        : { title: g.data().name, body: 'Votre demande pour rejoindre le groupe a été refusée.', tag: 'join-' + gid, data: { type: 'joinDecision' } };
      nf = { id: 'joind_' + gid + '_' + target, grouped: false, data: { type: 'joinDecision', title: msg.title, body: msg.body, fromUid: uid, fromName: name, gid: accepted ? gid : '', groupName: g.data().name, accepted: accepted } };
    } else {
      return res.status(400).json({ ok: false, error: 'Requete invalide.' });
    }

    if (uids.length) uids = await dropBlockers(uids, uid);
    // Appel entrant : sonnerie uniquement, aucune trace dans la liste (seul l'appel manque y apparait)
    if (nf && uids.length) await saveNotifs(uids, nf);
    const sent = uids.length ? await pushTo(uids, msg) : 0;
    return res.json({ ok: true, sent: sent });
  } catch (e) {
    console.error('notify', e);
    return res.status(500).json({ ok: false });
  }
});

/* POST /notifications/read  { ids: [...] } ou { all: true }  (jeton Firebase requis)
   L'appli ne peut pas ecrire dans la collection : le marquage « lu » passe aussi par le serveur. */
app.post('/notifications/read', requireUser, notifyLimiter, async function (req, res) {
  try {
    const col = db.collection('users').doc(req.uid).collection('notifications');
    let docs = [];
    if (req.body && req.body.all === true) {
      docs = (await col.where('read', '==', false).limit(200).get()).docs;
    } else {
      const ids = Array.isArray(req.body && req.body.ids)
        ? req.body.ids.map(String).filter(function (i) { return /^[A-Za-z0-9_-]{1,160}$/.test(i); }).slice(0, 50) : [];
      if (!ids.length) return res.status(400).json({ ok: false, error: 'Requete invalide.' });
      const snaps = await Promise.all(ids.map(function (i) { return col.doc(i).get(); }));
      docs = snaps.filter(function (sn) { return sn.exists && sn.data().read === false; });
    }
    if (docs.length) {
      const batch = db.batch();
      docs.forEach(function (d) { batch.update(d.ref, { read: true }); });
      await batch.commit();
    }
    return res.json({ ok: true, updated: docs.length });
  } catch (e) {
    console.error('notifications/read', e);
    return res.status(500).json({ ok: false });
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

/* ---------- Migration : copie des profils existants vers la collection publique profiles (une fois par demarrage) ---------- */
async function migrateProfiles() {
  if (String(process.env.MIGRATE_PROFILES || 'on').toLowerCase() === 'off') return;
  try {
    let last = null, created = 0, scanned = 0;
    for (;;) {
      let q = db.collection('users').orderBy(admin.firestore.FieldPath.documentId()).limit(300);
      if (last) q = q.startAfter(last);
      const snap = await q.get();
      if (snap.empty) break;
      const refs = snap.docs.map(function (d) { return db.collection('profiles').doc(d.id); });
      const existing = await db.getAll.apply(db, refs);
      const batch = db.batch();
      snap.docs.forEach(function (d, i) {
        scanned++;
        if (existing[i].exists) return;
        const x = d.data();
        const pr = x.prefs || {};
        batch.set(refs[i], {
          uid: d.id,
          firstName: x.firstName || '',
          lastName: x.lastName || '',
          displayName: x.displayName || ((x.firstName || '') + ' ' + (x.lastName || '')).trim() || 'Utilisateur',
          photoURL: x.photoURL || '',
          about: String(x.about || '').slice(0, 120),
          lastSeenAt: x.lastSeenAt || 0,
          prefs: { privacy: pr.privacy || {}, readReceipts: pr.readReceipts !== false }
        });
        created++;
      });
      if (created) await batch.commit();
      last = snap.docs[snap.docs.length - 1];
      if (snap.size < 300) break;
    }
    console.log('migrateProfiles : ' + scanned + ' comptes verifies, ' + created + ' profils crees');
  } catch (e) {
    console.error('migrateProfiles', e);
  }
}

app.listen(PORT, function () { console.log('NexChat backend sur le port ' + PORT); migrateProfiles(); });
