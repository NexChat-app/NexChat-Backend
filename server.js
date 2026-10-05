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
    if (req.body.kind === 'profile') await db.collection('profiles').doc(req.uid).collection('shared').doc('photo').set({ photoURL: next }, { merge: true });

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
    await db.recursiveDelete(db.collection('profiles').doc(uid)).catch(function () {});

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

/* ---------- Suivi de la consommation LiveKit (minutes-participant du mois) ----------
   L'appli declare la duree de chaque participation a un appel de groupe ; le serveur additionne par mois dans meta/usage_AAAA-MM
   et previent l'equipe par email a 80 % puis 100 % du quota (LIVEKIT_MONTHLY_QUOTA, 5000 par defaut = offre gratuite). */
function monthKey(d) { const x = d || new Date(); return x.getUTCFullYear() + '-' + String(x.getUTCMonth() + 1).padStart(2, '0'); }
function sendTeamMail(subject, html) {
  return fetch('https://api.brevo.com/v3/smtp/email', {
    method: 'POST',
    headers: { 'accept': 'application/json', 'content-type': 'application/json', 'api-key': BREVO_API_KEY },
    body: JSON.stringify({ sender: { name: SENDER_NAME, email: SENDER_EMAIL }, to: [{ email: SUPPORT_EMAIL }], subject: subject, htmlContent: html })
  }).catch(function () {});
}
app.post('/call-usage', requireUser, async function (req, res) {
  try {
    const callId = String(req.body.callId || '');
    const seconds = Math.floor(Number(req.body.seconds));
    if (!/^[A-Za-z0-9_-]{10,40}$/.test(callId) || !(seconds >= 1)) return res.status(400).json({ ok: false });
    if (!limitReview(req.uid, 20)) return res.status(429).json({ ok: false });
    const minutes = Math.min(Math.ceil(seconds / 60), 360);
    const FV = admin.firestore.FieldValue;
    const call = await db.collection('calls').doc(callId).get();
    if (call.exists && (call.data().type !== 'group' || (call.data().members || []).indexOf(req.uid) === -1)) return res.json({ ok: true });
    const once = db.collection('usage').doc(callId + '_' + req.uid);
    const mref = db.collection('meta').doc('usage_' + monthKey());
    const quota = Number(process.env.LIVEKIT_MONTHLY_QUOTA) || 5000;
    const out = await db.runTransaction(async function (tx) {
      const [o, m] = await Promise.all([tx.get(once), tx.get(mref)]);
      if (o.exists) return null;
      const before = m.exists ? Number(m.data().livekitMinutes) || 0 : 0, after = before + minutes;
      const patch = { livekitMinutes: after, updatedAt: FV.serverTimestamp() };
      const a80 = !(m.exists && m.data().alert80) && after >= quota * 0.8;
      const a100 = !(m.exists && m.data().alert100) && after >= quota;
      if (a80) patch.alert80 = true;
      if (a100) patch.alert100 = true;
      tx.set(once, { minutes: minutes, at: FV.serverTimestamp() });
      tx.set(mref, patch, { merge: true });
      return { after: after, a80: a80, a100: a100 };
    });
    if (out && (out.a80 || out.a100)) {
      sendTeamMail('[NexChat] Quota LiveKit : ' + Math.round(out.after / quota * 100) + ' % utilise ce mois',
        '<div style="font-family:Arial,sans-serif;font-size:14px;color:#0b1b4d;"><p>Les appels de groupe ont consomme <strong>' + out.after + ' minutes-participant</strong> sur ' + quota + ' ce mois (' + monthKey() + ').</p>' +
        '<p>' + (out.a100 ? 'Le quota est atteint : les nouveaux appels de groupe peuvent echouer jusqu\'au mois prochain, sauf passage a une offre payante.' : 'Pensez a surveiller le tableau de bord LiveKit ou a passer a une offre superieure.') + '</p></div>');
    }
    return res.json({ ok: true });
  } catch (e) {
    console.error('call-usage', e);
    return res.status(500).json({ ok: false });
  }
});

/* GET /admin/usage : consommation du mois (en-tete x-admin-key = ADMIN_KEY) */
app.get('/admin/usage', async function (req, res) {
  try {
    const key = String(process.env.ADMIN_KEY || ''), given = String(req.headers['x-admin-key'] || '');
    if (!key || given.length !== key.length || !crypto.timingSafeEqual(Buffer.from(given), Buffer.from(key))) return res.status(403).json({ ok: false });
    const quota = Number(process.env.LIVEKIT_MONTHLY_QUOTA) || 5000;
    const m = await db.collection('meta').doc('usage_' + monthKey()).get();
    const used = m.exists ? Number(m.data().livekitMinutes) || 0 : 0;
    return res.json({ ok: true, month: monthKey(), livekitMinutes: used, quota: quota, percent: Math.round(used / quota * 100) });
  } catch (e) {
    return res.status(500).json({ ok: false });
  }
});

/* ---------- Appels de groupe : jeton d'acces LiveKit (serveur media SFU) ----------
   Variables Render : LIVEKIT_URL (wss://...livekit.cloud), LIVEKIT_API_KEY, LIVEKIT_API_SECRET.
   Le jeton est un JWT HS256 signe ici ; le secret ne quitte jamais le serveur. */
function b64url(buf) { return Buffer.from(buf).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_'); }
function makeLiveKitToken(apiKey, apiSecret, identity, name, room, ttlSeconds) {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: 'HS256', typ: 'JWT' };
  const payload = {
    iss: apiKey, sub: identity, name: name, jti: identity,
    nbf: now - 10, exp: now + ttlSeconds,
    video: { room: room, roomJoin: true, canPublish: true, canSubscribe: true, canPublishData: false }
  };
  const input = b64url(JSON.stringify(header)) + '.' + b64url(JSON.stringify(payload));
  const sig = crypto.createHmac('sha256', apiSecret).update(input).digest();
  return input + '.' + b64url(sig);
}
const livekitLog = new Map();
/* POST /livekit-token  { callId }  : renvoie { token, url } si le compte est membre d'un appel de groupe en cours */
app.post('/livekit-token', requireUser, async function (req, res) {
  try {
    const url = String(process.env.LIVEKIT_URL || '');
    const key = String(process.env.LIVEKIT_API_KEY || '');
    const secret = String(process.env.LIVEKIT_API_SECRET || '');
    if (!url || !key || !secret) return res.status(503).json({ ok: false, error: 'Appels de groupe non configures sur le serveur.' });

    const callId = String(req.body.callId || '');
    if (!/^[A-Za-z0-9_-]{10,40}$/.test(callId)) return res.status(400).json({ ok: false, error: 'Requete invalide.' });

    const now = Date.now();
    const recent = (livekitLog.get(req.uid) || []).filter(function (t) { return now - t < 60000; });
    if (recent.length >= 20) return res.status(429).json({ ok: false, error: 'Trop de tentatives. Patientez un instant.' });
    recent.push(now); livekitLog.set(req.uid, recent);

    const snap = await db.collection('calls').doc(callId).get();
    if (!snap.exists) return res.status(404).json({ ok: false, error: 'Appel introuvable.' });
    const c = snap.data();
    if (c.type !== 'group' || c.status === 'ended') return res.status(403).json({ ok: false, error: 'Appel indisponible.' });
    if (!Array.isArray(c.members) || c.members.indexOf(req.uid) === -1) return res.status(403).json({ ok: false, error: 'Vous ne faites pas partie de cet appel.' });
    if (!c.groupId) return res.status(403).json({ ok: false, error: 'Appel indisponible.' });
    const grp = await db.collection('groups').doc(String(c.groupId)).get();
    if (!grp.exists || !Array.isArray(grp.data().members) || grp.data().members.indexOf(req.uid) === -1) {
      return res.status(403).json({ ok: false, error: 'Vous ne faites plus partie de ce groupe.' });
    }
    const bl = await db.collection('users').doc(c.callerId).collection('blocked').doc(req.uid).get().then(function (s2) { return s2.exists; }).catch(function () { return false; });
    if (bl) return res.status(403).json({ ok: false, error: 'Appel indisponible.' });

    let name = 'Participant';
    try { const u = await db.collection('profiles').doc(req.uid).get(); if (u.exists && u.data().displayName) name = String(u.data().displayName).slice(0, 80); } catch (e) { /* nom facultatif */ }

    const token = makeLiveKitToken(key, secret, req.uid, name, callId, 2 * 60 * 60);
    return res.json({ ok: true, token: token, url: url });
  } catch (e) {
    console.error('livekit-token', e);
    return res.status(500).json({ ok: false, error: 'Connexion a l\'appel impossible pour le moment.' });
  }
});

/* POST /call-decline  { callId, uid, token }  : bouton "Ignorer" de la notification d'appel prive.
   Le service worker n'a pas de session : le jeton (HMAC par appel et par destinataire) joint a la notification fait office de preuve. */
const declineLimiter = rateLimit({ windowMs: 60 * 1000, limit: 30, standardHeaders: true, legacyHeaders: false,
  message: { ok: false, error: 'Trop de requetes.' } });
app.post('/call-decline', declineLimiter, async function (req, res) {
  try {
    const callId = String(req.body.callId || ''), uid = String(req.body.uid || ''), token = String(req.body.token || '');
    if (!/^[A-Za-z0-9_-]{10,40}$/.test(callId) || !/^[A-Za-z0-9_-]{6,128}$/.test(uid) || !/^[0-9a-f]{64}$/.test(token)) {
      return res.status(400).json({ ok: false });
    }
    if (!safeEqual(token, hmac('decline:' + callId + ':' + uid))) return res.status(403).json({ ok: false });
    const ref = db.collection('calls').doc(callId);
    const snap = await ref.get();
    if (!snap.exists) return res.json({ ok: true });
    const c = snap.data();
    if (c.status === 'ended' || c.callerId === uid || !Array.isArray(c.members) || c.members.indexOf(uid) === -1) return res.json({ ok: true });
    if ((c.participants || []).indexOf(uid) !== -1) return res.json({ ok: true });
    if (c.type === 'private') {
      if (c.status !== 'ringing') return res.json({ ok: true });
      await ref.update({ status: 'ended', endedAt: admin.firestore.FieldValue.serverTimestamp() });
    } else {
      // appel de groupe : l'appelant voit qui a refuse, l'appel continue pour les autres
      await ref.update({ declined: admin.firestore.FieldValue.arrayUnion(uid) });
    }
    return res.json({ ok: true });
  } catch (e) {
    console.error('call-decline', e);
    return res.status(500).json({ ok: false });
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
  for (let i = 0; i < uids.length; i += 25) {
    const slice = uids.slice(i, i + 25);
    const part = await Promise.all(slice.map(function (u) {
      return db.collection('users').doc(u).collection('tokens').get().catch(function () { return null; });
    }));
    part.forEach(function (sn, k) {
      if (!sn) return;
      sn.forEach(function (d) { if (d.data().token) entries.push({ ref: d.ref, token: d.data().token, uid: slice[k] }); });
    });
  }
  if (!entries.length) return 0;
  const webpush = {
    fcmOptions: { link: msg.link || APP_URL },
    notification: Object.assign({ icon: APP_URL + 'icon-192.png', tag: msg.tag || 'nexchat' },
      msg.ring ? { requireInteraction: true, renotify: true, vibrate: [400, 200, 400, 200, 400, 200, 400],
        actions: [{ action: 'answer', title: 'Répondre' }, { action: 'ignore', title: 'Ignorer' }] } : {},
      msg.renotify ? { renotify: true } : {}),
    headers: { Urgency: msg.urgent ? 'high' : 'normal', TTL: msg.ring ? '30' : (msg.urgent ? '60' : '86400') }
  };
  let ok = 0;
  for (let i = 0; i < entries.length; i += 500) {
    const chunk = entries.slice(i, i + 500);
    let responses;
    if (typeof msg.dataFor === 'function') {
      // donnees propres a chaque destinataire (ex. jeton de refus d'un appel de groupe)
      const res = await admin.messaging().sendEach(chunk.map(function (e) {
        return { token: e.token, notification: { title: msg.title, body: msg.body }, data: msg.dataFor(e.uid), webpush: webpush };
      }));
      ok += res.successCount; responses = res.responses;
    } else {
      const res = await admin.messaging().sendEachForMulticast({
        tokens: chunk.map(function (e) { return e.token; }),
        notification: { title: msg.title, body: msg.body }, data: msg.data || {}, webpush: webpush
      });
      ok += res.successCount; responses = res.responses;
    }
    responses.forEach(function (r, j) {
      if (!r.success && r.error && /registration-token-not-registered|invalid-registration-token|invalid-argument/.test(r.error.code || '')) {
        chunk[j].ref.delete().catch(function () {});
      }
    });
  }
  return ok;
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
      msg = { title: 'Appel ' + (d.video ? 'vidéo' : 'audio') + ' entrant', body: d.type === 'group' ? (d.groupName + ' · ' + name) : name, tag: 'call-' + c.id, urgent: true, ring: true, dataFor: function (u) { return { type: 'call', callId: String(c.id), uid: u, dt: hmac('decline:' + c.id + ':' + u) }; },
        link: APP_URL + '?open=call:' + encodeURIComponent(String(c.id)) };
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
    } else if (b.kind === 'orderCancelled') {
      const o = await db.collection('orders').doc(String(b.orderId || '_')).get();
      if (!o.exists || o.data().buyerId !== uid || o.data().status !== 'cancelled' || o.data().cancelledBy !== 'buyer') return res.status(403).json({ ok: false });
      const d = o.data();
      uids = [d.sellerId];
      msg = { title: 'Commande ' + d.ref + ' annulée', body: name + ' a annulé sa commande.', tag: 'ord-' + o.id, data: { type: 'order' } };
      nf = { id: 'ord_' + o.id + '_cancelled', grouped: false, data: { type: 'order', title: msg.title, body: msg.body, fromUid: uid, fromName: name, orderId: o.id } };
    } else if (b.kind === 'orderCancelRequest') {
      const o = await db.collection('orders').doc(String(b.orderId || '_')).get();
      if (!o.exists || o.data().buyerId !== uid || !o.data().cancelRequest || o.data().status !== 'processing') return res.status(403).json({ ok: false });
      const d = o.data();
      uids = [d.sellerId];
      msg = { title: b.remind ? 'Rappel : annulation demandée' : 'Annulation demandée', body: name + (b.remind ? ' attend votre réponse pour l\'annulation de la commande ' : ' demande l\'annulation de la commande ') + d.ref + '.', tag: 'ord-' + o.id, data: { type: 'order' } };
      nf = { id: 'ord_' + o.id + (b.remind ? '_cancelremind' : '_cancelreq'), grouped: false, data: { type: 'order', title: msg.title, body: msg.body, fromUid: uid, fromName: name, orderId: o.id } };
    } else if (b.kind === 'orderCancelDeclined') {
      const o = await db.collection('orders').doc(String(b.orderId || '_')).get();
      if (!o.exists || o.data().sellerId !== uid || !o.data().cancelDeclinedAt) return res.status(403).json({ ok: false });
      const d = o.data();
      uids = [d.buyerId];
      msg = { title: d.shopName || 'Boutique', body: 'Votre demande d\'annulation de la commande ' + d.ref + ' a été refusée.', tag: 'ord-' + o.id, data: { type: 'orderStatus' } };
      nf = { id: 'ord_' + o.id + '_canceldeclined', grouped: false, data: { type: 'orderStatus', title: msg.title, body: msg.body, fromUid: uid, fromName: name, orderId: o.id } };
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

/* ---------- Profils publics : profiles/{uid} (nom, confidentialite) + profiles/{uid}/shared/{photo|about|presence} ---------- */
const PROFILES_VERSION = 2;
async function writePublicProfile(uid, x, withPresence) {
  const FV = admin.firestore.FieldValue;
  const pr = x.prefs || {};
  const base = db.collection('profiles').doc(uid);
  await base.set({
    uid: uid,
    firstName: x.firstName || '',
    lastName: x.lastName || '',
    displayName: x.displayName || ((x.firstName || '') + ' ' + (x.lastName || '')).trim() || 'Utilisateur',
    prefs: { privacy: pr.privacy || {}, readReceipts: pr.readReceipts !== false },
    // anciens champs d'une version precedente : retires du document lisible par tous
    photoURL: FV.delete(), about: FV.delete(), online: FV.delete(), lastSeenAt: FV.delete()
  }, { merge: true });
  await base.collection('shared').doc('photo').set({ photoURL: x.photoURL || '' }, { merge: true });
  await base.collection('shared').doc('about').set({ about: String(x.about || '').slice(0, 120) }, { merge: true });
  if (withPresence) await base.collection('shared').doc('presence').set({ lastSeenAt: x.lastSeenAt || 0 }, { merge: true });
}

/* POST /ensure-profile  { uid }  : cree le profil public d'un compte qui n'en a pas encore (anciens comptes, migration interrompue) */
const ensureLog = new Map();
app.post('/ensure-profile', requireUser, async function (req, res) {
  try {
    const uid = String(req.body.uid || '');
    if (!/^[A-Za-z0-9_-]{6,128}$/.test(uid)) return res.status(400).json({ ok: false, error: 'Requete invalide.' });
    const now = Date.now();
    const recent = (ensureLog.get(req.uid) || []).filter(function (t) { return now - t < 60000; });
    if (recent.length >= 60) return res.status(429).json({ ok: false, error: 'Trop de demandes.' });
    recent.push(now); ensureLog.set(req.uid, recent);

    const pSnap = await db.collection('profiles').doc(uid).get();
    if (pSnap.exists) return res.json({ ok: true, created: false });
    const uSnap = await db.collection('users').doc(uid).get();
    if (!uSnap.exists) return res.json({ ok: true, created: false });
    await writePublicProfile(uid, uSnap.data(), true);
    return res.json({ ok: true, created: true });
  } catch (e) {
    console.error('ensure-profile', e);
    return res.status(500).json({ ok: false, error: 'Profil indisponible pour le moment.' });
  }
});

/* Migration : copie des comptes existants vers profiles. Executee une seule fois (marqueur meta/profilesMigration),
   puis uniquement si PROFILES_VERSION augmente. MIGRATE_PROFILES=off la desactive. */
async function migrateProfiles() {
  if (String(process.env.MIGRATE_PROFILES || 'on').toLowerCase() === 'off') return;
  try {
    const markRef = db.collection('meta').doc('profilesMigration');
    const mark = await markRef.get();
    if (mark.exists && Number(mark.data().version || 0) >= PROFILES_VERSION) {
      console.log('migrateProfiles : deja effectuee (version ' + mark.data().version + ')');
      return;
    }
    let last = null, done = 0;
    for (;;) {
      let q = db.collection('users').orderBy(admin.firestore.FieldPath.documentId()).limit(200);
      if (last) q = q.startAfter(last);
      const snap = await q.get();
      if (snap.empty) break;
      const presRefs = snap.docs.map(function (d) { return db.collection('profiles').doc(d.id).collection('shared').doc('presence'); });
      const pres = await db.getAll.apply(db, presRefs);
      for (let i = 0; i < snap.docs.length; i++) {
        await writePublicProfile(snap.docs[i].id, snap.docs[i].data(), !pres[i].exists);
        done++;
      }
      last = snap.docs[snap.docs.length - 1];
      if (snap.size < 200) break;
    }
    await markRef.set({ version: PROFILES_VERSION, at: Date.now(), count: done });
    console.log('migrateProfiles : ' + done + ' profils copies');
  } catch (e) {
    console.error('migrateProfiles', e);
  }
}

/* ---------- Avis : ecrits uniquement par ce serveur (regles Firestore : aucune ecriture depuis l'appli) ----------
   Le serveur verifie le droit d'avis (commande livree), tient a jour la note moyenne du produit et de la boutique
   (ratingSum / ratingCount), gere la reponse du vendeur et les signalements. */
const reviewLog = new Map();
function limitReview(uid, max) {
  const now = Date.now();
  const recent = (reviewLog.get(uid) || []).filter(function (t) { return now - t < 60000; });
  if (recent.length >= max) return false;
  recent.push(now); reviewLog.set(uid, recent);
  return true;
}
function validPid(v) { return /^[A-Za-z0-9_-]{6,60}$/.test(String(v || '')); }

/* POST /review  { pid, rating, text } */
app.post('/review', requireUser, async function (req, res) {
  try {
    const pid = String(req.body.pid || '');
    const rating = Number(req.body.rating);
    const text = String(req.body.text || '').trim().slice(0, 300);
    if (!validPid(pid) || !Number.isInteger(rating) || rating < 1 || rating > 5) return res.status(400).json({ ok: false, error: 'Avis invalide.' });
    if (!limitReview(req.uid, 10)) return res.status(429).json({ ok: false, error: 'Trop de tentatives. Patientez un instant.' });

    const FV = admin.firestore.FieldValue;
    const pref = db.collection('products').doc(pid);
    const rref = pref.collection('reviews').doc(req.uid);
    const bref = pref.collection('buyers').doc(req.uid);
    let name = 'Utilisateur';
    try { const pr = await db.collection('profiles').doc(req.uid).get(); if (pr.exists && pr.data().displayName) name = String(pr.data().displayName).slice(0, 80); } catch (e) { /* nom facultatif */ }

    const out = await db.runTransaction(async function (tx) {
      const [p, b, r] = await Promise.all([tx.get(pref), tx.get(bref), tx.get(rref)]);
      if (!p.exists) return { code: 404, error: 'Produit introuvable.' };
      const shopId = p.data().shopId;
      if (shopId === req.uid) return { code: 403, error: 'Vous ne pouvez pas noter votre propre produit.' };
      if (!b.exists) return { code: 403, error: "Seuls les acheteurs d'un produit livre peuvent donner un avis." };
      const old = r.exists ? Number(r.data().rating) || 0 : 0;
      const data = { uid: req.uid, name: name, rating: rating, text: text, updatedAt: FV.serverTimestamp() };
      if (!r.exists) data.createdAt = FV.serverTimestamp();
      tx.set(rref, data, { merge: true });
      const delta = { ratingSum: FV.increment(rating - old) };
      if (!r.exists) delta.ratingCount = FV.increment(1);
      tx.set(pref, delta, { merge: true });
      tx.set(db.collection('shops').doc(String(shopId)), delta, { merge: true });
      return { code: 200 };
    });
    if (out.code !== 200) return res.status(out.code).json({ ok: false, error: out.error });
    return res.json({ ok: true });
  } catch (e) {
    console.error('review', e);
    return res.status(500).json({ ok: false, error: 'Avis non enregistre pour le moment.' });
  }
});

/* POST /review-reply  { pid, rid, text }  : reponse publique du vendeur (texte vide = suppression de la reponse) */
app.post('/review-reply', requireUser, async function (req, res) {
  try {
    const pid = String(req.body.pid || ''), rid = String(req.body.rid || '');
    const text = String(req.body.text || '').trim().slice(0, 300);
    if (!validPid(pid) || !validPid(rid)) return res.status(400).json({ ok: false, error: 'Requete invalide.' });
    if (!limitReview(req.uid, 20)) return res.status(429).json({ ok: false, error: 'Trop de tentatives. Patientez un instant.' });
    const FV = admin.firestore.FieldValue;
    const pref = db.collection('products').doc(pid);
    const p = await pref.get();
    if (!p.exists || p.data().shopId !== req.uid) return res.status(403).json({ ok: false, error: 'Acces refuse.' });
    const rref = pref.collection('reviews').doc(rid);
    const r = await rref.get();
    if (!r.exists) return res.status(404).json({ ok: false, error: 'Avis introuvable.' });
    await rref.update({ reply: text ? { text: text, at: FV.serverTimestamp() } : FV.delete() });
    return res.json({ ok: true });
  } catch (e) {
    console.error('review-reply', e);
    return res.status(500).json({ ok: false, error: 'Reponse non enregistree pour le moment.' });
  }
});

/* POST /review-report  { pid, rid, reason }  : le vendeur signale un avis abusif a l'equipe (email + copie dans reviewReports) */
app.post('/review-report', requireUser, async function (req, res) {
  try {
    const pid = String(req.body.pid || ''), rid = String(req.body.rid || '');
    const reason = String(req.body.reason || '').trim().slice(0, 300);
    if (!validPid(pid) || !validPid(rid)) return res.status(400).json({ ok: false, error: 'Requete invalide.' });
    if (reason.length < 5) return res.status(400).json({ ok: false, error: 'Expliquez le motif en quelques mots.' });
    const now = Date.now();
    const recent = (supportLog.get('rr:' + req.uid) || []).filter(function (t) { return now - t < 3600000; });
    if (recent.length >= 5) return res.status(429).json({ ok: false, error: 'Limite atteinte : 5 signalements par heure.' });
    const pref = db.collection('products').doc(pid);
    const p = await pref.get();
    if (!p.exists || p.data().shopId !== req.uid) return res.status(403).json({ ok: false, error: 'Acces refuse.' });
    const r = await pref.collection('reviews').doc(rid).get();
    if (!r.exists) return res.status(404).json({ ok: false, error: 'Avis introuvable.' });
    const rep = db.collection('reviewReports').doc(pid + '_' + rid);
    if ((await rep.get()).exists) return res.json({ ok: true, already: true });
    recent.push(now); supportLog.set('rr:' + req.uid, recent);
    const x = r.data();
    await rep.set({ pid: pid, rid: rid, shopId: req.uid, productName: p.data().name || '', rating: x.rating || 0, text: x.text || '', reviewer: x.name || '', reason: reason, status: 'open', at: admin.firestore.FieldValue.serverTimestamp() });
    const html = '<div style="font-family:Arial,Helvetica,sans-serif;font-size:14px;color:#0b1b4d;line-height:1.6;">' +
      '<p><strong>Avis signale</strong> pour le produit ' + escHtml(p.data().name || pid) + '</p>' +
      '<p>Note : ' + escHtml(String(x.rating || 0)) + '/5 par ' + escHtml(x.name || '') + '</p>' +
      '<p style="white-space:pre-wrap;background:#f4f7fc;border-radius:10px;padding:14px;">' + escHtml(x.text || '(sans commentaire)') + '</p>' +
      '<p><strong>Motif du vendeur :</strong> ' + escHtml(reason) + '</p>' +
      '<p style="font-size:12px;color:#7a86a8;">Produit : ' + escHtml(pid) + ' · Avis : ' + escHtml(rid) + '</p></div>';
    fetch('https://api.brevo.com/v3/smtp/email', {
      method: 'POST',
      headers: { 'accept': 'application/json', 'content-type': 'application/json', 'api-key': BREVO_API_KEY },
      body: JSON.stringify({ sender: { name: SENDER_NAME, email: SENDER_EMAIL }, to: [{ email: SUPPORT_EMAIL }], subject: '[NexChat Avis signale] ' + (p.data().name || pid), htmlContent: html })
    }).catch(function () {});
    return res.json({ ok: true });
  } catch (e) {
    console.error('review-report', e);
    return res.status(500).json({ ok: false, error: 'Signalement impossible pour le moment.' });
  }
});

/* POST /admin/review-remove  { pid, rid }  : retrait d'un avis par l'equipe (cle ADMIN_KEY dans l'en-tete x-admin-key ; desactive si ADMIN_KEY n'est pas definie) */
app.post('/admin/review-remove', async function (req, res) {
  try {
    const key = String(process.env.ADMIN_KEY || '');
    const given = String(req.headers['x-admin-key'] || '');
    if (!key || given.length !== key.length || !crypto.timingSafeEqual(Buffer.from(given), Buffer.from(key))) return res.status(403).json({ ok: false });
    const pid = String(req.body.pid || ''), rid = String(req.body.rid || '');
    if (!validPid(pid) || !validPid(rid)) return res.status(400).json({ ok: false });
    const FV = admin.firestore.FieldValue;
    const pref = db.collection('products').doc(pid), rref = pref.collection('reviews').doc(rid);
    await db.runTransaction(async function (tx) {
      const [p, r] = await Promise.all([tx.get(pref), tx.get(rref)]);
      if (!r.exists) return;
      const old = Number(r.data().rating) || 0;
      tx.delete(rref);
      if (p.exists) {
        const delta = { ratingSum: FV.increment(-old), ratingCount: FV.increment(-1) };
        tx.set(pref, delta, { merge: true });
        tx.set(db.collection('shops').doc(String(p.data().shopId)), delta, { merge: true });
      }
    });
    await db.collection('reviewReports').doc(pid + '_' + rid).set({ status: 'removed', resolvedAt: FV.serverTimestamp() }, { merge: true }).catch(function () {});
    return res.json({ ok: true });
  } catch (e) {
    console.error('admin/review-remove', e);
    return res.status(500).json({ ok: false });
  }
});

/* Migration (une fois, marqueur meta/reviewsMigration) : note moyenne des produits et boutiques a partir des avis existants */
async function migrateReviews() {
  try {
    const markRef = db.collection('meta').doc('reviewsMigration');
    const mark = await markRef.get();
    if (mark.exists && Number(mark.data().version || 0) >= 1) { console.log('migrateReviews : deja effectuee'); return; }
    const rv = await db.collectionGroup('reviews').get();
    const prod = {}, shop = {};
    const shopOf = {};
    for (const r of rv.docs) {
      const pr = r.ref.parent.parent;
      if (!pr || !pr.parent || pr.parent.id !== 'products') continue;
      const rating = Number(r.data().rating) || 0;
      if (rating < 1 || rating > 5) continue;
      const pid = pr.id;
      if (!(pid in shopOf)) { const ps = await pr.get(); shopOf[pid] = ps.exists ? String(ps.data().shopId || '') : ''; }
      const a = prod[pid] = prod[pid] || { ratingSum: 0, ratingCount: 0 };
      a.ratingSum += rating; a.ratingCount += 1;
      if (shopOf[pid]) { const b = shop[shopOf[pid]] = shop[shopOf[pid]] || { ratingSum: 0, ratingCount: 0 }; b.ratingSum += rating; b.ratingCount += 1; }
    }
    const jobs = [];
    Object.keys(prod).forEach(function (id) { jobs.push([db.collection('products').doc(id), prod[id]]); });
    Object.keys(shop).forEach(function (id) { jobs.push([db.collection('shops').doc(id), shop[id]]); });
    for (let i = 0; i < jobs.length; i += 200) {
      const batch = db.batch();
      jobs.slice(i, i + 200).forEach(function (j) { batch.set(j[0], j[1], { merge: true }); });
      await batch.commit().catch(function (e) { console.error('migrateReviews', e); });
    }
    await markRef.set({ version: 1, at: Date.now(), products: Object.keys(prod).length, shops: Object.keys(shop).length });
    console.log('migrateReviews : ' + Object.keys(prod).length + ' produits, ' + Object.keys(shop).length + ' boutiques');
  } catch (e) {
    console.error('migrateReviews', e);
  }
}

/* ---------- Stock reserve des la commande ----------
   Le stock (total et par couleur) baisse au moment de la commande, pas a l'acceptation : deux acheteurs ne peuvent plus commander
   le meme dernier article. Il est remis en stock si la commande est annulee ou refusee.
   Les commandes anterieures (sans reserved) gardent l'ancien comportement : baisse a l'acceptation. */
function readProducts(tx, items) {
  const pids = Array.from(new Set(items.map(function (i) { return String(i.productId); })));
  return Promise.all(pids.map(function (id) { return tx.get(db.collection('products').doc(id)); })).then(function (snaps) {
    const prods = {};
    snaps.forEach(function (ps, k) { prods[pids[k]] = ps.exists ? ps.data() : null; });
    return prods;
  });
}
function writeStock(tx, items, prods, sign) {
  const FV = admin.firestore.FieldValue;
  items.forEach(function (i) {
    const pd = prods[String(i.productId)];
    if (!pd) return;
    const qty = Math.max(0, Math.min(10000, Number(i.qty) || 0));
    if (!qty) return;
    const key = colorKey(i.color);
    const perColor = !!(key && pd.colorStock && typeof pd.colorStock === 'object' && (key in pd.colorStock));
    const d = { stock: FV.increment(sign * qty) };
    if (perColor) { d.colorStock = {}; d.colorStock[key] = FV.increment(sign * qty); }
    tx.set(db.collection('products').doc(String(i.productId)), d, { merge: true });
  });
}

/* POST /order-place  { shopId, items: [{ productId, color, qty }], address }
   Cree la commande d'une boutique : prix lus dans la base (jamais envoyes par l'appli), stock verifie et reserve de facon atomique. */
const placeLog = new Map();
app.post('/order-place', requireUser, async function (req, res) {
  try {
    const shopId = String(req.body.shopId || '');
    const rawItems = Array.isArray(req.body.items) ? req.body.items.slice(0, 40) : [];
    const ad = req.body.address || {};
    if (!/^[A-Za-z0-9_-]{6,128}$/.test(shopId) || !rawItems.length) return res.status(400).json({ ok: false, error: 'Commande invalide.' });
    if (shopId === req.uid) return res.status(403).json({ ok: false, error: 'Vous ne pouvez pas commander dans votre propre boutique.' });
    const street = String(ad.street || '').trim().slice(0, 200), phone = String(ad.phone || '').trim().slice(0, 30);
    if (!street || !phone) return res.status(400).json({ ok: false, error: 'Adresse et telephone de livraison requis.' });
    const address = { street: street, phone: phone };
    if (typeof ad.lat === 'number' && typeof ad.lng === 'number' && Math.abs(ad.lat) <= 90 && Math.abs(ad.lng) <= 180) { address.lat = ad.lat; address.lng = ad.lng; }

    const now = Date.now();
    const recent = (placeLog.get(req.uid) || []).filter(function (t) { return now - t < 60000; });
    if (recent.length >= 15) return res.status(429).json({ ok: false, error: 'Trop de commandes. Patientez un instant.' });
    recent.push(now); placeLog.set(req.uid, recent);

    const blocked = await db.collection('users').doc(shopId).collection('blocked').doc(req.uid).get().then(function (x) { return x.exists; }).catch(function () { return false; });
    if (blocked) return res.status(403).json({ ok: false, error: 'Commande impossible avec cette boutique.' });

    let buyerName = 'Client';
    try { const pr = await db.collection('profiles').doc(req.uid).get(); if (pr.exists && pr.data().displayName) buyerName = String(pr.data().displayName).slice(0, 80); } catch (e) { /* facultatif */ }

    const FV = admin.firestore.FieldValue;
    const oref = db.collection('orders').doc();
    const ref = 'NC-' + (Math.floor(Math.random() * 90000) + 10000);
    const wanted = rawItems.map(function (i) {
      return { productId: String(i.productId || ''), color: String(i.color || '').trim().slice(0, 20), qty: Math.floor(Number(i.qty)) };
    });
    for (const w of wanted) {
      if (!/^[A-Za-z0-9_-]{6,60}$/.test(w.productId) || !(w.qty >= 1 && w.qty <= 99)) return res.status(400).json({ ok: false, error: 'Commande invalide.' });
    }

    const out = await db.runTransaction(async function (tx) {
      const prods = await readProducts(tx, wanted);
      const need = {}, items = [];
      let total = 0, shopName = '';
      for (const w of wanted) {
        const pd = prods[w.productId];
        if (!pd || pd.shopId !== shopId) return { code: 400, error: 'Un produit de votre panier est introuvable.' };
        if (pd.inStock === false) return { code: 409, error: pd.name + ' n\'est plus disponible.' };
        const colors = Array.isArray(pd.colors) ? pd.colors : [];
        let color = '';
        if (colors.length) {
          const m = colors.filter(function (c) { return String(c).toLowerCase() === w.color.toLowerCase(); })[0];
          if (!m) return { code: 400, error: 'Choisissez une couleur pour ' + pd.name + '.' };
          color = m;
        }
        const key = colorKey(color);
        const perColor = !!(key && pd.colorStock && typeof pd.colorStock === 'object' && (key in pd.colorStock));
        const bucket = w.productId + '|' + (perColor ? key : '');
        need[bucket] = (need[bucket] || 0) + w.qty;
        const avail = perColor ? Number(pd.colorStock[key]) || 0 : Number(pd.stock) || 0;
        if (need[bucket] > avail) {
          return { code: 409, error: avail > 0 ? 'Stock insuffisant pour ' + pd.name + (color ? ' (' + color + ')' : '') + ' : il reste ' + avail + '.' : pd.name + (color ? ' (' + color + ')' : '') + ' est epuise.' };
        }
        const price = Number(pd.price) || 0;
        total += price * w.qty;
        shopName = pd.shopName || shopName;
        items.push({ productId: w.productId, name: pd.name + (color ? ' (' + color + ')' : ''), color: color, price: price, qty: w.qty, photo: (Array.isArray(pd.photos) && pd.photos[0]) || '' });
      }
      writeStock(tx, items, prods, -1);
      tx.set(oref, {
        ref: ref, buyerId: req.uid, buyerName: buyerName, sellerId: shopId, shopName: shopName, items: items, total: total,
        address: address, status: 'pending', reserved: true, createdAt: FV.serverTimestamp(), updatedAt: FV.serverTimestamp()
      });
      return { code: 200, items: items, total: total };
    });
    if (out.code !== 200) return res.status(out.code).json({ ok: false, error: out.error });
    return res.json({ ok: true, orderId: oref.id, ref: ref, total: out.total,
      lines: out.items.map(function (i) { return { name: i.name, qty: i.qty, price: i.price * i.qty, productId: i.productId, photo: i.photo }; }) });
  } catch (e) {
    console.error('order-place', e);
    return res.status(500).json({ ok: false, error: 'Commande impossible pour le moment.' });
  }
});

/* POST /order-cancel  { orderId }  : l'acheteur annule sa commande.
   - "En attente" : annulation immediate, stock remis en place
   - "En cours" (deja acceptee) : demande d'annulation (cancelRequest) que la boutique accepte ou refuse.
     Sans reponse : relance possible apres 24 h (une par 24 h) ; apres 72 h la demande est consideree comme expiree et peut etre refaite. */
app.post('/order-cancel', requireUser, async function (req, res) {
  try {
    const orderId = String(req.body.orderId || '');
    if (!/^[A-Za-z0-9_-]{10,40}$/.test(orderId)) return res.status(400).json({ ok: false, error: 'Requete invalide.' });
    if (!limitReview(req.uid, 10)) return res.status(429).json({ ok: false, error: 'Trop de tentatives. Patientez un instant.' });
    const FV = admin.firestore.FieldValue;
    const ref = db.collection('orders').doc(orderId);
    const out = await db.runTransaction(async function (tx) {
      const snap = await tx.get(ref);
      if (!snap.exists) return { code: 404, error: 'Commande introuvable.' };
      const o = snap.data();
      if (o.buyerId !== req.uid) return { code: 403, error: 'Acces refuse.' };
      if (o.status === 'cancelled') return { code: 200, same: true, mode: 'cancelled', fresh: false };
      if (o.status === 'pending') {
        const items = (Array.isArray(o.items) ? o.items : []).filter(function (i) { return i && i.productId; });
        const prods = o.reserved ? await readProducts(tx, items) : {};
        tx.update(ref, { status: 'cancelled', cancelledBy: 'buyer', updatedAt: FV.serverTimestamp() });
        if (o.reserved) writeStock(tx, items, prods, 1);
        return { code: 200, mode: 'cancelled', fresh: true };
      }
      if (o.status === 'processing') {
        const nowMs = Date.now(), DAY = 86400000;
        const at = o.cancelRequest && o.cancelRequest.at && o.cancelRequest.at.toMillis ? o.cancelRequest.at.toMillis() : 0;
        const remind = o.cancelRemindAt && o.cancelRemindAt.toMillis ? o.cancelRemindAt.toMillis() : 0;
        if (o.cancelRequest && at && nowMs - at < 3 * DAY) {
          if (nowMs - at >= DAY && nowMs - Math.max(at, remind) >= DAY) {
            tx.update(ref, { cancelRemindAt: FV.serverTimestamp(), updatedAt: FV.serverTimestamp() });
            return { code: 200, mode: 'reminded', fresh: true };
          }
          return { code: 200, same: true, mode: 'requested', fresh: false };
        }
        tx.update(ref, { cancelRequest: { at: FV.serverTimestamp() }, cancelDeclinedAt: FV.delete(), cancelRemindAt: FV.delete(), updatedAt: FV.serverTimestamp() });
        return { code: 200, mode: 'requested', fresh: true };
      }
      return { code: 409, error: 'Cette commande est deja livree : contactez la boutique.' };
    });
    if (out.code !== 200) return res.status(out.code).json({ ok: false, error: out.error });
    return res.json({ ok: true, mode: out.mode, fresh: !!out.fresh });
  } catch (e) {
    console.error('order-cancel', e);
    return res.status(500).json({ ok: false, error: 'Annulation impossible pour le moment.' });
  }
});

/* POST /order-cancel-decline  { orderId }  : la boutique refuse la demande d'annulation (l'acceptation passe par /order-status vers "cancelled") */
app.post('/order-cancel-decline', requireUser, async function (req, res) {
  try {
    const orderId = String(req.body.orderId || '');
    if (!/^[A-Za-z0-9_-]{10,40}$/.test(orderId)) return res.status(400).json({ ok: false, error: 'Requete invalide.' });
    if (!limitReview(req.uid, 20)) return res.status(429).json({ ok: false, error: 'Trop de tentatives. Patientez un instant.' });
    const FV = admin.firestore.FieldValue;
    const ref = db.collection('orders').doc(orderId);
    const out = await db.runTransaction(async function (tx) {
      const snap = await tx.get(ref);
      if (!snap.exists) return { code: 404, error: 'Commande introuvable.' };
      const o = snap.data();
      if (o.sellerId !== req.uid) return { code: 403, error: 'Acces refuse.' };
      if (!o.cancelRequest || o.status !== 'processing') return { code: 200, same: true };
      tx.update(ref, { cancelRequest: FV.delete(), cancelDeclinedAt: FV.serverTimestamp(), updatedAt: FV.serverTimestamp() });
      return { code: 200 };
    });
    if (out.code !== 200) return res.status(out.code).json({ ok: false, error: out.error });
    return res.json({ ok: true });
  } catch (e) {
    console.error('order-cancel-decline', e);
    return res.status(500).json({ ok: false, error: 'Refus impossible pour le moment.' });
  }
});

/* ---------- Commandes : changement de statut par le vendeur (stock, ventes et droit d'avis tenus a jour de facon atomique) ----------
   Les regles Firestore interdisent toute modification d'une commande depuis l'appli : seul ce serveur change le statut. */
/* Cle d'une couleur dans colorStock : identique a celle de l'appli (colorKey) */
function colorKey(c) { return String(c || '').toLowerCase().replace(/[.\/\\~*\[\]\s]+/g, '_').slice(0, 20); }
const ORDER_NEXT = { pending: ['processing', 'cancelled'], processing: ['delivered', 'cancelled'] };
const orderLog = new Map();
app.post('/order-status', requireUser, async function (req, res) {
  try {
    const orderId = String(req.body.orderId || ''), next = String(req.body.next || '');
    if (!/^[A-Za-z0-9_-]{10,40}$/.test(orderId) || ['processing', 'delivered', 'cancelled'].indexOf(next) === -1) {
      return res.status(400).json({ ok: false, error: 'Requete invalide.' });
    }
    const now = Date.now();
    const recent = (orderLog.get(req.uid) || []).filter(function (t) { return now - t < 60000; });
    if (recent.length >= 60) return res.status(429).json({ ok: false, error: 'Trop de modifications. Patientez un instant.' });
    recent.push(now); orderLog.set(req.uid, recent);

    const FV = admin.firestore.FieldValue;
    const ref = db.collection('orders').doc(orderId);
    const out = await db.runTransaction(async function (tx) {
      const snap = await tx.get(ref);
      if (!snap.exists) return { code: 404, error: 'Commande introuvable.' };
      const o = snap.data();
      if (o.sellerId !== req.uid) return { code: 403, error: 'Acces refuse.' };
      if (o.status === next) return { code: 200, same: true };
      if ((ORDER_NEXT[o.status] || []).indexOf(next) === -1) return { code: 409, error: 'Ce changement de statut n\'est pas possible.' };
      const items = (Array.isArray(o.items) ? o.items : []).filter(function (i) { return i && i.productId; });
      // lectures d'abord (produits concernes), ecritures ensuite
      const prods = await readProducts(tx, items);

      const patch = { status: next, updatedAt: FV.serverTimestamp() };
      if (next === 'delivered') { patch.deliveredAt = FV.serverTimestamp(); patch.deliveredSource = 'server'; }
      if (next === 'cancelled') { patch.cancelRequest = FV.delete(); if (!o.cancelledBy) patch.cancelledBy = o.cancelRequest ? 'buyer' : 'seller'; }
      tx.update(ref, patch);
      // Stock : reserve a la commande (reserved) ; les anciennes commandes baissent a l'acceptation
      if (o.status === 'pending' && next === 'processing' && !o.reserved) writeStock(tx, items, prods, -1);
      if (next === 'cancelled' && ((o.status === 'processing') || (o.status === 'pending' && o.reserved))) writeStock(tx, items, prods, 1);
      if (next === 'delivered') {
        items.forEach(function (i) {
          const qty = Math.max(0, Math.min(10000, Number(i.qty) || 0));
          if (!qty) return;
          const pref = db.collection('products').doc(String(i.productId));
          tx.set(pref, { sold: FV.increment(qty) }, { merge: true });
          // droit d'avis : verifie par les regles Firestore a partir de ce document
          tx.set(pref.collection('buyers').doc(String(o.buyerId)), { orderId: orderId, at: FV.serverTimestamp() }, { merge: true });
        });
      }
      return { code: 200 };
    });
    if (out.code !== 200) return res.status(out.code).json({ ok: false, error: out.error });
    return res.json({ ok: true });
  } catch (e) {
    console.error('order-status', e);
    return res.status(500).json({ ok: false, error: 'Mise a jour impossible pour le moment.' });
  }
});

/* Migration (une seule fois par version, marqueur meta/salesMigration) : commandes livrees avant la mise a jour.
   - deliveredAt : date reelle de livraison, retrouvee dans le message "Votre commande ... a ete livree." envoye a l'acheteur ;
     a defaut, derniere mise a jour de la commande (deliveredSource = 'message' ou 'estimate')
   - sold : recalcule a partir des commandes livrees, y compris celles qui n'avaient jamais ete comptees
   - products/{id}/buyers/{acheteur} : droit d'avis pour les acheteurs deja livres
   - avis sans commande livree : retires (ils contournaient la regle qui reserve l'avis aux acheteurs) */
const SALES_VERSION = 2;
async function deliveredMessageTime(o) {
  try {
    const cid = [o.sellerId, o.buyerId].sort().join('_');
    const sn = await db.collection('conversations').doc(cid).collection('messages')
      .where('text', '==', 'Votre commande ' + o.ref + ' a été livrée.').limit(1).get();
    if (!sn.empty && sn.docs[0].data().createdAt) return sn.docs[0].data().createdAt;
  } catch (e) { /* repli sur l'estimation */ }
  return null;
}
async function migrateSales() {
  try {
    const markRef = db.collection('meta').doc('salesMigration');
    const mark = await markRef.get();
    if (mark.exists && Number(mark.data().version || 0) >= SALES_VERSION) { console.log('migrateSales : deja effectuee'); return; }
    const FV = admin.firestore.FieldValue;
    const snap = await db.collection('orders').where('status', '==', 'delivered').get();
    const sold = {}, buyers = [], bought = {};
    let dated = 0, estimated = 0;
    for (const d of snap.docs) {
      const o = d.data();
      if (o.deliveredSource !== 'server') {
        const real = await deliveredMessageTime(o);
        if (real) { await d.ref.update({ deliveredAt: real, deliveredSource: 'message' }).catch(function () {}); dated++; }
        else if (!o.deliveredAt) { await d.ref.update({ deliveredAt: o.updatedAt || o.createdAt || FV.serverTimestamp(), deliveredSource: 'estimate' }).catch(function () {}); estimated++; }
        else if (!o.deliveredSource) { await d.ref.update({ deliveredSource: 'estimate' }).catch(function () {}); estimated++; }
      }
      (Array.isArray(o.items) ? o.items : []).forEach(function (i) {
        if (!i || !i.productId) return;
        sold[i.productId] = (sold[i.productId] || 0) + Math.max(0, Number(i.qty) || 0);
        buyers.push({ pid: String(i.productId), buyer: String(o.buyerId), orderId: d.id });
        bought[String(i.productId) + '|' + String(o.buyerId)] = 1;
      });
    }
    const pids = Object.keys(sold);
    for (let i = 0; i < pids.length; i += 200) {
      const batch = db.batch();
      pids.slice(i, i + 200).forEach(function (pid) { batch.set(db.collection('products').doc(pid), { sold: sold[pid] }, { merge: true }); });
      await batch.commit().catch(function (e) { console.error('migrateSales sold', e); });
    }
    for (let i = 0; i < buyers.length; i += 200) {
      const batch = db.batch();
      buyers.slice(i, i + 200).forEach(function (b) {
        batch.set(db.collection('products').doc(b.pid).collection('buyers').doc(b.buyer), { orderId: b.orderId, at: FV.serverTimestamp() }, { merge: true });
      });
      await batch.commit().catch(function (e) { console.error('migrateSales buyers', e); });
    }
    // avis sans commande livree
    let removed = 0;
    const rv = await db.collectionGroup('reviews').get();
    for (const r of rv.docs) {
      const prod = r.ref.parent.parent;
      const pid = (prod && prod.parent && prod.parent.id === 'products') ? prod.id : '';
      if (pid && !bought[pid + '|' + r.id]) { await r.ref.delete().catch(function () {}); removed++; }
    }
    await markRef.set({ version: SALES_VERSION, at: Date.now(), orders: snap.size, dated: dated, estimated: estimated, reviewsRemoved: removed });
    console.log('migrateSales : ' + snap.size + ' commandes livrees reprises (' + dated + ' datees par message, ' + estimated + ' estimees), ' + pids.length + ' produits, ' + removed + ' avis sans achat retires');
  } catch (e) {
    console.error('migrateSales', e);
  }
}

app.listen(PORT, function () { console.log('NexChat backend sur le port ' + PORT); migrateProfiles(); migrateSales().then(migrateReviews); });
