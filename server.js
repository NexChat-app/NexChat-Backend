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

/* Verification en deux etapes imposee par le serveur.
   Revendications du compte : needs2fa (true si la 2FA est activee) et tfS (liste des auth_time de connexions deja verifiees par code).
   Une session est acceptee si needs2fa est absent, si elle vient d'une reprise par appareil connu (revendication tfd = 1, delivree par /device-session)
   ou si l'auth_time de son jeton figure dans tfS. TF_ENFORCE=off desactive le controle serveur (les revendications restent lues par les regles Firestore :
   utiliser aussi /admin/2fa-release pour les effacer). */
const TF_ENFORCE = String(process.env.TF_ENFORCE || 'on').toLowerCase() !== 'off';
const TF_KEEP = 10;
function tfPassed(dec) {
  if (!TF_ENFORCE) return true;
  if (!dec || dec.needs2fa !== true) return true;
  if (Number(dec.tfd) === 1) return true;
  const list = Array.isArray(dec.tfS) ? dec.tfS : [];
  return list.indexOf(Number(dec.auth_time)) !== -1;
}
async function setTfClaims(uid, mutate) {
  const u = await auth.getUser(uid);
  const c = Object.assign({}, u.customClaims || {});
  mutate(c);
  await auth.setCustomUserClaims(uid, Object.keys(c).length ? c : null);
}
async function decodeUser(req, res, needTf, next) {
  const h = req.headers.authorization || '';
  const token = h.indexOf('Bearer ') === 0 ? h.slice(7) : '';
  try {
    const dec = await auth.verifyIdToken(token);
    if (dec.email_verified !== true) return res.status(403).json({ ok: false, error: 'Email non confirme.' });
    if (needTf && !tfPassed(dec)) return res.status(403).json({ ok: false, needs2fa: true, error: 'Verification en deux etapes requise.' });
    req.uid = dec.uid;
    req.decoded = dec;
    return next();
  } catch (e) {
    return res.status(401).json({ ok: false, error: 'Session invalide.' });
  }
}
/* Toutes les routes sauf la verification elle-meme exigent une session deja verifiee */
function requireUser(req, res, next) { return decodeUser(req, res, true, next); }
/* Routes /2fa/* : jeton valide, verification en deux etapes pas encore passee */
function requireUserPre(req, res, next) { return decodeUser(req, res, false, next); }

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

/* Messages d'un compte supprime : remplaces par « Message supprime » (meme marqueur que la suppression d'un message dans l'appli), pieces jointes detruites.
   Les cartes de commande restent (les commandes sont conservees). */
async function scrubMessages(colRef, uid, gone) {
  const mine = await colRef.where('senderId', '==', uid).get();
  const urls = [], refs = [];
  mine.docs.forEach(function (m) {
    const d = m.data();
    if (d.type === 'deleted' || d.type === 'order') return;
    if (d.url) urls.push(d.url);
    refs.push(m.ref);
  });
  if (urls.length) await destroyMany(urls);
  for (let i = 0; i < refs.length; i += 400) {
    const b = db.batch();
    refs.slice(i, i + 400).forEach(function (r) { b.update(r, gone); });
    await b.commit();
  }
  return refs.length;
}

/* ---------- Traces laissees par un compte : nettoyees a la suppression ----------
   Chaque etape est isolee : un echec (par exemple un index Firestore a creer) est journalise sans bloquer la suppression du compte. */
async function cleanAccountTraces(uid, groupDocs) {
  const step = async function (label, fn) {
    try { await fn(); } catch (e) { console.error('delete-account traces : ' + label, e && e.message ? e.message : e); }
  };

  // Confirmations de lecture et reponses aux sondages / evenements des groupes dont il etait membre
  for (const g of groupDocs) {
    await step('reads ' + g.id, async function () { await g.ref.collection('reads').doc(uid).delete(); });
    await step('answers ' + g.id, async function () {
      const msgs = await g.ref.collection('messages').where('type', 'in', ['poll', 'event']).get();
      for (const m of msgs.docs) { await m.ref.collection('answers').doc(uid).delete(); }
    });
  }

  // Demandes d'adhesion par lien (en attente ou refusees) : necessite l'index « groupe de collections » joinRequests / uid
  await step('joinRequests', async function () {
    const jr = await db.collectionGroup('joinRequests').where('uid', '==', uid).get();
    for (const d of jr.docs) await d.ref.delete();
  });

  // Avis laisses et droits d'avis : retrouves a partir des commandes de l'acheteur
  await step('avis', async function () {
    const ords = await db.collection('orders').where('buyerId', '==', uid).get();
    const pids = {};
    ords.forEach(function (o) { (o.data().items || []).forEach(function (i) { if (i && i.productId) pids[String(i.productId)] = true; }); });
    for (const pid of Object.keys(pids)) {
      if (!validPid(pid)) continue;
      await removeReview(pid, uid).catch(function () {});
      await db.collection('products').doc(pid).collection('buyers').doc(uid).delete().catch(function () {});
    }
  });

  // Usage des appels de groupe et appels dont il etait membre
  await step('usage', async function () {
    const us = await db.collection('usage').where('uid', '==', uid).get();
    for (const d of us.docs) await d.ref.delete();
  });
  await step('calls', async function () {
    const cs = await db.collection('calls').where('members', 'array-contains', uid).get();
    for (const c of cs.docs) {
      await db.collection('usage').doc(c.id + '_' + uid).delete().catch(function () {});
      await db.recursiveDelete(c.ref);
    }
  });
}

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
    const MEDIA_GONE = { type: 'deleted', text: 'Message supprime', url: FV.delete(), fileName: FV.delete(), size: FV.delete(), duration: FV.delete(), caption: FV.delete(),
      poll: FV.delete(), event: FV.delete(), contact: FV.delete(), location: FV.delete(), product: FV.delete(), replyTo: FV.delete(), deletedAt: FV.serverTimestamp() };

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

    // 4. Discussions privees : messages et medias remplaces par « Message supprime » chez l'autre personne
    const convs = await db.collection('conversations').where('members', 'array-contains', uid).get();
    for (const c of convs.docs) {
      await scrubMessages(c.ref.collection('messages'), uid, MEDIA_GONE);
      if (c.data().lastSenderId === uid) await c.ref.update({ lastMessage: 'Message supprim\u00e9' }).catch(function () {});
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
      await scrubMessages(g.ref.collection('messages'), uid, MEDIA_GONE);
      let admins = (data.admins || []).filter(function (a) { return a !== uid; });
      if (!admins.length) admins = [members[0]];
      const gpatch = { members: members, admins: admins };
      if (data.lastSenderId === uid) { gpatch.lastMessage = 'Message supprim\u00e9'; gpatch.lastSenderName = ''; }
      await g.ref.update(gpatch);
    }

    // 5 bis. Traces : confirmations de lecture, reponses aux sondages, demandes d'adhesion, avis et droits d'avis, appels
    await cleanAccountTraces(uid, groups.docs);

    // 6. Codes en attente puis profil et sous-collections (contacts, panier, jetons, bloques, appareils)
    const codesSnap = await codes.where('uid', '==', uid).get();
    for (const d of codesSnap.docs) await d.ref.delete();
    await bcol.doc(uid).delete().catch(function () {});
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
const TF_MODES = ['login', 'enable', 'disable', 'backup'];

/* ---------- Codes de secours : 10 codes a usage unique (stockes haches dans backupCodes/{uid}, collection reservee au serveur) ---------- */
const bcol = db.collection('backupCodes');
const BACKUP_COUNT = 10, BACKUP_FAILS = 5, BACKUP_LOCK_MS = 15 * 60 * 1000;
const BACKUP_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
function newBackupCode() {
  let c = '';
  for (let i = 0; i < 10; i++) c += BACKUP_ALPHABET[crypto.randomInt(BACKUP_ALPHABET.length)];
  return c.slice(0, 5) + '-' + c.slice(5);
}
function normBackup(v) { return String(v || '').toUpperCase().replace(/[^A-Z0-9]/g, ''); }
function backupHash(uid, code) { return hmac('backup:' + uid + ':' + normBackup(code)); }
/* Remplace tous les codes du compte et renvoie les nouveaux, en clair, une seule fois */
async function makeBackupCodes(uid) {
  const list = [];
  while (list.length < BACKUP_COUNT) { const c = newBackupCode(); if (list.indexOf(c) === -1) list.push(c); }
  await bcol.doc(uid).set({ hashes: list.map(function (c) { return backupHash(uid, c); }), generatedAt: Date.now(), fails: 0, lockUntil: 0 });
  return list;
}
/* Connexion verifiee : enregistre l'auth_time de la session dans tfS (10 dernieres connexions gardees) */
async function tfMarkVerified(uid, at) {
  if (!at) return;
  await setTfClaims(uid, function (c) {
    const list = (Array.isArray(c.tfS) ? c.tfS : []).filter(function (n) { return Number.isFinite(n) && n !== at; });
    list.push(at);
    c.needs2fa = true;
    c.tfS = list.slice(-TF_KEEP);
  });
}

/* POST /2fa/send  { mode: 'login' | 'enable' | 'disable' } */
app.post('/2fa/send', requireUserPre, async function (req, res) {
  try {
    const mode = String(req.body.mode || '');
    if (TF_MODES.indexOf(mode) === -1) return res.status(400).json({ ok: false, error: 'Requete invalide.' });
    // activer ou desactiver exige une session deja verifiee ; seule la connexion (login) se fait avant verification
    if (mode !== 'login' && !tfPassed(req.decoded)) return res.status(403).json({ ok: false, needs2fa: true, error: 'Verification en deux etapes requise.' });
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
app.post('/2fa/verify', requireUserPre, async function (req, res) {
  try {
    const mode = String(req.body.mode || '');
    const code = String(req.body.code || '').trim();
    if (TF_MODES.indexOf(mode) === -1 || !/^\d{6}$/.test(code)) return res.status(400).json({ ok: false, error: 'Code invalide.' });
    if (mode !== 'login' && !tfPassed(req.decoded)) return res.status(403).json({ ok: false, needs2fa: true, error: 'Verification en deux etapes requise.' });
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
    // revendications d'abord : si elles echouent, rien n'est active a moitie
    const at = Number(req.decoded.auth_time) || 0;
    if (mode === 'enable') {
      await setTfClaims(req.uid, function (c) { c.needs2fa = true; c.tfS = at ? [at] : []; });
      await db.collection('users').doc(req.uid).set({ twoFactor: true }, { merge: true });
      // les codes de secours sont crees des l'activation et montres une seule fois
      const fresh = await makeBackupCodes(req.uid);
      return res.json({ ok: true, enabled: true, codes: fresh });
    }
    if (mode === 'disable') {
      await setTfClaims(req.uid, function (c) { delete c.needs2fa; delete c.tfS; });
      await db.collection('users').doc(req.uid).set({ twoFactor: false }, { merge: true });
      await bcol.doc(req.uid).delete().catch(function () {});
    }
    if (mode === 'backup') {
      // nouveaux codes : les anciens ne fonctionnent plus
      const fresh = await makeBackupCodes(req.uid);
      try {
        const u = await auth.getUser(req.uid);
        if (u.email) sendMailTo(u.email, 'Nouveaux codes de secours NexChat', '<div style="font-family:Arial,Helvetica,sans-serif;font-size:14px;color:#0b1b4d;line-height:1.6;max-width:480px;"><p>De nouveaux codes de secours ont été générés pour votre compte NexChat. Les anciens ne fonctionnent plus.</p><p>Si ce n\'est pas vous, changez votre mot de passe.</p></div>');
      } catch (e) { /* email facultatif */ }
      return res.json({ ok: true, enabled: true, codes: fresh });
    }
    if (mode === 'login') await tfMarkVerified(req.uid, at);
    return res.json({ ok: true, enabled: mode === 'enable' ? true : (mode === 'disable' ? false : true) });
  } catch (e) {
    console.error('2fa/verify', e);
    return res.status(500).json({ ok: false, error: 'Verification impossible pour le moment.' });
  }
});

/* POST /2fa/backup-status  : nombre de codes de secours restants */
app.post('/2fa/backup-status', requireUser, async function (req, res) {
  try {
    const snap = await bcol.doc(req.uid).get();
    const d = snap.exists ? snap.data() : {};
    return res.json({ ok: true, remaining: Array.isArray(d.hashes) ? d.hashes.length : 0, generatedAt: d.generatedAt || 0 });
  } catch (e) {
    console.error('2fa/backup-status', e);
    return res.status(500).json({ ok: false, error: 'Lecture impossible pour le moment.' });
  }
});

/* POST /2fa/backup-use  { code }  : connexion avec un code de secours (usage unique) a la place du code par email */
app.post('/2fa/backup-use', requireUserPre, async function (req, res) {
  try {
    const norm = normBackup(req.body.code);
    if (!/^[A-Z0-9]{10}$/.test(norm)) return res.status(400).json({ ok: false, error: 'Code de secours invalide.' });
    const uSnap = await db.collection('users').doc(req.uid).get();
    if (!(uSnap.exists && uSnap.data().twoFactor === true)) return res.status(400).json({ ok: false, error: 'La verification en deux etapes n\'est pas activee.' });
    const ref = bcol.doc(req.uid);
    const h = backupHash(req.uid, norm);
    const out = await db.runTransaction(async function (tx) {
      const snap = await tx.get(ref);
      if (!snap.exists) return { status: 'none' };
      const d = snap.data();
      if ((d.lockUntil || 0) > Date.now()) return { status: 'locked', wait: Math.ceil((d.lockUntil - Date.now()) / 60000) };
      const list = Array.isArray(d.hashes) ? d.hashes : [];
      const i = list.indexOf(h);
      if (i === -1) {
        const fails = (d.fails || 0) + 1;
        tx.update(ref, fails >= BACKUP_FAILS ? { fails: 0, lockUntil: Date.now() + BACKUP_LOCK_MS } : { fails: fails });
        return { status: 'bad' };
      }
      const rest = list.slice(0, i).concat(list.slice(i + 1));
      tx.update(ref, { hashes: rest, fails: 0, lockUntil: 0 });
      return { status: 'ok', remaining: rest.length };
    });
    if (out.status === 'locked') return res.status(429).json({ ok: false, error: 'Trop d\'essais. Reessayez dans ' + out.wait + ' minute(s).' });
    if (out.status !== 'ok') return res.status(400).json({ ok: false, error: 'Code de secours incorrect.' });
    await tfMarkVerified(req.uid, Number(req.decoded.auth_time) || 0);
    const body = 'Un code de secours a été utilisé pour vous connecter. Il vous en reste ' + out.remaining + '. Si ce n\'est pas vous, changez votre mot de passe.';
    writeNotif(req.uid, 'bk_' + Date.now(), { type: 'security', title: 'Code de secours utilisé', body: body }, false).catch(function () {});
    try {
      const u = await auth.getUser(req.uid);
      if (u.email) sendMailTo(u.email, 'Code de secours utilisé sur NexChat', '<div style="font-family:Arial,Helvetica,sans-serif;font-size:14px;color:#0b1b4d;line-height:1.6;max-width:480px;"><p>' + escHtml(body) + '</p></div>');
    } catch (e) { /* email facultatif */ }
    return res.json({ ok: true, remaining: out.remaining });
  } catch (e) {
    console.error('2fa/backup-use', e);
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
      tx.set(once, { uid: req.uid, minutes: minutes, at: FV.serverTimestamp() });
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

/* Lesquels de ces comptes refusent d'etre ajoutes a un groupe par `adder` ?
   Reglage "Groupes" : Tout le monde / Mes contacts (adder doit figurer dans SON carnet) / Personne ; un compte qui a bloque adder refuse aussi. */
async function groupRefusals(adder, uids) {
  const refused = [];
  for (let i = 0; i < uids.length; i += 20) {
    await Promise.all(uids.slice(i, i + 20).map(async function (u) {
      const ref = db.collection('users').doc(u);
      const [bl, us] = await Promise.all([ref.collection('blocked').doc(adder).get(), ref.get()]);
      if (!us.exists) { refused.push(u); return; }
      if (bl.exists) { refused.push(u); return; }
      const pv = us.data().prefs && us.data().prefs.privacy && us.data().prefs.privacy.groups;
      const mode = pv || 'Mes contacts';
      if (mode === 'Tout le monde') return;
      if (mode === 'Personne') { refused.push(u); return; }
      const inBook = await ref.collection('contacts').doc(adder).get();
      if (!inBook.exists) refused.push(u);
    }));
  }
  return refused;
}
function cleanUids(list, self) {
  return Array.from(new Set((Array.isArray(list) ? list : []).map(String))).filter(function (u) { return /^[A-Za-z0-9_-]{6,128}$/.test(u) && u !== self; });
}
const groupLog = new Map();
function groupRate(uid, max) {
  const now = Date.now();
  const recent = (groupLog.get(uid) || []).filter(function (t) { return now - t < 60000; });
  if (recent.length >= max) return false;
  recent.push(now); groupLog.set(uid, recent);
  return true;
}

/* POST /group-check  { uids } : verification seule (apercu avant creation / ajout) */
app.post('/group-check', requireUser, async function (req, res) {
  try {
    const uids = cleanUids(req.body.uids, req.uid).slice(0, 200);
    if (!uids.length) return res.json({ ok: true, refused: [] });
    if (!groupRate(req.uid, 30)) return res.status(429).json({ ok: false, error: 'Trop de verifications. Patientez un instant.' });
    return res.json({ ok: true, refused: await groupRefusals(req.uid, uids) });
  } catch (e) {
    console.error('group-check', e);
    return res.status(500).json({ ok: false, error: 'Verification impossible pour le moment.' });
  }
});

/* POST /group-create  { name, photoURL, members }
   Les groupes sont crees par le serveur : les membres ajoutes respectent leur reglage "Groupes" (les regles Firestore interdisent la creation directe). */
app.post('/group-create', requireUser, async function (req, res) {
  try {
    const name = String(req.body.name || '').trim().slice(0, 80);
    const photoURL = String(req.body.photoURL || '');
    if (!name) return res.status(400).json({ ok: false, error: 'Donnez un nom au groupe.' });
    if (photoURL && !/^https:\/\/res\.cloudinary\.com\//.test(photoURL)) return res.status(400).json({ ok: false, error: 'Photo invalide.' });
    const wanted = cleanUids(req.body.members, req.uid).slice(0, 999);
    if (!groupRate(req.uid, 10)) return res.status(429).json({ ok: false, error: 'Trop de groupes crees. Patientez un instant.' });
    const refused = await groupRefusals(req.uid, wanted);
    const members = [req.uid].concat(wanted.filter(function (u) { return refused.indexOf(u) === -1; }));
    if (members.length < 2) return res.status(400).json({ ok: false, error: 'Aucun membre ne peut etre ajoute selon ses reglages de confidentialite.', refused: refused });
    const FV = admin.firestore.FieldValue;
    const ref = db.collection('groups').doc();
    await ref.set({
      photoURL: photoURL, name: name, members: members, admins: [req.uid], createdBy: req.uid,
      createdAt: FV.serverTimestamp(), lastMessage: '', lastMessageAt: FV.serverTimestamp(), lastSenderId: '', lastSenderName: ''
    });
    return res.json({ ok: true, gid: ref.id, refused: refused });
  } catch (e) {
    console.error('group-create', e);
    return res.status(500).json({ ok: false, error: 'Creation du groupe impossible pour le moment.' });
  }
});

/* POST /group-add  { gid, uids } : un administrateur ajoute des membres (reglage "Groupes" de chacun respecte) */
app.post('/group-add', requireUser, async function (req, res) {
  try {
    const gid = String(req.body.gid || '');
    if (!/^[A-Za-z0-9_-]{6,60}$/.test(gid)) return res.status(400).json({ ok: false, error: 'Requete invalide.' });
    if (!groupRate(req.uid, 20)) return res.status(429).json({ ok: false, error: 'Trop de demandes. Patientez un instant.' });
    const ref = db.collection('groups').doc(gid);
    const g = await ref.get();
    if (!g.exists || (g.data().admins || []).indexOf(req.uid) === -1) return res.status(403).json({ ok: false, error: 'Reserve aux administrateurs.' });
    const current = g.data().members || [];
    const wanted = cleanUids(req.body.uids, req.uid).filter(function (u) { return current.indexOf(u) === -1; }).slice(0, 200);
    const refused = await groupRefusals(req.uid, wanted);
    const add = wanted.filter(function (u) { return refused.indexOf(u) === -1; });
    if (add.length) {
      const FV = admin.firestore.FieldValue, upd = { members: FV.arrayUnion.apply(FV, add) };
      add.forEach(function (u) { upd['joinedAt.' + u] = FV.serverTimestamp(); });
      await ref.update(upd);
    }
    return res.json({ ok: true, added: add, refused: refused });
  } catch (e) {
    console.error('group-add', e);
    return res.status(500).json({ ok: false, error: 'Ajout impossible pour le moment.' });
  }
});

/* ---------- Appareils connectes : sessions par appareil, deconnexion a distance, alerte de nouvelle connexion ----------
   Chaque appareil recoit un secret (stocke sur l'appareil, seul son hache est garde ici). La deconnexion a distance :
   - marque l'appareil comme revoque et invalide tous les jetons de renouvellement du compte (revokeRefreshTokens) ;
   - les autres appareils reprennent seuls leur session avec leur secret (/device-session) ; l'appareil revoque ne le peut plus.
   Un appareil hors ligne est donc deconnecte au plus tard a son prochain renouvellement de jeton (au maximum une heure apres sa reconnexion). */
function sha(v) { return crypto.createHash('sha256').update(String(v)).digest('hex'); }
const deviceLog = new Map();
function deviceRate(key, max, windowMs) {
  const now = Date.now();
  const recent = (deviceLog.get(key) || []).filter(function (t) { return now - t < windowMs; });
  if (recent.length >= max) return false;
  recent.push(now); deviceLog.set(key, recent);
  return true;
}
/* Lieu approximatif d'une connexion (ville, pays) a partir de l'adresse IP, via un service public sans cle. Facultatif : vide en cas d'echec. */
async function placeOfIp(ip) {
  try {
    ip = String(ip || '').split(',')[0].trim().replace(/^::ffff:/, '');
    if (!ip || /^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1|fe80)/i.test(ip)) return '';
    const ctrl = new AbortController(); const t = setTimeout(function () { ctrl.abort(); }, 2500);
    const r = await fetch('https://ipwho.is/' + encodeURIComponent(ip) + '?fields=success,city,country', { signal: ctrl.signal });
    clearTimeout(t);
    const j = await r.json();
    if (!j || !j.success) return '';
    return [j.city, j.country].filter(Boolean).join(', ').slice(0, 80);
  } catch (e) { return ''; }
}
function cleanDeviceId(v) { v = String(v || ''); return /^[A-Za-z0-9_-]{6,60}$/.test(v) ? v : ''; }
function sendMailTo(email, subject, html) {
  return fetch('https://api.brevo.com/v3/smtp/email', {
    method: 'POST',
    headers: { 'accept': 'application/json', 'content-type': 'application/json', 'api-key': BREVO_API_KEY },
    body: JSON.stringify({ sender: { name: SENDER_NAME, email: SENDER_EMAIL }, to: [{ email: email }], subject: subject, htmlContent: html })
  }).catch(function () {});
}

/* POST /device-register  { deviceId, name }  : enregistre l'appareil (ou le met a jour) et renvoie son secret quand il en recoit un */
app.post('/device-register', requireUser, async function (req, res) {
  try {
    const id = cleanDeviceId(req.body.deviceId);
    const name = String(req.body.name || 'Appareil').slice(0, 80);
    const given = String(req.body.secret || '');
    if (!id) return res.status(400).json({ ok: false, error: 'Appareil invalide.' });
    if (!deviceRate('reg:' + req.uid, 30, 60000)) return res.status(429).json({ ok: false, error: 'Trop de requetes.' });
    const FV = admin.firestore.FieldValue;
    const col = db.collection('users').doc(req.uid).collection('devices');
    const ref = col.doc(id);
    const snap = await ref.get();
    if (snap.exists && snap.data().revoked) return res.json({ ok: true, revoked: true });
    const out = { ok: true, revoked: false };
    const data = { name: name, lastActiveAt: Date.now() };
    const hasSecret = snap.exists && snap.data().secretHash && given && sha(given) === snap.data().secretHash;
    if (!hasSecret) {
      const secret = crypto.randomBytes(32).toString('hex');
      data.secretHash = sha(secret);
      out.secret = secret;
    }
    const isNew = !snap.exists;
    if (isNew) data.createdAt = Date.now();
    let place = '';
    if (isNew || !(snap.exists && snap.data().place)) { place = await placeOfIp(req.headers['x-forwarded-for'] || req.ip); if (place) data.place = place; }
    await ref.set(data, { merge: true });

    // menage : appareils revoques depuis plus de 7 jours
    col.where('revoked', '==', true).get().then(function (q) {
      q.forEach(function (d) { if ((d.data().revokedAt || 0) < Date.now() - 7 * 86400000) d.ref.delete().catch(function () {}); });
    }).catch(function () {});

    if (isNew) {
      // alerte de nouvelle connexion : seulement si le compte avait deja un autre appareil
      const others = (await col.get()).docs.filter(function (d) { return d.id !== id && !d.data().revoked; });
      if (others.length && deviceRate('alert:' + req.uid, 5, 3600000)) {
        const when = new Date().toLocaleString('fr-FR', { timeZone: 'Africa/Porto-Novo', dateStyle: 'long', timeStyle: 'short' });
        const where = place ? ' près de ' + place + ' (approximatif)' : '';
        const body = name + where + ', ' + when + '. Si ce n\'est pas vous, fermez cette session dans Paramètres puis changez votre mot de passe.';
        writeNotif(req.uid, 'dev_' + id, { type: 'security', title: 'Nouvelle connexion à votre compte', body: body }, false).catch(function () {});
        pushTo([req.uid], { title: 'Nouvelle connexion à votre compte', body: body, tag: 'newdevice-' + id, urgent: true, data: { type: 'security' } }).catch(function () {});
        try {
          const u = await admin.auth().getUser(req.uid);
          if (u.email) {
            sendMailTo(u.email, 'Nouvelle connexion à votre compte NexChat',
              '<div style="font-family:Arial,Helvetica,sans-serif;font-size:14px;color:#0b1b4d;line-height:1.6;max-width:480px;">' +
              '<h2 style="margin:0 0 10px;">Nouvelle connexion</h2>' +
              '<p>Votre compte NexChat vient d\'être ouvert sur un nouvel appareil :</p>' +
              '<p style="background:#f4f7fc;border-radius:10px;padding:12px 14px;"><strong>' + escHtml(name) + '</strong><br>' + escHtml(when) + (place ? '<br>Lieu approximatif : ' + escHtml(place) : '') + '</p>' +
              '<p>Si c\'est vous, vous n\'avez rien à faire. Sinon, ouvrez NexChat, allez dans <strong>Paramètres &gt; Appareils connectés</strong>, fermez cette session, puis changez votre mot de passe.</p></div>');
          }
        } catch (e) { /* email facultatif */ }
      }
    }
    return res.json(out);
  } catch (e) {
    console.error('device-register', e);
    return res.status(500).json({ ok: false, error: 'Appareil non enregistre.' });
  }
});

/* POST /device-revoke  { deviceId }  : deconnexion a distance d'un autre appareil */
app.post('/device-revoke', requireUser, async function (req, res) {
  try {
    if (!deviceRate('rev:' + req.uid, 20, 60000)) return res.status(429).json({ ok: false, error: 'Trop de requetes.' });
    if (req.body.all === true) {
      // fermer tous les autres appareils : celui qui demande (keep) est conserve
      const keep = cleanDeviceId(req.body.keep);
      const all = await db.collection('users').doc(req.uid).collection('devices').get();
      const batch = db.batch();
      all.forEach(function (d) {
        if (d.id === keep || d.data().revoked) return;
        batch.set(d.ref, { revoked: true, revokedAt: Date.now(), secretHash: admin.firestore.FieldValue.delete() }, { merge: true });
      });
      await batch.commit();
      await admin.auth().revokeRefreshTokens(req.uid);
      return res.json({ ok: true });
    }
    const id = cleanDeviceId(req.body.deviceId);
    if (!id) return res.status(400).json({ ok: false, error: 'Appareil invalide.' });
    const ref = db.collection('users').doc(req.uid).collection('devices').doc(id);
    const snap = await ref.get();
    if (!snap.exists) return res.json({ ok: true });
    await ref.set({ revoked: true, revokedAt: Date.now(), secretHash: admin.firestore.FieldValue.delete() }, { merge: true });
    // invalide les jetons de renouvellement : l'appareil revoque est deconnecte au prochain renouvellement, meme hors ligne
    await admin.auth().revokeRefreshTokens(req.uid);
    return res.json({ ok: true });
  } catch (e) {
    console.error('device-revoke', e);
    return res.status(500).json({ ok: false, error: 'Deconnexion impossible pour le moment.' });
  }
});

/* POST /device-unregister  { deviceId }  : l'appareil se deconnecte lui-meme (pas de revocation des autres) */
app.post('/device-unregister', requireUser, async function (req, res) {
  try {
    const id = cleanDeviceId(req.body.deviceId);
    if (!id) return res.json({ ok: true });
    await db.collection('users').doc(req.uid).collection('devices').doc(id).delete().catch(function () {});
    return res.json({ ok: true });
  } catch (e) { return res.json({ ok: true }); }
});

/* POST /device-session  { uid, deviceId, secret }  : un appareil dont le jeton a ete invalide reprend sa session avec son secret.
   Pas de jeton Firebase ici (il est mort) : le secret de l'appareil fait foi ; un appareil revoque n'en a plus. */
const sessionLimiter = rateLimit({ windowMs: 60 * 1000, limit: 20, standardHeaders: true, legacyHeaders: false, message: { ok: false, error: 'Trop de tentatives.' } });
app.post('/device-session', sessionLimiter, async function (req, res) {
  try {
    const uid = String(req.body.uid || ''), id = cleanDeviceId(req.body.deviceId), secret = String(req.body.secret || '');
    if (!/^[A-Za-z0-9_-]{6,128}$/.test(uid) || !id || !/^[0-9a-f]{64}$/.test(secret)) return res.status(400).json({ ok: false });
    const ref = db.collection('users').doc(uid).collection('devices').doc(id);
    const snap = await ref.get();
    if (!snap.exists || snap.data().revoked) return res.status(403).json({ ok: false, revoked: true });
    const h = snap.data().secretHash || '';
    if (!h || h.length !== 64 || !crypto.timingSafeEqual(Buffer.from(h), Buffer.from(sha(secret)))) return res.status(403).json({ ok: false, revoked: true });
    // tfd : cet appareil a deja passe la verification en deux etapes (son secret n'est delivre qu'a une session verifiee)
    const token = await admin.auth().createCustomToken(uid, { tfd: 1 });
    ref.set({ lastActiveAt: Date.now() }, { merge: true }).catch(function () {});
    return res.json({ ok: true, token: token });
  } catch (e) {
    console.error('device-session', e);
    return res.status(500).json({ ok: false });
  }
});

/* POST /find-user  { email } ou { phoneKey } ou { phoneLocal }  : renvoie { uid, name, photo } pour une correspondance exacte (phoneLocal : numero saisi sans indicatif, correspondance sur les 8 derniers chiffres, renvoie { users: [...] }) (les profils prives ne sont plus lisibles par les autres comptes) */
app.post('/find-user', requireUser, async function (req, res) {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const phoneKey = String(req.body.phoneKey || '').replace(/\D/g, '');
    const phoneLocal = String(req.body.phoneLocal || '').replace(/\D/g, '');
    let field, val, tailMode = false;
    if (email) {
      if (email.length > 254 || email.indexOf('@') < 1) return res.status(400).json({ ok: false, error: 'Adresse email invalide.' });
      field = 'emailLower'; val = email;
    } else if (phoneKey) {
      if (phoneKey.length < 7 || phoneKey.length > 15) return res.status(400).json({ ok: false, error: 'Numero invalide.' });
      field = 'phoneKey'; val = phoneKey;
    } else if (phoneLocal) {
      if (phoneLocal.length < 8 || phoneLocal.length > 15) return res.status(400).json({ ok: false, error: 'Saisissez au moins 8 chiffres, ou le numero complet avec l\'indicatif.' });
      tailMode = true;
    } else {
      return res.status(400).json({ ok: false, error: 'Requete invalide.' });
    }

    const now = Date.now();
    const recent = (searchLog.get(req.uid) || []).filter(function (t) { return now - t < 60000; });
    if (recent.length >= 30) return res.status(429).json({ ok: false, error: 'Trop de recherches. Patientez un instant.' });
    recent.push(now); searchLog.set(req.uid, recent);

    if (tailMode) {
      // Correspondance sur les 8 derniers chiffres (champ phoneTail), puis tri par nombre de chiffres communs en fin de numero
      const typed = phoneLocal.replace(/^0+/, '');
      const ts = await db.collection('users').where('phoneTail', '==', phoneLocal.slice(-8)).limit(10).get();
      const cands = ts.docs.filter(function (c) { return c.id !== req.uid; }).map(function (c) {
        const pk = String(c.data().phoneKey || '');
        let common = 0;
        while (common < pk.length && common < typed.length && pk[pk.length - 1 - common] === typed[typed.length - 1 - common]) common++;
        return { d: c, common: common };
      }).filter(function (c) { return c.common >= 8; }).sort(function (a, b) { return b.common - a.common; }).slice(0, 5);
      const found = await Promise.all(cands.map(async function (c) {
        const x = c.d.data();
        const ref = db.collection('users').doc(c.d.id);
        const blk = await ref.collection('blocked').doc(req.uid).get().then(function (s2) { return s2.exists; }).catch(function () { return false; });
        if (blk) return null;
        const vis = (x.prefs && x.prefs.privacy && x.prefs.privacy.photo) || 'Mes contacts';
        let photo = '';
        if (x.photoURL) {
          if (vis === 'Tout le monde') photo = x.photoURL;
          else if (vis === 'Mes contacts') {
            const isC = await ref.collection('contacts').doc(req.uid).get().then(function (s2) { return s2.exists; }).catch(function () { return false; });
            if (isC) photo = x.photoURL;
          }
        }
        return { uid: c.d.id, name: x.displayName || 'Utilisateur', photo: photo };
      }));
      return res.json({ ok: true, users: found.filter(Boolean) });
    }

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

/* Retrait d'un avis : supprime l'avis et retire sa note du produit et de la boutique (une seule transaction) */
async function removeReview(pid, rid) {
  const FV = admin.firestore.FieldValue;
  const pref = db.collection('products').doc(pid), rref = pref.collection('reviews').doc(rid);
  const out = await db.runTransaction(async function (tx) {
    const [p, r] = await Promise.all([tx.get(pref), tx.get(rref)]);
    if (!r.exists) return false;
    const old = Number(r.data().rating) || 0;
    tx.delete(rref);
    if (p.exists) {
      const delta = { ratingSum: FV.increment(-old), ratingCount: FV.increment(-1) };
      tx.set(pref, delta, { merge: true });
      tx.set(db.collection('shops').doc(String(p.data().shopId)), delta, { merge: true });
    }
    return true;
  });
  return out;
}

/* POST /review-delete  { pid }  : l'acheteur supprime son propre avis (son droit d'avis reste : il peut en donner un nouveau) */
app.post('/review-delete', requireUser, async function (req, res) {
  try {
    const pid = String(req.body.pid || '');
    if (!validPid(pid)) return res.status(400).json({ ok: false, error: 'Requete invalide.' });
    if (!limitReview(req.uid, 10)) return res.status(429).json({ ok: false, error: 'Trop de tentatives. Patientez un instant.' });
    const removed = await removeReview(pid, req.uid);
    if (!removed) return res.status(404).json({ ok: false, error: 'Avis introuvable.' });
    return res.json({ ok: true });
  } catch (e) {
    console.error('review-delete', e);
    return res.status(500).json({ ok: false, error: 'Suppression impossible pour le moment.' });
  }
});

/* ---------- Administration des avis signales, depuis l'appli ----------
   Les administrateurs sont les comptes dont l'email (confirme) figure dans la variable ADMIN_EMAILS (separes par des virgules).
   Sans cette variable, aucun compte n'est administrateur. La route /admin/review-remove avec ADMIN_KEY reste disponible. */
const ADMIN_EMAILS = String(process.env.ADMIN_EMAILS || '').toLowerCase().split(',').map(function (x) { return x.trim(); }).filter(Boolean);
function isAdminUser(req) {
  const em = String((req.decoded && req.decoded.email) || '').toLowerCase();
  return !!em && ADMIN_EMAILS.indexOf(em) !== -1 && req.decoded.email_verified === true;
}
function requireAdminUser(req, res, next) {
  if (!isAdminUser(req)) return res.status(403).json({ ok: false, error: 'Acces refuse.' });
  return next();
}

/* POST /admin/me : indique si le compte connecte est administrateur */
app.post('/admin/me', requireUser, function (req, res) { return res.json({ ok: true, admin: isAdminUser(req) }); });

/* POST /admin/reports : avis signales en attente (les plus recents d'abord) */
app.post('/admin/reports', requireUser, requireAdminUser, async function (req, res) {
  try {
    const snap = await db.collection('reviewReports').where('status', '==', 'open').limit(100).get();
    const list = snap.docs.map(function (d) {
      const x = d.data();
      return { pid: x.pid, rid: x.rid, productName: x.productName || '', rating: x.rating || 0, text: x.text || '', reviewer: x.reviewer || '', reason: x.reason || '', at: (x.at && x.at.toMillis) ? x.at.toMillis() : 0 };
    }).sort(function (a, b) { return b.at - a.at; });
    return res.json({ ok: true, reports: list });
  } catch (e) {
    console.error('admin/reports', e);
    return res.status(500).json({ ok: false, error: 'Lecture impossible pour le moment.' });
  }
});

/* POST /admin/review-resolve  { pid, rid, action: 'remove' | 'dismiss' } */
app.post('/admin/review-resolve', requireUser, requireAdminUser, async function (req, res) {
  try {
    const pid = String(req.body.pid || ''), rid = String(req.body.rid || ''), action = String(req.body.action || '');
    if (!validPid(pid) || !validPid(rid) || (action !== 'remove' && action !== 'dismiss')) return res.status(400).json({ ok: false, error: 'Requete invalide.' });
    if (action === 'remove') await removeReview(pid, rid);
    await db.collection('reviewReports').doc(pid + '_' + rid).set({ status: action === 'remove' ? 'removed' : 'dismissed', resolvedAt: admin.firestore.FieldValue.serverTimestamp(), resolvedBy: req.uid }, { merge: true });
    return res.json({ ok: true });
  } catch (e) {
    console.error('admin/review-resolve', e);
    return res.status(500).json({ ok: false, error: 'Action impossible pour le moment.' });
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
    await removeReview(pid, rid);
    await db.collection('reviewReports').doc(pid + '_' + rid).set({ status: 'removed', resolvedAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true }).catch(function () {});
    return res.json({ ok: true });
  } catch (e) {
    console.error('admin/review-remove', e);
    return res.status(500).json({ ok: false });
  }
});

/* POST /admin/2fa-release  { uid } ou { email } ou { all: true }  (en-tete x-admin-key = ADMIN_KEY) : efface les revendications 2FA (needs2fa, tfS)
   pour debloquer un compte ; { disable: true } desactive aussi la 2FA du compte. Les jetons deja emis gardent leurs revendications jusqu'a une heure. */
app.post('/admin/2fa-release', async function (req, res) {
  try {
    const key = String(process.env.ADMIN_KEY || '');
    const given = String(req.headers['x-admin-key'] || '');
    if (!key || given.length !== key.length || !crypto.timingSafeEqual(Buffer.from(given), Buffer.from(key))) return res.status(403).json({ ok: false });
    const disable = req.body.disable === true;
    async function release(uid) {
      await setTfClaims(uid, function (c) { delete c.needs2fa; delete c.tfS; });
      if (disable) { await db.collection('users').doc(uid).set({ twoFactor: false }, { merge: true }); await bcol.doc(uid).delete().catch(function () {}); }
    }
    if (req.body.all === true) {
      let n = 0, token;
      do {
        const page = await auth.listUsers(1000, token);
        for (const u of page.users) {
          const c = u.customClaims || {};
          if (c.needs2fa !== undefined || c.tfS !== undefined) { await release(u.uid); n++; }
        }
        token = page.pageToken;
      } while (token);
      return res.json({ ok: true, released: n });
    }
    let uid = String(req.body.uid || '');
    if (!uid && req.body.email) { const u = await findUser(normEmail(req.body.email)); uid = u ? u.uid : ''; }
    if (!/^[A-Za-z0-9_-]{6,128}$/.test(uid)) return res.status(400).json({ ok: false });
    await release(uid);
    return res.json({ ok: true, released: 1 });
  } catch (e) {
    console.error('admin/2fa-release', e);
    return res.status(500).json({ ok: false });
  }
});

/* Migration (une fois, marqueur meta/phoneTailMigration) : champ phoneTail (8 derniers chiffres du telephone) pour la recherche par numero local.
   Les comptes crees apres cette mise a jour l'ont des l'inscription ; les autres l'ont aussi a leur prochaine connexion. */
async function migratePhoneTail() {
  try {
    const markRef = db.collection('meta').doc('phoneTailMigration');
    const mark = await markRef.get();
    if (mark.exists && Number(mark.data().version || 0) >= 1) { console.log('migratePhoneTail : deja effectuee'); return; }
    const all = await db.collection('users').select('phone', 'phoneKey', 'phoneTail').get();
    let n = 0, batch = db.batch(), inBatch = 0;
    for (const d of all.docs) {
      const x = d.data();
      const digits = String(x.phoneKey || x.phone || '').replace(/\D/g, '');
      if (digits.length < 8) continue;
      const tail = digits.slice(-8);
      if (x.phoneTail === tail && x.phoneKey === digits) continue;
      batch.set(d.ref, { phoneKey: digits, phoneTail: tail }, { merge: true }); n++; inBatch++;
      if (inBatch >= 400) { await batch.commit(); batch = db.batch(); inBatch = 0; }
    }
    if (inBatch) await batch.commit();
    await markRef.set({ version: 1, at: Date.now(), accounts: n });
    console.log('migratePhoneTail : ' + n + ' comptes');
  } catch (e) {
    console.error('migratePhoneTail', e);
  }
}

/* Migration (une fois, marqueur meta/twoFactorMigration) : les comptes dont la 2FA est deja activee recoivent la revendication needs2fa.
   Leurs sessions ouvertes devront saisir un code une fois (au plus tard au renouvellement du jeton). MIGRATE_2FA=off la desactive. */
async function migrateTwoFactor() {
  try {
    if (String(process.env.MIGRATE_2FA || 'on').toLowerCase() === 'off') return;
    const markRef = db.collection('meta').doc('twoFactorMigration');
    const mark = await markRef.get();
    if (mark.exists && Number(mark.data().version || 0) >= 1) { console.log('migrateTwoFactor : deja effectuee'); return; }
    const q = await db.collection('users').where('twoFactor', '==', true).get();
    let n = 0;
    for (const d of q.docs) {
      try { await setTfClaims(d.id, function (c) { c.needs2fa = true; if (!Array.isArray(c.tfS)) c.tfS = []; }); n++; }
      catch (e) { console.error('migrateTwoFactor', d.id, e.code || e.message); }
    }
    await markRef.set({ version: 1, at: Date.now(), accounts: n });
    console.log('migrateTwoFactor : ' + n + ' comptes');
  } catch (e) {
    console.error('migrateTwoFactor', e);
  }
}

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

app.listen(PORT, function () { console.log('NexChat backend sur le port ' + PORT); migrateProfiles(); migrateSales().then(migrateReviews).then(migrateTwoFactor).then(migratePhoneTail); });
