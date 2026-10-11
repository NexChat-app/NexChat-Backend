'use strict';
/* =====================================================================================================
   MODERATION NEXCHAT
   - Lit regulierement les nouveaux contenus (messages prives et de groupe, stories, commentaires, produits),
     analyse le texte (regles locales), les images et videos (nsfwjs local, ou Google Vision si une cle est fournie)
     et les vocaux (transcription Groq si une cle est fournie, puis analyse du texte).
   - Cree un signalement automatique dans modFlags. Contenu grave (severite "high") : masque tout de suite en
     attendant la decision de l'admin. Contenu douteux ("medium") : seulement signale.
   - L'admin peut : ignorer (le contenu est remis), mettre en garde (compteur modUsers, 3 maximum), retirer le contenu,
     puis desactiver ou bannir le compte apres 3 avertissements.
   Aucune sanction n'est automatique : seul l'admin decide.
   ===================================================================================================== */
const crypto = require('crypto');
const path = require('path');
const { fork } = require('child_process');
const { analyzeText } = require('./mod-text');

const WARN_LIMIT = 3;
const HIDDEN_PREVIEW = 'Contenu masqué par la modération';
const VISION_KEY = process.env.GOOGLE_VISION_API_KEY || '';
const GROQ_KEY = process.env.GROQ_API_KEY || '';
const POLL_MS = Math.max(15, Number(process.env.MOD_POLL_SECONDS) || 30) * 1000;
const ENABLED = String(process.env.MODERATION || 'on').toLowerCase() !== 'off';

const SEV = { high: 3, medium: 2, low: 1 };
const PRIORITY = { minors: 7, threat: 6, sexual: 5, violence: 4, hate: 3, harassment: 2, scam: 1, illegal: 1 };

function sha(s) { return crypto.createHash('sha1').update(String(s)).digest('hex'); }
function clip(v, n) { return String(v || '').slice(0, n); }

/* ------------------------------------------------------------------ images ------------------------------------------------------------------ */
const CLD = /^(https:\/\/res\.cloudinary\.com\/[^/]+\/)(image|video)(\/upload\/)(.+)$/;
/* miniatures Cloudinary : l'analyse porte sur une petite image JPEG, jamais sur le fichier d'origine */
function frameUrls(url, type) {
  const m = CLD.exec(String(url || ''));
  if (!m) return [];
  if (m[2] === 'image') return [m[1] + 'image' + m[3] + 'w_320,h_320,c_limit,f_jpg,q_70/' + m[4]];
  const base = m[4].replace(/\.[a-z0-9]{2,4}$/i, '') + '.jpg';
  return ['1', '4'].map(function (so) { return m[1] + 'video' + m[3] + 'so_' + so + ',w_320,c_limit,q_70/' + base; });
}

let worker = null, workerSeq = 0, localOffUntil = 0;
const workerPending = new Map();
function ensureWorker() {
  if (worker) return worker;
  worker = fork(path.join(__dirname, 'nsfw-worker.js'), [], { execArgv: ['--max-old-space-size=220'], stdio: ['ignore', 'inherit', 'inherit', 'ipc'] });
  worker.on('message', function (m) {
    const p = workerPending.get(m.id); if (!p) return;
    workerPending.delete(m.id); clearTimeout(p.t);
    if (m.ok) p.resolve(m.p); else p.reject(new Error(m.error || 'echec'));
  });
  worker.on('exit', function (code) {
    worker = null;
    workerPending.forEach(function (p) { clearTimeout(p.t); p.reject(new Error('processus arrete')); });
    workerPending.clear();
    if (code) { localOffUntil = Date.now() + 60 * 60 * 1000; console.error('moderation : analyse d\'images locale arretee (code ' + code + '). Verifiez que nsfwjs, @tensorflow/tfjs et jpeg-js sont installes.'); }
  });
  worker.on('error', function (e) { console.error('moderation worker', e.message); });
  return worker;
}
function classifyLocal(url) {
  return new Promise(function (resolve, reject) {
    if (Date.now() < localOffUntil) return reject(new Error('analyse locale indisponible'));
    const id = ++workerSeq;
    const t = setTimeout(function () { workerPending.delete(id); reject(new Error('delai depasse')); }, 60000);
    workerPending.set(id, { resolve: resolve, reject: reject, t: t });
    try { ensureWorker().send({ id: id, url: url }); } catch (e) { workerPending.delete(id); clearTimeout(t); reject(e); }
  });
}
function nsfwVerdict(p) {
  const porn = p.porn || 0, hentai = p.hentai || 0, sexy = p.sexy || 0;
  if (porn >= 0.75 || porn + hentai >= 0.85) return { severity: 'high', category: 'sexual', label: 'porn ' + Math.round((porn + hentai) * 100) + '%' };
  if (porn >= 0.45 || hentai >= 0.6 || sexy >= 0.88) return { severity: 'medium', category: 'sexual', label: 'suggestive ' + Math.round(Math.max(porn + hentai, sexy) * 100) + '%' };
  return null;
}
const LEVEL = { VERY_UNLIKELY: 0, UNLIKELY: 1, POSSIBLE: 2, LIKELY: 3, VERY_LIKELY: 4 };
async function visionVerdict(url) {
  const r = await fetch('https://vision.googleapis.com/v1/images:annotate?key=' + encodeURIComponent(VISION_KEY), {
    method: 'POST', headers: { 'content-type': 'application/json' }, signal: AbortSignal.timeout(20000),
    body: JSON.stringify({ requests: [{ image: { source: { imageUri: url } }, features: [{ type: 'SAFE_SEARCH_DETECTION' }] }] })
  });
  const j = await r.json();
  const s = j && j.responses && j.responses[0] && j.responses[0].safeSearchAnnotation;
  if (!s) throw new Error((j && j.error && j.error.message) || 'reponse vide');
  const adult = LEVEL[s.adult] || 0, racy = LEVEL[s.racy] || 0, violence = LEVEL[s.violence] || 0;
  if (adult >= 4) return { severity: 'high', category: 'sexual', label: 'adult' };
  if (adult === 3 || racy >= 4) return { severity: 'medium', category: 'sexual', label: adult === 3 ? 'adult (likely)' : 'racy' };
  if (violence >= 4) return { severity: 'medium', category: 'violence', label: 'violence' };
  return null;
}
const health = { image: VISION_KEY ? 'vision' : 'local', audio: GROQ_KEY ? 'groq' : 'off', imgOk: 0, imgFail: 0, lastImgError: '', streams: {}, lastCycleAt: 0, enabled: ENABLED };

async function scanImage(media) {
  const frames = frameUrls(media.url, media.type);
  let best = null;
  for (const f of frames) {
    try {
      const v = VISION_KEY ? await visionVerdict(f) : nsfwVerdict(await classifyLocal(f));
      health.imgOk++;
      if (v && (!best || SEV[v.severity] > SEV[best.severity])) best = v;
      if (best && best.severity === 'high') break;
    } catch (e) { health.imgFail++; health.lastImgError = clip(e.message, 160); }
  }
  return best;
}

/* ------------------------------------------------------------------ vocaux ------------------------------------------------------------------ */
async function transcribe(url) {
  if (!GROQ_KEY || !CLD.test(String(url || ''))) return '';
  try {
    const r = await fetch(url, { signal: AbortSignal.timeout(25000) });
    if (!r.ok) return '';
    const buf = Buffer.from(await r.arrayBuffer());
    if (buf.length > 12 * 1024 * 1024) return '';
    const fd = new FormData();
    fd.append('file', new Blob([buf]), 'voice.' + ((/\.([a-z0-9]{2,4})(?:\?|$)/i.exec(url) || [])[1] || 'webm'));
    fd.append('model', 'whisper-large-v3-turbo'); fd.append('response_format', 'json'); fd.append('temperature', '0');
    const t = await fetch('https://api.groq.com/openai/v1/audio/transcriptions', { method: 'POST', headers: { Authorization: 'Bearer ' + GROQ_KEY }, body: fd, signal: AbortSignal.timeout(60000) });
    const j = await t.json();
    return clip(j && j.text, 4000);
  } catch (e) { health.lastImgError = 'audio: ' + clip(e.message, 140); return ''; }
}

/* ------------------------------------------------------------------ module ------------------------------------------------------------------ */
function init(D) {
  const db = D.db, admin = D.admin, auth = D.auth;
  const FV = admin.firestore.FieldValue, TS = admin.firestore.Timestamp;
  const flags = db.collection('modFlags'), modUsers = db.collection('modUsers'), modTrack = db.collection('modTrack'), stateDoc = db.collection('modState').doc('cursors');

  /* ---------- annuaire (cache court) ---------- */
  const uCache = new Map();
  async function userInfo(uid) {
    const c = uCache.get(uid);
    if (c && Date.now() - c.at < 5 * 60 * 1000) return c.v;
    let v = { uid: uid, name: 'Utilisateur', email: '', disabled: false };
    try { const u = await auth.getUser(uid); v = { uid: uid, name: u.displayName || (u.email || '').split('@')[0] || 'Utilisateur', email: u.email || '', disabled: !!u.disabled }; } catch (e) { v.deleted = true; }
    uCache.set(uid, { at: Date.now(), v: v });
    return v;
  }
  let adminUids = { at: 0, list: [] };
  async function getAdminUids() {
    if (Date.now() - adminUids.at < 10 * 60 * 1000) return adminUids.list;
    const out = [];
    for (const e of D.adminEmails) { try { out.push((await auth.getUserByEmail(e)).uid); } catch (x) { /* compte absent */ } }
    adminUids = { at: Date.now(), list: out };
    return out;
  }

  /* ---------- description d'un contenu ---------- */
  const SKIP_TYPES = { deleted: 1, contact: 1, location: 1, poll: 1, event: 1, order: 1, product: 1, file: 1 };
  const CLOUD_URL = /^https:\/\/res\.cloudinary\.com\//;
  function describe(p, d) {
    const s = p.split('/');
    const media = [];
    function addMedia(type, url) { if (typeof url === 'string' && CLOUD_URL.test(url)) media.push({ type: type, url: url }); }
    if ((s[0] === 'conversations' || s[0] === 'groups') && s[2] === 'messages' && s.length === 4) {
      if (!d.senderId || SKIP_TYPES[d.type]) return null;
      if (d.type === 'image' || d.type === 'video' || d.type === 'audio') addMedia(d.type, d.url);
      const priv = s[0] === 'conversations';
      return { kind: 'message', owner: d.senderId, texts: typeof d.text === 'string' ? [d.text] : [], media: media,
        chat: { kind: priv ? 'private' : 'group', id: s[1] }, targets: priv ? s[1].split('_').filter(function (u) { return u !== d.senderId; }) : [] };
    }
    if (s[0] === 'statuses' && s.length === 2) {
      if (!d.authorId) return null;
      if (d.type === 'image' || d.type === 'video') addMedia(d.type, d.url);
      return { kind: 'status', owner: d.authorId, texts: typeof d.text === 'string' ? [d.text] : [], media: media, chat: { kind: 'status', id: s[1] }, targets: [] };
    }
    if (s[0] === 'statuses' && s[2] === 'comments' && s.length === 4) {
      if (!d.authorId) return null;
      addMedia('image', d.imageUrl);
      return { kind: 'comment', owner: d.authorId, texts: typeof d.text === 'string' ? [d.text] : [], media: media, chat: { kind: 'comment', id: s[1] }, targets: [] };
    }
    if (s[0] === 'products' && s.length === 2) {
      if (!d.shopId) return null;
      (Array.isArray(d.photos) ? d.photos.slice(0, 4) : []).forEach(function (u) { addMedia('image', u); });
      return { kind: 'product', owner: d.shopId, texts: [d.name, d.description].filter(function (t) { return typeof t === 'string'; }), media: media, chat: { kind: 'product', id: s[1] }, targets: [] };
    }
    return null;
  }

  /* ---------- analyse d'un contenu : renvoie le pire constat ou null ---------- */
  function worse(a, b) {
    if (!a) return b; if (!b) return a;
    const diff = (SEV[b.severity] - SEV[a.severity]) || ((PRIORITY[b.category] || 0) - (PRIORITY[a.category] || 0));
    return diff > 0 ? b : a;
  }
  async function analyze(info) {
    let best = null;
    for (const t of info.texts) {
      const r = analyzeText(t);
      if (r) best = worse(best, { severity: r.severity, category: r.category, label: r.label, insult: r.insult, source: 'text', excerpt: clip(t, 300) });
    }
    for (const m of info.media.slice(0, 4)) {
      if (best && best.severity === 'high') break;
      if (m.type === 'image' || m.type === 'video') {
        const v = await scanImage(m);
        if (v) best = worse(best, { severity: v.severity, category: v.category, label: v.label, source: m.type, mediaType: m.type, mediaUrl: m.url });
      } else if (m.type === 'audio') {
        const tx = await transcribe(m.url);
        const r = tx ? analyzeText(tx) : null;
        if (r) best = worse(best, { severity: r.severity, category: r.category, label: r.label, insult: r.insult, source: 'audio', mediaType: 'audio', mediaUrl: m.url, transcript: clip(tx, 500), excerpt: clip(tx, 300) });
      }
    }
    return best;
  }
  /* insultes isolees : suivies, signalees seulement si elles se repetent (harcelement) */
  async function trackInsult(info, res) {
    const ref = modTrack.doc(sha(info.owner + '|' + info.chat.kind + '|' + info.chat.id));
    const need = info.chat.kind === 'private' ? 3 : 2, now = Date.now();
    const snap = await ref.get();
    const times = ((snap.exists && snap.data().times) || []).filter(function (t) { return now - t < 24 * 3600 * 1000; });
    times.push(now);
    if (times.length >= need) {
      await ref.set({ times: [], owner: info.owner, at: now });
      return Object.assign({}, res, { severity: 'medium', category: 'harassment', repeat: times.length, label: res.label + ' (x' + times.length + ')' });
    }
    await ref.set({ times: times, owner: info.owner, at: now });
    return null;
  }

  /* ---------- masquer / remettre un contenu ---------- */
  const FIELDS = { message: ['text', 'url'], status: ['text', 'url', 'musicUrl'], comment: ['text', 'imageUrl'], product: [] };
  function sanitizeUpdate(kind, cat) {
    const u = { modHidden: true, modCat: cat };
    if (kind === 'message') { u.text = ''; u.url = FV.delete(); }
    if (kind === 'status') { u.text = ''; u.url = FV.delete(); u.musicUrl = FV.delete(); }
    if (kind === 'comment') { u.text = ''; u.imageUrl = FV.delete(); }
    return u;
  }
  async function hideContent(ref, kind, cat, d, ownerUid) {
    const orig = {};
    (FIELDS[kind] || []).forEach(function (k) { if (d[k] !== undefined) orig[k] = d[k]; });
    await ref.update(sanitizeUpdate(kind, cat));
    if (kind === 'message') fixLastMessage(ref, d).catch(function () {});
    return orig;
  }
  async function fixLastMessage(ref, d) {
    const parent = ref.parent.parent; if (!parent) return;
    const snap = await parent.get(); if (!snap.exists) return;
    const c = snap.data();
    const created = d.createdAt && d.createdAt.toMillis ? d.createdAt.toMillis() : 0;
    const last = c.lastMessageAt && c.lastMessageAt.toMillis ? c.lastMessageAt.toMillis() : 0;
    if (c.lastSenderId === d.senderId && created && Math.abs(last - created) < 120000) await parent.update({ lastMessage: HIDDEN_PREVIEW });
  }
  async function restoreContent(f) {
    const ref = db.doc(f.path);
    const snap = await ref.get(); if (!snap.exists) return;
    const upd = { modHidden: FV.delete(), modCat: FV.delete() };
    Object.keys(f.orig || {}).forEach(function (k) { upd[k] = f.orig[k]; });
    await ref.update(upd);
  }

  /* ---------- creation d'un signalement ---------- */
  let newFlags = 0, newHigh = 0;
  async function createFlag(info, res, doc, stamp) {
    const id = sha(doc.ref.path + (stamp ? ':' + stamp : ''));
    const ref = flags.doc(id);
    const d = doc.data();
    const hide = res.severity === 'high';
    let orig = {};
    if (hide) { try { orig = await hideContent(doc.ref, info.kind, res.category, d, info.owner); } catch (e) { console.error('moderation hide', e.message); } }
    const own = await userInfo(info.owner);
    let chatName = '';
    try {
      if (info.chat.kind === 'private') { const other = info.targets[0]; if (other) chatName = (await userInfo(other)).name; }
      else if (info.chat.kind === 'group') { const g = await db.collection('groups').doc(info.chat.id).get(); chatName = g.exists ? clip(g.data().name, 80) : ''; }
    } catch (e) { /* nom facultatif */ }
    const data = {
      path: doc.ref.path, kind: info.kind, chatKind: info.chat.kind, chatId: info.chat.id, chatName: chatName, ownerUid: info.owner, ownerName: own.name, targets: info.targets.slice(0, 20),
      category: res.category, severity: res.severity, label: clip(res.label, 60), source: res.source, excerpt: res.excerpt || '', mediaType: res.mediaType || '', mediaUrl: res.mediaUrl || '',
      transcript: res.transcript || '', repeat: res.repeat || 0, hidden: hide, orig: orig, status: 'pending', createdAt: FV.serverTimestamp()
    };
    try { await ref.create(data); } catch (e) { if (e.code === 6 || /already exists/i.test(e.message)) return; throw e; }
    newFlags++; if (hide) newHigh++;
    if (hide) {
      const T = 'Contenu masqué', B = 'Un de vos contenus a été masqué en attendant l\'examen de la modération de NexChat.';
      D.saveNotifs([info.owner], { id: 'mod_hide_' + id.slice(0, 12), grouped: false, data: { type: 'security', title: T, body: B } }).catch(function () {});
      D.pushTo([info.owner], { title: T, body: B, tag: 'modhide-' + id.slice(0, 8), data: { type: 'security' }, link: D.appUrl }).catch(function () {});
    }
  }

  /* ---------- lecture des nouveaux contenus ---------- */
  const STREAMS = [
    { key: 'messages', every: 1, field: 'createdAt', q: function () { return db.collectionGroup('messages'); } },
    { key: 'edits', every: 1, field: 'editedAt', q: function () { return db.collectionGroup('messages'); }, edit: true },
    { key: 'comments', every: 3, field: 'createdAt', q: function () { return db.collectionGroup('comments'); } },
    { key: 'statuses', every: 3, field: 'createdAt', q: function () { return db.collection('statuses'); } },
    { key: 'products', every: 3, field: 'createdAt', q: function () { return db.collection('products'); } }
  ];
  const seen = new Map();
  function markSeen(k) { seen.set(k, 1); if (seen.size > 4000) { const it = seen.keys(); for (let i = 0; i < 1000; i++) seen.delete(it.next().value); } }
  let cursors = null;
  async function loadCursors() {
    if (cursors) return cursors;
    const s = await stateDoc.get();
    cursors = s.exists ? s.data() : {};
    let dirty = false;
    STREAMS.forEach(function (st) { if (typeof cursors[st.key] !== 'number') { cursors[st.key] = Date.now(); dirty = true; } });
    if (dirty) await stateDoc.set(cursors, { merge: true });
    return cursors;
  }
  async function handle(st, doc) {
    const stamp = st.edit ? (doc.get('editedAt') && doc.get('editedAt').toMillis()) : 0;
    const key = doc.ref.path + (stamp ? '@' + stamp : '');
    if (seen.has(key)) return;
    markSeen(key);
    const d = doc.data();
    if (d.modHidden) return;
    const info = describe(doc.ref.path, d);
    if (!info) return;
    let res = await analyze(info);
    if (!res) return;
    if (res.severity === 'low') { if (!res.insult) return; res = await trackInsult(info, res); if (!res) return; }
    await createFlag(info, res, doc, stamp);
  }
  async function runStream(st, tick) {
    if (tick % st.every !== 0) return;
    const e = health.streams[st.key];
    if (e && e.until && Date.now() < e.until) return;
    try {
      const c = await loadCursors();
      for (let round = 0; round < 3; round++) {
        const snap = await st.q().where(st.field, '>=', TS.fromMillis(c[st.key])).orderBy(st.field).limit(60).get();
        for (const doc of snap.docs) { try { await handle(st, doc); } catch (x) { console.error('moderation handle', x.message); } }
        if (snap.size) {
          const last = snap.docs[snap.size - 1].get(st.field);
          const ms = last && last.toMillis ? last.toMillis() : c[st.key];
          if (ms > c[st.key]) { c[st.key] = ms; await stateDoc.set({ [st.key]: ms }, { merge: true }); }
        }
        if (snap.size < 60) break;
      }
      health.streams[st.key] = { ok: true };
    } catch (err) {
      const needIndex = /index/i.test(err.message);
      health.streams[st.key] = { ok: false, error: clip(err.message, 300), needIndex: needIndex, until: Date.now() + 10 * 60 * 1000 };
      console.error('moderation flux ' + st.key + ' : ' + err.message);
    }
  }
  async function notifyAdmins() {
    if (!newFlags) return;
    const n = newFlags, hi = newHigh; newFlags = 0; newHigh = 0;
    const uids = await getAdminUids();
    if (!uids.length) return;
    const T = 'Modération : à examiner';
    const B = n + ' nouveau(x) contenu(s) signalé(s) automatiquement' + (hi ? ' dont ' + hi + ' masqué(s).' : '.');
    D.saveNotifs(uids, { id: 'mod_pending', grouped: false, data: { type: 'security', title: T, body: B } }).catch(function () {});
    D.pushTo(uids, { title: T, body: B, tag: 'modpending', urgent: true, data: { type: 'security' }, link: D.appUrl }).catch(function () {});
  }
  let busy = false, tick = 0;
  async function cycle() {
    if (busy) return; busy = true;
    try {
      for (const st of STREAMS) await runStream(st, tick);
      tick++; health.lastCycleAt = Date.now();
      await notifyAdmins();
    } catch (e) { console.error('moderation cycle', e.message); }
    busy = false;
  }
  if (ENABLED) {
    setTimeout(cycle, 20000);
    setInterval(cycle, POLL_MS);
    console.log('Moderation active (images : ' + health.image + ', vocaux : ' + health.audio + ', releve toutes les ' + POLL_MS / 1000 + ' s)');
  } else { console.log('Moderation desactivee (MODERATION=off)'); }
  const api = { cycle: cycle };

  /* ---------- API administrateur ---------- */
  const CAT_FR = { sexual: 'contenu sexuel', minors: 'contenu inapproprié impliquant des mineurs', threat: 'menaces', hate: 'propos haineux', harassment: 'harcèlement', scam: 'arnaque', illegal: 'contenu illégal', violence: 'violence' };
  const WHAT_FR = { message: 'message', status: 'story', comment: 'commentaire', product: 'produit' };

  D.app.post('/admin/mod/flags', D.requireUser, D.requireAdminUser, async function (req, res) {
    try {
      const snap = await flags.where('status', '==', 'pending').limit(200).get();
      const docs = snap.docs.sort(function (a, b) { const x = a.get('createdAt'), y = b.get('createdAt'); return (y ? y.toMillis() : 0) - (x ? x.toMillis() : 0); }).slice(0, 100);
      const uids = Array.from(new Set(docs.map(function (d) { return d.get('ownerUid'); })));
      const warn = {}, ban = {};
      if (uids.length) {
        (await db.getAll.apply(db, uids.map(function (u) { return modUsers.doc(u); }))).forEach(function (s, i) { warn[uids[i]] = s.exists ? (s.data().warnings || 0) : 0; });
        (await db.getAll.apply(db, uids.map(function (u) { return db.collection('accountBans').doc(u); }))).forEach(function (s, i) { ban[uids[i]] = s.exists ? s.data().status : ''; });
      }
      const list = [];
      for (const d of docs) {
        const f = d.data(), own = await userInfo(f.ownerUid);
        list.push({ id: d.id, kind: f.kind, chatKind: f.chatKind, chatName: f.chatName, category: f.category, severity: f.severity, label: f.label, source: f.source,
          excerpt: f.excerpt, mediaType: f.mediaType, mediaUrl: f.mediaUrl, transcript: f.transcript, repeat: f.repeat, hidden: !!f.hidden,
          at: f.createdAt ? f.createdAt.toMillis() : 0,
          owner: { uid: f.ownerUid, name: own.name, email: own.email, deleted: !!own.deleted, disabled: own.disabled, ban: ban[f.ownerUid] || '', warnings: warn[f.ownerUid] || 0 } });
      }
      const streams = {}; Object.keys(health.streams).forEach(function (k) { const s = health.streams[k]; streams[k] = s.ok ? 'ok' : (s.needIndex ? 'index' : 'error'); });
      const idx = Object.keys(health.streams).map(function (k) { return health.streams[k]; }).filter(function (s) { return s.needIndex; })[0];
      return res.json({ ok: true, flags: list, warnLimit: WARN_LIMIT, health: { enabled: ENABLED, image: health.image, audio: health.audio, imgFail: health.imgFail, imgOk: health.imgOk, lastError: health.lastImgError, streams: streams, indexHelp: idx ? idx.error : '', lastCycleAt: health.lastCycleAt } });
    } catch (e) { console.error('admin/mod/flags', e); return res.status(500).json({ ok: false, error: 'Lecture impossible pour le moment.' }); }
  });

  async function closePending(owner, status, by) {
    const snap = await flags.where('ownerUid', '==', owner).where('status', '==', 'pending').get();
    for (let i = 0; i < snap.docs.length; i += 400) {
      const b = db.batch();
      snap.docs.slice(i, i + 400).forEach(function (d) { b.update(d.ref, { status: status, resolvedAt: FV.serverTimestamp(), resolvedBy: by }); });
      await b.commit();
    }
  }
  async function ensureHidden(f) {
    if (f.hidden) return f.orig || {};
    const ref = db.doc(f.path), snap = await ref.get();
    if (!snap.exists) return {};
    return hideContent(ref, f.kind, f.category, snap.data(), f.ownerUid);
  }

  D.app.post('/admin/mod/action', D.requireUser, D.requireAdminUser, async function (req, res) {
    try {
      const id = String(req.body.id || ''), action = String(req.body.action || ''), note = clip(req.body.note, 300).trim();
      if (!/^[a-f0-9]{40}$/.test(id) || ['dismiss', 'warn', 'remove', 'disable', 'ban'].indexOf(action) === -1) return res.status(400).json({ ok: false, error: 'Requete invalide.' });
      const ref = flags.doc(id), snap = await ref.get();
      if (!snap.exists) return res.status(404).json({ ok: false, error: 'Element introuvable.' });
      const f = snap.data();
      if (f.status !== 'pending') return res.json({ ok: true, already: true });
      const done = { resolvedAt: FV.serverTimestamp(), resolvedBy: req.uid };

      if (action === 'dismiss') {
        if (f.hidden) await restoreContent(f);
        await ref.update(Object.assign({ status: 'dismissed', orig: {} }, done));
        return res.json({ ok: true });
      }
      if (action === 'remove') {
        const orig = await ensureHidden(f);
        await ref.update(Object.assign({ status: 'removed', hidden: true, orig: orig }, done));
        return res.json({ ok: true });
      }
      if (action === 'warn') {
        const orig = await ensureHidden(f);
        const mref = modUsers.doc(f.ownerUid);
        const warnings = await db.runTransaction(async function (tx) {
          const s = await tx.get(mref), cur = s.exists ? (s.data().warnings || 0) : 0, hist = s.exists && Array.isArray(s.data().history) ? s.data().history : [];
          hist.push({ flag: id, at: Date.now(), category: f.category, kind: f.kind, by: req.uid, note: note });
          tx.set(mref, { warnings: cur + 1, history: hist.slice(-30), lastWarnAt: Date.now() }, { merge: true });
          return cur + 1;
        });
        await ref.update(Object.assign({ status: 'warned', hidden: true, orig: orig, note: note }, done));
        const T = 'Avertissement ' + warnings + '/' + WARN_LIMIT;
        const B = 'Votre ' + (WHAT_FR[f.kind] || 'contenu') + ' ne respecte pas les conditions d\'utilisation de NexChat (' + (CAT_FR[f.category] || 'contenu inapproprié') + '). Après ' + WARN_LIMIT + ' avertissements, votre compte peut être désactivé.' + (note ? ' Message de la modération : ' + note : '');
        D.saveNotifs([f.ownerUid], { id: 'mod_warn_' + id.slice(0, 12), grouped: false, data: { type: 'security', title: T, body: B } }).catch(function () {});
        D.pushTo([f.ownerUid], { title: T, body: B, tag: 'modwarn-' + id.slice(0, 8), urgent: true, data: { type: 'security' }, link: D.appUrl }).catch(function () {});
        return res.json({ ok: true, warnings: warnings, limit: WARN_LIMIT });
      }
      /* disable / ban : apres 3 avertissements seulement */
      const ms = await modUsers.doc(f.ownerUid).get();
      const warnings = ms.exists ? (ms.data().warnings || 0) : 0;
      if (warnings < WARN_LIMIT) return res.status(403).json({ ok: false, error: 'Pas assez d\'avertissements pour cette sanction.' });
      let u = null; try { u = await auth.getUser(f.ownerUid); } catch (e) { return res.status(404).json({ ok: false, error: 'Utilisateur introuvable.' }); }
      if (f.ownerUid === req.uid || D.isAdminEmail(u.email)) return res.status(403).json({ ok: false, error: 'Action non autorisee.' });
      await auth.updateUser(f.ownerUid, { disabled: true });
      await auth.revokeRefreshTokens(f.ownerUid).catch(function () {});
      await db.collection('accountBans').doc(f.ownerUid).set({
        status: action === 'ban' ? 'banned' : 'disabled', reason: 'moderation', warnings: warnings, email: String(u.email || '').toLowerCase(), name: u.displayName || '',
        disabledAt: FV.serverTimestamp(), disabledBy: req.uid, appeal: FV.delete()
      }, { merge: true });
      uCache.delete(f.ownerUid);
      await closePending(f.ownerUid, 'actioned', req.uid);
      if (u.email) {
        const en = (await D.userLangs([f.ownerUid]))[f.ownerUid] === 'en', banned = action === 'ban';
        const subj = en ? (banned ? '[NexChat] Your account has been banned' : '[NexChat] Your account has been deactivated') : (banned ? '[NexChat] Votre compte a été banni' : '[NexChat] Votre compte a été désactivé');
        const head = '<div style="font-family:Arial,Helvetica,sans-serif;font-size:14px;color:#0b1b4d;line-height:1.6;">';
        const body = en
          ? '<p>Hello,</p><p>After ' + WARN_LIMIT + ' warnings for content that does not comply with the NexChat terms of use, your account has been ' + (banned ? '<strong>permanently banned</strong>.' : '<strong>deactivated</strong>. You can request a review from the sign-in screen.') + '</p></div>'
          : '<p>Bonjour,</p><p>Après ' + WARN_LIMIT + ' avertissements pour des contenus non conformes aux conditions d\'utilisation de NexChat, votre compte a été ' + (banned ? '<strong>banni définitivement</strong>.' : '<strong>désactivé</strong>. Vous pouvez demander un examen depuis l\'écran de connexion.') + '</p></div>';
        D.sendMailTo(u.email, subj, head + body);
      }
      return res.json({ ok: true });
    } catch (e) { console.error('admin/mod/action', e); return res.status(500).json({ ok: false, error: 'Action impossible pour le moment.' }); }
  });
  return api;
}

module.exports = { init: init, analyzeText: analyzeText, WARN_LIMIT: WARN_LIMIT };
