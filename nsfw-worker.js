'use strict';
/* Processus separe qui classe les images (nsfwjs MobileNetV2 "mid", gratuit, sans service externe : aucune image ne quitte votre serveur).
   Lance a la demande par moderation.js, il s'arrete tout seul apres 2 minutes d'inactivite : le modele ne pese donc sur la memoire
   que lorsqu'il y a des images a verifier.
   Methode en deux temps, pour attraper aussi les captures d'ecran (un site dans une capture d'ecran) sans ralentir les images normales :
     1. passe rapide : image entiere + 3 carres le long de la plus grande dimension ;
     2. si un morceau est un peu suspect (score >= 0,15), analyse zoomee : fenetres qui se chevauchent sur la zone concernee. */
const fs = require('fs'), path = require('path');
const IDLE_MS = 120000;
let idle = null, model = null, tf = null, jpeg = null, PNG = null, loading = null, chain = Promise.resolve();

function arm() { clearTimeout(idle); idle = setTimeout(function () { process.exit(0); }, IDLE_MS); }

async function doLoad() {
  tf = require('@tensorflow/tfjs');
  jpeg = require('jpeg-js');
  try { PNG = require('pngjs').PNG; } catch (e) { PNG = null; }
  const nsfw = require('nsfwjs');
  await tf.setBackend('cpu'); await tf.ready();
  /* Modele converti en fichiers binaires (4 Mo), a deposer a cote de server.js : nsfw-mid.json et nsfw-mid.bin */
  const fj = path.join(__dirname, 'nsfw-mid.json'), fb = path.join(__dirname, 'nsfw-mid.bin');
  if (!fs.existsSync(fj) || !fs.existsSync(fb)) throw new Error('modele introuvable : deposez nsfw-mid.json et nsfw-mid.bin a cote de server.js');
  const mj = JSON.parse(fs.readFileSync(fj, 'utf8'));
  const bin = fs.readFileSync(fb);
  const handler = tf.io.fromMemory({
    modelTopology: mj.modelTopology,
    weightSpecs: mj.weightsManifest[0].weights,
    weightData: bin.buffer.slice(bin.byteOffset, bin.byteOffset + bin.byteLength)
  });
  model = new nsfw.NSFWJS(handler, { size: 224, type: 'graph' });
  await model.load();
}
function load() { if (!loading) loading = doLoad().catch(function (e) { loading = null; throw e; }); return loading; }

async function download(url) {
  const r = await fetch(url, { signal: AbortSignal.timeout(25000) });
  if (!r.ok) throw new Error('http ' + r.status);
  const buf = Buffer.from(await r.arrayBuffer());
  if (buf.length > 6 * 1024 * 1024) throw new Error('trop volumineux');
  return buf;
}

function toRgb(buf) {
  let w, h, data;
  if (buf[0] === 0xff && buf[1] === 0xd8) {
    const img = jpeg.decode(buf, { useTArray: true, maxMemoryUsageInMB: 48 }); w = img.width; h = img.height; data = img.data;   /* image trop grande : refusee avant d'occuper la memoire */
  } else if (buf[0] === 0x89 && buf[1] === 0x50 && PNG) {
    if (buf.readUInt32BE(16) * buf.readUInt32BE(20) > 4000000) throw new Error('image trop grande');
    const img = PNG.sync.read(buf); w = img.width; h = img.height; data = img.data;
  } else { throw new Error('format non pris en charge'); }
  const rgb = new Uint8Array(w * h * 3);
  for (let i = 0, j = 0; i < data.length; i += 4) { rgb[j++] = data[i]; rgb[j++] = data[i + 1]; rgb[j++] = data[i + 2]; }
  return { rgb: rgb, w: w, h: h };
}

function score(p) { return (p.porn || 0) + 0.9 * (p.hentai || 0); }
async function classify(t) {
  const out = await model.classify(t);
  const p = {}; out.forEach(function (o) { p[o.className.toLowerCase()] = o.probability; });
  return p;
}
function better(a, b) { return !a || score(b) > score(a) || (score(b) === score(a) && (b.sexy || 0) > (a.sexy || 0)) ? b : a; }

const BUDGET_MS = 100000;   /* temps maximal par image : sur un petit serveur lent, on s'arrete et on garde le meilleur resultat deja obtenu */
async function analyse(px) {
  const t0 = Date.now(), W = px.w, H = px.h, full = tf.tensor3d(px.rgb, [H, W, 3], 'int32');
  try {
    let best = await classify(full), deep = false, calls = 1;
    const short = Math.min(W, H), long = Math.max(W, H), tall = H >= W;
    /* passe rapide : carres le long de la plus grande dimension (3 au maximum) */
    const cands = [];   /* position (le long de la grande dimension) des morceaux un peu suspects */
    if (long > short * 1.25) {
      const n = Math.min(3, Math.ceil(long / short) + 1);
      for (let k = 0; k < n; k++) {
        if (Date.now() - t0 > BUDGET_MS) break;
        const pos = Math.round((long - short) * k / Math.max(1, n - 1));
        const t = tall ? tf.slice(full, [pos, 0, 0], [short, short, 3]) : tf.slice(full, [0, pos, 0], [short, short, 3]);
        const p = await classify(t); t.dispose(); calls++;
        if (score(p) >= 0.15 || (p.sexy || 0) >= 0.5) cands.push(pos);
        best = better(best, p);
      }
    }
    const suspicious = score(best) >= 0.15 || (best.sexy || 0) >= 0.5;
    if (suspicious && short >= 300) {
      /* analyse zoomee : fenetres carrees de 55 % du petit cote, qui se chevauchent a moitie, autour de la zone suspecte */
      deep = true;
      const win = Math.round(short * 0.55), step = Math.round(win / 2);
      let from = 0, to = long - win;
      if (long > short * 1.25 && cands.length) { from = Math.max(0, Math.min.apply(null, cands) - Math.round(short * 0.25)); to = Math.min(long - win, Math.max.apply(null, cands) + Math.round(short * 1.25) - win); }
      const along = [], across = [];
      for (let a = from; a <= to; a += step) along.push(a);
      if (!along.length) along.push(Math.max(0, Math.min(from, long - win)));
      for (let b = 0; b <= short - win; b += step) across.push(b);
      if (!across.length) across.push(0);
      let count = 0;
      outer: for (const a of along) for (const b of across) {
        if (count >= 14 || Date.now() - t0 > BUDGET_MS) break outer;
        const y = tall ? a : b, x = tall ? b : a;
        const hh = Math.min(win, H - y), ww = Math.min(win, W - x);
        const t = tf.slice(full, [y, x, 0], [hh, ww, 3]);
        const p = await classify(t); t.dispose(); calls++; count++;
        best = better(best, p);
      }
    }
    return { p: best, deep: deep, calls: calls };
  } finally { full.dispose(); }
}

async function handle(msg) {
  arm();
  if (!msg || msg.id === undefined) return;
  try {
    await load();
    const r = await analyse(toRgb(await download(msg.url)));
    process.send({ id: msg.id, ok: true, p: r.p, deep: r.deep, calls: r.calls });
  } catch (e) {
    process.send({ id: msg.id, ok: false, error: String(e && e.message ? e.message : e).slice(0, 200) });
  }
  if (global.gc) global.gc();   /* rend la memoire apres chaque image */
  arm();
}
/* une image a la fois : le modele n'est pas prevu pour des appels simultanes */
process.on('message', function (msg) { chain = chain.then(function () { return handle(msg); }); });
arm();
