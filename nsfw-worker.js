'use strict';
/* Processus separe qui classe les images (nsfwjs, modele integre, gratuit, sans service externe).
   Il est lance a la demande par moderation.js et s'arrete tout seul apres 2 minutes d'inactivite : le modele
   (environ 250 Mo en memoire) ne pese donc sur le serveur que lorsqu'il y a des images a verifier. */
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
  /* Modele MobileNetV2 deja converti en fichiers binaires (2,6 Mo) : le charger depuis le paquet npm demande plusieurs centaines de Mo
     de memoire, ici quelques dizaines. Fichiers attendus a cote de server.js : nsfw-model.json et nsfw-model.bin
     (ou, en variante, le dossier nsfw-model/ contenant model.json et group1-shard1of1.bin). */
  const pairs = [
    [path.join(__dirname, 'nsfw-model.json'), path.join(__dirname, 'nsfw-model.bin')],
    [path.join(__dirname, 'nsfw-model', 'model.json'), path.join(__dirname, 'nsfw-model', 'group1-shard1of1.bin')]
  ];
  const found = pairs.filter(function (p) { return fs.existsSync(p[0]) && fs.existsSync(p[1]); })[0];
  if (!found) throw new Error('modele introuvable : deposez nsfw-model.json et nsfw-model.bin a cote de server.js');
  const mj = JSON.parse(fs.readFileSync(found[0], 'utf8'));
  const bin = fs.readFileSync(found[1]);
  const handler = tf.io.fromMemory({
    modelTopology: mj.modelTopology,
    weightSpecs: mj.weightsManifest[0].weights,
    weightData: bin.buffer.slice(bin.byteOffset, bin.byteOffset + bin.byteLength)
  });
  model = new nsfw.NSFWJS(handler, { size: 224 });
  await model.load();
}
function load() { if (!loading) loading = doLoad().catch(function (e) { loading = null; throw e; }); return loading; }

async function download(url) {
  const r = await fetch(url, { signal: AbortSignal.timeout(20000) });
  if (!r.ok) throw new Error('http ' + r.status);
  const buf = Buffer.from(await r.arrayBuffer());
  if (buf.length > 4 * 1024 * 1024) throw new Error('trop volumineux');
  return buf;
}

function toRgb(buf) {
  let w, h, data;
  if (buf[0] === 0xff && buf[1] === 0xd8) {
    const img = jpeg.decode(buf, { useTArray: true, maxMemoryUsageInMB: 96 }); w = img.width; h = img.height; data = img.data;
  } else if (buf[0] === 0x89 && buf[1] === 0x50 && PNG) {
    const img = PNG.sync.read(buf); w = img.width; h = img.height; data = img.data;
  } else { throw new Error('format non pris en charge'); }
  const rgb = new Uint8Array(w * h * 3);
  for (let i = 0, j = 0; i < data.length; i += 4) { rgb[j++] = data[i]; rgb[j++] = data[i + 1]; rgb[j++] = data[i + 2]; }
  return { rgb: rgb, w: w, h: h };
}

async function handle(msg) {
  arm();
  if (!msg || msg.id === undefined) return;
  try {
    await load();
    const px = toRgb(await download(msg.url));
    const t = tf.tensor3d(px.rgb, [px.h, px.w, 3], 'int32');
    const out = await model.classify(t); t.dispose();
    const p = {}; out.forEach(function (o) { p[o.className.toLowerCase()] = o.probability; });
    process.send({ id: msg.id, ok: true, p: p });
  } catch (e) {
    process.send({ id: msg.id, ok: false, error: String(e && e.message ? e.message : e).slice(0, 200) });
  }
  arm();
}
/* une image a la fois : le modele n'est pas prevu pour des appels simultanes */
process.on('message', function (msg) { chain = chain.then(function () { return handle(msg); }); });
arm();
