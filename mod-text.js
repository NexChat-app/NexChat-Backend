'use strict';
/* Analyse de texte pour la moderation NexChat (francais + anglais).
   Tout se passe sur le serveur, sans service externe : aucune donnee ne sort. Le texte est normalise (accents, majuscules,
   "p0rn", lettres repetees ou espacees) puis compare a des regles. Resultat : severite 'high' (masque en attendant l'admin),
   'medium' (signale a l'admin) ou 'low' (suivi seulement : insulte isolee, comptee pour detecter le harcelement repete). */

function norm(s) {
  s = String(s || '').toLowerCase();
  s = s.normalize('NFD').replace(/[\u0300-\u036f]/g, '').replace(/\u0153/g, 'oe').replace(/\u00e6/g, 'ae');
  // chiffres et symboles utilises a la place de lettres, uniquement au milieu d'un mot
  s = s.replace(/(?<=[a-z])@(?=[a-z])/g, 'a').replace(/(?<=[a-z])\$(?=[a-z])/g, 's')
    .replace(/(?<=[a-z])0(?=[a-z])/g, 'o').replace(/(?<=[a-z])1(?=[a-z])/g, 'i').replace(/(?<=[a-z])3(?=[a-z])/g, 'e')
    .replace(/(?<=[a-z])4(?=[a-z])/g, 'a').replace(/(?<=[a-z])5(?=[a-z])/g, 's').replace(/(?<=[a-z])7(?=[a-z])/g, 't');
  // lettres separees ("p o r n", "p.o.r.n") : recollees
  s = s.replace(/(?:^|(?<=[^a-z]))(?:[a-z][ .\-_*]){3,}[a-z](?=$|[^a-z])/g, function (m) { return m.replace(/[ .\-_*]/g, ''); });
  // lettres repetees (saaalope -> salope) ; le x reste (xxx)
  s = s.replace(/([a-wyz])\1{2,}/g, '$1');
  s = s.replace(/[^a-z0-9]+/g, ' ').trim();
  return ' ' + s + ' ';
}

function R(cat, sev, label, re) { return { cat: cat, sev: sev, label: label, re: re }; }

const RULES = [
  /* --- mineurs : le plus grave --- */
  R('minors', 'high', 'minors', /\b(pedo(phil\w*|porn\w*)?|child ?porn\w*|kiddie ?porn|teen ?porn|loli ?(porn|nue|hentai)|porn\w* (d )?(enfants?|mineur\w*|ados?)|(enfants?|mineur\w*|collegienne?s?|lyceenne?s?) (nu\w*|a poil)|sexe avec (un|une|des) (enfants?|mineur\w*|gamin\w*|fillette\w*)|sex with (a )?(child|children|minor\w*|kid\w*))\b/),
  /* --- contenu sexuel explicite --- */
  R('sexual', 'high', 'sexual', /\b(porno\w*|pornograph\w*|porn|xxx|xnxx|xvideos?|pornhub|xhamster|redtube|youporn|brazzers|sex ?tape|blow ?job|hand ?job|gang ?bang|fellation|sodomi\w*|cum ?shot|creampie|bukkake|sexe? anal|anal sex)\b/),
  R('sexual', 'medium', 'sexual', /\b(nudes?|photos? (nue?s?|intimes?|sexy|a poil)|dick ?pic|sex ?chat|sexe? (chat|virtuel|au telephone|par telephone)|onlyfans|chaturbate|stripchat|bongacams)\b/),
  R('sexual', 'medium', 'sexual', /\b(env(oi|oy)\w*|montre\w*|send|show) (moi |me )?(tes?|ta|your) (nudes?|photos? (nue?s?|intimes?|sexy)|seins|fesses|chatte|bite|corps nu|body)\b/),
  R('sexual', 'medium', 'sexual', /\b(je veux|j ai envie de|i want to) (te |t )?(baiser|niquer|sucer|coucher avec|fuck|sleep with)\b/),
  R('sexual', 'medium', 'sexual', /\bsend (me )?(nudes|pics of your)\b/),
  /* --- menaces --- */
  R('threat', 'high', 'threat', /\b(je|j) (vais|va|veux) (te |t )?(violer|egorger|decouper|demembrer|bruler vif)\b|\b(i|ill|i ll|i will|im|i m) (going to )?(rape|behead|dismember) (you|u)\b/),
  R('threat', 'high', 'threat', /\bkys\b|\bkill yourself\b|\b(va|vas) (te )?(suicider|pendre|tuer)\b|\bsuicide toi\b/),
  R('threat', 'medium', 'threat', /\b(je|j) (vais|va|veux) (te |t )?(tuer|buter|frapper|massacrer|defoncer|casser|descendre|detruire|bruler)\b|\b(je te|j te) (tue|bute|frappe|defonce|massacre)\b/),
  R('threat', 'medium', 'threat', /\btu (vas|va) (mourir|crever|payer|le regretter|souffrir)\b|\b(on|ils|je) (va|vont) (te )?(tuer|buter|violer)\b|\bje (sais|connais) (ou tu |ton adresse|ta maison)/),
  R('threat', 'medium', 'threat', /\b(i|ill|i ll|i will|im|i m) (going to )?(kill|hurt|beat|destroy|shoot|stab) (you|u)\b|\byou (are|re) (dead|going to die)\b|\bi know where you (live|work|sleep)\b/),
  /* --- haine --- */
  R('hate', 'medium', 'hate', /\b(negres?|negresses?|negro|bamboula|bougnoules?|youpin\w*|chinetoques?|crouilles?|sale (noir|noire|blanc|blanche|arabe|juif|juive|chinois|africain|etranger|musulman))\b|\bnigg\w+\b|\bfaggots?\b|\bfags?\b|\bkikes?\b|\bchinks?\b|\btrann(y|ies)\b|\b(sale|sales) (pd|pede|pedale|tapette|tarlouze|gouine|homo)\b|\b(pedes?|pedales?|tapettes?|tarlouzes?|gouines?)\b/),
  /* --- arnaques / illegal --- */
  R('scam', 'medium', 'scam', /\b(env(oi|oy)\w*|transfer\w*) (moi )?(de l argent|\d+ ?(fcfa|f cfa|cfa|euros?|dollars?))\b|\bgagn\w* \d+ ?(fcfa|f cfa|euros?|dollars?)\b|\bdoubl\w* (votre|ton|ta|vos|tes) (argent|mise|capital|investissement)\b|\b(donne\w*|env(oi|oy)\w*) (moi )?(le |ton |votre )?(code|otp)( de (verification|validation))? (recu|que je viens)\b|\bsend (me )?money\b|\bdouble your (money|investment)\b|\bgive me (the |your )?(otp|verification code)\b|\byou (have )?won (a |the )?(prize|lottery|\$)/),
  R('illegal', 'medium', 'illegal', /\bfaux (billets?|papiers|diplomes?|passeports?|visas?)\b|\b(vend\w*|a vendre|vente de) (de la |du )?(cocaine|heroine|cannabis|weed|drogue|tramadol|ecstasy|kalachnikov|pistolet|arme a feu)\b|\bfake (id|passport|documents?)\b|\b(selling|buy) (cocaine|heroin|weed|guns?)\b/)
];

/* Insultes fortes : suivies, pas signalees seules (une insulte entre amis n'est pas du harcelement) */
const INSULT = /\b(enculee?s?|connards?|connasses?|salopes?|salauds?|putes?|fdp|ntm|nique ta mere|nik ta mere|ferme ta gueule|ta gueule|sous merdes?|sale merde|ordures?|batards?|batardes?|pourriture|va te faire foutre|vas te faire foutre|merdeux|fils de pute|fils de chien|sale chien|sale race|bitch(es)?|asshole|motherfucker|mother fucker|shut the fuck up|stfu|piece of shit|dumb ?ass|scumbag|go to hell|son of a bitch|fuck you|fuck off|whore|slut|bastard)\b/g;
const DIRECTED = /\b(tu|toi|te|t|ta|ton|tes|vous|votre|vos|you|your|youre|ur|u)\b/;
/* Mots sexuels ambigus : 2 differents dans le meme texte pour signaler */
const WEAK_SEX = /\b(bite|chatte|couilles?|sexe|seins?|nichons?|fesses|penis|vagin|erection|pussy|cock|dick|boobs?|tits?|sex|poitrine)\b/g;
const ADULT_DOMAINS = /\b(pornhub|xvideos|xnxx|xhamster|redtube|youporn|brazzers|onlyfans|chaturbate|stripchat|bongacams|spankbang|tnaflix)\b/;

const ORDER = { minors: 6, threat: 5, sexual: 4, hate: 3, harassment: 2, scam: 1, illegal: 1 };
const SEV = { high: 3, medium: 2, low: 1 };

/* analyzeText(texte) -> null ou { category, severity, label, insult, hits } */
function analyzeText(text) {
  const raw = String(text || '');
  if (raw.trim().length < 3) return null;
  const n = norm(raw);
  const hits = [];
  RULES.forEach(function (r) { const m = r.re.exec(n); if (m) hits.push({ category: r.cat, severity: r.sev, label: m[0].trim().slice(0, 40) }); });
  // liens vers des sites pour adultes
  const url = /(https?:\/\/|www\.)\S+/i.exec(raw);
  if (url && ADULT_DOMAINS.test(norm(url[0]))) hits.push({ category: 'sexual', severity: 'high', label: 'adult link' });
  // mots sexuels ambigus
  const weak = {}; let wm; WEAK_SEX.lastIndex = 0;
  while ((wm = WEAK_SEX.exec(n))) weak[wm[1]] = 1;
  if (Object.keys(weak).length >= 2) hits.push({ category: 'sexual', severity: 'medium', label: Object.keys(weak).slice(0, 3).join(', ') });
  // insultes
  const ins = {}; let im; INSULT.lastIndex = 0;
  while ((im = INSULT.exec(n))) ins[im[1]] = 1;
  const insKeys = Object.keys(ins);
  let insult = false;
  if (insKeys.length >= 2) hits.push({ category: 'harassment', severity: 'medium', label: insKeys.slice(0, 3).join(', ') });
  else if (insKeys.length === 1 && DIRECTED.test(n)) { insult = true; hits.push({ category: 'harassment', severity: 'low', label: insKeys[0] }); }
  if (!hits.length) return null;
  hits.sort(function (a, b) { return (SEV[b.severity] - SEV[a.severity]) || ((ORDER[b.category] || 0) - (ORDER[a.category] || 0)); });
  const top = hits[0];
  return { category: top.category, severity: top.severity, label: top.label, insult: insult && top.category === 'harassment' && top.severity === 'low', hits: hits };
}

module.exports = { analyzeText: analyzeText, norm: norm };
