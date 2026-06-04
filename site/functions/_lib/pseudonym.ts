/**
 * Friendly, deterministic pseudonym for a persistent visitor id (cl_vid). Same id =>
 * same name, derived purely by hashing — no PII, nothing stored. Lets us recognise
 * repeat readers in the dashboard ("Brave Badger is back") without identifying anyone.
 * 40 x 40 = 1600 stable handles; the cl_vid stays the real key, the name is just a
 * memorable label. Computed server-side so raw cl_vid UUIDs never reach the browser.
 *
 * Bots (crawlers / suspected automation) get a "clanker" — a mechanical handle drawn
 * from the same hash — so a non-human row reads as a machine at a glance.
 */

const ADJECTIVES = [
  'Amber', 'Brave', 'Clever', 'Dapper', 'Eager', 'Fuzzy', 'Gentle', 'Hardy', 'Icy', 'Jolly',
  'Keen', 'Lucky', 'Mellow', 'Nimble', 'Olive', 'Plucky', 'Quiet', 'Rusty', 'Swift', 'Teal',
  'Witty', 'Zesty', 'Bold', 'Cosmic', 'Drowsy', 'Electric', 'Frosty', 'Golden', 'Hidden', 'Iron',
  'Jade', 'Lunar', 'Mighty', 'Noble', 'Opal', 'Proud', 'Quirky', 'Royal', 'Silent', 'Velvet',
];
const ANIMALS = [
  'Otter', 'Badger', 'Falcon', 'Heron', 'Lynx', 'Marten', 'Newt', 'Owl', 'Puffin', 'Quokka',
  'Raven', 'Stoat', 'Tapir', 'Vole', 'Wombat', 'Yak', 'Ibex', 'Koala', 'Gecko', 'Crane',
  'Bison', 'Civet', 'Dingo', 'Egret', 'Ferret', 'Gibbon', 'Hare', 'Jackal', 'Kestrel', 'Lemur',
  'Macaw', 'Narwhal', 'Osprey', 'Panda', 'Ocelot', 'Ram', 'Seal', 'Toad', 'Urchin', 'Walrus',
];
// Mechanical handles for bots — every name reads as a machine ("Rusty Clanker").
const CLANKERS = [
  'Clanker', 'Cog', 'Bolt', 'Rivet', 'Sprocket', 'Servo', 'Gizmo', 'Droid', 'Piston', 'Ratchet',
  'Widget', 'Gear', 'Dynamo', 'Tin', 'Scrap', 'Circuit', 'Relay', 'Boiler', 'Crank', 'Valve',
  'Turbine', 'Gasket', 'Solder', 'Flange', 'Spindle', 'Lugnut', 'Camshaft', 'Manifold', 'Bearing', 'Coil',
  'Fuse', 'Auger', 'Winch', 'Pulley', 'Tappet', 'Grommet', 'Clamp', 'Bellows', 'Magneto', 'Carburettor',
];

export function pseudonym(vid: unknown, isBot = false): string {
  const str = String(vid ?? '');
  if (!str) return '—';
  let h = 2166136261 >>> 0; // FNV-1a
  for (let i = 0; i < str.length; i++) { h ^= str.charCodeAt(i); h = Math.imul(h, 16777619); }
  h >>>= 0;
  const adj = ADJECTIVES[h % ADJECTIVES.length];
  const nouns = isBot ? CLANKERS : ANIMALS;
  const noun = nouns[Math.floor(h / ADJECTIVES.length) % nouns.length];
  return `${adj} ${noun}`;
}

/**
 * Stable opaque token for a cl_vid — a 16-hex digest used to reference a visitor in
 * the journey drill-down without ever exposing the raw cl_vid to the browser. Two
 * differently-seeded FNV passes => collisions negligible at our volume. The journey
 * endpoint resolves it back by recomputing this over the candidate visitor set.
 */
export function readerId(vid: unknown): string {
  const str = String(vid ?? '');
  if (!str) return '';
  let h1 = 2166136261 >>> 0;
  let h2 = 0x9e3779b9 >>> 0;
  for (let i = 0; i < str.length; i++) {
    const c = str.charCodeAt(i);
    h1 = Math.imul(h1 ^ c, 16777619);
    h2 = Math.imul(h2 ^ c, 2246822519);
  }
  return (h1 >>> 0).toString(16).padStart(8, '0') + (h2 >>> 0).toString(16).padStart(8, '0');
}
