// A zero-dependency QR code encoder, for pairing a phone by pointing its camera
// at the setup page (or the terminal) instead of typing a 60-character link.
//
// Byte mode only - a tokened URL is what it is for - with all four error
// correction levels and versions 1-40, following ISO/IEC 18004. The structure
// is the classic one: build the data bit stream, split it into blocks, add
// Reed-Solomon codewords per block, interleave, draw the function patterns,
// zigzag the codewords in, then try all eight masks and keep the one with the
// lowest penalty. Any mask gives a readable code; the penalty only picks the one
// cameras find easiest.
//
// test/smoke.js pins the Reed-Solomon output against the published worked
// example and checks the drawn structure; it was also round-tripped through a
// real decoder while being written.

const ECL = {
  L: { ord: 0, bits: 1 },
  M: { ord: 1, bits: 0 },
  Q: { ord: 2, bits: 3 },
  H: { ord: 3, bits: 2 },
};

// Indexed [ecl.ord][version]; index 0 is unused.
const ECC_PER_BLOCK = [
  [-1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
  [-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28],
  [-1, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
  [-1, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
];
const NUM_BLOCKS = [
  [-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25],
  [-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49],
  [-1, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68],
  [-1, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81],
];

const bit = (x, i) => ((x >>> i) & 1) !== 0;

// Data modules in a symbol of this version, function patterns excluded.
function rawDataModules(ver) {
  let r = (16 * ver + 128) * ver + 64;
  if (ver >= 2) {
    const n = Math.floor(ver / 7) + 2;
    r -= (25 * n - 10) * n - 55;
    if (ver >= 7) r -= 36;
  }
  return r;
}

function dataCodewords(ver, ecl) {
  return Math.floor(rawDataModules(ver) / 8) - ECC_PER_BLOCK[ecl.ord][ver] * NUM_BLOCKS[ecl.ord][ver];
}

// --- Reed-Solomon over GF(2^8), polynomial 0x11D ---------------------------

function gfMul(x, y) {
  let z = 0;
  for (let i = 7; i >= 0; i--) {
    z = (z << 1) ^ ((z >>> 7) * 0x11d);
    z ^= ((y >>> i) & 1) * x;
  }
  return z & 0xff;
}

function rsDivisor(degree) {
  const r = new Array(degree).fill(0);
  r[degree - 1] = 1;
  let root = 1;
  for (let i = 0; i < degree; i++) {
    for (let j = 0; j < degree; j++) {
      r[j] = gfMul(r[j], root);
      if (j + 1 < degree) r[j] ^= r[j + 1];
    }
    root = gfMul(root, 0x02);
  }
  return r;
}

function rsRemainder(data, divisor) {
  const r = divisor.map(() => 0);
  for (const b of data) {
    const factor = b ^ r.shift();
    r.push(0);
    divisor.forEach((coef, i) => { r[i] ^= gfMul(coef, factor); });
  }
  return r;
}

// --- codewords ---------------------------------------------------------------

function encodeData(bytes, ver, ecl) {
  const bits = [];
  const put = (val, len) => { for (let i = len - 1; i >= 0; i--) bits.push((val >>> i) & 1); };
  put(0x4, 4); // byte mode
  put(bytes.length, ver <= 9 ? 8 : 16);
  for (const b of bytes) put(b, 8);
  const capBits = dataCodewords(ver, ecl) * 8;
  put(0, Math.min(4, capBits - bits.length));
  put(0, (8 - (bits.length % 8)) % 8);
  for (let pad = 0xec; bits.length < capBits; pad ^= 0xec ^ 0x11) put(pad, 8);
  const out = [];
  for (let i = 0; i < bits.length; i += 8) {
    let v = 0;
    for (let j = 0; j < 8; j++) v = (v << 1) | bits[i + j];
    out.push(v);
  }
  return out;
}

function addEccAndInterleave(data, ver, ecl) {
  const numBlocks = NUM_BLOCKS[ecl.ord][ver];
  const eccLen = ECC_PER_BLOCK[ecl.ord][ver];
  const raw = Math.floor(rawDataModules(ver) / 8);
  const numShort = numBlocks - (raw % numBlocks);
  const shortLen = Math.floor(raw / numBlocks);
  const divisor = rsDivisor(eccLen);
  const blocks = [];
  for (let i = 0, k = 0; i < numBlocks; i++) {
    const dat = data.slice(k, k + shortLen - eccLen + (i < numShort ? 0 : 1));
    k += dat.length;
    const ecc = rsRemainder(dat, divisor);
    if (i < numShort) dat.push(0); // placeholder, skipped when interleaving
    blocks.push(dat.concat(ecc));
  }
  const out = [];
  for (let i = 0; i < blocks[0].length; i++) {
    blocks.forEach((b, j) => {
      if (i !== shortLen - eccLen || j >= numShort) out.push(b[i]);
    });
  }
  return out;
}

// --- drawing -----------------------------------------------------------------

function alignmentPositions(ver, size) {
  if (ver === 1) return [];
  const n = Math.floor(ver / 7) + 2;
  const step = ver === 32 ? 26 : Math.ceil((ver * 4 + 4) / (n * 2 - 2)) * 2;
  const r = [6];
  for (let pos = size - 7; r.length < n; pos -= step) r.splice(1, 0, pos);
  return r;
}

function makeGrid(size) {
  return {
    size,
    m: Array.from({ length: size }, () => new Array(size).fill(false)),
    fn: Array.from({ length: size }, () => new Array(size).fill(false)),
  };
}

// x is the column, y the row.
function setFn(g, x, y, dark) { g.m[y][x] = dark; g.fn[y][x] = true; }

function drawFormat(g, ecl, mask) {
  const data = (ecl.bits << 3) | mask;
  let rem = data;
  for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
  const bits = ((data << 10) | rem) ^ 0x5412;
  const s = g.size;
  for (let i = 0; i <= 5; i++) setFn(g, 8, i, bit(bits, i));
  setFn(g, 8, 7, bit(bits, 6));
  setFn(g, 8, 8, bit(bits, 7));
  setFn(g, 7, 8, bit(bits, 8));
  for (let i = 9; i < 15; i++) setFn(g, 14 - i, 8, bit(bits, i));
  for (let i = 0; i < 8; i++) setFn(g, s - 1 - i, 8, bit(bits, i));
  for (let i = 8; i < 15; i++) setFn(g, 8, s - 15 + i, bit(bits, i));
  setFn(g, 8, s - 8, true); // the dark module
}

function drawVersion(g, ver) {
  if (ver < 7) return;
  let rem = ver;
  for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
  const bits = (ver << 12) | rem;
  for (let i = 0; i < 18; i++) {
    const a = g.size - 11 + (i % 3);
    const b = Math.floor(i / 3);
    setFn(g, a, b, bit(bits, i));
    setFn(g, b, a, bit(bits, i));
  }
}

function drawFunctionPatterns(g, ver, ecl) {
  const s = g.size;
  for (let i = 0; i < s; i++) { setFn(g, 6, i, i % 2 === 0); setFn(g, i, 6, i % 2 === 0); }
  for (const [cx, cy] of [[3, 3], [s - 4, 3], [3, s - 4]]) {
    for (let dy = -4; dy <= 4; dy++) {
      for (let dx = -4; dx <= 4; dx++) {
        const d = Math.max(Math.abs(dx), Math.abs(dy));
        const x = cx + dx; const y = cy + dy;
        if (x >= 0 && x < s && y >= 0 && y < s) setFn(g, x, y, d !== 2 && d !== 4);
      }
    }
  }
  const pos = alignmentPositions(ver, s);
  const last = pos.length - 1;
  for (let i = 0; i < pos.length; i++) {
    for (let j = 0; j < pos.length; j++) {
      if ((i === 0 && j === 0) || (i === 0 && j === last) || (i === last && j === 0)) continue;
      for (let dy = -2; dy <= 2; dy++) {
        for (let dx = -2; dx <= 2; dx++) setFn(g, pos[i] + dx, pos[j] + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
      }
    }
  }
  drawFormat(g, ecl, 0); // reserved now, redrawn with the chosen mask
  drawVersion(g, ver);
}

function drawCodewords(g, data) {
  const s = g.size;
  let i = 0;
  for (let right = s - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let vert = 0; vert < s; vert++) {
      for (let j = 0; j < 2; j++) {
        const x = right - j;
        const up = ((right + 1) & 2) === 0;
        const y = up ? s - 1 - vert : vert;
        if (!g.fn[y][x] && i < data.length * 8) {
          g.m[y][x] = bit(data[i >>> 3], 7 - (i & 7));
          i++;
        }
      }
    }
  }
}

const MASKS = [
  (x, y) => (x + y) % 2 === 0,
  (x, y) => y % 2 === 0,
  (x) => x % 3 === 0,
  (x, y) => (x + y) % 3 === 0,
  (x, y) => (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0,
  (x, y) => ((x * y) % 2) + ((x * y) % 3) === 0,
  (x, y) => (((x * y) % 2) + ((x * y) % 3)) % 2 === 0,
  (x, y) => (((x + y) % 2) + ((x * y) % 3)) % 2 === 0,
];

function applyMask(g, mask) {
  for (let y = 0; y < g.size; y++) {
    for (let x = 0; x < g.size; x++) if (!g.fn[y][x] && MASKS[mask](x, y)) g.m[y][x] = !g.m[y][x];
  }
}

// The standard's four penalty rules, close enough to pick a camera-friendly
// mask. Not load-bearing: every mask decodes.
function penalty(g) {
  const s = g.size;
  const m = g.m;
  let p = 0;
  const lines = (get) => {
    for (let a = 0; a < s; a++) {
      let run = 1;
      for (let b = 1; b <= s; b++) {
        if (b < s && get(a, b) === get(a, b - 1)) { run++; continue; }
        if (run >= 5) p += run - 2;
        run = 1;
      }
      for (let b = 0; b + 6 < s; b++) {
        const seq = [0, 1, 2, 3, 4, 5, 6].map((k) => get(a, b + k));
        if (seq.join() === 'true,false,true,true,true,false,true') p += 40;
      }
    }
  };
  lines((y, x) => m[y][x]);
  lines((x, y) => m[y][x]);
  for (let y = 0; y + 1 < s; y++) {
    for (let x = 0; x + 1 < s; x++) {
      const c = m[y][x];
      if (c === m[y][x + 1] && c === m[y + 1][x] && c === m[y + 1][x + 1]) p += 3;
    }
  }
  let dark = 0;
  for (const row of m) for (const c of row) if (c) dark++;
  p += Math.floor(Math.abs(dark * 20 - s * s * 10) / (s * s)) * 10;
  return p;
}

// -> { size, version, modules: boolean[row][col] } (true = dark)
function encode(text, { ecl = 'M', minVersion = 1 } = {}) {
  const level = ECL[ecl];
  if (!level) throw new Error(`unknown error correction level ${ecl}`);
  const bytes = [...Buffer.from(String(text), 'utf8')];
  let ver = Math.max(1, minVersion);
  for (; ver <= 40; ver++) {
    const header = 4 + (ver <= 9 ? 8 : 16);
    if (header + bytes.length * 8 <= dataCodewords(ver, level) * 8) break;
  }
  if (ver > 40) throw new Error('too long for a QR code');
  const codewords = addEccAndInterleave(encodeData(bytes, ver, level), ver, level);
  const size = ver * 4 + 17;
  let best = null;
  for (let mask = 0; mask < 8; mask++) {
    const g = makeGrid(size);
    drawFunctionPatterns(g, ver, level);
    drawCodewords(g, codewords);
    applyMask(g, mask);
    drawFormat(g, level, mask);
    const score = penalty(g);
    if (!best || score < best.score) best = { score, g, mask };
  }
  return { size, version: ver, mask: best.mask, modules: best.g.m };
}

// --- renderers -------------------------------------------------------------

function toSvg(qr, { quiet = 4, scale = 8, dark = '#111', light = '#fff' } = {}) {
  const n = qr.size + quiet * 2;
  let d = '';
  qr.modules.forEach((row, y) => row.forEach((c, x) => { if (c) d += `M${x + quiet},${y + quiet}h1v1h-1z`; }));
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${n} ${n}" width="${n * scale}" height="${n * scale}" shape-rendering="crispEdges" role="img" aria-label="QR code">`
    + `<rect width="${n}" height="${n}" fill="${light}"/><path d="${d}" fill="${dark}"/></svg>`;
}

// Two rows per character line with an upper half block, coloured explicitly,
// so it scans on a dark terminal as well as a light one.
function toTerminal(qr, { quiet = 2 } = {}) {
  const n = qr.size + quiet * 2;
  const at = (x, y) => {
    const xx = x - quiet; const yy = y - quiet;
    return xx >= 0 && yy >= 0 && xx < qr.size && yy < qr.size && qr.modules[yy][xx];
  };
  const lines = [];
  for (let y = 0; y < n; y += 2) {
    let line = '';
    for (let x = 0; x < n; x++) {
      const top = at(x, y); const bot = y + 1 < n ? at(x, y + 1) : false;
      line += `\x1b[${top ? 30 : 97};${bot ? 40 : 107}m▀`;
    }
    lines.push(`${line}\x1b[0m`);
  }
  return lines.join('\n');
}

module.exports = { encode, toSvg, toTerminal, rsDivisor, rsRemainder, encodeData, dataCodewords, ECL };
