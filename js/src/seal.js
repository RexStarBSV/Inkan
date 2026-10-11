// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 RexStarBSV
// Inkan verification path (see LICENSE-VERIFY and NOTICE). Repository default licence: BSL 1.1.
/**
 * inkan/seal -- Inkan Seal v3 (ISv3), byte-exact JS port of the Python reference.
 *
 * Structure is coded (bit-interleaved extended Golay [24,12,8], cell profiles 24/48/72), so
 * any two distinct seals differ in at least 8 interior cells: popcount(A|B) >= max(|A|,|B|) >= 8.
 * The kind selects the rotational symmetry order; (cells, k) is a function of the kind,
 * never a caller knob -- one digest must render one seal, everywhere, forever.
 *
 * Precision notes for this port:
 *   - Golay codewords are 24-bit: safe in JS 32-bit integer ops, but every XOR result
 *     is coerced with `>>> 0` (JS `^` yields SIGNED int32).
 *   - No floating point anywhere; tables are integers frozen at build time.
 *
 * Shares no code, structure, or output with LifeHash. An original design.
 * Parity gate: test/seal-parity.test.mjs vs ../test-vectors/seal-v3-vectors.json.
 */
import { sha256, requireBytes } from './sha256.js'
import { encodeUtf8, rejectUnassigned } from './seed.js'
import { CANVAS as CANVAS_, CORE_PATTERNS, KINDS, KMAX, ORBIT_REPS, PALETTE, REGION_RLE, SELECT_WEIGHTS, TIER_CELLS } from './seal_tables.js'

export const SEAL_VERSION = 3
export { CANVAS, KINDS } from './seal_tables.js'

const STREAM_DOMAIN = new TextEncoder().encode('inkan/seal/v3')
const KIND_DOMAIN = new TextEncoder().encode('inkan/kind/v1\0')

/**
 * Resolve any kind string to [cells, k, motif]. Reserved kinds use their curated entry; any other
 * string is derived deterministically (tier from an optional @t1/@t2/@t3 suffix, k and frame motif
 * from a domain-separated SHA-256 of the string). The standard is open to ANY kind, tier-weighted,
 * third-party assignable with no registry: any non-reserved string is a valid kind.
 */
export function resolveKind (kind) {
  if (typeof kind !== 'string') throw new TypeError('kind must be a string, got ' + (kind === null ? 'null' : typeof kind))
  if (Object.prototype.hasOwnProperty.call(KINDS, kind)) return KINDS[kind]
  // A kind the anchor rejects (an unassigned code point, SPEC §4.2 E14) is rejected here too, so no
  // seal is ever drawn for a kind that has no anchor.
  rejectUnassigned(kind, 'kind')
  let tier = 't2'
  for (const t of ['t1', 't2', 't3']) if (kind.endsWith('@' + t)) { tier = t; break }
  const cells = TIER_CELLS[tier]
  // Strict UTF-8 (SPEC §4.2 E4): TextEncoder would turn an unpaired surrogate into U+FFFD, so every
  // malformed kind would resolve like the kind "\uFFFD…" instead of being refused.
  const kb = encodeUtf8(kind, 'kind')
  const msg = new Uint8Array(KIND_DOMAIN.length + kb.length)
  msg.set(KIND_DOMAIN, 0); msg.set(kb, KIND_DOMAIN.length)
  const kh = sha256(msg)
  const k = 1 + (kh[0] % KMAX[cells])
  const motif = ORBIT_REPS[kh[1] % ORBIT_REPS.length]
  return [cells, k, motif]
}

// Weighted palette draw table; expansion order is normative and matches Python.
const SELECT_TABLE = []
SELECT_WEIGHTS.forEach((w, i) => { for (let n = 0; n < w; n++) SELECT_TABLE.push(i) })

// ------------------------------------------------------------------ codes
const GOLAY_G = 0xae3

export function golay24 (info12) {
  if (!Number.isInteger(info12)) throw new TypeError('golay24 takes an integer, got ' + String(info12))
  let c = 0
  for (let b = 0; b < 12; b++) {
    if ((info12 >> b) & 1) c = (c ^ (GOLAY_G << b)) >>> 0
  }
  let parity = 0
  for (let x = c; x; x >>>= 1) parity ^= x & 1
  return ((c << 1) | parity) >>> 0
}


// ------------------------------------------------------------------ field extraction
class Stream {
  constructor (digest) { this.d = digest; this.buf = []; this.ctr = 0 }
  byte () {
    if (this.buf.length === 0) {
      const ctr = new Uint8Array(4)
      new DataView(ctr.buffer).setUint32(0, this.ctr++, false)
      const msg = new Uint8Array(this.d.length + STREAM_DOMAIN.length + 4)
      msg.set(this.d, 0)
      msg.set(STREAM_DOMAIN, this.d.length)
      msg.set(ctr, this.d.length + STREAM_DOMAIN.length)
      this.buf = Array.from(sha256(msg))
    }
    return this.buf.shift()
  }
}

function uniform (stream, n) {
  const limit = 256 - (256 % n)
  for (;;) {
    const b = stream.byte()
    if (b < limit) return b % n
  }
}

export function sealFields (digest, kind = '') {
  requireBytes(digest, 'digest')
  if (digest.length !== 32) throw new RangeError('digest must be 32 bytes, got ' + digest.length)
  const cells = resolveKind(kind)[0]
  const s = new Stream(digest)
  const words = []
  for (let i = 0; i < cells / 12; i++) words.push(((s.byte() << 8) | s.byte()) & 0xfff)
  const paletteIx = SELECT_TABLE[uniform(s, SELECT_TABLE.length)]
  const corePattern = CORE_PATTERNS[uniform(s, CORE_PATTERNS.length)]
  return { words, paletteIx, corePattern }
}

function requireWords (words, n) {
  if (!(Array.isArray(words) || ArrayBuffer.isView(words)) || words.length < n) {
    throw new TypeError('words must be an array of at least ' + n + ' integers')
  }
  for (let i = 0; i < n; i++) {
    if (!Number.isInteger(words[i])) throw new TypeError('words[' + i + '] must be an integer, got ' + String(words[i]))
  }
}

export function cellsFromWords (words, cells) {
  if (!Number.isInteger(cells) || cells < 0) throw new TypeError('cells must be a non-negative integer')
  requireWords(words, Math.floor(cells / 24) * 2)
  const out = []
  for (let g = 0; g < cells / 24; g++) {
    const A = golay24(words[2 * g])
    const B = golay24(words[2 * g + 1])
    for (let i = 0; i < 24; i++) out.push((((B >>> i) & 1) << 1) | ((A >>> i) & 1))
  }
  return out
}

// ------------------------------------------------------------------ region maps
const regionCache = new Map()

function b64decode (str) {
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
  const out = []
  let bits = 0
  let acc = 0
  for (const ch of str) {
    if (ch === '=') break
    acc = (acc << 6) | A.indexOf(ch)
    bits += 6
    if (bits >= 8) { bits -= 8; out.push((acc >> bits) & 0xff) }
  }
  return out
}

function region (cells, k) {
  const key = `${cells},${k}`
  let reg = regionCache.get(key)
  if (!reg) {
    const blob = b64decode(REGION_RLE[key])
    reg = []
    for (let i = 0; i < blob.length; i += 3) {
      const v = blob[i]
      const n = blob[i + 1] | (blob[i + 2] << 8)
      for (let j = 0; j < n; j++) reg.push(v)
    }
    if (reg.length !== CANVAS_ * CANVAS_) throw new Error(`corrupt region table ${key}`)
    regionCache.set(key, reg)
  }
  return reg
}

// ------------------------------------------------------------------ render
export function sealRgbFromFields (words, paletteIx, corePattern, kind = '') {
  const [cells, k, motif] = resolveKind(kind)
  requireWords(words, cells / 12)
  if (!Number.isInteger(paletteIx) || paletteIx < 0 || paletteIx >= PALETTE.length) {
    throw new RangeError('paletteIx must be an integer from 0 to ' + (PALETTE.length - 1) + ', got ' + String(paletteIx))
  }
  if (!Number.isInteger(corePattern)) throw new TypeError('corePattern must be an integer, got ' + String(corePattern))
  const cl = cellsFromWords(words, cells)
  const [ground, a1, a2, a3, core] = PALETTE[paletteIx]
  const petal = [ground, a1, a2, a3]
  const reg = region(cells, k)
  const out = new Uint8Array(reg.length * 3)
  for (let i = 0; i < reg.length; i++) {
    const r = reg[i]
    let c
    if (r < cells) c = petal[cl[r]]
    else if (r < 200) c = ((corePattern >> (r - 100)) & 1) ? core : ground
    else if (r < 255) c = ((motif >> (r - 200)) & 1) ? a1 : ground
    else c = ground
    out[i * 3] = c[0]; out[i * 3 + 1] = c[1]; out[i * 3 + 2] = c[2]
  }
  return { width: CANVAS_, height: CANVAS_, pixels: out }
}

/** Render a 32-byte digest to a {width, height, pixels} RGB888 image (row-major). */
export function sealRgb (digest, kind = '') {
  const f = sealFields(digest, kind)
  return sealRgbFromFields(f.words, f.paletteIx, f.corePattern, kind)
}

/** Integer nearest-neighbour upscale of a {width, height, pixels} image. */
export function scaleNearest (img, scale = 1) {
  if (!Number.isInteger(scale) || scale < 1) throw new RangeError('scale must be a positive integer, got ' + String(scale))
  if (scale === 1) return img
  const W = img.width * scale
  const H = img.height * scale
  const out = new Uint8Array(W * H * 3)
  for (let y = 0; y < H; y++) {
    for (let x = 0; x < W; x++) {
      const src = (((y / scale) | 0) * img.width + ((x / scale) | 0)) * 3
      const dst = (y * W + x) * 3
      out[dst] = img.pixels[src]; out[dst + 1] = img.pixels[src + 1]; out[dst + 2] = img.pixels[src + 2]
    }
  }
  return { width: W, height: H, pixels: out }
}

// ------------------------------------------------------------------ PNG export
// A valid PNG whose PIXELS match the reference exactly. Uses STORED (uncompressed) deflate so it
// needs no compression library and works identically in every browser and in node. The
// cross-language INVARIANT is the RGB (verified over 1500 vectors); PNG byte-encoding is
// per-implementation (all valid, all decode to the same pixels). `tag` embeds the ik1 code + kind
// as iTXt, matching the Python/tag format read/written by the verifier.
function crc32png (u) {
  let c = 0xFFFFFFFF
  for (let i = 0; i < u.length; i++) {
    c ^= u[i]
    for (let k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1)
  }
  return (c ^ 0xFFFFFFFF) >>> 0
}

function adler32 (u) {
  let a = 1; let b = 0
  for (let i = 0; i < u.length; i++) { a = (a + u[i]) % 65521; b = (b + a) % 65521 }
  return ((b << 16) | a) >>> 0
}

function zlibStored (data) {
  // 2-byte zlib header, then stored deflate blocks (<= 65535 each), then adler32.
  const out = [0x78, 0x01]
  let i = 0
  while (i < data.length) {
    const n = Math.min(65535, data.length - i)
    const last = (i + n >= data.length) ? 1 : 0
    out.push(last, n & 0xFF, (n >> 8) & 0xFF, (~n) & 0xFF, ((~n) >> 8) & 0xFF)
    for (let j = 0; j < n; j++) out.push(data[i + j])
    i += n
  }
  const ad = adler32(data)
  out.push((ad >>> 24) & 0xFF, (ad >>> 16) & 0xFF, (ad >>> 8) & 0xFF, ad & 0xFF)
  return Uint8Array.from(out)
}

function pngChunk (name, data) {
  const nameB = new TextEncoder().encode(name)
  const body = new Uint8Array(nameB.length + data.length)
  body.set(nameB, 0); body.set(data, nameB.length)
  const out = new Uint8Array(4 + body.length + 4)
  const dv = new DataView(out.buffer)
  dv.setUint32(0, data.length); out.set(body, 4); dv.setUint32(4 + body.length, crc32png(body))
  return out
}

function iTxtChunk (keyword, text) {
  const kw = new TextEncoder().encode(keyword); const tx = new TextEncoder().encode(text)
  const body = new Uint8Array(kw.length + 5 + tx.length)
  body.set(kw, 0); body.set(tx, kw.length + 5)   // 5 zero bytes: nul + comp + method + lang nul + transkw nul
  return pngChunk('iTXt', body)
}

/** Encode a seal to an 8-bit indexed PNG (Uint8Array). `tag` embeds the ik1 code + kind as iTXt. */
export function sealPng (digest, kind = '', { tag = false } = {}) {
  const img = sealRgb(digest, kind)
  const n = img.width
  // build the indexed palette (sorted unique RGB, matching the reference ordering)
  const seen = new Map()
  const key = (r, g, b) => (r << 16) | (g << 8) | b
  for (let i = 0; i < n * n; i++) seen.set(key(img.pixels[i * 3], img.pixels[i * 3 + 1], img.pixels[i * 3 + 2]), 1)
  const pal = [...seen.keys()].sort((a, b) => a - b)
  const ix = new Map(pal.map((k, i) => [k, i]))
  // scanlines: filter byte 0 + one index per pixel
  const raw = new Uint8Array(n * (n + 1))
  let o = 0
  for (let y = 0; y < n; y++) {
    raw[o++] = 0
    for (let x = 0; x < n; x++) {
      const p = (y * n + x) * 3
      raw[o++] = ix.get(key(img.pixels[p], img.pixels[p + 1], img.pixels[p + 2]))
    }
  }
  const ihdr = new Uint8Array(13); const dv = new DataView(ihdr.buffer)
  dv.setUint32(0, n); dv.setUint32(4, n); ihdr[8] = 8; ihdr[9] = 3   // bit depth 8, colour type 3 (indexed)
  const plte = new Uint8Array(pal.length * 3)
  pal.forEach((k, i) => { plte[i * 3] = (k >> 16) & 0xFF; plte[i * 3 + 1] = (k >> 8) & 0xFF; plte[i * 3 + 2] = k & 0xFF })
  const parts = [
    Uint8Array.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    pngChunk('IHDR', ihdr), pngChunk('PLTE', plte), pngChunk('IDAT', zlibStored(raw)),
  ]
  if (tag) { parts.push(iTxtChunk('inkan-code', 'ik1' + bytesToHexLocal(digest)), iTxtChunk('inkan-kind', kind)) }
  parts.push(pngChunk('IEND', new Uint8Array(0)))
  const total = parts.reduce((s, p) => s + p.length, 0)
  const out = new Uint8Array(total)
  let off = 0; for (const p of parts) { out.set(p, off); off += p.length }
  return out
}

function bytesToHexLocal (u) { return Array.from(u).map(b => b.toString(16).padStart(2, '0')).join('') }

