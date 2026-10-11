#!/usr/bin/env node
// Execute the ENGINE OUT OF THE GENERATED PAGE and run every vector the page would run.
//
// Deliberately extracts from the built HTML rather than importing js/src: the question is not
// "is the source correct" but "is the artifact we are about to ship correct". Those differ
// whenever the inliner does something unexpected -- which it has: a duplicate `const encoder`
// once made the whole inline script unparseable while every size and reference check passed.
import { readFileSync } from 'node:fs'

const file = process.argv[2]
if (!file) { console.error('usage: check_web_verifier.mjs <inkan-verify.html>'); process.exit(2) }
const html = readFileSync(file, 'utf8')

const start = html.indexOf('// ==== canonical Inkan engine')
const stIx = html.indexOf('const SELFTEST =', start)
if (start < 0 || stIx < 0) { console.error('build gate: engine block not found in ' + file); process.exit(1) }
const engine = html.slice(start, html.indexOf('\n', stIx))

let E
try {
  E = new Function(engine + '\nreturn {sealRgb,sealPng,iTxtChunk,sha256,inkanSeed,resolveKind,fingerprintHex,canonicalBytes,messageHash,verify,status,SELFTEST};')()
} catch (e) { console.error('build gate: inlined engine does not parse — ' + e.message); process.exit(1) }

const toHex = b => [...b].map(x => x.toString(16).padStart(2, '0')).join('')
const bytes = hx => Uint8Array.from(hx.match(/../g).map(x => parseInt(x, 16)))
const S = E.SELFTEST
let pass = 0, total = 0, brc = 0, brcTotal = 0
const fails = []
const eq = (a, b, what) => { total++; if (a === b) pass++; else fails.push(what); return a === b }
const eqB = (a, b, what) => { brcTotal++; if (eq(a, b, what)) brc++ }

for (const v of S.brc.seed) eqB(toHex(E.inkanSeed(v.d, v.k)), v.h, 'brc seed ' + v.w)
for (const v of S.brc.code) eqB('ik1' + toHex(E.sha256(E.inkanSeed(v.d, v.k))), v.h, 'brc code ' + v.w)
for (const v of S.brc.kind) eqB(JSON.stringify(E.resolveKind(v.k)), JSON.stringify(v.h), 'brc kind ' + v.w)
for (const v of S.brc.fp) eqB(E.fingerprintHex(new TextEncoder().encode(v.p), v.a, v.v), v.h, 'brc fp ' + v.w)
for (const v of S.brc.canary || []) {
  eqB(String(E.canonicalBytes(v.r).length), String(v.bytes), 'brc canary canonical bytes')
  eqB(toHex(E.messageHash(v.r)), v.mh, 'brc canary message hash')
  eqB(String(E.verify(v.r, v.sig, v.pub)), 'true', 'brc canary signature')
  eq(String(E.verify({ ...v.r, seq: v.r.seq + 1 }, v.sig, v.pub)), 'false', 'canary rejects tampered record')
  eq(String(E.verify(v.r, v.sig.slice(0, -2) + '00', v.pub)), 'false', 'canary rejects corrupted signature')
}
for (const v of S.anchor) {
  const seed = E.inkanSeed(v.d, v.k)
  eq(toHex(seed), v.s, 'anchor seed ' + v.k)
  eq(toHex(E.sha256(E.sealRgb(E.sha256(seed), v.k).pixels)), v.h, 'anchor e2e ' + v.k)
}
for (const v of S.render) eq(toHex(E.sha256(E.sealRgb(bytes(v.d), v.k).pixels)), v.h, 'render ' + v.k)
{
  const png = E.sealPng(bytes(S.render[0].d), S.render[0].k)
  const names = []
  for (let o = 8; o + 8 <= png.length;) {
    const len = (png[o] << 24 | png[o + 1] << 16 | png[o + 2] << 8 | png[o + 3]) >>> 0
    names.push(String.fromCharCode(png[o + 4], png[o + 5], png[o + 6], png[o + 7]))
    o += 12 + len
  }
  eq(names.join(','), 'IHDR,PLTE,IDAT,IEND', 'png chunk structure')
  eq(String.fromCharCode(...png.slice(1, 4)) + png[0], 'PNG' + 137, 'png signature')
}
for (const v of S.fp) eq(E.fingerprintHex(new TextEncoder().encode(v.p), v.a, v.v), v.h, 'fp ' + v.a)

if (total === 0 || brcTotal === 0) {
  console.error('build gate: empty vector set — no evidence is not a pass'); process.exit(1)
}
if (pass !== total) {
  console.error('build gate: ' + (total - pass) + ' FAILED of ' + total)
  for (const f of fails) console.error('  - ' + f)
  process.exit(1)
}
console.log('build gate: ' + pass + '/' + total + ' vectors OK (' + brc + '/' + brcTotal + ' published in BRC-145)')

// ---- the page's own UI, run against a minimal stand-in for the DOM ----
// The vectors above prove the engine. These prove two things about the UI around it that no vector
// can. (1) It never builds markup from a string. Several values it shows come from outside the page
// (the code in an uploaded PNG's metadata, the fields of a pasted canary record, a typed kind or
// adopter); markup built from any of them could run script and repaint a verdict, so a crafted file
// could make a forgery read GENUINE. (2) A canary check that could not run (MALFORMED) reads as
// exactly that, never as a valid signature.
const uiStart = html.indexOf('// ==== verifier UI ====', start)
const scriptEnd = html.indexOf('</script>', uiStart)
if (uiStart < 0 || scriptEnd < 0) { console.error('build gate: UI block not found in ' + file); process.exit(1) }
const ui = html.slice(uiStart, scriptEnd)
let uiPass = 0, uiTotal = 0
const uiFails = []
const check = (cond, what) => { uiTotal++; if (cond) uiPass++; else uiFails.push(what) }

for (const sink of ['innerHTML', 'outerHTML', 'insertAdjacentHTML', 'document.write',
  'createContextualFragment', 'srcdoc', 'DOMParser']) {
  check(!ui.includes(sink), 'the UI never parses a string as markup (it uses ' + sink + ')')
}

class TextNode {
  constructor (s) { this.nodeType = 3; this.data = String(s) }
  get textContent () { return this.data }
}
class Elem {
  constructor (tag, id = '') {
    Object.assign(this, { tagName: String(tag).toUpperCase(), id, nodeType: 1, childNodes: [],
      style: {}, value: '', files: [], attrs: {}, listeners: {}, hidden: false, disabled: false,
      className: '', title: '', selectedIndex: -1, width: 224, height: 224 })
  }
  get textContent () { return this.childNodes.map(n => n.textContent).join('') }
  set textContent (v) { this.childNodes = v === '' ? [] : [new TextNode(v)] }
  get innerHTML () { throw new Error('innerHTML read on #' + this.id) }
  set innerHTML (v) { throw new Error('a string was parsed as markup into #' + this.id) }
  get parentNode () { return this._parent || (this._parent = new Elem('span')) }
  appendChild (n) { this.childNodes.push(n); return n }
  addEventListener (type, fn) { (this.listeners[type] = this.listeners[type] || []).push(fn) }
  setAttribute (k, v) { this.attrs[k] = String(v) }
  removeAttribute (k) { delete this.attrs[k] }
  scrollIntoView () {}
  toBlob () {}
  getContext () {
    return { createImageData: (w, h) => ({ data: new Uint8ClampedArray(w * h * 4) }),
      putImageData () {}, drawImage () {}, clearRect () {},
      getImageData: (x, y, w, h) => ({ data: new Uint8ClampedArray(w * h * 4) }) }
  }
  descendants () {
    const out = []
    const walk = n => { for (const c of n.childNodes) if (c.nodeType === 1) { out.push(c.tagName); walk(c) } }
    walk(this)
    return out
  }
}
const byId = new Map()
const $ = id => { if (!byId.has(id)) byId.set(id, new Elem('div', id)); return byId.get(id) }
const doc = { getElementById: $, createElement: tag => new Elem(tag),
  createTextNode: s => new TextNode(s), addEventListener () {} }
// The page decodes presented files itself (SPEC §6.1) and never through an Image, so the stand-in
// Image refuses to load anything: a page that fell back on the browser's decoder would fail here.
class NoDecodeImage { set src (u) { throw new Error('the page asked the browser to decode an image') } }
const ownElements = el => el.descendants().every(t => t === 'B' || t === 'SPAN' || t === 'BR')
const settle = () => new Promise(resolve => setTimeout(resolve, 20))

$('kind').value = 'address'; $('fpver').value = '1'; $('cnwin').value = '35'   // the page's defaults
const pageErrors = []      // the page starts work it does not await (the first render, for one)
process.on('unhandledRejection', e => { pageErrors.push(String((e && e.message) || e)) })
let uiRan = true
try { new Function('document', 'Image', html.slice(start, scriptEnd))(doc, NoDecodeImage) } catch (e) {
  uiRan = false; check(false, 'the page script runs: ' + e.message)
}
if (uiRan) {
  await settle()
  check(/^self-test ✓/.test($('selftest').textContent), 'the page reports its own self-test passed')

  // 1. The ik1 code in a presented PNG's metadata is shown as text, whatever it contains.
  const payload = '<img src=x onerror="globalThis.inkanMarkupRan=1">'
  const png = E.sealPng(E.sha256(E.inkanSeed('evil', 'address')), 'address')
  const chunk = E.iTxtChunk('inkan-code', payload)
  const crafted = new Uint8Array(png.length + chunk.length)
  crafted.set(png.subarray(0, png.length - 12), 0)
  crafted.set(chunk, png.length - 12)
  crafted.set(png.subarray(png.length - 12), png.length - 12 + chunk.length)
  $('data').value = ''
  $('file').files = [new File([crafted], 'seal.png', { type: 'image/png' })]
  try {
    await $('go').onclick()
    await settle()
    check($('kv').textContent.includes(payload) && $('kv').textContent.includes('DOES NOT MATCH'),
      'the code embedded in a presented PNG is shown as text, and flagged as not matching')
    check(ownElements($('kv')), 'the seal result holds only the page\'s own elements')
  } catch (e) { check(false, 'a presented PNG with markup in its metadata: ' + e.message) }
  check(globalThis.inkanMarkupRan === undefined, 'nothing from a presented PNG ran')

  // 1b. Every presented file in png-profile-vectors.json gets its pinned verdict from the page's own
  // decoder (SPEC §6.1, E24): GENUINE, MISMATCH or REJECTED, exactly as the reference verifier says.
  {
    const pv = JSON.parse(readFileSync(new URL('../../test-vectors/png-profile-vectors.json', import.meta.url), 'utf8'))
    $('data').value = pv.data_utf8; $('kind').value = pv.kind
    let agree = 0
    for (const v of pv.cases) {
      $('file').files = [new File([Buffer.from(v.png_base64, 'base64')], 'seal.png', { type: 'image/png' })]
      try {
        await $('go').onclick()
        const t = $('verdict').textContent
        const shown = /GENUINE/.test(t) ? 'GENUINE' : /MISMATCH/.test(t) ? 'MISMATCH' : /REJECTED/.test(t) ? 'REJECTED' : '?'
        if (shown === v.expect) agree++; else uiFails.push('png vector ' + v.name + ': page shows ' + shown + ', pinned ' + v.expect + ' (' + t.slice(0, 120) + ')')
      } catch (e) { uiFails.push('png vector ' + v.name + ': ' + e.message) }
    }
    check(agree === pv.cases.length, 'the page gives the pinned verdict for every PNG profile vector (' + agree + '/' + pv.cases.length + ')')
    $('file').files = []; $('kind').value = 'address'; $('data').value = ''
  }

  // 1b2. A file whose header declares a size no seal can have reads REJECTED, as in the reference
  // verifier, even when that size is too large for the page to decode.
  {
    const zlib = await import('node:zlib')
    const chunk = (name, data) => {
      const b = Buffer.alloc(12 + data.length)
      b.writeUInt32BE(data.length, 0); b.write(name, 4, 'latin1'); Buffer.from(data).copy(b, 8)
      b.writeUInt32BE(zlib.crc32(b.subarray(4, 8 + data.length)), 8 + data.length)
      return b
    }
    const ihdr = Buffer.alloc(13); ihdr.writeUInt32BE(100000, 0); ihdr.writeUInt32BE(90000, 4); ihdr[8] = 8; ihdr[9] = 2
    const huge = Buffer.concat([Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]), chunk('IHDR', ihdr),
      chunk('IDAT', zlib.deflateSync(Buffer.alloc(10))), chunk('IEND', Buffer.alloc(0))])
    $('data').value = 'x'; $('kind').value = 'address'
    $('file').files = [new File([huge], 'seal.png', { type: 'image/png' })]
    try {
      await $('go').onclick()
      check(/^\u2717 REJECTED/.test($('verdict').textContent) && /100000\u00d790000/.test($('verdict').textContent),
        'a file declaring a size no seal has reads REJECTED, not "too large to check"')
    } catch (e) { check(false, 'a file declaring a huge size: ' + e.message) }
    $('file').files = []; $('data').value = ''
  }

  // 1c. The page's own inflate refuses exactly what zlib refuses, and agrees with it on every stream it
  // accepts: node's zlib, the library the reference verifier uses, over streams of every deflate level,
  // strategy and window, and corrupted, truncated and over-long copies of them.
  {
    const zlib = await import('node:zlib')
    const crypto = await import('node:crypto')
    const a = html.indexOf('// ==== verifiable-PNG decoder'), b = html.indexOf('// ==== end verifiable-PNG decoder')
    let D = null
    try { D = new Function(html.slice(a, b) + '\nreturn { inflateZlib, NotVerifiable }')() } catch (e) { check(false, 'the page decoder parses on its own: ' + e.message) }
    if (D) {
      let seed = 20261011
      const rnd = n => { seed = (seed * 1103515245 + 12345) >>> 0; return seed % n }
      const ref = (z, want) => {       // the reference's rule 6, on zlib
        if (z.length < 2 || (z[0] & 15) !== 8 || (z[0] >> 4) > 7 || ((z[0] << 8) | z[1]) % 31 || (z[1] & 32)) return null
        let out
        try { out = zlib.inflateSync(z, { info: true, maxOutputLength: want + 1 }) } catch (e) { return null }
        const used = out.engine.bytesWritten
        return (out.buffer.length === want && used === z.length) ? out.buffer : null
      }
      let n = 0, same = 0
      for (let i = 0; i < 300; i++) {
        const len = [0, 1, 7, 100, 1000, 20000][rnd(6)]
        const data = Buffer.alloc(len)
        const mode = rnd(3)
        for (let j = 0; j < len; j++) data[j] = mode === 0 ? rnd(256) : mode === 1 ? 97 + rnd(2) : (j % 37) & 3
        const z0 = zlib.deflateSync(data, { level: [0, 1, 6, 9][rnd(4)], windowBits: [9, 12, 15][rnd(3)],
          strategy: [0, 1, 2, 3, 4][rnd(5)] })
        const variants = [[z0, len], [z0.subarray(0, rnd(z0.length)), len], [Buffer.concat([z0, Buffer.from([rnd(256)])]), len],
          [z0, len + 1], [z0, Math.max(0, len - 1)]]
        { const m = Buffer.from(z0); m[2 + rnd(Math.max(1, m.length - 2))] ^= 1 << rnd(8); variants.push([m, len]) }
        for (const [z, want] of variants) {
          n++
          const r = ref(z, want)
          let got = null
          try { got = D.inflateZlib(Uint8Array.from(z), want) } catch (e) { if (!(e instanceof D.NotVerifiable)) throw e }
          const h = x => x === null ? null : crypto.createHash('sha256').update(x).digest('hex')
          if (h(r) === h(got)) same++; else uiFails.push('inflate differs from zlib on a stream of ' + want + ' bytes')
        }
      }
      check(same === n, 'the page inflate agrees with zlib on ' + same + '/' + n + ' streams')
    }
  }

  // 1d. The live seal sits directly above the data box, with its ik1 code beneath it, and the hint
  // beside the box: there on load and whenever the box is empty, gone once anything is typed, never
  // laid over the box, announced politely, and still under prefers-reduced-motion.
  {
    // the artifact variant has no <body> tag; its markup starts after the style block
    const body = html.slice(html.indexOf('<body>') >= 0 ? html.indexOf('<body>') : html.indexOf('</style>'))
    const at = id => body.indexOf('id="' + id + '"')
    check(at('cvExpected') >= 0 && at('livecode') > at('cvExpected') && at('datalabel') > at('livecode') &&
      at('data') > at('datalabel') && body.slice(at('livecode'), at('data')).indexOf('<input type="file" id="file"') < 0 &&
      at('result') > at('data'), 'the live seal and its code come directly before the data box, and the result panel after it')
    check(/<p class="hint" id="datahint" aria-live="polite"><\/p>/.test(html), 'the hint is a polite live region')
    const css = html.slice(html.indexOf('<style>'), html.indexOf('</style>'))
    const hintCss = (css.match(/\.hint[^{]*\{[^}]*\}/g) || []).join(' ')
    check(hintCss && !/position\s*:\s*(absolute|fixed)/.test(hintCss) && /prefers-reduced-motion:reduce\)\{\.hint\.again/.test(css) &&
      !/\.hint:not\(:empty\)\{animation/.test(css),
      'the hint is never laid over the box, and stops animating under prefers-reduced-motion')
    // At these widths the hint wraps to two lines (measured in Firefox: up to 630 px), so two lines are
    // kept for it, and the box does not move when the hint comes and goes.
    const reserve = /@media\(max-width:(\d+)px\)\{\.hint\{min-height:3em\}\}/.exec(css)
    check(reserve && +reserve[1] >= 640, 'two lines are kept for the hint on narrow screens, so the box does not move')
    const HINT = 'Type text here to watch your Inkan generate live'
    const fire = id => { for (const f of $(id).listeners.input || []) f() }
    $('data').value = ''; fire('data')
    const onLoad = $('datahint').textContent
    $('data').value = 'x'; fire('data')
    const typed = $('datahint').textContent
    $('data').value = ''; fire('data')
    check(onLoad === HINT && typed === '' && $('datahint').textContent === HINT,
      'the hint shows while the box is empty and goes once something is typed')

    const codeOf = async () => { await $('go').onclick(); return $('livecode').textContent }
    const uv = JSON.parse(readFileSync(new URL('../../test-vectors/unicode-vectors.json', import.meta.url), 'utf8'))
    const cafe = uv.accept.find(v => v.name === 'decomposed-cafe')
    $('file').files = []; $('kind').value = ''
    $('data').value = 'Hello'
    check(await codeOf() === S.brc.code[0].h, 'the live code under the seal is the ik1 code of the typed text (TV1)')
    $('data').value = 'cafe\u0301'
    check(await codeOf() === cafe.result_if_accepted.code, 'typed text is text: decomposed caf\u00e9 gives the text anchor (E19)')
    $('modeHex').checked = true; $('modeText').checked = false
    for (const f of $('modeHex').listeners.change || []) f()
    $('datahex').value = '63 61 66 65 cc 81'
    check(await codeOf() === cafe.if_passed_as_bytes && $('datahint').textContent === '' && !$('datahex').hidden && $('data').hidden,
      'raw bytes in hex give the bytes anchor, and the text hint is not shown')
    $('datahex').value = '6g'
    await $('go').onclick()
    check(/not a hex digit/.test($('livecode').textContent), 'a hex string with a non-hex digit is refused, with the reason')
    $('modeHex').checked = false; $('modeFile').checked = true
    $('datafile').files = [new File([new TextEncoder().encode('cafe\u0301')], 'note.txt')]
    for (const f of $('datafile').listeners.change || []) await f()
    check(await codeOf() === cafe.if_passed_as_bytes, 'a text file gives the anchor of its exact bytes, as the command line does')
    $('modeFile').checked = false; $('modeText').checked = true
    for (const f of $('modeText').listeners.change || []) f()
    await new Promise(resolve => setTimeout(resolve, 200))   // the live render the mode change scheduled
    $('data').value = 'cafe\u0301'
    await $('go').onclick()
    $('avgo').onclick()
    check(/bits flipped: 40(?!\d)/.test($('avkv').textContent), 'the avalanche check flips the NFC bytes of the text (5 bytes, 40 bits)')
    check($('univer').textContent === 'Unicode ' + process.versions.unicode.split('.').slice(0, 2).join('.'),
      'the page shows the Unicode version its character check reads')
    // The seal the page offers for saving is the canonical tagged PNG, and reads GENUINE when presented back.
    $('data').value = 'Hello'
    await $('go').onclick()
    const saved = Buffer.from(String($('dlseal').href).split(',')[1], 'base64')
    $('file').files = [new File([saved], 'saved.png', { type: 'image/png' })]
    await $('go').onclick()
    check(/GENUINE/.test($('verdict').textContent) && /embedded code \(untrusted\): ik1\S+ \u2014 matches/.test($('kv').textContent),
      'a seal saved from the page reads GENUINE when presented back, with its tag')

    // 1e. A result is shown only for the input it was computed from. Typing while a presented file
    // is still being read supersedes that comparison: the page must not then show a verdict for the
    // old data under a box holding new data, nor put the old seal back above it. Likewise a data file
    // picked later is never replaced by an earlier pick that took longer to read.
    const wait = ms => new Promise(resolve => setTimeout(resolve, ms))
    const slowFile = (name, bytes, ms) => ({ name, size: bytes.length,
      arrayBuffer: () => new Promise(resolve => setTimeout(() => resolve(bytes.slice().buffer), ms)) })
    const codeFor = d => 'ik1' + toHex(E.sha256(E.inkanSeed(d, '')))
    const sealUrl = d => 'data:image/png;base64,' + Buffer.from(E.sealPng(E.sha256(E.inkanSeed(d, '')), '', { tag: true })).toString('base64')
    $('kind').value = ''; $('data').value = 'Hello'
    $('file').files = [slowFile('seal.png', E.sealPng(E.sha256(E.inkanSeed('Hello', '')), ''), 300)]
    const comparing = $('go').onclick()
    await wait(20)
    $('data').value = 'Goodbye'; fire('data')
    await wait(200)
    await comparing
    check(!/GENUINE/.test($('verdict').textContent) && $('livecode').textContent === codeFor('Goodbye') &&
      $('imExpected').src === sealUrl('Goodbye') && $('kv').textContent.includes(codeFor('Goodbye')),
    'typing while a presented file is read: no verdict for the old data is shown, and the live seal stays the new one')
    $('file').files = []
    $('modeText').checked = false; $('modeFile').checked = true
    for (const f of $('modeFile').listeners.change || []) f()
    const utf8 = new TextEncoder()
    $('datafile').files = [slowFile('a.txt', utf8.encode('A'), 200)]
    const first = Promise.all(($('datafile').listeners.change || []).map(f => f()))
    $('datafile').files = [slowFile('b.txt', utf8.encode('B'), 0)]
    await Promise.all(($('datafile').listeners.change || []).map(f => f()))
    await first
    check($('livecode').textContent === codeFor(utf8.encode('B')),
      'a data file picked later is not replaced by an earlier pick that was slower to read')
    $('datafile').files = []
    $('modeFile').checked = false; $('modeText').checked = true
    for (const f of $('modeText').listeners.change || []) f()
    await wait(200)
    $('file').files = []; $('kind').value = 'address'; $('data').value = ''
  }

  // 2. A typed kind is shown as text, in the seal result and in the avalanche panel.
  $('file').files = []
  $('kind').value = '<img src=x>'
  $('data').value = 'x'
  try {
    await $('go').onclick()
    check($('kv').textContent.includes('<img src=x>') && ownElements($('kv')), 'a typed kind is shown as text')
    $('avgo').onclick()
    check($('avkv').textContent.includes('<img src=x>') && ownElements($('avkv')),
      'a typed kind is shown as text in the avalanche panel')
  } catch (e) { check(false, 'a typed kind containing markup: ' + e.message) }
  $('kind').value = 'address'

  // 2b. Input the standard refuses is reported, never thrown: a code point this runtime's Unicode
  // database leaves unassigned (E14), in the data and in the kind.
  for (const [what, data, kind] of [['data', 'a\u0378', 'address'], ['kind', 'x', 'x\u0378@t3']]) {
    $('file').files = []; $('data').value = data; $('kind').value = kind
    try {
      await $('go').onclick()
      check(/Cannot seal this input/.test($('verdict').textContent) && /E14/.test($('verdict').textContent) &&
        $('kv').textContent === '', 'an unassigned code point in the ' + what + ' is refused with E14, and no code is shown')
    } catch (e) { check(false, 'an unassigned code point in the ' + what + ': ' + e.message) }
  }
  $('kind').value = 'x\u0378@t3'; $('data').value = 'x'
  try {
    $('avgo').onclick()
    check(/Cannot run the check/.test($('avverdict').textContent), 'the avalanche check refuses a kind the standard refuses')
  } catch (e) { check(false, 'the avalanche check with a refused kind: ' + e.message) }
  $('kind').value = 'address'; $('data').value = ''

  // 3. Every field of a pasted canary record is shown as text.
  const c = S.brc.canary[0]
  $('cnpub').value = c.pub; $('cnsig').value = c.sig; $('cnas').value = ''; $('cnheight').value = ''
  const canon = r => new TextDecoder().decode(E.canonicalBytes(r))
  $('cnrec').value = canon({ ...c.r, statement: '<img src=x onerror=alert(1)>', domain: '<i>acme</i>' })
  try {
    $('cngo').onclick()
    check($('cnkv').textContent.includes('<img src=x onerror=alert(1)>') &&
      $('cnkv').textContent.includes('<i>acme</i>') && ownElements($('cnkv')),
    'canary record fields are shown as text')
    check(/INVALID/.test($('cnverdict').textContent), 'an altered canary record reads INVALID')
  } catch (e) { check(false, 'a canary record containing markup: ' + e.message) }

  // 5. A canary check that could not run never reads as a valid signature.
  const malformed = [
    ['a truncated signature', JSON.stringify(c.r), c.sig.slice(0, 20)],
    ['a signature that is not hex', JSON.stringify(c.r), 'zz'],
    ['a record that is not an object', 'null', c.sig],
    ['a record missing a field', JSON.stringify({ ...c.r, statement: undefined }), c.sig],
  ]
  for (const [why, rec, sig] of malformed) {
    $('cnrec').value = rec; $('cnpub').value = c.pub; $('cnsig').value = sig
    try {
      $('cngo').onclick()
      const v = $('cnverdict').textContent, k = $('cnkv').textContent
      check(/MALFORMED/.test(v) && /could not check/.test(v), why + ' reads MALFORMED, could not check')
      check(!/\bVALID\b/.test(k) && !/^\u2713/.test(v) && !/undefined/.test(v + k) &&
        !/\b(good|bad)\b/.test($('cnverdict').className),
      why + ' never reads as a valid signature, or as a forgery')
    } catch (e) { check(false, why + ' is reported, not thrown: ' + e.message) }
  }
  $('cnrec').value = '\n ' + canon(c.r) + '\n'; $('cnsig').value = c.sig; $('cnas').value = '2026-07-01'
  try {
    $('cngo').onclick()
    check(/^\u2713 OK/.test($('cnverdict').textContent) && /\bVALID\b/.test($('cnkv').textContent),
      'the BRC-145 example canary reads OK, signature VALID, as of 2026-07-01 (blank space around it ignored)')
  } catch (e) { check(false, 'the BRC-145 example canary: ' + e.message) }

  // 6. The canary card judges the record's bytes (SPEC §8 E23): a re-formatted copy is MALFORMED, and
  // the page agrees with the engine on every canary vector.
  $('cnrec').value = JSON.stringify(c.r, Object.keys(c.r).sort(), 1)
  try {
    $('cngo').onclick()
    check(/MALFORMED/.test($('cnverdict').textContent) && /canonical/.test($('cnkv').textContent),
      'a re-formatted copy of the example reads MALFORMED, and says the bytes are not canonical')
  } catch (e) { check(false, 'a re-formatted record: ' + e.message) }
  {
    const cv = JSON.parse(readFileSync(new URL('../../test-vectors/canary-vectors.json', import.meta.url), 'utf8'))
    const asOf = cv.now.slice(0, 10)
    let agree = 0
    for (const v of cv.cases) {
      $('cnrec').value = v.record_json; $('cnsig').value = v.signature_der_hex
      $('cnpub').value = v.pubkey_hex || cv.pubkey_hex; $('cnas').value = asOf; $('cnwin').value = String(cv.max_age_days)
      try {
        $('cngo').onclick()
        const shown = (/^\S+ (OK|STALE|INVALID|MALFORMED|UNSUPPORTED)/.exec($('cnverdict').textContent) ||
          /^(UNSUPPORTED)/.exec($('cnverdict').textContent) || [])[1]
        if (shown === v.expect) agree++; else uiFails.push('canary vector ' + v.name + ': page shows ' + shown + ', pinned ' + v.expect)
      } catch (e) { uiFails.push('canary vector ' + v.name + ': ' + e.message) }
    }
    check(agree === cv.cases.length, 'the canary card gives the pinned verdict for every canary vector (' + agree + '/' + cv.cases.length + ')')
  }
  $('cnwin').value = '35'

  // 4a. The fingerprint card refuses a version that is not a positive integer, and an adopter name
  // the profile refuses (E21, E22), with the reason, never a digest.
  $('fpfile').files = [new File([new TextEncoder().encode('build-bytes-v1')], 'build.bin')]
  for (const [why, adopter, ver, want] of [['a fractional version', 'acme', '1.5', /positive integer/],
    ['a zero version', 'acme', '0', /positive integer/], ['an nkan/ adopter', 'nkan/x', '1', /E21/],
    ['an adopter holding a tab', 'ac\tme', '1', /E21/]]) {
    $('fpadopter').value = adopter; $('fpver').value = ver; $('fpclaim').value = ''
    try {
      await $('fpgo').onclick()
      check(want.test($('fpverdict').textContent) && $('fpkv').textContent === '', why + ' is refused with its reason')
    } catch (e) { check(false, why + ': ' + e.message) }
  }
  $('fpadopter').value = 'acme'; $('fpver').value = '2'
  $('fpclaim').value = 'c49474fde2088a50426a1add9e0ea0eec8733d9f98ec93f9df4d1579245ca979'
  try {
    await $('fpgo').onclick()
    check(/^MATCH/.test($('fpverdict').textContent), 'a version-2 fingerprint matches when version 2 is given')
  } catch (e) { check(false, 'a version-2 fingerprint: ' + e.message) }
  $('fpver').value = '1'

  // 4. A typed adopter is shown as text.
  $('fpadopter').value = '<img src=x>'; $('fpclaim').value = ''
  $('fpfile').files = [new File([new TextEncoder().encode('build-bytes-v1')], 'build.bin')]
  try {
    await $('fpgo').onclick()
    check($('fpkv').textContent.includes('<img src=x>') && ownElements($('fpkv')), 'a typed adopter is shown as text')
  } catch (e) { check(false, 'an adopter containing markup: ' + e.message) }
}

await settle()
check(pageErrors.length === 0, 'the page raised no errors (' + pageErrors.join('; ') + ')')

// 7. A browser whose normaliser does not know a character its character check knows (an engine may
// take the two from different Unicode data) is detected by the self-test, and the page then refuses
// non-ASCII text instead of normalising it wrongly; ASCII still works.
{
  const ids2 = new Map()
  const $2 = id => { if (!ids2.has(id)) ids2.set(id, new Elem('div', id)); return ids2.get(id) }
  const doc2 = { getElementById: $2, createElement: tag => new Elem(tag), createTextNode: t => new TextNode(t), addEventListener () {} }
  $2('kind').value = 'address'; $2('fpver').value = '1'; $2('cnwin').value = '35'
  const normalize = String.prototype.normalize
  // eslint-disable-next-line no-extend-native
  String.prototype.normalize = function (form) { const t = String(this); return t.includes('\u1AD0') ? t : normalize.call(t, form) }
  try {
    new Function('document', 'Image', html.slice(start, scriptEnd))(doc2, NoDecodeImage)
    await settle()
    check(/non-ASCII text refused/.test($2('selftest').textContent), 'a normaliser that disagrees with the character check is caught by the self-test')
    $2('kind').value = ''; $2('data').value = 'caf\u00e9'
    await $2('go').onclick()
    const refusedText = /cannot normalise non-ASCII text/.test($2('livecode').textContent)
    $2('data').value = 'Hello'
    await $2('go').onclick()
    check(refusedText && $2('livecode').textContent === S.brc.code[0].h, 'that browser refuses non-ASCII text and still seals ASCII')
  } catch (e) { check(false, 'a disagreeing normaliser: ' + e.message) } finally {
    // eslint-disable-next-line no-extend-native
    String.prototype.normalize = normalize
  }
}

if (uiPass !== uiTotal) {
  console.error('build gate: UI ' + (uiTotal - uiPass) + ' FAILED of ' + uiTotal)
  for (const f of uiFails) console.error('  - ' + f)
  process.exit(1)
}
console.log('build gate: UI ' + uiPass + '/' + uiTotal + ' checks OK (results are text, never markup; MALFORMED is never a valid signature)')
