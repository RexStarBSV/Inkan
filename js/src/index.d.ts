// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 RexStarBSV
// Inkan verification path (see LICENSE-VERIFY and NOTICE). Repository default licence: BSL 1.1.
//
// CANONICAL type declarations for the `inkan-standard` npm package (this directory). They live beside the
// runtime they describe, and an application that vendors the JS port copies this file with it.
//
// A declaration file is a promise about the runtime it describes. Kept anywhere but beside that
// runtime, it can go on declaring a function the runtime no longer exports, and TypeScript will
// then compile a call that fails when it runs. Kept here, it changes in the same commit as the
// runtime, where the two can be read side by side.

/** An RGB888 raster. `pixels` is row-major, stride = `width * 3`. */
export interface InkanImage {
  width: number
  height: number
  pixels: Uint8Array
}

/** Reserved kind name -> its tier configuration. Any non-reserved string is also a valid kind. */
export declare const KINDS: Record<string, unknown>
/** Domain-separation prefix for the glyph seed: `inkan/v1\0`. */
export declare const INKAN_DOMAIN: Uint8Array
/** Seal format version implemented by this build. */
export declare const SEAL_VERSION: number

// Every byte argument must be a Uint8Array (a Node Buffer is one); anything else throws a
// TypeError rather than being converted. Every kind is a string. A digest is exactly 32 bytes.

// ---- hashing -------------------------------------------------------------------------------
export declare function sha256(data: Uint8Array): Uint8Array
export declare function bytesToHex(data: Uint8Array): string

// ---- anchor --------------------------------------------------------------------------------
/** Domain-separated glyph seed: `INKAN_DOMAIN + u8(len(kind)) + kind + data`. NOT the digest. */
export declare function inkanSeed(data: string | Uint8Array, kind?: string): Uint8Array
/**
 * Throws a RangeError if `text` holds a code point this runtime's Unicode database leaves unassigned
 * (General_Category Cn, noncharacters excepted). Such text is never normalised or hashed (SPEC §1 E14).
 */
export declare function rejectUnassigned(text: string, what: string): void
/** The Unicode version of this runtime's character database, e.g. "17.0"; null before Unicode 3.0. */
export declare function unicodeVersion(): string | null

// ---- seal ----------------------------------------------------------------------------------
/** The three seal fields a digest resolves to. */
export interface SealFields {
  words: number[]
  paletteIx: number
  corePattern: number
}

/** `[cells, k, motif]` — the tier's cell count, the select weight, and the core motif. */
export declare function resolveKind(kind: string): [number, number, number]
export declare function golay24(word: number): number
export declare function sealFields(digest: Uint8Array, kind?: string): SealFields
export declare function cellsFromWords(words: number[], cells: number): number[]
export declare function sealRgb(digest: Uint8Array, kind?: string): InkanImage
export declare function sealRgbFromFields(
  words: number[], paletteIx: number, corePattern: number, kind?: string): InkanImage
/** `tag: true` embeds the self-describing iTXt code chunk. There is no scale parameter. */
export declare function sealPng(
  digest: Uint8Array, kind?: string, options?: { tag?: boolean }): Uint8Array
export declare function scaleNearest(image: InkanImage, scale: number): InkanImage
/** Convenience: seed -> digest -> seal, at `scale`. This is what UI wrappers call. */
export declare function inkanGlyph(data: string | Uint8Array, kind?: string, scale?: number): InkanImage

// ---- code-provenance fingerprint -------------------------------------------------------------
/**
 * A fingerprint version: a positive integer, below 10^21 as a number, or a BigInt (SPEC §7 E22).
 * Anything else throws.
 */
export type FingerprintVersion = number | bigint
/** Returns dec(version), or throws if it is not a positive integer (SPEC §7 E22). */
export declare function checkVersion(version: FingerprintVersion): string
/** Returns the NFC form of an adopter name, or throws if the profile refuses it (SPEC §7 E4, E14, E21). */
export declare function checkAdopter(adopter: string): string
export declare function domainPrefix(adopter: string, version?: FingerprintVersion): Uint8Array
export declare function fingerprintDigest(
  payload: string | Uint8Array, adopter: string, version?: FingerprintVersion): Uint8Array
export declare function fingerprintHex(
  payload: string | Uint8Array, adopter: string, version?: FingerprintVersion): string

// ---- warrant canary --------------------------------------------------------------------------
/** A canary record: exactly the seven fields SPEC §8 fixes (E1, E13). */
export interface CanaryRecord {
  v: number
  domain: string
  seq: number
  date: string
  block_height: number
  block_hash: string
  statement: string
}

/**
 * Thrown when the key, signature or record could not be PARSED, so no signature check ever ran.
 * Distinct from a check that ran and failed — see `canaryStatus` (SPEC §8 E11, E13).
 */
export declare class MalformedCanaryInput extends Error {}
/** Thrown for a record version this verifier does not implement: report UNSUPPORTED (SPEC §8 E2). */
export declare class UnsupportedCanaryVersion extends Error {}

/**
 * A record as an object, or in its wire form: the text or the UTF-8 bytes it was published as. A
 * wire form must be exactly the record's canonical bytes, or the record is MALFORMED (SPEC §8 E23).
 */
export type CanaryRecordInput = CanaryRecord | string | Uint8Array

export declare function canaryCanonicalBytes(record: CanaryRecord): Uint8Array
export declare function canaryMessageHash(record: CanaryRecord): Uint8Array
/** Strict UTF-8 and JSON; returns the parsed value and the text. Throws `MalformedCanaryInput`. */
export declare function canaryParseRecord(wire: string | Uint8Array): [unknown, string]
/** The checks made before the signature (E2, E13, E23). Throws `UnsupportedCanaryVersion` or `MalformedCanaryInput`. */
export declare function canaryCheckRecord(record: unknown, wireText?: string | null): void
export declare function canaryIsFresh(
  record: CanaryRecord, nowMs?: number, maxAgeDays?: number): boolean
/** Throws `MalformedCanaryInput` on input that breaks the record rules or does not parse, and
 *  `UnsupportedCanaryVersion` on an unknown record version. */
export declare function canaryVerify(
  record: CanaryRecordInput, signatureHex: string, pubkeyHex: string): boolean
/**
 * `OK` — signature verifies and the record is fresh.
 * `STALE` — verifies, but outside the freshness window.
 * `INVALID` — a check RAN and the signature was wrong.
 * `MALFORMED` — the check could not run: the key, the signature or the record is not in the form
 *   SPEC §8 fixes (shape, input rules, canonical bytes).
 * An unknown record version throws, so a caller can report UNSUPPORTED rather than imply tampering.
 */
export declare function canaryStatus(
  record: CanaryRecordInput, signatureHex: string, pubkeyHex: string,
  nowMs?: number, maxAgeDays?: number): 'OK' | 'STALE' | 'INVALID' | 'MALFORMED'
