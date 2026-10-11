// SPDX-License-Identifier: BUSL-1.1
// SPDX-FileCopyrightText: 2026 RexStarBSV
//
// The suite that checks the suite is complete.
//
// WHY THIS FILE EXISTS. `npm test` used to name its four test files one by one:
//
//     node --test ./test/parity.test.mjs ./test/seal-parity.test.mjs \
//          ./test/normalization.test.mjs ./test/canary.test.mjs
//
// A file added to this directory was therefore not run, and `npm test` stayed GREEN while it sat
// there — measured, not assumed: dropping a deliberately failing suite into test/ left the run at
// "# tests 20, # pass 20, # fail 0" and exit 0. That is the failure mode this repo's doctrine
// names first, and the Python port had its own version of it next door.
//
// The script is now bare `node --test`, which discovers files itself. That closes the "forgot to
// add it to the list" hole but not the "named it something the discovery pattern does not match"
// hole, which fails exactly as quietly. So the naming rule is asserted here.
//
// Node's discovery matches **/*.test.{js,mjs,cjs} plus a few `test-*` and `test.js` forms. This
// repo uses one convention — `<name>.test.mjs` — so anything else in this directory is either a
// helper (allowed, and listed) or a suite that will never run (not allowed).
import { test } from "node:test";
import assert from "node:assert";
import { readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));

// Non-suite files that may live here. Keep this list SHORT and justify every entry: each one is a
// file the runner will not execute, so a suite mistakenly added here disappears silently.
const ALLOWED_HELPERS = new Set([]);

test("every .mjs file in test/ is named so the runner will discover it", () => {
  const stray = readdirSync(HERE)
    .filter((name) => name.endsWith(".mjs"))
    .filter((name) => !name.endsWith(".test.mjs"))
    .filter((name) => !ALLOWED_HELPERS.has(name));

  assert.deepEqual(
    stray, [],
    `these files are in test/ but do not match the discovery pattern, so they are never run: ` +
    `${stray.join(", ")}. Rename them to <name>.test.mjs, or add them to ALLOWED_HELPERS if they ` +
    `are genuinely not suites.`);
});

test("the directory still holds the suites this port is meant to have", () => {
  // A floor, not an exact count: adding a suite must not require editing this file, but a suite
  // VANISHING — deleted, renamed, or moved — should not pass unnoticed.
  const suites = readdirSync(HERE).filter((name) => name.endsWith(".test.mjs"));

  assert.ok(
    suites.length >= 5,
    `expected at least 5 suites in test/ (parity, seal-parity, normalization, canary, and this ` +
    `one); found ${suites.length}: ${suites.join(", ")}`);
});
