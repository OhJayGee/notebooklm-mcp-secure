#!/usr/bin/env node
/**
 * Refuse to build if any direct dep in package.json uses a range specifier.
 *
 * Run from CI before `npm run build`. Exits 1 with a list of offending
 * packages if any non-exact version pin is found in `dependencies` or
 * `peerDependencies`. `devDependencies` are checked too because a
 * compromised dev dep can compromise the build artefact.
 *
 * Why pin-only:
 *   - The reproducibility argument for `npm ci` only holds if the lockfile
 *     was generated against an exact version. Allowing `^1.2.3` lets a
 *     fresh `npm install` (e.g. by a contributor) silently bump the
 *     resolved version, breaking the "this is the tarball we reviewed"
 *     contract.
 *   - For a security-focused fork, we are explicit: every direct dep must
 *     be a `MAJOR.MINOR.PATCH[-PRE]` literal. Use `npm install <pkg>@x.y.z
 *     --save-exact` (or `npm config set save-exact true`) to add deps.
 */
'use strict';

const fs = require('fs');
const path = require('path');

const EXACT_VERSION = /^\d+\.\d+\.\d+(-[\w.]+)?$/;

const pkg = JSON.parse(
  fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8'),
);

const fields = ['dependencies', 'devDependencies', 'peerDependencies'];
const offenders = [];

for (const field of fields) {
  const block = pkg[field];
  if (!block) continue;
  for (const [name, range] of Object.entries(block)) {
    if (typeof range !== 'string' || !EXACT_VERSION.test(range)) {
      offenders.push(`${field}: ${name}@${range}`);
    }
  }
}

if (offenders.length > 0) {
  console.error('Non-exact version pins detected:');
  for (const entry of offenders) console.error('  ' + entry);
  console.error(
    '\nFix by replacing each range with an exact MAJOR.MINOR.PATCH version,',
  );
  console.error('e.g. `npm install <pkg>@x.y.z --save-exact`.');
  process.exit(1);
}

console.log('All direct dependencies are pinned to exact versions.');
