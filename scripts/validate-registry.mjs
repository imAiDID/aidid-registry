#!/usr/bin/env node
/**
 * validate-registry.mjs — self-contained validator for this repository's
 * `rp-registry.json`.
 *
 * It is the ONLY gate behind the automatic merge in
 * `.github/workflows/validate.yml`, so it deliberately keeps no dependency on any
 * other repository (node built-ins only, no `npm install`).
 *
 * What it checks:
 *
 *   1. the document shape (`schema` / `version` / `source` / `updatedAt` / `entries`)
 *      and every entry field, including the plain-https origin rule and the
 *      `aidid-rp-verify-<16..64 hex>` challenge format;
 *   2. origin uniqueness (the origin is the primary key);
 *   3. for every `status: "verified"` entry, that
 *      `https://<origin>/.well-known/aidid-rp.txt` serves EXACTLY the registered
 *      challenge (after trimming surrounding whitespace).
 *
 * A **mismatch** (wrong value / non-2xx HTTP) is a hard failure (exit 1). A
 * **network failure** is reported as SKIP and does **not** set the exit code, so a
 * network-restricted runner does not turn a transient outage into a false alarm.
 * Fail-closed for auto-merge is therefore enforced one level up: the workflow
 * greps this output for `[SKIP]` and refuses to merge if a verified entry could
 * not be checked live.
 *
 * Usage:
 *
 *   node scripts/validate-registry.mjs            # structure + live challenges
 *   node scripts/validate-registry.mjs --offline  # structure only
 *
 * Exit codes: 0 = pass, 1 = failure.
 */

import { existsSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const registryPath = resolve(scriptDir, '..', 'rp-registry.json');

const EXPECTED_SCHEMA = 'aidid.rp-registry';
const EXPECTED_VERSION = '1';
const CHALLENGE_PATTERN = /^aidid-rp-verify-[0-9a-f]{16,64}$/;
const DID_PATTERN = /^did:msg:[A-Za-z0-9._:%-]+$/;
const CAPABILITIES = new Set(['login', 'vc-verify', 'delegation']);
const TIERS = new Set(['first-party', 'verified-partner', 'community']);
const STATUSES = new Set(['verified', 'pending']);
const TOP_LEVEL_KEYS = new Set(['schema', 'version', 'source', 'updatedAt', 'notes', 'entries']);
const ENTRY_KEYS = new Set([
  'origin',
  'name',
  'homepage',
  'did',
  'capabilities',
  'tier',
  'challenge',
  'status',
  'registeredAt',
  'official',
]);
const REQUEST_TIMEOUT_MS = 10_000;

const offline = process.argv.includes('--offline');

let failures = 0;
let warnings = 0;
let skips = 0;

const pass = (label) => process.stdout.write(`  [PASS] ${label}\n`);
const fail = (label, detail) => {
  failures += 1;
  process.stdout.write(`  [FAIL] ${label}${detail ? `\n         ${detail}` : ''}\n`);
};
const warn = (label) => {
  warnings += 1;
  process.stdout.write(`  [WARN] ${label}\n`);
};
const skip = (label, detail) => {
  skips += 1;
  process.stdout.write(`  [SKIP] ${label}${detail ? ` — ${detail}` : ''}\n`);
};

/** Canonical plain-https origin: scheme + host (+ port), nothing else. */
const normalizeOrigin = (value) => {
  if (typeof value !== 'string' || value.trim() === '') return null;
  let url;
  try {
    url = new URL(value.trim());
  } catch {
    return null;
  }
  if (url.protocol !== 'https:') return null;
  if (url.pathname !== '/' || url.search !== '' || url.hash !== '') return null;
  if (url.username !== '' || url.password !== '') return null;
  return `${url.protocol}//${url.host}`;
};

const isPlainObject = (value) => typeof value === 'object' && value !== null && !Array.isArray(value);

const unknownKeys = (value, allowed) => Object.keys(value).filter((key) => !allowed.has(key));

const fetchChallenge = async (origin) => {
  try {
    const response = await fetch(`${origin}/.well-known/aidid-rp.txt`, {
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      redirect: 'follow',
    });
    if (!response.ok) return { kind: 'mismatch', detail: `HTTP ${response.status}` };
    return { kind: 'value', value: (await response.text()).trim() };
  } catch (error) {
    return { kind: 'network', detail: error instanceof Error ? error.message : String(error) };
  }
};

const main = async () => {
  process.stdout.write('[validate-registry] checking rp-registry.json\n');

  if (!existsSync(registryPath)) {
    fail('rp-registry.json exists');
    return;
  }
  pass('rp-registry.json exists');

  let document;
  try {
    document = JSON.parse(readFileSync(registryPath, 'utf8'));
  } catch (error) {
    fail('rp-registry.json parses', error instanceof Error ? error.message : String(error));
    return;
  }
  pass('rp-registry.json parses');

  if (!isPlainObject(document)) {
    fail('rp-registry.json is a JSON object');
    return;
  }
  pass('rp-registry.json is a JSON object');

  const extraTop = unknownKeys(document, TOP_LEVEL_KEYS);
  if (extraTop.length > 0) fail('no unknown top-level keys', extraTop.join(', '));
  else pass('no unknown top-level keys');

  if (document.schema !== EXPECTED_SCHEMA) fail(`schema is ${EXPECTED_SCHEMA}`, String(document.schema));
  else pass(`schema is ${EXPECTED_SCHEMA}`);
  if (document.version !== EXPECTED_VERSION) fail(`version is ${EXPECTED_VERSION}`, String(document.version));
  else pass(`version is ${EXPECTED_VERSION}`);
  if (typeof document.source !== 'string' || document.source.trim() === '') fail('source is a non-empty string');
  else pass('source is a non-empty string');
  if (typeof document.updatedAt !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(document.updatedAt)) {
    fail('updatedAt is a YYYY-MM-DD date', String(document.updatedAt));
  } else {
    pass('updatedAt is a YYYY-MM-DD date');
  }
  if (document.notes !== undefined && typeof document.notes !== 'string') fail('notes, if present, is a string');
  else pass('notes, if present, is a string');

  if (!Array.isArray(document.entries)) {
    fail('entries is an array');
    return;
  }
  pass('entries is an array');
  process.stdout.write(
    `  [INFO] ${document.entries.length} entr${document.entries.length === 1 ? 'y' : 'ies'}\n`
  );

  const seen = new Set();
  const verified = [];

  for (const [index, entry] of document.entries.entries()) {
    const label = `entries[${index}]`;
    if (!isPlainObject(entry)) {
      fail(`${label} is an object`);
      continue;
    }

    const extraEntry = unknownKeys(entry, ENTRY_KEYS);
    if (extraEntry.length > 0) fail(`${label} has no unknown keys`, extraEntry.join(', '));

    const origin = normalizeOrigin(entry.origin);
    if (origin === null) {
      fail(`${label}.origin is a plain https origin`, String(entry.origin));
      continue;
    }
    if (seen.has(origin)) {
      fail(`${label}.origin is unique`, origin);
      continue;
    }
    seen.add(origin);

    if (typeof entry.name !== 'string' || entry.name.trim() === '') fail(`${label}.name is non-empty`);
    else if (normalizeOrigin(entry.homepage) === null) fail(`${label}.homepage is a plain https origin`);
    else if (!CHALLENGE_PATTERN.test(String(entry.challenge))) {
      fail(`${label}.challenge has the expected format`, String(entry.challenge));
    } else if (!STATUSES.has(entry.status)) {
      fail(`${label}.status is "verified" or "pending"`, String(entry.status));
    } else {
      pass(`${label} ${origin} is well-formed`);
    }

    if (entry.capabilities !== undefined) {
      if (!Array.isArray(entry.capabilities)) {
        fail(`${label}.capabilities is an array`);
      } else {
        for (const capability of entry.capabilities) {
          if (!CAPABILITIES.has(capability)) fail(`${label}.capabilities has an unknown value`, String(capability));
        }
      }
    }
    if (entry.tier !== undefined && !TIERS.has(entry.tier)) {
      fail(`${label}.tier is first-party | verified-partner | community`, String(entry.tier));
    }
    if (entry.registeredAt !== undefined && !/^\d{4}-\d{2}-\d{2}$/.test(String(entry.registeredAt))) {
      fail(`${label}.registeredAt is a YYYY-MM-DD date`, String(entry.registeredAt));
    }
    if (entry.official !== undefined && typeof entry.official !== 'boolean') {
      fail(`${label}.official, if present, is a boolean`);
    }

    if (entry.did === undefined || entry.did === null || entry.did === '') {
      warn(`${label} ${origin} has no did (required from on-chain phase 1; recommended now)`);
    } else if (!DID_PATTERN.test(String(entry.did))) {
      fail(`${label}.did looks like a did:msg identifier`, String(entry.did));
    } else {
      pass(`${label} ${origin} publishes a did:msg identifier`);
    }

    if (entry.status === 'verified') verified.push({ label, origin, challenge: entry.challenge });
  }

  if (offline) {
    skip('live .well-known challenge checks', '--offline');
  } else {
    for (const { label, origin, challenge } of verified) {
      const result = await fetchChallenge(origin);
      if (result.kind === 'network') {
        skip(`${label} ${origin} serves the registry challenge`, result.detail);
      } else if (result.kind === 'mismatch') {
        fail(`${label} ${origin} serves the registry challenge`, result.detail);
      } else if (result.value !== challenge) {
        fail(
          `${label} ${origin} serves the registry challenge`,
          `served "${result.value}" != registered "${challenge}"`
        );
      } else {
        pass(`${label} ${origin} serves the registry challenge`);
      }
    }
  }

  process.stdout.write(
    `\n[validate-registry] ${failures} failure(s), ${warnings} warning(s), ${skips} skipped\n`
  );
  if (failures > 0) process.exit(1);
  if (skips > 0) {
    process.stdout.write(
      '[validate-registry] structure OK, but some live challenges were not confirmed (see [SKIP] above)\n'
    );
  }
  process.stdout.write('[validate-registry] registry is consistent\n');
};

await main();
