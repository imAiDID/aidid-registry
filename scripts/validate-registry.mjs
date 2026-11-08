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
 *      challenge (after trimming surrounding whitespace);
 *   4. **DID proof** — when an entry declares `challengeSignature` it must also carry
 *      its `didPublicKey` (standard base64, 2592 bytes) and its Dilithium-5 signature
 *      (4595 bytes) must verify the canonical, origin-bound message
 *      `aidid-rp-challenge-v1\n<origin>\n<challenge>`. Entries that declare nothing
 *      are phase-0 style declarations and still pass (backward compatible); anything
 *      *declared* but unusable is a hard failure.
 *
 * Signature verification needs a Dilithium-5 verifier, and this repository
 * deliberately has **no dependencies** (the workflow that calls it must never run an
 * `npm install`, let alone code from a pull request). If `@msg-chain/sdk/wallet` is not
 * importable, a declared signature is reported as **SKIP** — never PASS — which stops
 * the automatic merge (the workflow greps for `[SKIP]`), so a maintainer merges after
 * the AIDID build re-verifies the same bytes. Everything else (structure, base64
 * lengths, fingerprint, message binding) is still checked here.
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

import { createHash } from 'node:crypto';
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
  'didPublicKey',
  'didPublicKeyFingerprint',
  'challengeSignature',
]);
const REQUEST_TIMEOUT_MS = 10_000;
/* DID-proof constants — must match `frontend/lib/rpChallengeSignature.ts`. */
const CHALLENGE_MESSAGE_DOMAIN = 'aidid-rp-challenge-v1';
const DILITHIUM5_PUBLIC_KEY_BYTES = 2592;
const DILITHIUM5_SIGNATURE_BYTES = 4595;
const FINGERPRINT_PATTERN = /^[0-9a-f]{16}$/;

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

/** Strict base64 (standard or urlsafe, padding optional). */
const decodeBase64 = (value) => {
  if (typeof value !== 'string') return null;
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, '');
  if (normalized === '' || normalized.length % 4 === 1) return null;
  if (!/^[A-Za-z0-9+/]+$/.test(normalized)) return null;
  return Buffer.from(normalized, 'base64');
};

/**
 * Decodes a Dilithium-5 public key. A multibase `z` prefix is stripped only when the
 * value as given is not already a full-length key (`z` is a legal base64 character).
 */
const decodePublicKey = (value) => {
  const direct = decodeBase64(value);
  if (direct !== null && direct.length === DILITHIUM5_PUBLIC_KEY_BYTES) return direct;
  if (value.startsWith('z')) {
    const stripped = decodeBase64(value.slice(1));
    if (stripped !== null && stripped.length === DILITHIUM5_PUBLIC_KEY_BYTES) return stripped;
    if (stripped !== null) return stripped;
  }
  return direct;
};

const fingerprintOf = (bytes) => createHash('sha256').update(bytes).digest('hex').slice(0, 16);

let cachedVerifier;
/** Dilithium-5 verifier, or `null` when this checkout has none (reported as SKIP). */
const loadVerifier = async () => {
  if (cachedVerifier !== undefined) return cachedVerifier;
  try {
    const sdk = await import('@msg-chain/sdk/wallet');
    cachedVerifier = typeof sdk.verifySignature === 'function' ? sdk.verifySignature : null;
  } catch {
    cachedVerifier = null;
  }
  return cachedVerifier;
};

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
  const signed = [];

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

    // --- DID proof (optional, but all-or-nothing when declared) --------------
    const hasKey = entry.didPublicKey !== undefined;
    const hasSignature = entry.challengeSignature !== undefined;
    const hasFingerprint = entry.didPublicKeyFingerprint !== undefined;
    if (!hasKey && !hasSignature && !hasFingerprint) {
      // Legacy declaration: accepted as before.
    } else if (hasSignature && !hasKey) {
      fail(`${label} ${origin} declares a challengeSignature`, 'a didPublicKey is required to verify it');
    } else if (!hasSignature) {
      fail(
        `${label} ${origin} declares a ${hasKey ? 'didPublicKey' : 'didPublicKeyFingerprint'} without a challengeSignature`,
        'a key without a proof cannot be verified'
      );
    } else if (hasFingerprint && !FINGERPRINT_PATTERN.test(String(entry.didPublicKeyFingerprint))) {
      fail(`${label}.didPublicKeyFingerprint is 16 lowercase hex characters`, String(entry.didPublicKeyFingerprint));
    } else {
      const publicKey = decodePublicKey(String(entry.didPublicKey));
      if (publicKey === null || publicKey.length !== DILITHIUM5_PUBLIC_KEY_BYTES) {
        fail(
          `${label}.didPublicKey decodes to ${DILITHIUM5_PUBLIC_KEY_BYTES} bytes`,
          publicKey === null ? 'not base64' : `got ${publicKey.length} bytes`
        );
      } else if (hasFingerprint && String(entry.didPublicKeyFingerprint) !== fingerprintOf(publicKey)) {
        fail(
          `${label}.didPublicKeyFingerprint matches the key`,
          `declared ${entry.didPublicKeyFingerprint}, key is ${fingerprintOf(publicKey)}`
        );
      } else {
        const signature = decodeBase64(String(entry.challengeSignature).replace(/^dilithium5_/i, ''));
        if (signature === null || signature.length !== DILITHIUM5_SIGNATURE_BYTES) {
          fail(
            `${label}.challengeSignature decodes to ${DILITHIUM5_SIGNATURE_BYTES} bytes`,
            signature === null ? 'not base64' : `got ${signature.length} bytes`
          );
        } else if (!CHALLENGE_PATTERN.test(String(entry.challenge))) {
          fail(`${label} ${origin} cannot be verified`, 'its challenge is malformed (see above)');
        } else {
          signed.push({
            label,
            origin,
            publicKey,
            signature,
            message: `${CHALLENGE_MESSAGE_DOMAIN}\n${origin}\n${entry.challenge}`,
          });
        }
      }
    }
  }

  // --- DID proof verification ------------------------------------------------
  if (signed.length > 0) {
    const verifySignature = await loadVerifier();
    for (const item of signed) {
      if (verifySignature === null) {
        skip(
          `${item.label} ${item.origin} did proof`,
          'no Dilithium-5 verifier in this dependency-free checkout — a maintainer must merge'
        );
        continue;
      }
      let ok = false;
      try {
        ok = verifySignature(item.publicKey, item.message, item.signature) === true;
      } catch (error) {
        fail(`${item.label} ${item.origin} did proof`, error instanceof Error ? error.message : String(error));
        continue;
      }
      if (ok) pass(`${item.label} ${item.origin} did proof (aidid-rp-challenge-v1, origin-bound)`);
      else {
        fail(
          `${item.label} ${item.origin} did proof`,
          `the Dilithium-5 signature does not verify "${CHALLENGE_MESSAGE_DOMAIN}\\n<origin>\\n<challenge>" ` +
            '(wrong key, tampered challenge/origin, or a replay)'
        );
      }
    }
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
