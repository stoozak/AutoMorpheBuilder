'use strict';

/**
 * Was the original APK signed by the app's real developer?
 *
 * Before an APK is patched, the SHA-256 of its signing certificate must
 * match what is expected for the app. There are two places the expectation
 * can come from, and a listed entry always wins:
 *
 *  1. .github/scripts/apk-signers.json: fingerprints taken from APKMirror's
 *     "APK certificate fingerprints" and edited by hand.
 *  2. A learned pin ("trust on first use") for an app that is not listed:
 *     the signer recorded in `build-inputs.json` of the app's newest release
 *     (see .github/scripts/signer-pin.js). It is learned only from an APK
 *     downloaded in this run from APKMirror or APKPure, directly or by an
 *     HTTPS URL on their own hosts (`learnableOrigin`), so the first pin is
 *     the trust anchor for every later build. An app with neither is not checked (with a notice).
 *
 * If a mirror or a fallback source serves a repackaged APK, the build fails
 * instead of patching and publishing it. When the developer really changes
 * their key, the new fingerprint is added to apk-signers.json (the failure
 * message prints a ready-to-paste entry).
 *
 * In a bundle (.apkm/.xapk/.apks, or a bundle saved as .apk) every APK is
 * checked, base and splits, before APKEditor merges them (the merged APK is
 * unsigned): the merge takes all of them, so a genuine base with a swapped
 * split must fail too. A wrong signer fails. So does an APK that apksigner
 * can't verify, because an unsigned or broken original can't be trusted
 * either. Learning from a bundle needs every APK in it to share a signer.
 */

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const SIGNERS_FILE = path.join(__dirname, '..', '..', '.github', 'scripts', 'apk-signers.json');
const SIGNERS_FILE_NAME = '.github/scripts/apk-signers.json';
const LIST_BUFFER = 64 * 1024 * 1024;
const APK_BUFFER = 2 * 1024 * 1024 * 1024;
const HEX64 = /^[0-9a-f]{64}$/;
/** Sources a signer is learned from: unified-downloader results freshly resolved from APKMirror or APKPure. */
const LEARN_ORIGINS = ['apkmirror-api', 'apkmirror', 'apkeep', 'apkpure-exact'];
/** Store hosts a `direct-url` download (a cached or listed URL) may be learned from, over HTTPS. */
const LEARN_HOSTS = ['www.apkmirror.com', 'apkmirror.com', 'd.apkpure.com', 'download.pureapk.com'];

/** apksigner found no valid signature (e.g. our own APKEditor merge), as opposed to a wrong one. */
class UnsignedApkError extends Error {}

/**
 * The lines of `apksigner verify --print-certs` output about the APK's
 * signers. Not the `Source Stamp Signer` lines: that certificate is the
 * store's (Google Play stamps the APKs it delivers), not the developer's.
 */
function signerLines(stdout) {
  return String(stdout || '').split(/\r?\n/).filter((line) => !/^\s*Source Stamp/i.test(line)).join('\n');
}

/** Signer certificate SHA-256 digests from `apksigner verify --print-certs` output. */
function certDigests(stdout) {
  const out = new Set();
  for (const m of signerLines(stdout).matchAll(/certificate SHA-256 digest:\s*([0-9a-fA-F:]{64,95})/g)) {
    const digest = m[1].replace(/:/g, '').toLowerCase();
    if (HEX64.test(digest)) out.add(digest);
  }
  return [...out];
}

/** The first certificate DN from `apksigner verify --print-certs` output, or ''. */
function certSubject(stdout) {
  const m = /certificate DN:[ \t]*(.+)/.exec(signerLines(stdout));
  return m ? m[1].trim() : '';
}

/** The fingerprints listed for an app, lower-cased. */
function knownDigests(signers, appId) {
  const entry = signers && Object.prototype.hasOwnProperty.call(signers, appId) ? signers[appId] : null;
  return Array.isArray(entry && entry.sha256) ? entry.sha256.map((s) => String(s).toLowerCase()) : [];
}

/** { ok, known, got, skipped } for the digests apksigner found, against an explicit list. */
function judgeAgainst(known, digests) {
  if (!known.length) return { ok: true, known, got: digests, skipped: true };
  return { ok: digests.some((d) => known.includes(d)), known, got: digests, skipped: false };
}

/** { ok, known, got, skipped } for the digests apksigner found, against apk-signers.json. */
function judge(signers, appId, digests) {
  return judgeAgainst(knownDigests(signers, appId), digests);
}

/**
 * The learned pin in `value` (the `signer` field of a build-inputs.json):
 * { sha256: [hex...], learnedFrom, learnedVersion }. Throws if it is not
 * one, because a pin that can't be read must fail the build, not switch the
 * check off.
 */
function parsePin(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('"signer" is not an object');
  const digests = Array.isArray(value.sha256) ? value.sha256.map((d) => String(d).toLowerCase()) : [];
  if (!digests.length || !digests.every((d) => HEX64.test(d))) throw new Error('"signer.sha256" is not a list of SHA-256 fingerprints');
  for (const key of ['learnedFrom', 'learnedVersion']) {
    if (typeof value[key] !== 'string' || !value[key]) throw new Error(`"signer.${key}" is missing`);
  }
  return { sha256: [...new Set(digests)], learnedFrom: value.learnedFrom, learnedVersion: value.learnedVersion };
}

/**
 * The learned pin recorded in the text of a release's build-inputs.json, or
 * null if it records none (a release made before pins, or of a listed app).
 * Throws if the file, or a pin in it, can't be read.
 */
function pinFromBuildInputs(text) {
  let inputs;
  try {
    inputs = JSON.parse(text);
  } catch (e) {
    throw new Error(`build-inputs.json is not valid JSON: ${e.message}`, { cause: e });
  }
  if (!inputs || typeof inputs !== 'object' || Array.isArray(inputs)) throw new Error('build-inputs.json is not a JSON object');
  return Object.prototype.hasOwnProperty.call(inputs, 'signer') ? parsePin(inputs.signer) : null;
}

/** True if apk-signers.json lists a signer for the app. */
function isListed(signers, appId) {
  return knownDigests(signers, appId).length > 0;
}

/**
 * Where a signer may be learned from, given what the unified-downloader
 * printed: its `origin` (the source that resolved the URL) or else its
 * `source`. APKMirror and APKPure qualify. A cached or listed URL
 * (`direct-url`) qualifies only if it is an HTTPS URL on one of their own
 * hosts (LEARN_HOSTS), and is labelled with that host. Google Play and
 * anything else don't. Returns the label or null.
 */
function learnableOrigin(result) {
  if (!result) return null;
  const origin = result.origin || result.source;
  if (LEARN_ORIGINS.includes(origin)) return origin;
  if (origin !== 'direct-url' || typeof result.url !== 'string') return null;
  let url;
  try { url = new URL(result.url); } catch { return null; }
  const plain = url.protocol === 'https:' && !url.username && !url.password && !url.port;
  return plain && LEARN_HOSTS.includes(url.hostname) ? `direct-url (${url.hostname})` : null;
}

/** Which entry of a bundle holds the base APK, from its entry names. */
function baseEntry(names) {
  const apks = names.filter((n) => /\.apk$/i.test(n) && !n.includes('/'));
  return apks.find((n) => /^base\.apk$/i.test(n))
    || apks.find((n) => !/split|config\./i.test(n))
    || null;
}

/** The fingerprint list. A missing or broken file throws: it must never turn the check off. */
function readSigners(file = SIGNERS_FILE) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

/**
 * Throws when the APK at `file` isn't signed by the expected signer for
 * `appId`: the one listed in apk-signers.json or, for an app not listed, the
 * learned `pin`. With neither, the APK is verified and its signer returned
 * as `learned` if `learn` says it may be recorded, else not checked.
 *
 * @param {string} file
 * @param {string} appId
 * @param {object} [opts]
 * @param {object} [opts.signers] parsed apk-signers.json
 * @param {object|null} [opts.pin] the app's learned pin (see parsePin); ignored for a listed app
 * @param {object|null} [opts.learn] { from, version }: the app may be learned from this download
 * @param {string} [opts.version] the version being built, for the entry a mismatch suggests
 * @param {string} [opts.noLearnReason] why nothing is learned, for the notice
 * @param {string} [opts.apksigner] apksigner binary (on PATH after install_aapt.sh)
 * @param {Function} [opts.run] execFileSync stand-in, for tests
 * @param {Function} [opts.log]
 * @returns {object} { skipped: true }, a verdict ({ ok, kind: 'listed' | 'learned', matched, ... }),
 *   or { ok, kind: 'learning', learned: { sha256, learnedFrom, learnedVersion } }
 */
function checkSigner(file, appId, {
  signers = readSigners(), pin = null, learn = null, version = '', noLearnReason = '',
  apksigner = 'apksigner', run = execFileSync, log = console.log,
} = {}) {
  const listed = knownDigests(signers, appId);
  const expected = listed.length
    ? { kind: 'listed', known: listed, pin: null }
    : pin ? { kind: 'learned', known: pin.sha256, pin } : null;
  if (!expected && !learn) {
    log(`::notice::No signer listed for ${appId} in ${SIGNERS_FILE_NAME}; signature not checked`
      + `${noLearnReason ? `, and none was learned: ${noLearnReason}` : ''}.`);
    return { skipped: true };
  }
  if (expected && listed.length && pin) {
    log(`::notice::${SIGNERS_FILE_NAME} lists ${appId}; its recorded signer is ignored.`);
  }
  let learnedDigests = null;
  let verdict;
  const count = eachApk(file, apksigner, run, (label, info) => {
    if (expected) {
      verdict = expectSigner(expected, { appId, label, info, version });
      return;
    }
    // Learning: the first APK sets the signer and the others must share it.
    if (!info.digests.length) throw new Error(`apksigner printed no certificate for ${label}; no signer can be learned from it.`);
    if (!learnedDigests) learnedDigests = info.digests;
    else if (!info.digests.some((d) => learnedDigests.includes(d))) {
      throw new Error(`${label} is signed by ${info.digests.join(', ')}, not by the key of the other APKs in the bundle `
        + `(${learnedDigests.join(', ')}); no signer is learned from a mixed bundle.`);
    }
  });
  const name = path.basename(file);
  const subject = count === 1 ? name : `all ${count} APKs in ${name}`;
  if (!expected) {
    const learned = { sha256: learnedDigests, learnedFrom: learn.from, learnedVersion: learn.version };
    log(`::notice::Learned the signer of ${appId} from ${learn.from} v${learn.version} (${learnedDigests.join(', ')}); later builds must match it.`);
    return { ok: true, skipped: false, kind: 'learning', learned };
  }
  log(`Signer${count === 1 ? '' : 's'} of ${subject} match${count === 1 ? 'es' : ''} `
    + `${expected.kind === 'listed' ? 'apk-signers.json' : `the signer recorded from ${expected.pin.learnedFrom} v${expected.pin.learnedVersion}`} (${verdict.matched}).`);
  return verdict;
}

/** Calls onApk(label, { digests, subject }) for the APK, or for every APK in the bundle; returns how many. */
function eachApk(file, apksigner, run, onApk) {
  const names = run('unzip', ['-Z1', file], { encoding: 'utf8', maxBuffer: LIST_BUFFER, stdio: ['ignore', 'pipe', 'pipe'] })
    .split('\n').map((n) => n.trim()).filter(Boolean);
  const isBundle = !names.includes('AndroidManifest.xml');
  if (!isBundle) {
    onApk(path.basename(file), verifyCerts(file, path.basename(file), apksigner, run));
    return 1;
  }
  if (!baseEntry(names)) throw new Error(`no base APK inside ${path.basename(file)} to check the signature of`);
  // APKEditor merges every APK in the bundle, so every one of them must be
  // the developer's: a genuine base with a swapped split must not pass.
  const entries = bundleApks(names);
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'signer-'));
  try {
    entries.forEach((entry, i) => {
      const label = `${path.basename(file)} (${entry})`;
      const target = path.join(tmp, `${i}.apk`);
      fs.writeFileSync(target, run('unzip', ['-p', file, entry], { maxBuffer: APK_BUFFER, stdio: ['ignore', 'pipe', 'pipe'] }));
      onApk(label, verifyCerts(target, label, apksigner, run));
      fs.rmSync(target, { force: true });
    });
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
  return entries.length;
}

/** Every APK inside a bundle, at any depth: APKEditor merges whatever it finds. */
function bundleApks(names) {
  return names.filter((n) => /\.apk$/i.test(n) && !n.endsWith('/'));
}

/** The certificate digests and subject apksigner reports for one APK. */
function verifyCerts(target, label, apksigner, run) {
  try {
    const out = run(apksigner, ['verify', '--print-certs', target], {
      encoding: 'utf8', maxBuffer: LIST_BUFFER, stdio: ['ignore', 'pipe', 'pipe'],
    });
    return { digests: certDigests(out), subject: certSubject(out) };
  } catch (e) {
    // A missing apksigner is a broken runner, not an unsigned APK.
    if (e && e.code === 'ENOENT') throw new Error(`${apksigner} not found; is Android build-tools on PATH?`, { cause: e });
    const why = String((e && (e.stderr || e.message)) || '').split('\n').find(Boolean) || 'unknown error';
    throw new UnsignedApkError(`apksigner could not verify ${label}: ${why}`, { cause: e });
  }
}

/** The entry to add to apk-signers.json for a signer, in that file's own format. */
function suggestedEntry(appId, digests, subject, version) {
  return `  ${JSON.stringify(appId)}: {\n`
    + `    "sha256": [${digests.map((d) => JSON.stringify(d)).join(', ')}],\n`
    + `    "subject": ${JSON.stringify(subject || 'unknown')},\n`
    + `    "seen": ${JSON.stringify(version || 'unknown')}\n`
    + '  }';
}

/** The verdict for one APK, or the "wrong signer" error. */
function expectSigner(expected, { appId, label, info, version }) {
  const verdict = judgeAgainst(expected.known, info.digests);
  if (!verdict.ok) {
    const got = verdict.got.join(', ') || 'nothing apksigner recognised';
    if (expected.kind === 'listed') {
      throw new Error(`${label} is signed by ${got}, `
        + `not by ${appId}'s developer (${verdict.known.join(', ')} in ${SIGNERS_FILE_NAME}). `
        + 'The source may be serving a modified APK. If the developer really changed their key, add the new '
        + `fingerprint from APKMirror to ${SIGNERS_FILE_NAME}.`);
    }
    const { pin } = expected;
    throw new Error(`${label} is signed by ${got}, not by the signer first recorded for ${appId} `
      + `(${verdict.known.join(', ')}, learned from ${pin.learnedFrom} v${pin.learnedVersion}). `
      + 'The source may be serving a modified APK. If the developer really changed their key, '
      + `add this entry to ${SIGNERS_FILE_NAME} (a listed entry replaces the recorded signer):\n`
      + (verdict.got.length ? suggestedEntry(appId, verdict.got, info.subject, version) : '(apksigner printed no certificate, so there is no entry to suggest)'));
  }
  return { ...verdict, kind: expected.kind, matched: verdict.got.find((d) => verdict.known.includes(d)) };
}

module.exports = {
  certDigests, certSubject, judge, judgeAgainst, baseEntry, bundleApks, readSigners, checkSigner,
  parsePin, pinFromBuildInputs, isListed, learnableOrigin, suggestedEntry,
  UnsignedApkError, SIGNERS_FILE, LEARN_ORIGINS, LEARN_HOSTS,
};
