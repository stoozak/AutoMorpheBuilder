'use strict';

/**
 * The learned signer pin of an app: where it is read from and how it travels.
 *
 * A pin is "trust on first use" (see src/download/signer.js): the signer of
 * the first APKMirror or APKPure download of an app that apk-signers.json
 * doesn't list.
 * It is kept as the `signer` field of the build-inputs.json that
 * create_release.sh uploads to the app's own release, so nothing is committed
 * to the repo. Every build reads it back from the app's newest release and
 * carries it into the next one; a release without it leaves the app unpinned.
 *
 * Path of a record through a run (all names derive from the app's tag):
 *   download-supported-apk.js  writes  $RUNNER_TEMP/signer-<appId>.json
 *   patch_apk.sh               copies it to out/<name>-v<ver>-<patches>.signer.json
 *                              (beside the .package file) and the build job uploads it
 *   create_release.sh          puts it in build-inputs.json as `signer`
 */

const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const { appReleases, listReleases } = require('./prune-old-releases');
const { pinFromBuildInputs, checkSigner, isListed, UnsignedApkError } = require('../../src/download/signer');

const ATTEMPTS = 3;
const DOWNLOAD_BUFFER = 8 * 1024 * 1024;

function sleepSync(ms) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

/** Runs `fn`, trying up to `attempts` times with a growing pause; throws the last error. */
function retried(fn, { attempts = ATTEMPTS, sleep = sleepSync } = {}) {
  for (let attempt = 1; ; attempt += 1) {
    try {
      return fn();
    } catch (e) {
      if (attempt >= attempts) throw e;
      sleep(attempt * 2000);
    }
  }
}

/** The app's short name (the release tag prefix), from config.json. Throws if it has none. */
function appName(config, appId) {
  const name = config && config.patch_repos && config.patch_repos[appId] && config.patch_repos[appId].name;
  if (typeof name !== 'string' || !name) throw new Error(`${appId} has no name in config.json patch_repos, so its releases can't be found`);
  return name;
}

/**
 * The pin recorded in the app's most recently built release, as
 * { pin, tag }: pin is null when there is no such release or it records none.
 * Releases without a build-inputs.json (a publish that stopped part-way) are
 * passed over. Any failure to ask GitHub, or to read what comes back,
 * throws: it must never look like "no pin".
 *
 * @param {string} name the app's short name from config.json
 * @param {object} [opts]
 * @param {Function} [opts.run] execFileSync stand-in, for tests
 * @param {Function} [opts.sleep] pause between attempts, for tests
 * @param {number} [opts.attempts]
 */
function lookupPin(name, { run = execFileSync, sleep = sleepSync, attempts = ATTEMPTS } = {}) {
  let tag = '';
  try {
    const releases = retried(() => listReleases(run, { timeout: 120000, stdio: ['ignore', 'pipe', 'pipe'] }), { attempts, sleep });
    const latest = appReleases(releases, name).find((r) => r.publishedAt
      && Array.isArray(r.assets) && r.assets.some((a) => a && a.name === 'build-inputs.json'));
    if (!latest) return { pin: null, tag: '' };
    tag = latest.tagName;
    const text = retried(() => run('gh', ['release', 'download', tag, '--pattern', 'build-inputs.json', '--output', '-'], {
      encoding: 'utf8', maxBuffer: DOWNLOAD_BUFFER, timeout: 60000, stdio: ['ignore', 'pipe', 'pipe'],
    }), { attempts, sleep });
    return { pin: pinFromBuildInputs(text), tag };
  } catch (e) {
    const stderr = String((e && e.stderr) || '').trim().split('\n')[0];
    throw new Error(`could not read the signer recorded for ${name}${tag ? ` in release ${tag}` : ''}: ${stderr || (e && e.message)}. `
      + 'Without it the original APK could be checked against nothing, so the build stops; re-run the failed job.', { cause: e });
  }
}

/** Where download-supported-apk.js leaves the signer record for patch_apk.sh. */
function recordPath(appId, dir) {
  return path.join(dir, `signer-${appId}.json`);
}

/** Writes the app's signer record, or removes a stale one when there is none. */
function writeRecord(appId, dir, record) {
  const file = recordPath(appId, dir);
  if (!record) {
    fs.rmSync(file, { force: true });
    return null;
  }
  fs.writeFileSync(file, `${JSON.stringify(record)}\n`);
  return file;
}

/**
 * Checks the original APK's signer for the app and leaves the record to
 * publish (or none) where patch_apk.sh looks for it.
 *
 * A listed app is checked against apk-signers.json and records nothing. An
 * unlisted app is checked against the signer recorded in its newest release;
 * with none recorded, its signer is learned from this download if
 * `learnOrigin` says it came from APKMirror or APKPure. A recorded signer is
 * carried forward unchanged. Only an unsigned `<appId>.apk` (this builder's
 * own earlier merge) gets a second check of the bundle it came from.
 *
 * @param {object} o
 * @param {string} o.appId
 * @param {string} o.file the candidate APK or bundle
 * @param {string} o.version the version being built
 * @param {object} o.signers parsed apk-signers.json
 * @param {object} o.config parsed config.json (for the app's name)
 * @param {string|null} o.learnOrigin the learnableOrigin() label when this run's download may be learned from
 * @param {string} o.noLearnReason why not, for the notice
 * @param {string} o.recordDir where the record is left (signer-<appId>.json)
 * @param {Function} o.findBundle () => path of the bundle beside the candidate, or null
 * @param {Function} [o.run] execFileSync stand-in for unzip/apksigner, and for gh
 * @param {Function} [o.sleep] pause between GitHub attempts, for tests
 * @param {Function} [o.log]
 * @returns {{ file: string, record: object|null }} the file that was checked (the bundle after a second chance) and the record written
 */
function checkOriginal({
  appId, file, version, signers, config, learnOrigin, noLearnReason, recordDir, findBundle,
  run = execFileSync, sleep = sleepSync, log = console.log,
}) {
  writeRecord(appId, recordDir, null); // never publish a record from an earlier run
  // A listed entry always wins, so only an unlisted app needs its release read.
  let pin = null;
  if (!isListed(signers, appId)) {
    const found = lookupPin(appName(config, appId), { run, sleep });
    pin = found.pin;
    if (pin) log(`Signer of ${appId} was recorded from ${pin.learnedFrom} v${pin.learnedVersion} (release ${found.tag}).`);
  }
  const opts = {
    signers, pin, version, noLearnReason, run, log,
    learn: !pin && learnOrigin ? { from: learnOrigin, version } : null,
  };
  let checked = file;
  let verdict;
  try {
    verdict = checkSigner(file, appId, opts);
  } catch (error) {
    const bundle = findBundle();
    if (!(error instanceof UnsignedApkError) || path.basename(file) !== `${appId}.apk` || !bundle) throw error;
    log(`${path.basename(file)} is an earlier merge (unsigned); checking the bundle and merging it again.`);
    verdict = checkSigner(bundle, appId, opts);
    checked = bundle;
  }
  // The signer to keep in this build's release: a newly learned one, or the
  // recorded one carried forward unchanged. A listed app records none.
  const record = verdict.kind === 'learning' ? verdict.learned : verdict.kind === 'learned' ? pin : null;
  writeRecord(appId, recordDir, record);
  return { file: checked, record };
}

module.exports = { lookupPin, appName, recordPath, writeRecord, retried, checkOriginal };
