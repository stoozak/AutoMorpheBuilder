'use strict';

// signer-pin.js: finding the signer recorded in an app's newest release, and
// the whole original-APK check (listed / recorded / learned). The real code
// runs; only `gh`, unzip and apksigner are faked through the `run` argument.

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { lookupPin, appName, recordPath, writeRecord, retried, checkOriginal } = require('../signer-pin');
const { UnsignedApkError } = require('../../../src/download/signer');

const GOOD = 'a'.repeat(64);
const OTHER = 'b'.repeat(64);
const APP = 'com.unlisted.app';
const CONFIG = { patch_repos: { [APP]: { name: 'unlisted' }, 'com.listed.app': { name: 'listed' } } };
const SIGNERS = { 'com.listed.app': { sha256: [GOOD] } };
const PIN = { sha256: [GOOD], learnedFrom: 'apkmirror', learnedVersion: '1.0.0' };
const printCerts = (digest) => `Signer #1 certificate DN: CN=Dev\nSigner #1 certificate SHA-256 digest: ${digest}\n`;
const noSleep = () => {};
const log = () => {};

const release = (tagName, publishedAt, assets = ['build-inputs.json'], updatedAt = publishedAt) => (
  { tagName, publishedAt, assets: assets.map((name) => ({ name, updatedAt })) }
);

/**
 * A `run` that answers `gh api` (the release list), `gh release download`
 * (build-inputs.json by tag), unzip and apksigner, and records every call.
 */
function fakeRun({ releases = [], inputs = {}, listError, downloadError, verify = () => printCerts(GOOD), entries } = {}) {
  const calls = [];
  const run = (cmd, args) => {
    calls.push([cmd, ...args]);
    if (cmd === 'gh' && args[0] === 'api') {
      if (listError) throw listError;
      return `${releases.map((r) => JSON.stringify(r)).join('\n')}\n`;
    }
    if (cmd === 'gh' && args[0] === 'release' && args[1] === 'download') {
      if (downloadError) throw downloadError;
      const text = inputs[args[2]];
      if (text === undefined) throw new Error(`no build-inputs.json for ${args[2]}`);
      return typeof text === 'string' ? text : JSON.stringify(text);
    }
    if (cmd === 'unzip' && args[0] === '-Z1') return `${(entries ? entries(args[1]) : ['AndroidManifest.xml']).join('\n')}\n`;
    if (cmd === 'unzip' && args[0] === '-p') return Buffer.from(`bytes of ${args[2]}`);
    if (cmd === 'apksigner') return verify(args[args.length - 1]);
    throw new Error(`unexpected command ${cmd}`);
  };
  return { run, calls, gh: () => calls.filter(([cmd]) => cmd === 'gh') };
}

describe('retried', () => {
  test('retries with a growing pause, then throws the last error', () => {
    const pauses = [];
    let n = 0;
    expect(() => retried(() => { n += 1; throw new Error(`fail ${n}`); }, { attempts: 3, sleep: (ms) => pauses.push(ms) })).toThrow('fail 3');
    expect(pauses).toEqual([2000, 4000]);
  });

  test('returns the first success', () => {
    let n = 0;
    expect(retried(() => { n += 1; if (n < 2) throw new Error('once'); return 'ok'; }, { sleep: noSleep })).toBe('ok');
  });

  test('the default pause really waits', () => {
    const start = Date.now();
    let n = 0;
    retried(() => { n += 1; if (n < 2) throw new Error('once'); }, { attempts: 2 });
    expect(Date.now() - start).toBeGreaterThanOrEqual(1500);
  });
});

describe('appName', () => {
  test('is the name in config.json, and a missing one throws', () => {
    expect(appName(CONFIG, APP)).toBe('unlisted');
    expect(() => appName(CONFIG, 'com.other')).toThrow(/com\.other has no name in config\.json/);
    expect(() => appName({}, APP)).toThrow(/no name/);
    expect(() => appName(null, APP)).toThrow(/no name/);
  });
});

describe('lookupPin', () => {
  test('no release of the app means no pin', () => {
    const { run, gh } = fakeRun({ releases: [release('other-v1-v1', '2026-01-01T00:00:00Z')] });
    expect(lookupPin('unlisted', { run, sleep: noSleep })).toEqual({ pin: null, tag: '' });
    expect(gh()).toHaveLength(1); // only the list
  });

  test('reads the signer from the newest release by last build, not by tag order', () => {
    const { run, gh } = fakeRun({
      releases: [
        release('unlisted-v2-v9', '2026-01-02T00:00:00Z'),
        // An old tag rebuilt later: build-inputs.json is newer than the other release.
        release('unlisted-v1-v9', '2026-01-01T00:00:00Z', ['build-inputs.json'], '2026-01-05T00:00:00Z'),
      ],
      inputs: { 'unlisted-v1-v9': { signer: PIN }, 'unlisted-v2-v9': { signer: { ...PIN, sha256: [OTHER] } } },
    });
    expect(lookupPin('unlisted', { run, sleep: noSleep })).toEqual({ pin: PIN, tag: 'unlisted-v1-v9' });
    expect(gh().at(-1)).toEqual(['gh', 'release', 'download', 'unlisted-v1-v9', '--pattern', 'build-inputs.json', '--output', '-']);
  });

  test('a release without a signer field leaves the app unpinned', () => {
    const { run } = fakeRun({
      releases: [release('unlisted-v2-v9', '2026-01-02T00:00:00Z')],
      inputs: { 'unlisted-v2-v9': { fingerprint: 'f', cliVersion: 'v1' } },
    });
    expect(lookupPin('unlisted', { run, sleep: noSleep })).toEqual({ pin: null, tag: 'unlisted-v2-v9' });
  });

  test('passes over a release whose publish stopped before build-inputs.json, and over drafts', () => {
    const { run, gh } = fakeRun({
      releases: [
        release('unlisted-v3-v9', '2026-01-03T00:00:00Z', ['unlisted.apk']),
        release('unlisted-v4-v9', null, ['build-inputs.json']),
        release('unlisted-v2-v9', '2026-01-02T00:00:00Z'),
      ],
      inputs: { 'unlisted-v2-v9': { signer: PIN } },
    });
    expect(lookupPin('unlisted', { run, sleep: noSleep }).tag).toBe('unlisted-v2-v9');
    expect(gh().at(-1)[3]).toBe('unlisted-v2-v9');
  });

  test('does not read another app whose name starts the same', () => {
    const { run } = fakeRun({
      releases: [release('unlisted-music-v9-v9', '2026-01-09T00:00:00Z')],
      inputs: { 'unlisted-music-v9-v9': { signer: PIN } },
    });
    expect(lookupPin('unlisted', { run, sleep: noSleep }).pin).toBeNull();
  });

  test('a failing release list fails closed after retrying, with a clear message', () => {
    const pauses = [];
    const { run, gh } = fakeRun({ listError: Object.assign(new Error('gh failed'), { stderr: 'HTTP 502: bad gateway\nmore' }) });
    const error = (() => { try { lookupPin('unlisted', { run, sleep: (ms) => pauses.push(ms) }); } catch (e) { return e; } return null; })();
    expect(error.message).toMatch(/^could not read the signer recorded for unlisted: HTTP 502: bad gateway\. .*the build stops/);
    expect(gh()).toHaveLength(3);
    expect(pauses).toHaveLength(2);
  });

  test('an unparsable release list fails closed', () => {
    const run = (cmd) => (cmd === 'gh' ? 'not json\n' : '');
    expect(() => lookupPin('unlisted', { run, sleep: noSleep })).toThrow(/could not read the signer recorded for unlisted: Failed to parse the release list/);
  });

  test('a transient download failure is retried', () => {
    let tries = 0;
    const { run } = fakeRun({ releases: [release('unlisted-v2-v9', '2026-01-02T00:00:00Z')], inputs: { 'unlisted-v2-v9': { signer: PIN } } });
    const flaky = (cmd, args, opts) => {
      if (cmd === 'gh' && args[1] === 'download' && (tries += 1) < 2) throw new Error('timeout');
      return run(cmd, args, opts);
    };
    expect(lookupPin('unlisted', { run: flaky, sleep: noSleep }).pin).toEqual(PIN);
    expect(tries).toBe(2);
  });

  test('a download that keeps failing fails closed, naming the release', () => {
    const { run } = fakeRun({ releases: [release('unlisted-v2-v9', '2026-01-02T00:00:00Z')], downloadError: new Error('HTTP 404') });
    expect(() => lookupPin('unlisted', { run, sleep: noSleep })).toThrow(/signer recorded for unlisted in release unlisted-v2-v9: HTTP 404/);
  });

  test.each([
    ['unparsable', '{ nope', /not valid JSON/],
    ['not an object', '[]', /not a JSON object/],
    ['has a malformed signer', JSON.stringify({ signer: { sha256: ['zz'] } }), /signer\.sha256/],
  ])('a build-inputs.json that is %s fails closed instead of meaning "no pin"', (_, text, message) => {
    const { run } = fakeRun({ releases: [release('unlisted-v2-v9', '2026-01-02T00:00:00Z')], inputs: { 'unlisted-v2-v9': text } });
    expect(() => lookupPin('unlisted', { run, sleep: noSleep })).toThrow(message);
    expect(() => lookupPin('unlisted', { run, sleep: noSleep })).toThrow(/release unlisted-v2-v9/);
  });
});

describe('recordPath / writeRecord', () => {
  let dir;
  beforeEach(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signer-record-')); });
  afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

  test('writes the record as one line of JSON, and removes a stale one when there is none', () => {
    const file = writeRecord(APP, dir, PIN);
    expect(file).toBe(recordPath(APP, dir));
    expect(path.basename(file)).toBe(`signer-${APP}.json`);
    expect(fs.readFileSync(file, 'utf8')).toBe(`${JSON.stringify(PIN)}\n`);
    expect(writeRecord(APP, dir, null)).toBeNull();
    expect(fs.existsSync(file)).toBe(false);
    expect(writeRecord(APP, dir, null)).toBeNull(); // nothing to remove is fine
  });
});

describe('checkOriginal', () => {
  let dir;
  beforeEach(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signer-check-')); });
  afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

  const base = (extra = {}) => ({
    appId: APP, file: '/apps/app.apk', version: '2.0.0', signers: SIGNERS, config: CONFIG,
    learnOrigin: null, noLearnReason: 'it came from apkeep', recordDir: dir, findBundle: () => null, sleep: noSleep, log,
    ...extra,
  });
  const record = () => (fs.existsSync(recordPath(APP, dir)) ? JSON.parse(fs.readFileSync(recordPath(APP, dir), 'utf8')) : null);

  test('a listed app is checked against apk-signers.json, asks GitHub for nothing and records nothing', () => {
    const { run, gh } = fakeRun();
    const result = checkOriginal(base({ appId: 'com.listed.app', run }));
    expect(result).toEqual({ file: '/apps/app.apk', record: null });
    expect(gh()).toEqual([]);
    expect(fs.readdirSync(dir)).toEqual([]);
  });

  test('a listed entry beats a conflicting recorded signer, which is never even read', () => {
    const { run, gh } = fakeRun({ releases: [release('listed-v1-v1', '2026-01-01T00:00:00Z')], inputs: { 'listed-v1-v1': { signer: { ...PIN, sha256: [OTHER] } } } });
    expect(() => checkOriginal(base({ appId: 'com.listed.app', run }))).not.toThrow();
    expect(gh()).toEqual([]);
    const wrong = fakeRun({ verify: () => printCerts(OTHER) });
    expect(() => checkOriginal(base({ appId: 'com.listed.app', run: wrong.run }))).toThrow(/not by com\.listed\.app's developer/);
    expect(fs.readdirSync(dir)).toEqual([]);
  });

  test.each(['apkmirror-api', 'apkmirror'])('an unlisted app with no release learns from a fresh %s download and records it', (learnOrigin) => {
    const { run } = fakeRun();
    const result = checkOriginal(base({ run, learnOrigin }));
    expect(result.record).toEqual({ sha256: [GOOD], learnedFrom: learnOrigin, learnedVersion: '2.0.0' });
    expect(record()).toEqual(result.record);
  });

  test('an unlisted app with a release that records no signer learns too', () => {
    const { run } = fakeRun({ releases: [release('unlisted-v1-v1', '2026-01-01T00:00:00Z')], inputs: { 'unlisted-v1-v1': { fingerprint: 'f' } } });
    expect(checkOriginal(base({ run, learnOrigin: 'apkmirror' })).record).toMatchObject({ learnedFrom: 'apkmirror' });
  });

  test('without a source that may be learned from, nothing is checked or recorded, and the notice says why', () => {
    const { run, calls } = fakeRun();
    const messages = [];
    const result = checkOriginal(base({ run, log: (m) => messages.push(m) }));
    expect(result).toEqual({ file: '/apps/app.apk', record: null });
    expect(calls.some(([cmd]) => cmd === 'apksigner')).toBe(false);
    expect(messages.join('\n')).toMatch(/signature not checked, and none was learned: it came from apkeep\./);
    expect(record()).toBeNull();
  });

  test('a recorded signer that matches passes and is carried forward unchanged', () => {
    const { run } = fakeRun({ releases: [release('unlisted-v1-v1', '2026-01-01T00:00:00Z')], inputs: { 'unlisted-v1-v1': { signer: PIN } } });
    // Even a fresh APKMirror download does not re-learn: the old version and source stay.
    const result = checkOriginal(base({ run, learnOrigin: 'apkmirror-api' }));
    expect(result.record).toEqual(PIN);
    expect(record()).toEqual(PIN);
  });

  test('a recorded signer that does not match fails, whatever the source, and leaves no record', () => {
    writeRecord(APP, dir, PIN); // a record left by an earlier run must not survive a failure
    const { run } = fakeRun({
      releases: [release('unlisted-v1-v1', '2026-01-01T00:00:00Z')], inputs: { 'unlisted-v1-v1': { signer: PIN } },
      verify: () => printCerts(OTHER),
    });
    const attempt = () => checkOriginal(base({ run, learnOrigin: 'apkmirror' }));
    expect(attempt).toThrow(`signed by ${OTHER}, not by the signer first recorded for ${APP} (${GOOD}, learned from apkmirror v1.0.0)`);
    expect(attempt).toThrow(/"sha256": \[".{64}"\]/);
    expect(record()).toBeNull();
  });

  test('an unreadable release fails the check instead of treating the app as unpinned', () => {
    const { run } = fakeRun({ listError: new Error('boom') });
    expect(() => checkOriginal(base({ run, learnOrigin: 'apkmirror' }))).toThrow(/could not read the signer recorded for unlisted/);
    expect(record()).toBeNull();
  });

  test('an app with no name in config.json fails: its releases cannot be found', () => {
    expect(() => checkOriginal(base({ run: fakeRun().run, config: {} }))).toThrow(/has no name in config\.json/);
  });

  test('an earlier unsigned merge gets its bundle checked instead, against the recorded signer', () => {
    const merged = `/apps/${APP}.apk`;
    const bundle = '/apps/bundle.apkm';
    const { run } = fakeRun({
      releases: [release('unlisted-v1-v1', '2026-01-01T00:00:00Z')], inputs: { 'unlisted-v1-v1': { signer: PIN } },
      entries: (file) => (file === bundle ? ['base.apk', 'split_config.arm64_v8a.apk'] : ['AndroidManifest.xml']),
      verify: (file) => {
        if (file === merged) throw new Error('DOES NOT VERIFY');
        return printCerts(GOOD);
      },
    });
    const result = checkOriginal(base({ run, file: merged, findBundle: () => bundle }));
    expect(result).toEqual({ file: bundle, record: PIN });
  });

  test('the second chance is for an unsigned merge only: a wrong signer, another file name or no bundle still fail', () => {
    const merged = `/apps/${APP}.apk`;
    const wrong = fakeRun({ verify: () => printCerts(OTHER), releases: [release('unlisted-v1-v1', '2026-01-01T00:00:00Z')], inputs: { 'unlisted-v1-v1': { signer: PIN } } });
    expect(() => checkOriginal(base({ run: wrong.run, file: merged, findBundle: () => '/apps/bundle.apkm' }))).toThrow(/first recorded/);
    const unsigned = fakeRun({ verify: () => { throw new Error('DOES NOT VERIFY'); }, releases: [release('unlisted-v1-v1', '2026-01-01T00:00:00Z')], inputs: { 'unlisted-v1-v1': { signer: PIN } } });
    const attempt = (file, findBundle) => checkOriginal(base({ run: unsigned.run, file, findBundle }));
    expect(() => attempt('/apps/other.apk', () => '/apps/bundle.apkm')).toThrow(UnsignedApkError);
    expect(() => attempt(merged, () => null)).toThrow(UnsignedApkError);
  });

  test('a bundle with one swapped split fails against the recorded signer', () => {
    const { run } = fakeRun({
      releases: [release('unlisted-v1-v1', '2026-01-01T00:00:00Z')], inputs: { 'unlisted-v1-v1': { signer: PIN } },
      entries: () => ['base.apk', 'split_config.arm64_v8a.apk'],
      verify: (file) => printCerts(fs.readFileSync(file, 'utf8').includes('split_') ? OTHER : GOOD),
    });
    expect(() => checkOriginal(base({ run, file: '/apps/app.apkm', learnOrigin: 'apkmirror' })))
      .toThrow(/app\.apkm \(split_config\.arm64_v8a\.apk\) is signed by b{64}, not by the signer first recorded/);
  });
});
