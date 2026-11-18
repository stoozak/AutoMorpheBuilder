'use strict';

// Learned signer pins ("trust on first use"): checkSigner against a recorded
// signer, learning one, and the helpers around them. The real functions run;
// only unzip and apksigner are faked, through `opts.run`.

const fs = require('node:fs');
const {
  checkSigner, certSubject, parsePin, pinFromBuildInputs, isListed, learnableOrigin, suggestedEntry, UnsignedApkError,
} = require('../signer');

const GOOD = 'a'.repeat(64);
const OTHER = 'b'.repeat(64);
const THIRD = 'c'.repeat(64);
const SIGNERS = { 'com.example': { sha256: [GOOD] } };
const UNLISTED = 'com.unlisted';
const PIN = { sha256: [GOOD], learnedFrom: 'apkmirror-api', learnedVersion: '1.2.3' };
const DN = 'CN=Real Dev, O=Real Dev Ltd, C=GB';
const printCerts = (digest, dn = DN) => `Signer #1 certificate DN: ${dn}\nSigner #1 certificate SHA-256 digest: ${digest}\n`;
const log = () => {};
const catchError = (fn) => { try { fn(); } catch (e) { return e; } return null; };

/** A stand-in for execFileSync that answers unzip and apksigner. */
function fakeRun({ entries = ['AndroidManifest.xml', 'classes.dex'], verify = () => printCerts(GOOD) } = {}) {
  const calls = [];
  const run = (cmd, args) => {
    calls.push([cmd, ...args]);
    if (cmd === 'unzip' && args[0] === '-Z1') return `${entries.join('\n')}\n`;
    if (cmd === 'unzip' && args[0] === '-p') return Buffer.from(`bytes of ${args[2]}`);
    if (cmd === 'apksigner') return verify(args[args.length - 1]);
    throw new Error(`unexpected command ${cmd}`);
  };
  return { run, calls };
}

describe('certSubject', () => {
  test('reads the first certificate DN, else nothing', () => {
    expect(certSubject(`${printCerts(GOOD)}Signer #2 certificate DN: CN=Other\n`)).toBe(DN);
    expect(certSubject(`Source Stamp Signer certificate DN: CN=Store\n${printCerts(GOOD)}`)).toBe(DN);
    expect(certSubject('Verifies\n')).toBe('');
    expect(certSubject(undefined)).toBe('');
  });
});

describe('parsePin / pinFromBuildInputs', () => {
  test('a well-formed pin is normalised', () => {
    expect(parsePin({ sha256: [GOOD.toUpperCase(), GOOD], learnedFrom: 'apkmirror', learnedVersion: '9' }))
      .toEqual({ sha256: [GOOD], learnedFrom: 'apkmirror', learnedVersion: '9' });
  });

  test.each([
    ['not an object', null],
    ['an array', []],
    ['no fingerprints', { sha256: [], learnedFrom: 'a', learnedVersion: '1' }],
    ['no sha256 field', { learnedFrom: 'a', learnedVersion: '1' }],
    ['a short fingerprint', { sha256: ['abc'], learnedFrom: 'a', learnedVersion: '1' }],
    ['no source', { sha256: [GOOD], learnedVersion: '1' }],
    ['no version', { sha256: [GOOD], learnedFrom: 'a', learnedVersion: '' }],
  ])('a pin that is %s throws', (_, value) => {
    expect(() => parsePin(value)).toThrow(/signer/);
  });

  test('build-inputs.json: the pin if there is one, null if there is no signer field', () => {
    expect(pinFromBuildInputs(JSON.stringify({ fingerprint: 'x', signer: PIN }))).toEqual(PIN);
    expect(pinFromBuildInputs(JSON.stringify({ fingerprint: 'x', cliVersion: 'v1' }))).toBeNull();
  });

  test.each([
    ['text that is not JSON', '{ nope', /not valid JSON/],
    ['JSON that is not an object', '[1]', /not a JSON object/],
    ['null', 'null', /not a JSON object/],
    ['a signer that is null', '{"signer": null}', /"signer" is not an object/],
    ['a signer that is malformed', '{"signer": {"sha256": ["x"]}}', /signer\.sha256/],
  ])('build-inputs.json with %s throws, so a broken pin never means "no pin"', (_, text, message) => {
    expect(() => pinFromBuildInputs(text)).toThrow(message);
  });
});

describe('isListed / learnableOrigin', () => {
  test('isListed', () => {
    expect(isListed(SIGNERS, 'com.example')).toBe(true);
    expect(isListed(SIGNERS, UNLISTED)).toBe(false);
  });

  test.each([
    [{ source: 'apkmirror-api' }, 'apkmirror-api'],
    [{ source: 'apkmirror' }, 'apkmirror'],
    [{ source: 'direct-url', origin: 'apkmirror-api' }, 'apkmirror-api'],
    [{ source: 'direct-url', origin: 'apkmirror' }, 'apkmirror'],
    [{ source: 'apkeep' }, 'apkeep'],
    [{ source: 'direct-url', origin: 'apkeep' }, 'apkeep'],
    [{ source: 'apkpure-exact' }, 'apkpure-exact'],
    [{ source: 'direct-url' }, null], // a cached or listed URL with no URL to judge
    // A cached or listed URL counts only over HTTPS on an APKMirror or APKPure host.
    [{ source: 'direct-url', url: 'https://d.apkpure.com/b/XAPK/com.x?versionCode=1' }, 'direct-url (d.apkpure.com)'],
    [{ source: 'direct-url', url: 'https://download.pureapk.com/b/APK/x' }, 'direct-url (download.pureapk.com)'],
    [{ source: 'direct-url', url: 'https://www.apkmirror.com/wp-content/x.apk' }, 'direct-url (www.apkmirror.com)'],
    [{ source: 'direct-url', url: 'http://d.apkpure.com/b/APK/x' }, null],
    [{ source: 'direct-url', url: 'https://d.apkpure.com.evil.example/x' }, null],
    [{ source: 'direct-url', url: 'https://evil.example/d.apkpure.com/x' }, null],
    [{ source: 'direct-url', url: 'https://user@evil.example/x' }, null],
    [{ source: 'direct-url', url: 'https://u@www.apkmirror.com/x.apk' }, null],
    [{ source: 'direct-url', url: 'https://u:p@d.apkpure.com/x' }, null],
    [{ source: 'direct-url', url: 'https://www.apkmirror.com:8443/x.apk' }, null],
    [{ source: 'direct-url', url: 'not a url' }, null],
    [{ source: 'cache', url: 'https://d.apkpure.com/b/APK/x' }, null],
    [{ source: 'goopdl', url: 'https://d.apkpure.com/b/APK/x' }, null],
    [{ source: 'goopdl' }, null],
    [{ source: 'cache' }, null],
    [{ source: 'preloaded' }, null],
    [{}, null],
    [null, null],
    [undefined, null],
  ])('learnableOrigin(%j) is %s', (result, expected) => {
    expect(learnableOrigin(result)).toBe(expected);
  });
});

describe('suggestedEntry', () => {
  test('is a pasteable apk-signers.json entry', () => {
    const entry = suggestedEntry('com.x', [GOOD, OTHER], 'CN=A, O="B"', '2.0');
    expect(JSON.parse(`{${entry}}`)).toEqual({ 'com.x': { sha256: [GOOD, OTHER], subject: 'CN=A, O="B"', seen: '2.0' } });
    expect(JSON.parse(`{${suggestedEntry('com.x', [GOOD], '', '')}}`)['com.x']).toMatchObject({ subject: 'unknown', seen: 'unknown' });
  });
});

describe('checkSigner: listed apps are unchanged', () => {
  test('a listed entry beats a conflicting recorded signer, in both directions', () => {
    const conflicting = { sha256: [OTHER], learnedFrom: 'apkmirror', learnedVersion: '1' };
    const messages = [];
    const ok = checkSigner('/apks/app.apk', 'com.example', { signers: SIGNERS, pin: conflicting, run: fakeRun().run, log: (m) => messages.push(m) });
    expect(ok).toMatchObject({ ok: true, kind: 'listed', matched: GOOD });
    expect(messages[0]).toMatch(/lists com\.example; its recorded signer is ignored/);
    // An APK signed by the recorded (but not the listed) key fails with the listed-app message.
    const { run } = fakeRun({ verify: () => printCerts(OTHER) });
    const error = catchError(() => checkSigner('app.apk', 'com.example', { signers: SIGNERS, pin: conflicting, run, log }));
    expect(error.message).toMatch(/not by com\.example's developer \(a{64} in \.github\/scripts\/apk-signers\.json\)/);
    expect(error.message).not.toMatch(/first recorded/);
  });

  test('a listed app never learns, even from APKMirror', () => {
    const result = checkSigner('/apks/app.apk', 'com.example', {
      signers: SIGNERS, learn: { from: 'apkmirror', version: '1' }, run: fakeRun().run, log,
    });
    expect(result.kind).toBe('listed');
    expect(result.learned).toBeUndefined();
  });
});

describe('checkSigner: an unlisted app with nothing recorded', () => {
  test('is not checked when nothing may be learned, and the notice says why', () => {
    const { run, calls } = fakeRun();
    const messages = [];
    expect(checkSigner('x.apk', UNLISTED, { signers: SIGNERS, run, log: (m) => messages.push(m), noLearnReason: 'it came from apkeep' }))
      .toEqual({ skipped: true });
    expect(calls).toEqual([]);
    expect(messages).toEqual([`::notice::No signer listed for ${UNLISTED} in .github/scripts/apk-signers.json; signature not checked, and none was learned: it came from apkeep.`]);
  });

  test.each(['apkmirror-api', 'apkmirror'])('learns the signer of an APK freshly downloaded from %s', (from) => {
    const { run, calls } = fakeRun();
    const messages = [];
    const result = checkSigner('/apks/app.apk', UNLISTED, { signers: SIGNERS, learn: { from, version: '1.2.3' }, run, log: (m) => messages.push(m) });
    expect(result).toMatchObject({ ok: true, skipped: false, kind: 'learning' });
    expect(result.learned).toEqual({ sha256: [GOOD], learnedFrom: from, learnedVersion: '1.2.3' });
    expect(calls[1]).toEqual(['apksigner', 'verify', '--print-certs', '/apks/app.apk']);
    expect(messages[0]).toMatch(new RegExp(`Learned the signer of ${UNLISTED} from ${from} v1\\.2\\.3`));
  });

  test('learning still needs the APK to verify', () => {
    const { run } = fakeRun({ verify: () => { throw new Error('DOES NOT VERIFY'); } });
    const error = catchError(() => checkSigner('app.apk', UNLISTED, { signers: SIGNERS, learn: { from: 'apkmirror', version: '1' }, run, log }));
    expect(error).toBeInstanceOf(UnsignedApkError);
  });

  test('nothing is learned from an APK with no certificate', () => {
    const { run } = fakeRun({ verify: () => 'Verifies\n' });
    expect(() => checkSigner('app.apk', UNLISTED, { signers: SIGNERS, learn: { from: 'apkmirror', version: '1' }, run, log }))
      .toThrow(/printed no certificate for app\.apk; no signer can be learned/);
  });

  test('learns from a bundle whose APKs share a signer', () => {
    const { run } = fakeRun({ entries: ['base.apk', 'split_config.arm64_v8a.apk'] });
    const result = checkSigner('app.apkm', UNLISTED, { signers: SIGNERS, learn: { from: 'apkmirror', version: '4' }, run, log });
    expect(result.learned).toEqual({ sha256: [GOOD], learnedFrom: 'apkmirror', learnedVersion: '4' });
  });

  test('learns nothing from a bundle with APKs signed by different keys', () => {
    const { run } = fakeRun({
      entries: ['base.apk', 'split_config.arm64_v8a.apk'],
      verify: (file) => printCerts(fs.readFileSync(file, 'utf8').includes('split_') ? OTHER : GOOD),
    });
    expect(() => checkSigner('app.apkm', UNLISTED, { signers: SIGNERS, learn: { from: 'apkmirror', version: '4' }, run, log }))
      .toThrow(/app\.apkm \(split_config\.arm64_v8a\.apk\) is signed by b{64}, not by the key of the other APKs in the bundle \(a{64}\); no signer is learned/);
  });
});

describe('checkSigner: an unlisted app with a recorded signer', () => {
  test('passes an APK signed by it and says which signer matched', () => {
    const messages = [];
    const result = checkSigner('/apks/app.apk', UNLISTED, { signers: SIGNERS, pin: PIN, run: fakeRun().run, log: (m) => messages.push(m) });
    expect(result).toMatchObject({ ok: true, kind: 'learned', matched: GOOD });
    expect(messages[0]).toBe(`Signer of app.apk matches the signer recorded from apkmirror-api v1.2.3 (${GOOD}).`);
  });

  test('a recorded signer wins over learning', () => {
    const result = checkSigner('/apks/app.apk', UNLISTED, {
      signers: SIGNERS, pin: PIN, learn: { from: 'apkmirror', version: '9' }, run: fakeRun().run, log,
    });
    expect(result.kind).toBe('learned');
    expect(result.learned).toBeUndefined();
  });

  test('a different signer fails, naming the new and recorded fingerprints, where they were learned, and a ready entry', () => {
    const { run } = fakeRun({ verify: () => printCerts(OTHER, 'CN=Someone Else') });
    const error = catchError(() => checkSigner('app.apk', UNLISTED, { signers: SIGNERS, pin: PIN, version: '2.0.0', run, log }));
    expect(error).not.toBeInstanceOf(UnsignedApkError);
    const [first, ...entryLines] = error.message.split('\n');
    expect(first).toContain(`app.apk is signed by ${OTHER}, not by the signer first recorded for ${UNLISTED} (${GOOD}, learned from apkmirror-api v1.2.3).`);
    expect(first).toContain('add this entry to .github/scripts/apk-signers.json');
    expect(JSON.parse(`{${entryLines.join('\n')}}`)).toEqual({
      [UNLISTED]: { sha256: [OTHER], subject: 'CN=Someone Else', seen: '2.0.0' },
    });
  });

  test('an APK with no certificate fails without a pasteable entry', () => {
    const { run } = fakeRun({ verify: () => 'Verifies\n' });
    expect(() => checkSigner('app.apk', UNLISTED, { signers: SIGNERS, pin: PIN, run, log }))
      .toThrow(/is signed by nothing apksigner recognised, not by the signer first recorded.*no entry to suggest/s);
  });

  test('every APK of a bundle must match: a swapped split fails and names the split', () => {
    const { run } = fakeRun({
      entries: ['base.apk', 'split_config.arm64_v8a.apk'],
      verify: (file) => printCerts(fs.readFileSync(file, 'utf8').includes('split_') ? THIRD : GOOD),
    });
    expect(() => checkSigner('app.apkm', UNLISTED, { signers: SIGNERS, pin: PIN, run, log }))
      .toThrow(new RegExp(`app\\.apkm \\(split_config\\.arm64_v8a\\.apk\\) is signed by ${THIRD}, not by the signer first recorded`));
  });

  test('a bundle whose APKs all match passes, and the message says all of them', () => {
    const messages = [];
    const { run } = fakeRun({ entries: ['base.apk', 'split_a.apk', 'split_b.apk'] });
    expect(checkSigner('app.apkm', UNLISTED, { signers: SIGNERS, pin: PIN, run, log: (m) => messages.push(m) }).kind).toBe('learned');
    expect(messages[0]).toBe(`Signers of all 3 APKs in app.apkm match the signer recorded from apkmirror-api v1.2.3 (${GOOD}).`);
  });

  test('an unsigned APK is still reported as unsigned (the retry in download-supported-apk.js relies on it)', () => {
    const { run } = fakeRun({ verify: () => { throw new Error('DOES NOT VERIFY'); } });
    expect(catchError(() => checkSigner('app.apk', UNLISTED, { signers: SIGNERS, pin: PIN, run, log }))).toBeInstanceOf(UnsignedApkError);
  });
});
