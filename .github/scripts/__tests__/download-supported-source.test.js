'use strict';

// download-supported-apk.js: the `source` output (cache | preloaded | download) and
// FRESH_DOWNLOAD, which ignores the apps/ cache. Run as the workflow runs it, with
// a stubbed aapt and apksigner; and the signer it learns from a pre-download.

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync, spawnSync } = require('node:child_process');

const root = path.resolve(__dirname, '../../..');
const FILE = 'com.expected_24.3.apk';
const DEV_KEY = 'a'.repeat(64);
const STAMP_KEY = 'b'.repeat(64);
let dir;
let apps;
let tools;

// A valid APK; `tag` makes two files differ.
function makeApk(target, tag) {
  const input = fs.mkdtempSync(path.join(dir, 'in-'));
  fs.writeFileSync(path.join(input, 'AndroidManifest.xml'), `manifest ${tag}`);
  fs.writeFileSync(path.join(input, 'classes.dex'), `dex ${tag}`);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  execFileSync('zip', ['-q', target, 'AndroidManifest.xml', 'classes.dex'], { cwd: input });
}

function run(extra = {}) {
  const bin = path.join(dir, 'bin');
  fs.mkdirSync(bin, { recursive: true });
  const badging = "printf '%s\n' \"package: name='com.expected' versionName='24.3'\"";
  for (const tool of ['aapt', 'aapt2']) fs.writeFileSync(path.join(bin, tool), `#!/usr/bin/env bash\n${badging}\n`, { mode: 0o755 });
  const configFile = path.join(dir, 'config.json');
  // The app isn't listed in apk-signers.json, so its releases are asked for a recorded signer: none.
  fs.writeFileSync(path.join(bin, 'gh'), '#!/usr/bin/env bash\nexit 0\n', { mode: 0o755 });
  // Signed by one developer key, stamped by the store (whose key is never pinned).
  fs.writeFileSync(path.join(bin, 'apksigner'), `#!/usr/bin/env bash\nprintf '%s\\n' 'Signer #1 certificate DN: CN=Expected' 'Signer #1 certificate SHA-256 digest: ${DEV_KEY}' 'Source Stamp Signer certificate SHA-256 digest: ${STAMP_KEY}'\n`, { mode: 0o755 });
  fs.writeFileSync(configFile, JSON.stringify({ preferred_arch: '', patch_repos: { 'com.expected': { name: 'expected' } } }));
  const output = path.join(dir, 'output');
  fs.writeFileSync(output, '');
  const result = spawnSync(process.execPath, [path.join(root, '.github/scripts/download-supported-apk.js')], {
    encoding: 'utf8', timeout: 30000,
    env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, APP_ID: 'com.expected', TARGET_VERSION: '24.3',
      APKS_DIR: apps, TOOLS_DIR: tools, CONFIG_FILE: configFile, GITHUB_OUTPUT: output, RUNNER_TEMP: dir, ...extra },
  });
  return { status: result.status, outputs: fs.readFileSync(output, 'utf8') };
}

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'source-output-'));
  apps = path.join(dir, 'apps');
  tools = path.join(dir, 'tools');
});
afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

test('source is cache for a file already in the apps/ cache', () => {
  makeApk(path.join(apps, FILE), 'cached');
  const { status, outputs } = run();
  expect(status).toBe(0);
  expect(outputs).toContain('source=cache');
});

test('source is preloaded for the file the check-versions job downloaded', () => {
  makeApk(path.join(tools, 'apks/com.expected', FILE), 'preloaded');
  const { status, outputs } = run();
  expect(status).toBe(0);
  expect(outputs).toContain('source=preloaded');
});

/** The signer record download-supported-apk.js left for patch_apk.sh, or null. */
function record() {
  const file = path.join(dir, 'signer-com.expected.json');
  return fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, 'utf8')) : null;
}

/** The download-origin.json pre_download_apks.sh writes beside the file it fetched. */
function originRecord(rec) {
  fs.writeFileSync(path.join(tools, 'apks/com.expected', 'download-origin.json'), JSON.stringify(rec));
}

test('a pre-downloaded file recorded as from APKPure has its signer learned, without the store stamp', () => {
  makeApk(path.join(tools, 'apks/com.expected', FILE), 'preloaded');
  originRecord({ source: 'apkeep', origin: null, url: null, file: FILE, version: '24.3' });
  const { status, outputs } = run();
  expect(status).toBe(0);
  expect(outputs).toContain('source=preloaded');
  expect(record()).toEqual({ sha256: [DEV_KEY], learnedFrom: 'apkeep', learnedVersion: '24.3' });
});

test.each([
  ['no record', null],
  ['a Google Play record', { source: 'goopdl', origin: null, url: null, file: FILE, version: '24.3' }],
  ['a record for another file', { source: 'apkeep', origin: null, url: null, file: 'other.apk', version: '24.3' }],
  ['a record for another version', { source: 'apkeep', origin: null, url: null, file: FILE, version: '24.2' }],
])('a pre-downloaded file with %s has nothing learned', (_name, rec) => {
  makeApk(path.join(tools, 'apks/com.expected', FILE), 'preloaded');
  if (rec) originRecord(rec);
  const { status, outputs } = run();
  expect(status).toBe(0);
  expect(outputs).toContain('source=preloaded');
  expect(record()).toBeNull();
});

test('FRESH_DOWNLOAD ignores the cached file, a merged <appId>.apk and the preloaded file', () => {
  makeApk(path.join(apps, FILE), 'cached');
  makeApk(path.join(apps, 'com.expected.apk'), 'merged');
  makeApk(path.join(tools, 'apks/com.expected', FILE), 'preloaded');
  const { status, outputs } = run({ FRESH_DOWNLOAD: '1' });
  // No network in the test: with every local copy skipped the downloader has nothing to use.
  expect(outputs).not.toContain('source=cache');
  expect(outputs).not.toContain('source=preloaded');
  expect(status).not.toBe(0);
  expect(fs.existsSync(path.join(apps, 'com.expected.apk'))).toBe(false);
  expect(fs.existsSync(path.join(apps, FILE))).toBe(false);
});
