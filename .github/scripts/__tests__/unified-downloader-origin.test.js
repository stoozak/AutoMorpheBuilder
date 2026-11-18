'use strict';

// download() reports where a file really came from in `origin`: the source
// that resolved its URL in this run. downloadWithUrl labels every file
// 'direct-url', which says nothing about the mirror. An APKMirror or APKPure
// origin, or a URL on one of their hosts, may be used to learn an app's
// signer (signer.js learnableOrigin).

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { EventEmitter } = require('node:events');
const { download } = require('../unified-downloader');
const { learnableOrigin } = require('../../../src/download/signer');

const PKG = 'com.google.android.youtube';
const VER = '20.44.38';
const fixtureRoot = path.resolve(__dirname, '../../../test/fixtures');
const URL_ON_MIRROR = 'https://example.invalid/fixtures/placeholder.apk';

let apksDir;
let homeDir;

beforeEach(() => {
  apksDir = fs.mkdtempSync(path.join(os.tmpdir(), 'origin-apks-'));
  homeDir = fs.mkdtempSync(path.join(os.tmpdir(), 'origin-home-'));
  process.env.URL_CACHE_DIR = path.join(homeDir, 'urls');
  global.fetch = jest.fn(() => Promise.resolve({ ok: true, status: 200 }));
  jest.spyOn(console, 'error').mockImplementation(() => {});
});
afterEach(() => {
  jest.restoreAllMocks();
  delete process.env.URL_CACHE_DIR;
  delete global.fetch;
  fs.rmSync(apksDir, { recursive: true, force: true });
  fs.rmSync(homeDir, { recursive: true, force: true });
});

/** Options that download the placeholder APK instead of using the network, aapt or a real mirror. */
function offline(extra = {}) {
  const target = path.join(apksDir, `${PKG}_${VER}.apk`);
  const spawnImpl = jest.fn(() => {
    const child = new EventEmitter();
    child.stderr = new EventEmitter();
    setImmediate(() => {
      fs.copyFileSync(path.join(fixtureRoot, 'apk-metadata', 'placeholder.apk'), target);
      child.emit('close', 0);
    });
    return child;
  });
  const execFileSyncImpl = (file, args, options) => (file === 'aapt'
    ? fs.readFileSync(path.join(fixtureRoot, 'apk-metadata', 'valid-badging.txt'), 'utf8')
    : require('node:child_process').execFileSync(file, args, options));
  return { spawnImpl, execFileSyncImpl, apkpureExactBudgetMs: 20, ...extra };
}

const reject = (name) => () => Promise.reject(new Error(`${name} is down`));
const resolver = (url, source) => () => Promise.resolve({ url, source });

test.each([
  ['apkmirror-api', { apkeep: reject('apkeep'), apkmirrorApi: resolver(URL_ON_MIRROR, 'apkmirror-api'), apkmirror: reject('apkmirror') }, 'apkmirror-api'],
  ['apkmirror', { apkeep: reject('apkeep'), apkmirrorApi: reject('api'), apkmirror: resolver(URL_ON_MIRROR, 'apkmirror') }, 'apkmirror'],
  ['apkeep', { apkeep: resolver(URL_ON_MIRROR, 'apkeep'), apkmirrorApi: reject('api'), apkmirror: reject('apkmirror') }, 'apkeep'],
])('a parallel resolution won by %s is labelled with its origin', async (origin, sourceResolvers, learnable) => {
  const result = await download(PKG, VER, apksDir, offline({ sourceResolvers }));
  expect(result).toMatchObject({ success: true, source: 'direct-url', origin });
  expect(learnableOrigin(result)).toBe(learnable);
});

/** A URL-cache entry for PKG/VER that says it came from APKMirror. */
function cacheEntry(url) {
  const cacheDir = path.join(process.env.URL_CACHE_DIR, PKG);
  fs.mkdirSync(cacheDir, { recursive: true });
  fs.writeFileSync(path.join(cacheDir, `${VER}.json`), JSON.stringify({ url, source: 'apkmirror', downloads: 0, lastWorkingAt: '2025-01-01T00:00:00Z' }));
}

test('a URL-cache hit has no origin, so nothing is learned from it off a store host', async () => {
  // The entry's own `source` isn't proof; only the URL's host is judged.
  cacheEntry(URL_ON_MIRROR);
  const result = await download(PKG, VER, apksDir, offline());
  expect(result).toMatchObject({ success: true, source: 'direct-url', url: URL_ON_MIRROR });
  expect(result.origin).toBeUndefined();
  expect(learnableOrigin(result)).toBeNull();
});

test('a URL-cache hit on an APKPure host is learned from, labelled with the host', async () => {
  const url = 'https://d.apkpure.com/b/APK/com.google.android.youtube?versionCode=1';
  cacheEntry(url);
  const result = await download(PKG, VER, apksDir, offline());
  expect(result).toMatchObject({ success: true, source: 'direct-url', url });
  expect(learnableOrigin(result)).toBe('direct-url (d.apkpure.com)');
});
