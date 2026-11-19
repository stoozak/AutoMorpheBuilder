'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])]));
  return value;
}

function fingerprint(inputs) {
  return crypto.createHash('sha256').update(JSON.stringify(canonical(inputs))).digest('hex');
}

// The epoch remains an explicit escape hatch for inputs outside this digest.
const REBUILD_EPOCH = 1;

// Browser and inspection-tool refreshes do not by themselves alter APK output.
function outputToolPins(text) {
  return [...text.matchAll(/^([0-9a-f]{64})\s+(morphe-desktop\.jar|APKEditor\.jar)(?=\s|$)/gm)]
    .map((m) => `${m[1]}  ${m[2]}\n`).join('');
}

// Files that decide when, whether and how a build is published, but cannot
// change the APK's bytes or what the download is checked against. With
// LAZY_LOGISTICS_REBUILD on, changing only these files no longer rebuilds
// current releases; apps pick the change up on their next rebuild. Anything
// not listed here, including a new file, still rebuilds at once. Not listed on
// purpose: check-existing-releases.js (sets each build's extra-patch tags) and
// failure-reasons.js (decides whether a download succeeded).
const LOGISTICS_FILES = new Set([
  '.github/scripts/apkmirror-pacing.js',
  '.github/scripts/cleanup-caches.js',
  '.github/scripts/compat-probe.js',
  '.github/scripts/install-playwright-browsers.js',
  '.github/scripts/only-apps.js',
  '.github/scripts/patch-playwright-cft-path.js',
  '.github/scripts/preflight-apps.js',
  '.github/scripts/prune-old-releases.js',
  '.github/scripts/sync-patch-selections.js',
  '.github/scripts/pipeline/check_existing_releases.sh',
  '.github/scripts/pipeline/delete_run_artifacts.sh',
  '.github/scripts/pipeline/install_playwright.sh',
  '.github/scripts/pipeline/prune_old_releases.sh',
  '.github/scripts/pipeline/push_with_rebase.sh',
  '.github/scripts/pipeline/sync-patches.sh',
  'scripts/check-playwright-browsers.js',
  'scripts/detect-new-repos.js',
  'scripts/sync-patches.sh',
]);

// Drops what cannot change a build's result from the workflow text: comment
// and blank lines, step names, timeouts and the commit SHA of each pinned
// action (inputs such as java-version are kept). Docker digests are kept.
function normalizeWorkflow(text) {
  return text.replace(/\r\n/g, '\n').split('\n')
    .filter((line) => !/^\s*(#.*)?$/.test(line) && !/^\s*timeout-minutes:/.test(line))
    .map((line) => line
      .replace(/^(\s*)- name:.*$/, '$1-')
      .replace(/^(\s*(?:- )?uses:\s*[\w.-]+\/[\w./-]+)@[0-9a-f]{40}(\s+#.*)?$/, '$1'))
    .join('\n');
}

function pipelineDigest(root = path.resolve(__dirname, '../..'), { outputOnly = false } = {}) {
  const files = ['package-lock.json', '.github/workflows/morphe-build.yml'];
  function visit(dir) {
    if (!fs.existsSync(path.join(root, dir))) return;
    for (const entry of fs.readdirSync(path.join(root, dir), { withFileTypes: true })) {
      if (['__tests__', 'fixtures'].includes(entry.name)) continue;
      const file = `${dir}/${entry.name}`;
      if (entry.isDirectory()) visit(file);
      else if (/\.(js|sh|json)$/.test(entry.name)
        && !['check-agents-doc.js', 'generate-readme-tables.js'].includes(entry.name)) files.push(file);
    }
  }
  for (const dir of ['src', '.github/scripts', 'scripts']) visit(dir);
  const hash = crypto.createHash('sha256').update(`epoch:${REBUILD_EPOCH}\0`)
    .update(outputToolPins(fs.readFileSync(path.join(root, 'checksums/tools.sha256'), 'utf8')));
  if (outputOnly) hash.update('output-only\0');
  for (const file of files.sort()) {
    if (outputOnly && LOGISTICS_FILES.has(file)) continue;
    const bytes = fs.readFileSync(path.join(root, file));
    const body = outputOnly && file === '.github/workflows/morphe-build.yml'
      ? normalizeWorkflow(bytes.toString('utf8')) : bytes;
    hash.update(file).update('\0').update(body).update('\0');
  }
  return hash.digest('hex');
}

function appFingerprint(config, patches, appId, cliVersion, pipeline) {
  const entry = config.patch_repos[appId];
  return fingerprint({ appId, app: entry, patches: patches[entry.repo]?.[appId] || {},
    architecture: config.preferred_arch || '', cli: config.cli, cliVersion, pipeline,
    ...(config.honor_patch_opt_ins === true ? { honorPatchOptIns: true } : {}) });
}

// outputDigest is passed only when LAZY_LOGISTICS_REBUILD is on: a release
// built from the same output inputs then stays current even if logistics
// files changed since.
function releaseIsCurrent(release, name, digest, outputDigest) {
  const names = new Set((release.assets || []).map((asset) => asset.name));
  const body = release.body || '';
  return (body.includes(`<!-- build-input:${digest} -->`)
      || (!!outputDigest && body.includes(`<!-- build-output:${outputDigest} -->`)))
    && [`${name}.apk`, 'SHA256SUMS', 'build-inputs.json'].every((asset) => names.has(asset));
}

if (require.main === module) {
  const config = JSON.parse(fs.readFileSync(process.env.CONFIG_FILE || 'config.json', 'utf8'));
  const patches = JSON.parse(fs.readFileSync(process.env.PATCHES_FILE || 'patches.json', 'utf8'));
  // FINGERPRINT_TIER=output prints the fingerprints without logistics files.
  const pipeline = pipelineDigest(undefined, { outputOnly: process.env.FINGERPRINT_TIER === 'output' });
  console.log(JSON.stringify(Object.fromEntries(Object.keys(config.patch_repos).map((appId) =>
    [config.patch_repos[appId].name, appFingerprint(config, patches, appId, process.env.CLI_VERSION || '', pipeline)]))));
}

module.exports = { fingerprint, appFingerprint, releaseIsCurrent, pipelineDigest, normalizeWorkflow, LOGISTICS_FILES };
