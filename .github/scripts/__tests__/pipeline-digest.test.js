'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { pipelineDigest } = require('../build-fingerprint');

const jar = (c) => `${c.repeat(64)}  morphe-desktop.jar  # v1\n`;
let root;
const write = (file, text) => {
  fs.mkdirSync(path.dirname(path.join(root, file)), { recursive: true });
  fs.writeFileSync(path.join(root, file), text);
};

beforeEach(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'digest-'));
  write('checksums/tools.sha256', jar('a'));
  write('.github/workflows/morphe-build.yml', 'a');
  write('package-lock.json', '{}');
});
afterEach(() => fs.rmSync(root, { recursive: true, force: true }));

test.each([
  'src/patch.js', '.github/scripts/pipeline/patch_apk.sh',
  '.github/workflows/morphe-build.yml', 'scripts/download-tool.sh',
  'package-lock.json', '.github/scripts/apk-signers.json',
])('output or validation input %s changes the digest', (file) => {
  write(file, 'before');
  const before = pipelineDigest(root);
  write(file, 'after');
  expect(pipelineDigest(root)).not.toBe(before);
});

test('CI-only files and unrelated pins do not change the digest', () => {
  const before = pipelineDigest(root);
  write('.github/workflows/ci.yml', 'new CI');
  write('.github/workflows/codeql.yml', 'new analysis');
  write('docs/release-process.md', 'new docs');
  write('src/__tests__/patch.test.js', 'new test');
  write('scripts/check-agents-doc.js', 'new doc check');
  write('checksums/tools.sha256', `# note\n${jar('a')}${'c'.repeat(64)}  chrome-linux64.zip\n`);
  expect(pipelineDigest(root)).toBe(before);
});

test('a patcher pin changes the digest', () => {
  const before = pipelineDigest(root);
  write('checksums/tools.sha256', jar('b'));
  expect(pipelineDigest(root)).not.toBe(before);
});

describe('output-only digest (LAZY_LOGISTICS_REBUILD)', () => {
  const { LOGISTICS_FILES, releaseIsCurrent } = require('../build-fingerprint');
  const both = () => [pipelineDigest(root), pipelineDigest(root, { outputOnly: true })];

  test('every logistics file exists, so a rename cannot leave a stale entry', () => {
    const repo = path.resolve(__dirname, '../../..');
    for (const file of LOGISTICS_FILES) expect(fs.existsSync(path.join(repo, file))).toBe(true);
  });

  test('a logistics-only change moves the full digest but not the output digest', () => {
    write('.github/scripts/prune-old-releases.js', 'before');
    const [full, output] = both();
    write('.github/scripts/prune-old-releases.js', 'after');
    expect(both()).toEqual([expect.not.stringMatching(full), output]);
  });

  test.each([
    '.github/scripts/new-helper.js', '.github/scripts/pipeline/sign_apks.sh', 'src/apk/candidate.js',
    '.github/scripts/check-existing-releases.js', '.github/scripts/failure-reasons.js',
  ])(
    'an unlisted or output file %s still moves the output digest', (file) => {
      const [, output] = both();
      write(file, 'changed');
      expect(pipelineDigest(root, { outputOnly: true })).not.toBe(output);
    });

  const workflow = (lines) => lines.join('\n');
  const base = [
    'jobs:', '  build:', '    timeout-minutes: 30', '    steps:',
    '      # set up', '      - name: Checkout',
    `        uses: actions/checkout@${'a'.repeat(40)}  # v4`, '      - name: Patch', '        run: bash patch.sh',
  ];

  test('comments, step names, timeouts and action refs do not move the output digest', () => {
    write('.github/workflows/morphe-build.yml', workflow(base));
    const [full, output] = both();
    write('.github/workflows/morphe-build.yml', workflow([
      'jobs:', '  build:', '    timeout-minutes: 45', '    steps:', '',
      '      - name: Check out the repo',
      `        uses: actions/checkout@${'b'.repeat(40)}  # v5`, '      - name: Patch APKs', '        run: bash patch.sh',
    ]).replace(/\n/g, '\r\n'));
    expect(both()).toEqual([expect.not.stringMatching(full), output]);
  });

  test.each([
    ['a run command', (l) => l.map((x) => x.replace('patch.sh', 'patch.sh --fast'))],
    ['the action used', (l) => l.map((x) => x.replace('actions/checkout', 'other/checkout'))],
    ['a new step', (l) => [...l, '      - run: echo extra']],
  ])('changing %s moves the output digest', (_, edit) => {
    write('.github/workflows/morphe-build.yml', workflow(base));
    const output = pipelineDigest(root, { outputOnly: true });
    write('.github/workflows/morphe-build.yml', workflow(edit(base)));
    expect(pipelineDigest(root, { outputOnly: true })).not.toBe(output);
  });

  test('a docker image digest still moves the output digest', () => {
    const docker = (c) => workflow([...base, `      - uses: docker://img@sha256:${c.repeat(64)}`]);
    write('.github/workflows/morphe-build.yml', docker('c'));
    const output = pipelineDigest(root, { outputOnly: true });
    write('.github/workflows/morphe-build.yml', docker('d'));
    expect(pipelineDigest(root, { outputOnly: true })).not.toBe(output);
  });

  const release = (body) => ({ body, assets: ['App.apk', 'SHA256SUMS', 'build-inputs.json'].map((name) => ({ name })) });
  test('the output marker counts only when the lazy digest is passed', () => {
    const r = release('<!-- build-input:old -->\n<!-- build-output:same -->');
    expect(releaseIsCurrent(r, 'App', 'new')).toBe(false);
    expect(releaseIsCurrent(r, 'App', 'new', 'same')).toBe(true);
    expect(releaseIsCurrent(r, 'App', 'new', 'other')).toBe(false);
    expect(releaseIsCurrent(release('<!-- build-input:new -->'), 'App', 'new', 'same')).toBe(true);
  });
});
