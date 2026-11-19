#!/usr/bin/env node
'use strict';
// Throwaway A/B probe: does APKMirror's Cloudflare challenge pass with
// Playwright or patchright? Prints one PROBE line per page.
// Usage: node probe-apkmirror.js <playwright|patchright> <ours|recommended>

const [engine, mode] = process.argv.slice(2);
const { chromium } = require(engine);

const PAGES = [
  'https://www.apkmirror.com/',
  'https://www.apkmirror.com/apk/discord-inc/discord-talk-play-hang-out/discord-talk-play-hang-out-351-11-release/',
  'https://www.apkmirror.com/apk/redditinc/reddit/reddit-2026-45-0-release/',
  'https://www.apkmirror.com/apk/x-corp/twitter/twitter-12-19-1-release-0-release/',
  'https://www.apkmirror.com/apk/google-inc/gboard/gboard-the-google-keyboard-18-5-4-993608717-release/',
];
const CHALLENGE = /attention required|just a moment|checking your browser|cloudflare/i;

async function launch() {
  if (mode === 'recommended') {
    // patchright's advice: real Chrome, headed, no UA or args overrides.
    const context = await chromium.launchPersistentContext('/tmp/probe-profile', {
      channel: 'chrome', headless: false, viewport: null,
    });
    return { context, close: () => context.close() };
  }
  // Same options as apkmirror-browser.js openApkmirror().
  const browser = await chromium.launch({
    headless: true,
    channel: 'chromium',
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage', '--disable-blink-features=AutomationControlled'],
  });
  const context = await browser.newContext({
    userAgent: `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${browser.version()} Safari/537.36`,
    locale: 'en-US', acceptDownloads: true,
  });
  return { context, close: () => browser.close() };
}

(async () => {
  const { context, close } = await launch();
  const page = context.pages()[0] || await context.newPage();
  let passed = 0;
  for (const url of PAGES) {
    let latest;
    const onResponse = (r) => { if (r.request().isNavigationRequest() && r.frame() === page.mainFrame()) latest = r; };
    page.on('response', onResponse);
    const t0 = Date.now();
    let title = '', status = 0, err = '';
    try {
      const initial = await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30_000 });
      if (!latest) latest = initial;
      await page.waitForTimeout(1500);
      title = await page.title();
      // Give a challenge up to 20 s to clear itself.
      for (let i = 0; i < 10 && CHALLENGE.test(title); i++) {
        await page.waitForTimeout(2000);
        title = await page.title();
      }
      status = latest?.status() || 0;
    } catch (e) { err = e.message.split('\n')[0]; }
    page.off('response', onResponse);
    const ok = !err && !CHALLENGE.test(title) && status >= 200 && status < 400;
    if (ok) passed++;
    console.log(`PROBE ${engine}/${mode} ${ok ? 'PASS' : 'FAIL'} status=${status} secs=${((Date.now() - t0) / 1000).toFixed(1)} title=${JSON.stringify(title.slice(0, 60))} ${err ? `err=${JSON.stringify(err)} ` : ''}url=${url}`);
    await page.waitForTimeout(1500);
  }
  console.log(`PROBE-SUMMARY ${engine}/${mode} ${passed}/${PAGES.length}`);
  await close();
})().catch((e) => { console.log(`PROBE-SUMMARY ${engine}/${mode} crashed: ${e.message.split('\n')[0]}`); process.exit(0); });
