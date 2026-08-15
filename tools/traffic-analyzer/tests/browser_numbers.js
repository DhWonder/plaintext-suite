/*
 * Load each capture into the real browser page and print what it worked out.
 *
 * This exists so "the browser version agrees with the Python version" is a
 * thing I can check rather than a thing I claim. It drives the actual page in
 * headless Chromium, feeds it the same files, and prints JSON that
 * test_parity.py compares against the command line tool.
 *
 *   node tests/browser_numbers.js <page.html> <capture> [capture...]
 */
const { chromium } = require('playwright');
const path = require('path');

const pagePath = path.resolve(process.argv[2]);
const captures = process.argv.slice(3);

(async () => {
  const browser = await chromium.launch({
    executablePath: process.env.CHROMIUM || '/opt/pw-browsers/chromium'
  });
  const page = await browser.newPage();
  const problems = [];
  page.on('pageerror', e => problems.push(String(e.message)));

  await page.goto('file://' + pagePath, { waitUntil: 'domcontentloaded' });
  // The page starts empty on purpose, so there is nothing to wait for beyond
  // the script having run.
  await page.waitForFunction(() => typeof window.__state !== 'undefined', { timeout: 30000 });

  const results = {};
  for (const capture of captures) {
    const name = path.basename(capture);
    await page.evaluate(() => { document.getElementById('k1').textContent = 'PENDING'; });
    await page.setInputFiles('#file', path.resolve(capture));

    let ok = true;
    try {
      await page.waitForFunction(() => {
        const k = document.getElementById('k1').textContent;
        const err = document.getElementById('err').classList.contains('on');
        return err || (k !== 'PENDING' && k !== '0');
      }, { timeout: 180000 });
    } catch (e) { ok = false; }

    results[name] = await page.evaluate(() => {
      if (document.getElementById('err').classList.contains('on'))
        return { error: document.getElementById('err').textContent.trim() };
      const s = window.__state ? window.__state.summary : null;
      const num = id => Number(document.getElementById(id).textContent.replace(/,/g, ''));
      return {
        packets: num('k1'), sources: num('k2'), hostile: num('k3'),
        peak: num('k4'), vectors: num('k5'),
        verdict: document.getElementById('verdictHead').textContent,
        counts: s ? s.counts : null,
        vectorList: s ? s.vectors : null,
        format: s && s.read ? s.read.format : null,
        framesUsed: s && s.read ? s.read.used : null
      };
    });
    if (!ok) results[name].timedOut = true;
  }

  if (problems.length) results._pageErrors = problems;
  console.log(JSON.stringify(results, null, 1));
  await browser.close();
})();
