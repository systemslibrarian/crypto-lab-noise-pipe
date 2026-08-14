import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';
import { auditNonText } from './nontext';
import { NONTEXT_BASELINE } from './nontext-baseline';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 };

/**
 * Shared machinery for the WCAG gate.
 *
 * Five rules govern everything here, and each one corrects something the gate
 * this replaces did:
 *
 *  1. NOTHING IS INJECTED INTO THE PAGE BEFORE A SCAN. The old spec's
 *     `revealAll()` opened with an `addStyleTag` pushing `animation: none
 *     !important; transition: none !important` into the page. That BYPASSES
 *     this lab's own reduced-motion handling instead of exercising it — and on
 *     this page that handling is not only CSS. `ui.ts` reads
 *     `matchMedia('(prefers-reduced-motion: reduce)')` ONCE at module load and
 *     branches on it in five places: the `animate-in` class on log entries,
 *     the `diagram-animate` class on the message-lane SVG, the anatomy keys'
 *     `slide-in` re-trigger, and the explainer's `scrollIntoView` behaviour. A
 *     style tag cannot reach a `matchMedia` call, so the old gate always
 *     scanned the animated-classes rendering and never once scanned the
 *     rendering a reader with the preference set actually gets. This gate sets
 *     the preference through `emulateMedia` BEFORE navigation (so the
 *     module-load read sees it), asserts from inside the page that it took
 *     effect, and injects nothing.
 *
 *  2. IT FORCE-REVEALED EVERYTHING AND SCANNED A PAGE THAT CANNOT EXIST.
 *     `revealAll()` set `.open` on every `<details>`, stripped every `hidden`
 *     attribute and `aria-hidden`, and forced `display: block` on everything
 *     `display: none` — which on THIS page meant all six tab panels rendered
 *     at once (a state the tab machinery never produces), the glossary
 *     tooltip floating unpositioned, and `aria-hidden` decorations exposed to
 *     the scan. Violations in that franken-state may not exist in any real
 *     one, and real ones can hide behind it. This gate reaches every hidden
 *     surface the way a reader does: clicking tabs, clicking summaries,
 *     running the demo.
 *
 *  3. IT NEVER DROVE THE DEMO. The old gate scanned the arrival render twice
 *     (once per theme) and nothing else. Everything this lab renders in
 *     response to use — the walkthrough's per-step logs and DH visuals, the
 *     wire-block ENCRYPTED/PLAINTEXT split, the transport lanes' ciphertext
 *     and error branches, all four Break-it badge kinds, the comparison
 *     explainer, the predict quiz's right/wrong tints — had never been
 *     measured. This drive runs them and scans each, in
 *     {dark, light} x {1280, 380}.
 *
 *  4. `violations` IS NOT THE WHOLE ORACLE. See `scan`. axe files what it
 *     cannot resolve under `incomplete`, which a violations-only assertion
 *     never reads — and that is where `color-mix()` surfaces (the shared top
 *     bar) and `aria-prohibited-attr` (an `aria-label` on a role-less
 *     element, which this page's markup used liberally) both land.
 *
 *  5. IT HAD NO REFLOW, NON-TEXT-CONTRAST OR GENERATED-CONTENT ORACLE. axe
 *     has no rule at all for WCAG 1.4.10 or 1.4.11. The old spec did carry
 *     one hand-rolled non-text check — `textInputBorderRatio()`, the border
 *     of ONE `.text-input` against its own fill — which was the right idea
 *     applied to a single control out of the dozens on this page, with the
 *     flat-token arithmetic that cannot survive the top bar's `color-mix()`.
 *     `nontext.ts` generalises it to every control at every driven state, and
 *     `expectNoHorizontalOverflow` adds the reflow half.
 */

/**
 * Wait for every running animation and transition to drain.
 *
 * Two rAFs are not enough. A transition sampled mid-flight has a colour that
 * exists in no state of the page, and axe will happily report it: elsewhere in
 * this fleet that produced a phantom 2.00:1 failure on a button whose settled
 * ratio is 9:1. Transitions also drain in waves rather than in one batch, so a
 * poll for "nothing running right now" can exit through a gap between waves —
 * hence six consecutive quiet frames rather than one.
 *
 * Bounded three ways, because a gate that can hang is a gate nobody runs:
 * animations that never finish (`iterations: Infinity`) are excluded from the
 * quiescence test rather than waited on, a wall-clock budget inside the page
 * gives up and proceeds, and Playwright's own timeout is the backstop.
 *
 * Under the reduced motion this gate asserts, every `@keyframes` animation in
 * `main.css` is cancelled — `fadeSlideIn` and `drawArrow` by the explicit
 * reduced-motion blocks plus `ui.ts` withholding their classes,
 * `stateHighlight` by its own block, and the anatomy `slideFrom*` pair by
 * being declared inside `@media (prefers-reduced-motion: no-preference)` — so
 * what this usually drains is the short `transition:` set (`background`,
 * `border-color`, `color`, `opacity` at 0.15–0.3s) that hover, focus and the
 * live theme switch still fire, none of which the reduced-motion block
 * touches.
 */
export async function settle(page: Page, budgetMs = 4000): Promise<void> {
  await page.waitForFunction(
    (budget: number) => {
      const w = window as unknown as { __quietFrames?: number; __settleStart?: number };
      if (w.__settleStart === undefined) w.__settleStart = performance.now();
      const done = (): boolean => {
        w.__quietFrames = 0;
        w.__settleStart = undefined;
        return true;
      };
      const running = document.getAnimations().filter((a) => {
        if (a.playState !== 'running') return false;
        const timing = a.effect?.getComputedTiming?.();
        // An infinite decorative animation never drains; waiting on it hangs.
        return timing?.iterations !== Infinity;
      });
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      if (w.__quietFrames >= 6) return done();
      if (performance.now() - (w.__settleStart ?? 0) > budget) return done();
      return false;
    },
    budgetMs,
    { timeout: 20_000, polling: 'raf' }
  );
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion block
 * cancels that animation without restoring its end state — the element then
 * renders at `opacity: 0` for every reader with the preference set.
 *
 * This page has two animations whose `from` frame is transparent or nearly so,
 * and each cancels safely for a different reason, which is exactly why the
 * check is a measurement rather than a reading:
 *
 *  - `fadeSlideIn` starts at `opacity: 0`. Its reduced-motion block sets
 *    `animation: none` on `.animate-in` — safe only because the keyframe
 *    animates opacity rather than the element declaring `opacity: 0` and
 *    animating to 1, AND because `ui.ts` also withholds the class under
 *    reduced motion.
 *  - `drawArrow` leaves `stroke-dashoffset: 260` (an invisible arrow) if
 *    merely cancelled; its reduced-motion block explicitly restores the end
 *    state with `stroke-dashoffset: 0`. (Stroke offsets are not opacity, so
 *    THIS check cannot see that one — the drive asserts the diagram's arrow
 *    line exists and the notBlank check covers its `<text>` labels.)
 *
 * The check runs in every state because it is a property of the current
 * stylesheet rather than of any one render.
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue;
      if (el.closest('[aria-hidden="true"]')) continue;
      let effective = 1;
      let node: Element | null = el;
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity);
        node = node.parentElement;
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    return Array.from(new Set(out));
  });
  expect(invisible, `no visible text may render at opacity 0 in state: ${label}`).toEqual([]);
}

/**
 * Uncaught page errors and console errors, collected from the moment the page
 * is created. This lab's handshake runs async off a click: `selectPattern()`
 * paints "Running handshake…" and awaits `runFullHandshake`, and its `catch`
 * paints the error INTO the status line — but a rejection escaping anywhere
 * else (a transport send, an attack simulation, the export click) surfaces
 * only on the console while the page keeps looking plausible. Attach before
 * `boot`, assert after the drive.
 */
export function watchPageErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push(`console.error: ${m.text()}`);
  });
  return errors;
}

/**
 * Exactly one banner landmark.
 *
 * This page ships two `<header>`s: the shared `.cl-topbar` with an explicit
 * `role="banner"`, and the lab's own `.cl-hero`, which sits as a DIRECT CHILD
 * of `<body>` — not inside any sectioning content — so it implies `banner` on
 * its own. The single banner therefore depends entirely on the shared bar's
 * `dedupeBanner()` demoting the hero to `role="group"`, which runs on
 * `DOMContentLoaded`. Asserting the OUTCOME rather than the mechanism is what
 * catches a change to that ordering.
 */
export async function assertSingleBanner(page: Page): Promise<void> {
  const banners = await page.evaluate(() => {
    const scoped = new Set(['MAIN', 'ARTICLE', 'ASIDE', 'NAV', 'SECTION']);
    const isBanner = (el: Element): boolean => {
      if (el.getAttribute('role') === 'banner') return true;
      if (el.tagName !== 'HEADER') return false;
      if (el.getAttribute('role')) return false; // explicit non-banner role wins
      for (let p = el.parentElement; p; p = p.parentElement) if (scoped.has(p.tagName)) return false;
      return true;
    };
    return [...document.querySelectorAll('header,[role="banner"]')].filter(isBanner).length;
  });
  expect(banners, 'exactly one banner landmark').toBe(1);
}

/**
 * An explicit role on a list REPLACES its implicit `list` role, orphaning every
 * `<li>` under it — and a redundant `role="list"` makes axe apply
 * `aria-required-children`, which fails whenever the list is empty. Neither is
 * reliably visible to a source grep, because a role can be assigned as a JS
 * property in an element-creation helper rather than as markup. Ask the DOM.
 *
 * This lab's only real `<ul>`s are the WireGuard panel's "Why IKpsk2?" list
 * and nothing else; its `role="list"` containers (`.step-logs`,
 * `.wg-messages`) are `<div>`s building the role up rather than `<ul>`s
 * tearing it down, and their children carry `role="listitem"`. Never empty
 * today — a property of the content, not the code, which is exactly why the
 * assertion is cheap enough to keep.
 */
export async function assertListSemantics(page: Page): Promise<void> {
  const broken = await page.$$eval('ul[role], ol[role]', (els) =>
    els.map(
      (e) => `${e.tagName.toLowerCase()}[role=${e.getAttribute('role')}] with ${e.children.length} children`
    )
  );
  expect(broken, 'an explicit role on a list deletes its list semantics').toEqual([]);
}

/**
 * Load the page in a known theme with reduced motion actually in effect, and
 * assert the content every scan relies on is really on the page — including
 * the lab's DEFAULTS, which are never assumed.
 *
 * `test.use({ reducedMotion })` silently does nothing on Playwright 1.61.1, so
 * the emulation is applied imperatively BEFORE the navigation and then
 * *asserted* from inside the page. The ordering matters more here than usual:
 * `ui.ts` samples `matchMedia('(prefers-reduced-motion: reduce)')` once, at
 * module scope, so an emulation applied after `goto` would leave the module's
 * copy stale and the gate would scan animated renderings while claiming the
 * reduced-motion ones.
 *
 * The theme is seeded through `localStorage` rather than by clicking the
 * toggle, which pins a real coherence requirement as a side effect: the
 * anti-flash script in `index.html` reads `localStorage.getItem('theme')`, the
 * shared bar's toggle writes `'theme'`, and the lab's own (hidden) toggle in
 * `main.ts` reads and writes the same key. All three agree today; if any
 * drifted, this boot fails on `data-theme` rather than quietly scanning dark
 * twice.
 *
 * The defaults are asserted at length because everything below the static
 * shell is rendered by JS after `DOMContentLoaded`, and the headline content —
 * the handshake walkthrough, the transport keys — exists only after an ASYNC
 * X25519 handshake finishes. A navigation that resolves proves nothing: a
 * render that threw leaves empty containers behind, and an empty container is
 * exactly what a scan reports as perfectly accessible. `goto → scan` on this
 * page would certify a blank demo.
 */
export async function boot(page: Page, theme: 'dark' | 'light'): Promise<void> {
  // A click on a control that never becomes actionable otherwise burns the
  // whole test timeout and reports nothing useful. 20s turns that silent hang
  // into a named failure naming the locator.
  page.setDefaultTimeout(20_000);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.addInitScript((t) => localStorage.setItem('theme', t), theme);
  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect'
  ).toBe(true);
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
  await assertSingleBanner(page);
  await assertListSemantics(page);

  // ── Both skip links point at a target that exists ───────────────────────
  // axe's skip-link rule is best-practice, not WCAG-tagged, so `withTags`
  // never runs it. This page has no `#app` element — the shared bar's link
  // used to target one anyway, a dead anchor that swallowed the very first
  // keyboard action on every load and that nothing had ever tested.
  for (const sel of ['a.cl-skip-link', 'a.skip-link']) {
    const href = await page.locator(sel).getAttribute('href');
    expect(href, `${sel} must have a fragment href`).toMatch(/^#./);
    await expect(
      page.locator(`[id="${href!.slice(1)}"]`),
      `${sel} target ${href} must exist`
    ).toHaveCount(1);
  }

  // ── The lab's own theme toggle is out of the way, AND actually is ───────
  // Belt and braces here: the markup ships it with the `hidden` attribute and
  // the shared bar's CSS `display: none !important`s it by id. Either alone
  // done wrongly (`opacity: 0` + `pointer-events: none`) would leave a
  // tabbable invisible button. Measured by trying to focus it.
  expect(
    await page.evaluate(() => {
      const t = document.getElementById('theme-toggle');
      if (!t) return 'the lab theme toggle is missing entirely';
      t.focus();
      return document.activeElement === t ? 'it took focus while hidden' : 'ok';
    }),
    'the lab own theme toggle must be hidden in a way that also removes it from the tab order'
  ).toBe('ok');

  // ── The async handshake really finished ─────────────────────────────────
  // THE load-bearing wait: `initUI()` selects NN and awaits a real X25519
  // handshake before the walkthrough, transport keys and step logs exist.
  await expect(page.locator('#handshake-status')).toHaveText('Handshake complete', {
    timeout: 30_000,
  });
  await expect(page.locator('#pattern-name')).toHaveText('Noise_NN_25519_AESGCM_SHA256');

  // ── The shell really rendered, in its shipped state ─────────────────────
  await expect(page.locator('main#main-content')).toHaveCount(1);
  await expect(page.locator('[role="tab"]')).toHaveCount(6);
  await expect(page.locator('#tab-pattern')).toHaveAttribute('aria-selected', 'true');
  await expect(page.locator('[role="tabpanel"]:not([hidden])')).toHaveCount(1);
  await expect(page.locator('.guided-path-step')).toHaveCount(4);
  await expect(page.locator('.pattern-chip')).toHaveCount(13);
  await expect(page.locator('#security-properties .security-row')).toHaveCount(3);
  // NN has a "What's new" blurb and no pre-messages: banner shown, card hidden.
  await expect(page.locator('#whats-new-banner')).toBeVisible();
  await expect(page.locator('#premessage-card')).toBeHidden();

  // ── Disclosures in their shipped states ─────────────────────────────────
  // Anatomy ships OPEN; the 13-chip picker and the predict quiz ship SHUT.
  // The gate this replaces forced all three open before its only scan.
  await expect(page.locator('#anatomy-box')).toHaveAttribute('open', '');
  expect(
    await page.locator('#all-patterns-disclosure').evaluate((el) => (el as HTMLDetailsElement).open)
  ).toBe(false);
  expect(
    await page.locator('#predict-box').evaluate((el) => (el as HTMLDetailsElement).open)
  ).toBe(false);

  // ── Transport ships bound to the fresh session, counters at zero ────────
  await expect(page.locator('#i-to-r-nonce')).toHaveText('0');
  await expect(page.locator('#r-to-i-nonce')).toHaveText('0');
  await expect(page.locator('#transport-send-key')).not.toBeEmpty();

  // ── The hidden panels are populated, not just present ───────────────────
  // Comparison and WireGuard render at DOMContentLoaded into hidden
  // tabpanels; an exception in either leaves an empty div a scan cannot
  // distinguish from success once the tab is clicked open at 380px width.
  await expect(page.locator('#comparison-table table')).toHaveCount(1);
  await expect(page.locator('#wireguard-content .wg-section')).not.toHaveCount(0);

  await settle(page);
  await expectNotBlank(page, `${theme} first paint`);
}

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all. This page has
 * form: `main.css` documents that an earlier revision hid wide content with
 * `overflow-x: hidden` on `<body>` — which propagates to the viewport, CLIPS
 * anything wide instead of reflowing it, and makes
 * `scrollWidth === clientWidth` true by construction so any overflow check
 * passes vacuously ("Measured at 380px with it in place: 380 === 380"). That
 * rule is gone; this assertion is what keeps it gone, and what catches the
 * next wide box — the comparison table, the tab strip and the `white-space:
 * pre` pattern listings are the candidates, each in its own `overflow-x:
 * auto` scroller today.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    if (doc.scrollWidth <= doc.clientWidth) return null;

    // Only elements that actually push the DOCUMENT sideways are culprits. A
    // wide box inside an `overflow: auto` wrapper has a huge bounding rect but
    // is clipped by its scroller and contributes nothing to the document's
    // scroll width — naming it sends you off fixing the wrong element. The
    // comparison table inside `.comparison-container` and the tab row inside
    // `.panel-nav` are exactly such decoys at 380px.
    const clipped = (el: Element): boolean => {
      let n = el.parentElement;
      while (n && n !== doc) {
        const ox = getComputedStyle(n).overflowX;
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true;
        n = n.parentElement;
      }
      return false;
    };

    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right);
    const widest = over.filter((x) => !clipped(x.el))[0] ?? over[0];
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest: widest
        ? `${clipped(widest.el) ? '[clipped] ' : ''}${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
          `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
          ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`
        : '(none identified)',
    };
  });
  expect(overflow, `page must not scroll horizontally in state: ${label}`).toBeNull();
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1).
 * If it holds no focusable content it needs `tabindex="0"`, so it becomes a
 * focus target arrow keys can then scroll.
 *
 * This page's scrollers satisfy the rule three different ways, which is why
 * the assertion is on the OUTCOME rather than any mechanism: `.panel-nav` and
 * `.comparison-container` scroll at 380px and hold focusable content (the six
 * tabs; every `.compare-cell` button); `#wire-blocks` holds none and carries
 * `tabindex="0"` + `role="region"` in the markup; and each `.pattern-display`
 * listing holds only text, so whether IT overflows at 380px decides whether it
 * needs the same treatment — the kind of width-dependent requirement that only
 * exists in one of the two viewports this gate runs.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,summary,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY);
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`
      );
  });
  expect(
    Array.from(new Set(unreachable)),
    `scrolling regions with no keyboard route in state: ${label}`
  ).toEqual([]);
}

/**
 * Nothing may be focusable while it paints nothing (WCAG 2.4.3 / 2.4.7).
 *
 * `opacity: 0` with `pointer-events: none` is NOT hiding: the element keeps
 * `tabIndex: 0`, so a keyboard reader tabs to a control that is not on screen
 * and the focus ring lands nowhere. `display: none` and `visibility: hidden`
 * DO remove an element from the tab order, so those are skipped rather than
 * flagged — the failure is specifically the invisible-but-tabbable pair. It
 * is a live risk on this page: the glossary `.gl` spans carry `tabindex="0"`
 * BY DESIGN (focus is what summons the tooltip), so every rendering path that
 * emits them — the security rows, the token legend, the state cards, the
 * premessage rows — mints new tab stops that must all paint.
 *
 * Off-screen-but-focusable is the WCAG-sanctioned skip-link idiom and is
 * deliberately not flagged: both skip links here have full opacity and a real
 * box, and each slides into view on focus. The drive scans both focused.
 */
export async function expectNoInvisibleFocusTargets(page: Page, label: string): Promise<void> {
  const bad = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,summary,[tabindex]:not([tabindex="-1"])';
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll<HTMLElement>(FOCUSABLE))) {
      if (el.tabIndex < 0) continue;
      // display:none / visibility:hidden already remove it from the tab order.
      if (!el.checkVisibility?.({ checkVisibilityCSS: true })) continue;
      let effective = 1;
      for (let n: Element | null = el; n; n = n.parentElement) {
        effective *= parseFloat(getComputedStyle(n).opacity);
      }
      const r = el.getBoundingClientRect();
      if (effective !== 0 && r.width > 0 && r.height > 0) continue;
      // Confirm it really is reachable rather than inferring it.
      const before = document.activeElement;
      el.focus();
      const took = document.activeElement === el;
      (before as HTMLElement | null)?.focus?.();
      if (took) {
        out.push(
          `${el.tagName.toLowerCase()}${el.id ? '#' + el.id : ''}.${(el.getAttribute('class') ?? '').trim()}` +
            ` (opacity ${effective}, ${Math.round(r.width)}x${Math.round(r.height)})`
        );
      }
    }
    return Array.from(new Set(out));
  });
  expect(bad, `focusable elements that paint nothing in state: ${label}`).toEqual([]);
}

/**
 * When `A11Y_COLLECT` is set, `scan` records failures instead of throwing.
 *
 * A strict gate reports the first failing assertion in the first failing state
 * and stops, so a page with defects in several states needs one full run per
 * defect to enumerate them. The collection pass turns that into a single run.
 * It is a debugging aid only: `A11Y_COLLECT` is never set in CI, and a run
 * with it set prints every finding as it happens and then fails at the end, so
 * a green collection run cannot be mistaken for a green gate.
 */
const COLLECTING = !!process.env.A11Y_COLLECT;
const collected: string[] = [];

function record(entry: string): void {
  collected.push(entry);
  // Printed as it happens, not only at the end: a hard assertion later in the
  // drive would otherwise abort the test before anything collected so far was
  // ever shown.
  console.log(`\n[A11Y_COLLECT #${collected.length}] ${entry}`);
}

export function softExpect(actual: unknown, message: string, expected: unknown): void {
  if (!COLLECTING) {
    expect(actual, message).toEqual(expected);
    return;
  }
  try {
    expect(actual, message).toEqual(expected);
  } catch {
    record(`${message}\n  ${JSON.stringify(actual, null, 2)}`);
  }
}

/**
 * Fail the test if the collection pass recorded anything. Without this a
 * collection run would end green, and a green collection run is
 * indistinguishable from a green gate — which is the exact confusion the whole
 * exercise exists to remove.
 */
export function reportCollected(): void {
  if (!COLLECTING) return;
  expect(collected, `A11Y_COLLECT recorded ${collected.length} failure(s)`).toEqual([]);
}

async function soft(fn: () => Promise<void>): Promise<void> {
  if (!COLLECTING) return fn();
  try {
    await fn();
  } catch (e) {
    // Generous, not 900: a truncated oracle dump is how a second and third
    // finding in the same state get missed on a collection pass.
    record(String(e).slice(0, 6000));
  }
}

/**
 * WCAG 1.4.11 and generated content, ratcheted against a per-repo baseline.
 *
 * Neither class has ANY other oracle: axe has no rule for non-text contrast,
 * and the arithmetic text walk cannot reach a control's boundary, because a
 * boundary owns no text node.
 *
 * IT IS CALLED FROM `scan()`, deliberately and not by accident. Fleet-wide
 * this oracle had once been called from inside a soft wrapper AFTER its
 * `if (!COLLECTING) return` guard — so in a strict run, which is every run in
 * CI and every run anyone reads as a pass, the guard returned first and
 * `nontext.ts` never executed at all. Thirteen repos certified themselves
 * clean on an oracle that had never looked. Calling it here means it runs at
 * every driven state, including `:hover`.
 *
 * A check that merely logs is not a gate, so it ratchets: anything NOT in the
 * baseline fails, anything in the baseline that got WORSE fails, and anything
 * in the baseline that has been FIXED fails until its entry is deleted. That
 * last rule is what stops the allowlist becoming a permanent exemption.
 */
const nonTextSeen = new Set<string>();

export async function expectNoNewNonTextFailures(page: Page, label: string): Promise<void> {
  const found = await auditNonText(page);
  // Capture mode: emit every finding and assert nothing, so a baseline can be
  // generated by the SAME path that checks it.
  if (process.env.NT_BASELINE_CAPTURE) {
    for (const f of found) {
      console.log(`NTCAP|${f.kind}|${f.selector}|${f.ratio}|${f.required}|${/POSITIONED/.test(f.detail)}`);
    }
    return;
  }
  const problems: string[] = [];
  for (const f of found) {
    const key = `${f.kind}|${f.selector}`;
    nonTextSeen.add(key);
    const base = NONTEXT_BASELINE[key];
    if (!base) {
      problems.push(`NEW ${f.ratio}:1 (needs ${f.required}:1) [${f.kind}] ${f.selector} — ${f.detail}`);
    } else if (f.ratio < base.ratio - 0.01) {
      problems.push(`WORSE ${f.selector}: ${f.ratio}:1, baseline recorded ${base.ratio}:1`);
    }
  }
  expect(problems, `new or worsened non-text contrast in state: ${label}`).toEqual([]);
}

/**
 * Fail if a baselined finding never appeared during the whole drive.
 *
 * It has either been fixed — in which case delete the entry, which is the
 * point — or the drive stopped reaching the state that shows it, which is a
 * coverage regression worth knowing about. Call once, after `driveAllStates`.
 */
export function expectBaselineNotStale(): void {
  const unseen = Object.keys(NONTEXT_BASELINE).filter((k) => !nonTextSeen.has(k));
  expect(
    unseen,
    'baselined non-text findings that no longer appear — delete them from nontext-baseline.ts (or restore the drive state that showed them)'
  ).toEqual([]);
}

/**
 * Scan the page as it currently stands.
 *
 * Eight assertions, because axe's `violations` array alone is not a complete
 * oracle:
 *
 *  - reduced-motion end state — see `expectNotBlank`.
 *  - `violations` — the usual WCAG A/AA rule failures, plus four landmark
 *    best-practice rules `withTags` does not run on its own.
 *  - `incomplete` — axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain incomplete is
 *    `color-contrast`, and only because the next assertion computes those
 *    ratios arithmetically — on this page that is the shared top bar's
 *    `color-mix()` ink and borders, which axe refuses to resolve. Everything
 *    else in that bucket is a real result axe simply could not finish —
 *    including `aria-prohibited-attr`, which is where an `aria-label` on a
 *    role-less element hides and never reaches the violations array at all.
 *    This page leaned hard on that pattern before this gate: bare `<div>`s,
 *    `<span>`s, `<pre>`s and even `<p>`s carried `aria-label`s that every
 *    assistive technology silently discarded. They now pair a role with the
 *    label or drop it; this assertion is what keeps it that way.
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node.
 *  - non-text contrast and generated content — SC 1.4.11, ratcheted; see
 *    `expectNoNewNonTextFailures`. The only oracle that judges a control's
 *    boundary against the surface OUTSIDE it — on a page of two dozen
 *    same-token controls, the whole ballgame.
 *  - keyboard reachability of scrolling regions — WCAG 2.1.1.
 *  - no focusable element that paints nothing — WCAG 2.4.3/2.4.7.
 *  - reflow — WCAG 1.4.10, which axe has no rule for at all.
 */
export async function scan(page: Page, label: string): Promise<void> {
  await settle(page);
  await expectNotBlank(page, label);
  // TWO axe runs, deliberately, and this is not a style choice.
  //
  // `AxeBuilder.withTags()` and `AxeBuilder.withRules()` both write the same
  // `options.runOnly` field, so the second call SILENTLY REPLACES the first —
  // the axe-core/playwright source says so in as many words on `withRules`
  // ("Cannot be used with AxeBuilder#withTags"). Chained as
  // `.withTags(TAGS).withRules([...4 landmark rules])`, axe runs those FOUR
  // best-practice rules and NOT ONE WCAG RULE, while a green result reads
  // exactly like a full A/AA pass. For scale, `withTags(TAGS)` selects 69 of
  // axe-core 4.12's 105 rule definitions; the chained form executes 4.
  //
  // The landmark four are still wanted because they are best-practice rather
  // than WCAG-tagged, so `withTags` alone does not reach them — and this page
  // has the shape they catch: a sticky `role="banner"` top bar above a
  // `<header class="cl-hero">` that holds an `<aside>`, two `<nav>`s, six
  // tabpanel `<section>`s and a labelled cross-links `<section>`, with a
  // `<footer>` behind them.
  const wcag = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const landmarks = await new AxeBuilder({ page })
    .withRules([
      'landmark-no-duplicate-banner',
      'landmark-unique',
      'landmark-one-main',
      'landmark-complementary-is-top-level',
    ])
    .analyze();
  const results = {
    violations: [...wcag.violations, ...landmarks.violations],
    incomplete: [...wcag.incomplete, ...landmarks.incomplete],
  };

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  softExpect(violations, `axe violations in state: ${label}`, []);

  // The `incomplete` bucket is asserted, not skimmed. `aria-prohibited-attr`
  // and `aria-required-children` appear ONLY here — never in `violations` — so
  // a gate that ignores this bucket cannot see either. Only `color-contrast`
  // is allowed to remain, and only because the arithmetic walk below judges
  // those ratios for real; no other rule is filtered out.
  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }));
  softExpect(unexplainedIncomplete, `axe incomplete results in state: ${label}`, []);

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  softExpect(contrast, `measured contrast failures in state: ${label}`, []);

  await soft(() => expectNoNewNonTextFailures(page, label));
  await soft(() => expectScrollersReachable(page, label));
  await soft(() => expectNoInvisibleFocusTargets(page, label));
  await soft(() => expectNoHorizontalOverflow(page, label));
}

// ── The drive ───────────────────────────────────────────────────────────────

/** Click a tab and wait for its panel to actually swap in. */
async function openTab(page: Page, tabId: string, panelId: string): Promise<void> {
  await page.locator(`#${tabId}`).click();
  await expect(page.locator(`#${tabId}`)).toHaveAttribute('aria-selected', 'true');
  await expect(page.locator(`#${panelId}`)).toBeVisible();
  await expect(page.locator('[role="tabpanel"]:not([hidden])')).toHaveCount(1);
}

/**
 * Select a pattern by its chip and wait for ITS handshake, not a leftover one.
 *
 * `selectPattern()` in `ui.ts` sets the status line to "Running handshake…"
 * synchronously and back to "Handshake complete" only when the awaited
 * handshake lands (its generation counter discards stale runs). Waiting on the
 * pattern NAME first and the status SECOND is what makes this race-free: the
 * name is painted synchronously with the new selection, so once it reads the
 * new protocol string, a "Handshake complete" can only be the new pattern's.
 */
async function selectPatternChip(page: Page, name: string): Promise<void> {
  const disclosure = page.locator('#all-patterns-disclosure');
  if (!(await disclosure.evaluate((el) => (el as HTMLDetailsElement).open))) {
    await disclosure.locator('summary').click();
  }
  await page.locator('.pattern-chip', { hasText: new RegExp(`^${name}$`) }).click();
  await expect(page.locator('#pattern-name')).toHaveText(`Noise_${name}_25519_AESGCM_SHA256`);
  await expect(page.locator('#handshake-status')).toHaveText('Handshake complete', {
    timeout: 30_000,
  });
}

/** Run one Break-it attack and wait for its verdict badge to render. */
async function runAttack(page: Page, attack: string, badgeClass: string): Promise<void> {
  await page.locator(`.breakit-btn[data-attack="${attack}"]`).click();
  await expect(
    page.locator(`[data-result="${attack}"] .${badgeClass}`),
    `${attack} must render its ${badgeClass} verdict badge`
  ).toBeVisible({ timeout: 60_000 });
}

/**
 * Drive the lab through the states that render content, scanning each.
 *
 * What shapes this drive:
 *
 *  - THE ARRIVAL STATE IS SCANNED FIRST, exactly as shipped: NN selected, the
 *    Pattern panel open, the 13-chip picker and predict quiz shut, the
 *    anatomy open. The gate this replaces force-opened everything before its
 *    only scan, so the state every reader actually arrives in was never
 *    measured.
 *
 *  - EVERY TAB PANEL IS A SEPARATE PAGE to a scan, because the other five are
 *    `display: none` at any moment. Walkthrough, Transport, Break it,
 *    Compare and WireGuard are each opened through their real tab and
 *    scanned in their driven states.
 *
 *  - IK RATHER THAN NN FOR THE DEEP STATES. NN's two messages carry only
 *    `e`/`ee`, so scanning it exercises neither the encrypted-static wire
 *    block (the 🔒 ENCRYPTED rendering `renderWireBlocks` exists to show),
 *    nor a pre-message card, nor an rs-swap that succeeds. IK reaches all
 *    three, and its Break-it grid renders three different badge kinds from
 *    real simulations: held (bitflip), succeeded (rs-swap — IK trusts the
 *    pre-known key), n/a (psk mismatch — IK has no psk).
 *
 *  - ERROR STATES ARE STATES. The transport lane's "Enter a plaintext to
 *    encrypt" assertive error and the post-rekey advisory both paint text
 *    nothing else renders; both are scanned.
 *
 *  - HOVER IS A STATE, AND IT PERSISTS AFTER A CLICK. `:hover` stays wherever
 *    the pointer last was, so it is the state a reader occupies the instant
 *    after pressing any button — and `.cl-btn:hover` repaints its fill with a
 *    `color-mix()` axe cannot judge. Scanned explicitly.
 *
 *  - THE GLOSSARY TOOLTIP IS SUMMONED BY FOCUS, which is its keyboard route
 *    (`tabindex="0"` on every `.gl` term) and the only way its floating box
 *    ever paints. Scanned open.
 *
 *  - NO FIXED TIMEOUTS. Every wait is on a real DOM completion signal: the
 *    status line's finished wording, a badge appearing, a counter's text, a
 *    panel's hidden attribute.
 */
export async function driveAllStates(page: Page, theme: string): Promise<void> {
  const scanAt = (s: string): Promise<void> => scan(page, `${theme} / ${s}`);

  await scanAt('arrival: NN selected, picker and predict shut, anatomy open');

  // ── The two skip links, focused ─────────────────────────────────────────
  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur?.());
  await page.keyboard.press('Tab');
  await expect(page.locator('a.cl-skip-link')).toBeFocused();
  await scanAt('shared skip link focused, slid into view');

  await page.locator('a.skip-link').focus();
  await expect(page.locator('a.skip-link')).toBeFocused();
  await scanAt('the lab own skip link focused, slid down from top:-100%');

  // ── The glossary tooltip, summoned by keyboard ──────────────────────────
  const glossaryTerm = page.locator('#security-properties .gl').first();
  await glossaryTerm.focus();
  await expect(page.locator('#glossary-tip')).toBeVisible();
  await expect(page.locator('#glossary-tip')).not.toBeEmpty();
  await scanAt('glossary tooltip open on a focused term');
  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur?.());
  await expect(page.locator('#glossary-tip')).toBeHidden();

  // ── The 13-pattern picker, opened the way a reader opens it ─────────────
  await page.locator('#all-patterns-disclosure summary').click();
  await expect(page.locator('#all-patterns-disclosure')).toHaveAttribute('open', '');
  await expect(page.locator('.pattern-chip')).toHaveCount(13);
  await scanAt('pattern picker open, 13 chips in their radiogroup');

  // ── IK: pre-message card, encrypted-static wire block, rs-swap risk ─────
  await selectPatternChip(page, 'IK');
  // The card lives in the (still hidden) walkthrough panel; here only its
  // own `hidden` flag can be asserted. Its visibility is asserted after the
  // tab opens below.
  expect(
    await page.locator('#premessage-card').evaluate((el) => (el as HTMLElement).hidden)
  ).toBe(false);
  await expect(page.locator('.pattern-chip', { hasText: /^IK$/ })).toHaveAttribute(
    'aria-checked',
    'true'
  );
  await scanAt('IK selected: pre-message card armed, chip checked, guided path un-highlighted');

  // ── Walkthrough, message 1 of IK ────────────────────────────────────────
  await openTab(page, 'tab-walkthrough', 'panel-walkthrough');
  await expect(page.locator('#premessage-card')).toBeVisible();
  await expect(page.locator('#step-counter')).toHaveText('Message 1 of 2');
  // IK message 1 (e, es, s, ss): the static key block must render ENCRYPTED —
  // the identity-hiding half of what renderWireBlocks() exists to teach.
  await expect(page.locator('#wire-blocks .blk-s-enc')).toHaveCount(1);
  await expect(page.locator('#message-diagram svg')).toHaveCount(1);
  await expect(page.locator('#step-info .log-entry')).not.toHaveCount(0);
  await scanAt('IK walkthrough message 1: DH visuals, encrypted static wire block, party states');

  // ── The anatomy exhibit, driven through both controls ───────────────────
  await page.locator('.anatomy-token-btn[data-token="es"]').click();
  await expect(page.locator('.anatomy-token-btn[data-token="es"]')).toHaveAttribute(
    'aria-pressed',
    'true'
  );
  await page.locator('.role-btn[data-role="responder"]').click();
  await expect(page.locator('.role-btn[data-role="responder"]')).toHaveAttribute(
    'aria-checked',
    'true'
  );
  // es viewed by the responder is DH(my static, their ephemeral) — asserting
  // the narration proves the exhibit repainted, not merely the buttons.
  await expect(page.locator('#anatomy-explain')).toContainText('my static × their ephemeral');
  await scanAt('anatomy: es token viewed as responder, both toggles active');

  // ── The predict quiz: wrong answer first, then the reveal tints ─────────
  await page.locator('#predict-box summary').click();
  await expect(page.locator('#predict-box')).toHaveAttribute('open', '');
  await page.locator('.predict-choice[data-choice="none"]').click();
  // IK message 1 fires es+ss, so "none" is wrong: the wrong pick and the
  // correct answer are both tinted, and the answer paragraph paints its
  // "Not quite" branch.
  await expect(page.locator('.predict-choice.choice-wrong')).toHaveCount(1);
  await expect(page.locator('.predict-choice.choice-correct')).toHaveCount(1);
  await expect(page.locator('#predict-answer')).toHaveClass(/answer-wrong/);
  await scanAt('predict quiz answered wrongly: both tints and the answer panel');

  // ── Step to message 2; the walkthrough repaints wholesale ───────────────
  await page.locator('#step-next').click();
  await expect(page.locator('#step-counter')).toHaveText('Message 2 of 2');
  await expect(page.locator('#step-next')).toBeDisabled();
  // Message 2 (e, ee, se) closes the handshake: the Split shows and the
  // predict quiz has reset to its unanswered state.
  await expect(page.locator('#step-info')).toContainText('Split');
  await expect(page.locator('.predict-choice.choice-wrong')).toHaveCount(0);
  await scanAt('IK walkthrough message 2: Split logs, quiz reset, Next disabled');

  // ── Transport: both lanes, the error branch, and a rekey ────────────────
  await openTab(page, 'tab-transport', 'panel-transport');
  await scanAt('transport panel as bound to the fresh IK session, lanes empty');

  // The error branch: Send with nothing typed paints the assertive error.
  await page.locator('#send-i-to-r').click();
  await expect(page.locator('#transport-error')).toHaveText('Enter a plaintext to encrypt');
  await scanAt('transport error state: empty-plaintext rejection');

  await page.locator('#msg-i-to-r').fill('attack at dawn');
  await page.locator('#send-i-to-r').click();
  await expect(page.locator('#pt-i-to-r')).toHaveText('attack at dawn');
  await expect(page.locator('#ct-i-to-r')).not.toBeEmpty();
  await expect(page.locator('#i-to-r-nonce')).toHaveText('1');
  await scanAt('transport i→r sent: ciphertext hex, round-tripped plaintext, counter at 1');

  await page.locator('#rekey-i-btn').click();
  await expect(page.locator('#transport-error')).toContainText('c₁ rekeyed');
  // The readouts were produced under the old k; the panel retires them.
  await expect(page.locator('#ct-i-to-r')).toBeEmpty();
  await scanAt('transport after rekey: advisory painted, stale lane readouts cleared');

  await page.locator('#msg-r-to-i').fill('roger that');
  await page.locator('#send-r-to-i').click();
  await expect(page.locator('#pt-r-to-i')).toHaveText('roger that');
  await expect(page.locator('#r-to-i-nonce')).toHaveText('1');

  // ── Break it: three badge kinds from three real simulations ─────────────
  await openTab(page, 'tab-breakit', 'panel-breakit');
  await scanAt('break-it panel idle, six attack cards unrun');

  await runAttack(page, 'bitflip', 'badge-ok');
  await runAttack(page, 'rsswap', 'badge-fail'); // IK trusts the pre-known rs
  await scanAt('break-it: AEAD held (green) and rs-swap succeeded (warning) side by side');

  await runAttack(page, 'pskmismatch', 'badge-na'); // IK has no psk
  await runAttack(page, 'noncereuse', 'badge-fail');
  await expect(page.locator('[data-result="noncereuse"] .detail-row')).not.toHaveCount(0);
  await scanAt('break-it: n/a badge and the nonce-reuse XOR detail rows');

  // ── Compare: the table, a live chip toggle, and the explainer ───────────
  await openTab(page, 'tab-comparison', 'panel-comparison');
  await expect(page.locator('.comparison-table tbody tr')).toHaveCount(4);
  await scanAt('comparison table with the four default patterns');

  await page.locator('.compare-chip', { hasText: /^NK$/ }).click();
  await expect(page.locator('.comparison-table tbody tr')).toHaveCount(5);
  await page
    .locator('.compare-cell[data-pattern="IK"][data-prop="identityHiding"]')
    .click();
  await expect(page.locator('#comparison-explainer')).toBeVisible();
  await expect(page.locator('#comparison-explainer h4')).toContainText('IK');
  await scanAt('comparison: NK added live, IK identity-hiding explainer open, cell still hovered');

  // ── WireGuard deep dive ─────────────────────────────────────────────────
  await openTab(page, 'tab-wireguard', 'panel-wireguard');
  await expect(page.locator('.packet-diagram')).toHaveCount(2);
  await expect(page.locator('.packet-block')).not.toHaveCount(0);
  await scanAt('WireGuard panel: both packet diagrams and the token legend');

  // ── Hover and focus-visible states ──────────────────────────────────────
  await page.locator('.cl-btn').first().hover();
  await scanAt('shared top bar button hovered — its color-mix hover fill');

  await page.locator('#tab-transport').hover();
  await scanAt('an inactive tab hovered');

  await openTab(page, 'tab-transport', 'panel-transport');
  await page.locator('#msg-i-to-r').focus();
  await expect(page.locator('#msg-i-to-r')).toBeFocused();
  await scanAt('a text input focused, showing its focus ring and box-shadow');

  await page.locator('#send-i-to-r').focus();
  await scanAt('a primary button focused, showing its focus-visible outline');

  // ── Keyboard shortcuts are a real route; prove one end-to-end ───────────
  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur?.());
  await page.keyboard.press('5');
  await expect(page.locator('#tab-comparison')).toHaveAttribute('aria-selected', 'true');
  await expect(page.locator('#panel-comparison')).toBeVisible();

  // ── The theme switched IN PLACE, without a reload ───────────────────────
  // Every other configuration seeds the theme through localStorage before
  // `goto`, so this is the only state where the page repaints live — with an
  // IK session, sent transport lanes and run attacks all already on it.
  const other = theme.startsWith('dark') ? 'light' : 'dark';
  await page.click('#cl-theme-toggle');
  await expect(page.locator('html')).toHaveAttribute('data-theme', other);
  await scan(page, `${theme} / switched live to ${other} with the whole session driven`);
}
