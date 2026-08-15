import { expect, test } from '@playwright/test';
import {
  boot,
  driveAllStates,
  expectBaselineNotStale,
  NARROW,
  reportCollected,
  watchPageErrors,
} from './gate';

/**
 * WCAG A/AA regression gate.
 *
 * The lab is driven along everything it teaches: the arrival state, NN
 * selected with the pattern picker and predict quiz shut and the anatomy
 * exhibit open; both skip links focused; the glossary tooltip summoned by
 * keyboard; the picker opened and IK selected, which is the pattern that
 * renders a pre-message card and an ENCRYPTED static wire block; the
 * walkthrough stepped through both IK messages with the anatomy toggled to
 * es-as-responder and the predict quiz answered wrongly on purpose; the
 * transport lanes driven through a send, the empty-plaintext error branch, a
 * rekey with its stale-readout clearing, and the reverse lane; the Break-it
 * grid through three verdict kinds — held, succeeded, not-applicable — from
 * real simulations plus the nonce-reuse XOR details; the comparison table
 * with a pattern added live and a property explainer opened; the WireGuard
 * packet diagrams; hover on the shared bar's color-mix fill and an inactive
 * tab; focus rings on an input and a button; the number-key tab shortcut; and
 * finally the theme switched live with the whole session still on screen.
 * Every one of those states is scanned, in both themes, at desktop and phone
 * width.
 *
 * See `gate.ts` for why nothing is injected into the page (`ui.ts` branches
 * on a module-scope `matchMedia` read that a style tag cannot reach, so the
 * old gate never once scanned the reduced-motion rendering), why nothing is
 * force-revealed from script (the old `revealAll()` scanned a
 * six-panels-at-once page the tab machinery can never produce), and why
 * `violations` is not the whole oracle.
 */

for (const theme of ['dark'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page }) => {
    test.setTimeout(1_800_000);
    const errors = watchPageErrors(page);
    await boot(page, theme);
    await driveAllStates(page, theme);
    expect(errors, errors.join('\n')).toEqual([]);
    expectBaselineNotStale();
    reportCollected();
  });

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page }) => {
    test.setTimeout(1_800_000);
    const errors = watchPageErrors(page);
    await page.setViewportSize(NARROW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @380px`);
    expect(errors, errors.join('\n')).toEqual([]);
    expectBaselineNotStale();
    reportCollected();
  });
}
