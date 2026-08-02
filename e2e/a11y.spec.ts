import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * WCAG regression gate. Deploys are already gated on functional correctness;
 * this gates them on accessibility the same way. Scans the full page with
 * every <details> and class-toggled panel expanded, in both themes.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

async function revealAll(page: Page): Promise<void> {
  await page.addStyleTag({
    content: `*, *::before, *::after {
      animation: none !important;
      transition: none !important;
    }`,
  });
  await page.evaluate(() => {
    // Expand every native disclosure.
    for (const details of Array.from(document.querySelectorAll('details'))) {
      (details as HTMLDetailsElement).open = true;
    }
    // Reveal class/attribute-hidden panels, tabs, accordions, modals.
    for (const el of Array.from(document.querySelectorAll<HTMLElement>('*'))) {
      if (el.hasAttribute('hidden')) el.removeAttribute('hidden');
      if (el.getAttribute('aria-hidden') === 'true') el.removeAttribute('aria-hidden');
      const style = getComputedStyle(el);
      if (style.display === 'none') el.style.setProperty('display', 'block', 'important');
      if (style.visibility === 'hidden') el.style.setProperty('visibility', 'visible', 'important');
      if (parseFloat(style.opacity) < 1) el.style.setProperty('opacity', '1', 'important');
    }
  });
  // Do not un-hide the shared site header's intentionally-hidden skip link
  // duplicate; the above only affects author-visible content once opened.
  await page.waitForTimeout(50);
}

async function scan(page: Page): Promise<void> {
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const summary = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
  }));
  expect(summary).toEqual([]);
}

async function textInputBorderRatio(page: Page): Promise<number> {
  return page.locator('.text-input').first().evaluate((el) => {
    const rgb = (value: string) => value.match(/[\d.]+/g)!.slice(0, 3).map(Number);
    const luminance = (parts: number[]) => {
      const c = parts.map((part) => {
        const value = part / 255;
        return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
      });
      return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2];
    };
    const style = getComputedStyle(el);
    const border = luminance(rgb(style.borderTopColor));
    const fill = luminance(rgb(style.backgroundColor));
    return (Math.max(border, fill) + 0.05) / (Math.min(border, fill) + 0.05);
  });
}

test('no WCAG A/AA violations in dark theme', async ({ page }) => {
  await page.goto('.');
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await revealAll(page);
  expect(await textInputBorderRatio(page)).toBeGreaterThanOrEqual(3);
  await scan(page);
});

test('no WCAG A/AA violations in light theme', async ({ page }) => {
  await page.goto('.');
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await revealAll(page);
  expect(await textInputBorderRatio(page)).toBeGreaterThanOrEqual(3);
  await scan(page);
});
