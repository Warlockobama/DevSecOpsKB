/**
 * Confluence rendering assertions for zap-kb exported pages.
 *
 * Tests are grouped by page type. Each group navigates to the relevant
 * Confluence page and asserts DOM structure — not just that content exists,
 * but that Confluence rendered the storage XML into the expected interactive
 * elements (lozenges, task lists, expand macros, code blocks, etc.).
 *
 * @sme tagged tests take full-page screenshots for SME review.
 */

import { test, expect } from '@playwright/test';
import { gotoPage, getPropertyValue, pagePropertiesRows, screenshotPage } from './helpers';

// ─── Definition Page ─────────────────────────────────────────────────────────

test.describe('Definition page', () => {
  test.beforeEach(async ({ page }) => {
    await gotoPage(page, 'Content Security Policy (CSP) Header Not Set');
  });

  test('@sme screenshot', async ({ page }) => {
    await screenshotPage(page, 'definition-page');
  });

  test('CWE link is a clickable anchor with correct href', async ({ page }) => {
    const cweLink = page.locator('a[href*="cwe.mitre.org/data/definitions/693"]');
    await expect(cweLink).toBeVisible();
    await expect(cweLink).toHaveText(/CWE-693/);
  });

  test('OWASP Top 10 reference is present', async ({ page }) => {
    await expect(page.locator('text=A05:2021')).toBeVisible();
  });

  test('remediation references are rendered as links', async ({ page }) => {
    const mdnLink = page.locator('a[href*="developer.mozilla.org"]');
    await expect(mdnLink).toBeVisible();
  });
});

// ─── Finding Page ─────────────────────────────────────────────────────────────

test.describe('Finding page', () => {
  test.beforeEach(async ({ page }) => {
    // Title matches findingPageTitle() output format
    await gotoPage(page, 'Content Security Policy (CSP) Header Not Set — /login — e2eaabb');
  });

  test('@sme screenshot', async ({ page }) => {
    await screenshotPage(page, 'finding-page');
  });

  test('Page Properties macro renders as a table', async ({ page }) => {
    const rows = pagePropertiesRows(page);
    await expect(rows).not.toHaveCount(0);
  });

  test('Risk row contains a status lozenge (not plain text)', async ({ page }) => {
    // Confluence Cloud renders status macros as span elements with data-macro-name="status"
    const lozenge = page.locator('[data-macro-name="status"]').first();
    await expect(lozenge).toBeVisible();
    // Verify it has colour — Confluence adds a class or inline style for colour
    const colour = await lozenge.getAttribute('data-macro-parameters');
    expect(colour).toBeTruthy();
  });

  test('Source Tool row is present', async ({ page }) => {
    const value = await getPropertyValue(page, 'Source Tool');
    expect(value.trim()).toBe('OWASP ZAP');
  });

  test('CWE row links to MITRE', async ({ page }) => {
    const cweLink = page.locator('[data-macro-name="details"] a[href*="cwe.mitre.org"]');
    await expect(cweLink).toBeVisible();
  });

  test('First Seen row is present', async ({ page }) => {
    const value = await getPropertyValue(page, 'First Seen');
    expect(value.trim()).not.toBe('');
  });

  test('Most recent occurrence traffic section is present', async ({ page }) => {
    const heading = page.locator('h2:has-text("Most recent occurrence traffic")');
    await expect(heading).toBeVisible();
  });
});

// ─── Occurrence Page (open status) ───────────────────────────────────────────

test.describe('Occurrence page — open', () => {
  test.beforeEach(async ({ page }) => {
    await gotoPage(page, 'Content Security Policy (CSP) Header Not Set — /login — e2e1122');
  });

  test('@sme screenshot', async ({ page }) => {
    await screenshotPage(page, 'occurrence-open');
  });

  test('Page Properties table renders', async ({ page }) => {
    const rows = pagePropertiesRows(page);
    await expect(rows).not.toHaveCount(0);
  });

  test('Status row shows a lozenge not plain text', async ({ page }) => {
    const lozenge = page.locator('[data-macro-name="details"] [data-macro-name="status"]');
    await expect(lozenge).toBeVisible();
  });

  test('Source Tool row present', async ({ page }) => {
    const value = await getPropertyValue(page, 'Source Tool');
    expect(value.trim()).toBe('OWASP ZAP');
  });

  test('Evidence section heading is present', async ({ page }) => {
    await expect(page.locator('h2:has-text("Evidence")')).toBeVisible();
  });

  test('Repro curl section is present and contains a code block', async ({ page }) => {
    await expect(page.locator('h2:has-text("Repro")')).toBeVisible();
    // Confluence renders fenced code blocks as a div with data-macro-name="code"
    const codeBlock = page.locator('[data-macro-name="code"]').first();
    await expect(codeBlock).toBeVisible();
    await expect(codeBlock).toContainText('curl');
  });

  test('Reproduction steps render as an ordered list (not plain text)', async ({ page }) => {
    // Steps should be <ol><li> not a paragraph
    const steps = page.locator('h3:has-text("Reproduction steps") + ol li');
    await expect(steps).toHaveCount(3);
  });

  test('Traffic section expand macro is interactive', async ({ page }) => {
    const expandMacro = page.locator('[data-macro-name="expand"]');
    await expect(expandMacro).toBeVisible();
    // Click to expand and verify content appears
    await expandMacro.locator('button, .expand-control, [role="button"]').first().click();
    await expect(page.locator('text=Show traffic')).toBeVisible();
  });

  test('TASK LIST — checkboxes are interactive ac:task elements (not unicode ☐)', async ({ page }) => {
    // This test is EXPECTED TO FAIL until storage.go is fixed to emit <ac:task-list>
    // Current implementation emits ☐ unicode character as plain text in <li>
    // Confluence Cloud renders ac:task-list as checkbox inputs
    const taskCheckbox = page.locator('input[type="checkbox"], [data-testid="task-item-checkbox"]');
    // If this fails, the storage converter is emitting ☐ instead of <ac:task-list>
    await expect(taskCheckbox).toBeVisible({ timeout: 5_000 });
  });
});

// ─── Occurrence Page (accept-risk status) ─────────────────────────────────────

test.describe('Occurrence page — accept-risk', () => {
  test.beforeEach(async ({ page }) => {
    await gotoPage(page, 'Content Security Policy (CSP) Header Not Set — /api/v1/products — e2e5566');
  });

  test('@sme screenshot', async ({ page }) => {
    await screenshotPage(page, 'occurrence-accept-risk');
  });

  test('Status lozenge shows ACCEPT-RISK', async ({ page }) => {
    const lozenge = page.locator('[data-macro-name="details"] [data-macro-name="status"]');
    await expect(lozenge).toContainText(/accept.risk/i);
  });

  test('Accepted Reason row present (not "Notes")', async ({ page }) => {
    const value = await getPropertyValue(page, 'Accepted Reason');
    expect(value.trim()).toContain('trusted internal clients');
    // "Notes" row should NOT appear — it is renamed to "Accepted Reason"
    const rows = pagePropertiesRows(page);
    const count = await rows.count();
    for (let i = 0; i < count; i++) {
      const th = await rows.nth(i).locator('th').textContent();
      expect(th?.trim()).not.toBe('Notes');
    }
  });
});
