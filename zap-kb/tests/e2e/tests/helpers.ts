import * as fs from 'fs';
import * as path from 'path';
import { Page } from '@playwright/test';

const PAGE_IDS_FILE = path.resolve(__dirname, '../.page-ids.json');

/**
 * Load the page URL map written by globalSetup.
 * Keys are Confluence page titles; values are full page URLs.
 */
export function loadPageIds(): Record<string, string> {
  if (!fs.existsSync(PAGE_IDS_FILE)) {
    throw new Error(
      `Page IDs file not found at ${PAGE_IDS_FILE}. Run export-fixtures first.`
    );
  }
  return JSON.parse(fs.readFileSync(PAGE_IDS_FILE, 'utf8'));
}

/**
 * Navigate to a Confluence page by title and wait for the page body to load.
 * Throws if the title is not in the page ID map.
 */
export async function gotoPage(page: Page, title: string): Promise<void> {
  const ids = loadPageIds();
  const url = ids[title];
  if (!url) {
    throw new Error(
      `No URL found for page title "${title}". Available: ${Object.keys(ids).join(', ')}`
    );
  }
  await page.goto(url);
  // Wait for Confluence page content to render (Cloud uses dynamic loading)
  await page.waitForSelector('[data-testid="confluence-frontend-page-content"], .ia-splitter-main', {
    timeout: 30_000,
  });
}

/**
 * Find the Page Properties macro table on the current page.
 * Returns a locator for the table body rows.
 */
export function pagePropertiesRows(page: Page) {
  // Confluence Cloud renders the details macro as a table inside
  // a div with data-macro-name="details"
  return page.locator('[data-macro-name="details"] table tbody tr');
}

/**
 * Get the text value of a named row in the Page Properties table.
 */
export async function getPropertyValue(page: Page, rowLabel: string): Promise<string> {
  const rows = pagePropertiesRows(page);
  const count = await rows.count();
  for (let i = 0; i < count; i++) {
    const row = rows.nth(i);
    const th = await row.locator('th').textContent();
    if (th?.trim() === rowLabel) {
      return (await row.locator('td').textContent()) ?? '';
    }
  }
  throw new Error(`Property row "${rowLabel}" not found in Page Properties table`);
}

/**
 * Take a full-page screenshot and return the path. Used by @sme tagged tests.
 */
export async function screenshotPage(page: Page, name: string): Promise<string> {
  const dir = path.resolve(__dirname, '../screenshots');
  fs.mkdirSync(dir, { recursive: true });
  const filePath = path.join(dir, `${name}.png`);
  await page.screenshot({ path: filePath, fullPage: true });
  return filePath;
}
