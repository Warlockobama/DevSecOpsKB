import { defineConfig, devices } from '@playwright/test';
import * as dotenv from 'dotenv';
import * as path from 'path';

dotenv.config({ path: path.resolve(__dirname, '.env.e2e') });

export default defineConfig({
  testDir: './tests',
  timeout: 60_000,
  retries: 1,
  reporter: [
    ['list'],
    ['html', { outputFolder: 'playwright-report', open: 'never' }],
  ],
  use: {
    baseURL: process.env.CONFLUENCE_URL ?? 'https://jameslerud.atlassian.net/wiki',
    // Basic auth header for Confluence Cloud API token auth
    extraHTTPHeaders: {
      Authorization:
        'Basic ' +
        Buffer.from(
          `${process.env.CONFLUENCE_USER}:${process.env.CONFLUENCE_TOKEN}`
        ).toString('base64'),
    },
    screenshot: 'only-on-failure',
    video: 'off',
    trace: 'off',
  },
  globalSetup: './setup/export-fixtures.ts',
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
  // Store exported page URLs here so tests can look them up
  // (populated by globalSetup)
  outputDir: 'test-results',
});
