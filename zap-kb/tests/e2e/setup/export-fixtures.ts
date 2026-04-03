/**
 * Playwright globalSetup — exports e2e fixture entities to Confluence Cloud.
 *
 * Runs once before the test suite. Builds the zap-kb binary if needed, writes
 * a temporary Obsidian vault from fixture data, then pushes it to Confluence
 * under a dedicated "zap-kb E2E Test Fixtures" parent page.
 *
 * Writes tests/e2e/.page-ids.json so individual tests can navigate directly
 * to the relevant Confluence page URLs without scraping titles.
 */

import { execSync, spawnSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as dotenv from 'dotenv';

dotenv.config({ path: path.resolve(__dirname, '../.env.e2e') });

const CONFLUENCE_URL = process.env.CONFLUENCE_URL ?? 'https://jameslerud.atlassian.net/wiki';
const CONFLUENCE_USER = process.env.CONFLUENCE_USER ?? '';
const CONFLUENCE_TOKEN = process.env.CONFLUENCE_TOKEN ?? '';
const CONFLUENCE_SPACE = process.env.CONFLUENCE_SPACE ?? 'KB';
const E2E_PARENT_TITLE = process.env.E2E_PARENT_TITLE ?? 'zap-kb E2E Test Fixtures';
const ZAP_KB_BIN = path.resolve(__dirname, process.env.ZAP_KB_BIN ?? '../../../bin/zap-kb');
const FIXTURES_DIR = path.resolve(__dirname, '../fixtures');
const PAGE_IDS_FILE = path.resolve(__dirname, '../.page-ids.json');

export default async function globalSetup() {
  // 1. Build binary if missing
  if (!fs.existsSync(ZAP_KB_BIN)) {
    console.log('[e2e setup] Building zap-kb binary...');
    execSync('go build -o bin/zap-kb ./cmd/zap-kb', {
      cwd: path.resolve(__dirname, '../../..'),
      stdio: 'inherit',
    });
  }

  // 2. Write fixture entities to a temp obsidian vault
  const tmpVault = fs.mkdtempSync(path.join(os.tmpdir(), 'zap-kb-e2e-'));
  console.log(`[e2e setup] Writing fixture vault to ${tmpVault}`);

  const exportResult = spawnSync(
    ZAP_KB_BIN,
    [
      '-entities-in', path.join(FIXTURES_DIR, 'e2e-entities.json'),
      '-format', 'obsidian',
      '-obsidian-dir', tmpVault,
      '-scan-label', 'e2e-test-run',
    ],
    { encoding: 'utf8' }
  );
  if (exportResult.status !== 0) {
    throw new Error(`[e2e setup] zap-kb obsidian export failed:\n${exportResult.stderr}`);
  }

  // 3. Upsert fixture pages to Confluence under the e2e parent page
  console.log(`[e2e setup] Pushing fixture pages to Confluence space=${CONFLUENCE_SPACE}...`);
  const confResult = spawnSync(
    ZAP_KB_BIN,
    [
      '-obsidian-dir', tmpVault,
      '-confluence-url', CONFLUENCE_URL,
      '-confluence-user', CONFLUENCE_USER,
      '-confluence-token', CONFLUENCE_TOKEN,
      '-confluence-space', CONFLUENCE_SPACE,
      '-confluence-parent', E2E_PARENT_TITLE,
      '-conf-full',
    ],
    {
      encoding: 'utf8',
      env: { ...process.env },
    }
  );
  if (confResult.status !== 0) {
    throw new Error(`[e2e setup] Confluence export failed:\n${confResult.stderr}`);
  }
  console.log('[e2e setup] Confluence export output:', confResult.stdout);

  // 4. Resolve page URLs by title via Confluence REST API so tests can navigate directly
  const pageIds = await resolvePageIds(CONFLUENCE_SPACE, E2E_PARENT_TITLE);
  fs.writeFileSync(PAGE_IDS_FILE, JSON.stringify(pageIds, null, 2));
  console.log('[e2e setup] Page IDs written to', PAGE_IDS_FILE);
}

async function resolvePageIds(spaceKey: string, parentTitle: string): Promise<Record<string, string>> {
  const base = CONFLUENCE_URL.replace(/\/+$/, '');
  const auth = Buffer.from(`${CONFLUENCE_USER}:${CONFLUENCE_TOKEN}`).toString('base64');
  const headers = { Authorization: `Basic ${auth}`, 'Content-Type': 'application/json' };

  // Find or create parent page
  const searchUrl = `${base}/rest/api/content?spaceKey=${spaceKey}&title=${encodeURIComponent(parentTitle)}&expand=id`;
  const parentRes = await fetch(searchUrl, { headers });
  const parentData = await parentRes.json() as any;

  let parentId: string | null = null;
  if (parentData.results?.length > 0) {
    parentId = parentData.results[0].id;
  }

  if (!parentId) {
    // Create the parent page
    const createRes = await fetch(`${base}/rest/api/content`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        type: 'page',
        title: parentTitle,
        space: { key: spaceKey },
        body: { storage: { value: '<p>zap-kb Playwright e2e fixture pages.</p>', representation: 'storage' } },
      }),
    });
    const created = await createRes.json() as any;
    parentId = created.id;
    console.log(`[e2e setup] Created parent page "${parentTitle}" id=${parentId}`);
  }

  // Fetch children of parent page
  const childrenRes = await fetch(`${base}/rest/api/content/${parentId}/child/page?limit=50`, { headers });
  const childrenData = await childrenRes.json() as any;

  const ids: Record<string, string> = { _parentId: parentId! };
  for (const page of (childrenData.results ?? [])) {
    ids[page.title] = `${base}/wiki/spaces/${spaceKey}/pages/${page.id}`;
    // Also fetch grandchildren (finding and occurrence pages)
    const grandRes = await fetch(`${base}/rest/api/content/${page.id}/child/page?limit=50`, { headers });
    const grandData = await grandRes.json() as any;
    for (const gp of (grandData.results ?? [])) {
      ids[gp.title] = `${base}/wiki/spaces/${spaceKey}/pages/${gp.id}`;
      const ggRes = await fetch(`${base}/rest/api/content/${gp.id}/child/page?limit=50`, { headers });
      const ggData = await ggRes.json() as any;
      for (const ggp of (ggData.results ?? [])) {
        ids[ggp.title] = `${base}/wiki/spaces/${spaceKey}/pages/${ggp.id}`;
      }
    }
  }

  return ids;
}
