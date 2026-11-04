import {defineConfig} from '@playwright/test';

export default defineConfig({
  testDir: './tests/e2e',
  fullyParallel: false,
  workers: 1,
  retries: 0,
  use: {baseURL: 'http://127.0.0.1:8787', browserName: 'chromium', trace: 'retain-on-failure'},
  webServer: {
    command: `${process.env.AI_TRICKY_TEST_PYTHON || 'python3'} tests/e2e/server.py`,
    url: 'http://127.0.0.1:8787/api/runs',
    reuseExistingServer: false,
    timeout: 30000,
  },
});
