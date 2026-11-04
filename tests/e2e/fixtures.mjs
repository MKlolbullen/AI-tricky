import {test as base, expect} from '@playwright/test';

export const test = base.extend({
  page: async ({page, request}, use) => {
    const response = await request.post('/api/_qa/reset', {data: {}});
    expect(response.ok()).toBe(true);
    await use(page);
  },
});
export {expect};
