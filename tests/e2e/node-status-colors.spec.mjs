import {test, expect} from './fixtures.mjs';

test('canvas shows idle, running and terminal node colors', async ({page}) => {
  const now = new Date('2026-11-18T12:00:00Z');
  await page.clock.install({time: now});
  await page.clock.pauseAt(new Date(now.getTime() + 1000));
  await page.goto('/');

  const first = page.locator('[data-id="01"] .tool-node');
  const second = page.locator('[data-id="02"] .tool-node');
  await expect(first).toHaveCSS('border-top-color', 'rgb(96, 157, 245)');
  await page.getByRole('button', {name: 'Preview run'}).click();
  await page.getByRole('button', {name: 'Start simulation'}).click();
  await expect(first).toHaveCSS('border-top-color', 'rgb(188, 138, 255)');
  await expect(first).toHaveCSS('animation-name', 'workflow-node-pulse');

  await page.emulateMedia({reducedMotion: 'reduce'});
  await expect(first).toHaveCSS('animation-name', 'none');
  await page.emulateMedia({reducedMotion: 'no-preference'});
  await page.getByRole('button', {name: 'Pause simulation'}).click();
  await expect(first).toHaveCSS('animation-name', 'none');
  await page.getByRole('button', {name: 'Resume simulation'}).click();
  await page.clock.runFor(700);
  await expect(first).toHaveCSS('border-top-color', 'rgb(85, 217, 160)');
  await expect(second).toHaveCSS('animation-name', 'workflow-node-pulse');

  await page.getByRole('button', {name: 'Cancel simulation'}).click();
  await expect(second).toHaveCSS('border-top-color', 'rgb(255, 130, 148)');
  await expect(second).toHaveCSS('animation-name', 'none');
});
