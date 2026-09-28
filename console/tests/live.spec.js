import { test, expect } from '@playwright/test';

test('local backend: publish a policy and store secret metadata through the UI', async ({ page }) => {
  const upstream = process.env.RASP_CONSOLE_LIVE_URL;
  test.skip(!upstream, 'Set a dedicated local control-plane URL and test credential to run integration.');
  const url = new URL(upstream);
  expect(['127.0.0.1', 'localhost', '[::1]']).toContain(url.hostname);
  const appId = process.env.RASP_CONSOLE_LIVE_APP;
  const credential = process.env.RASP_CONSOLE_LIVE_TOKEN;
  expect(appId).toBeTruthy(); expect(credential).toBeTruthy();
  // Simulate the same-origin reverse proxy while sending real requests to the
  // dedicated local backend. No response data or status is mocked here.
  await page.route('**/v1/console/**', async route => {
    const requestUrl = new URL(route.request().url());
    const response = await route.fetch({url:new URL(requestUrl.pathname + requestUrl.search,url).href});
    await route.fulfill({response});
  });
  await page.goto('/');
  await page.getByLabel('Application ID').fill(appId);
  await page.getByLabel('Console credential').fill(credential);
  await page.getByRole('button',{name:'Connect',exact:true}).click();
  await expect(page.getByRole('heading',{name:'Overview',exact:true})).toBeVisible();
  await page.getByRole('link',{name:'Policies',exact:true}).click();
  await page.getByLabel('Protection configuration (JSON)').fill('{"checkIntervalSeconds":30}');
  await page.getByRole('button',{name:'Create draft'}).click();
  await page.getByLabel('Initial rollout percentage').fill('100');
  await page.getByRole('button',{name:'Publish',exact:true}).click();
  await page.getByRole('button',{name:'Confirm',exact:true}).click();
  await expect(page.locator('#notice')).toHaveText('Policy published.');
  await expect(page.getByText('stable',{exact:true})).toBeVisible();
  await page.getByRole('link',{name:'Secrets & keys'}).click();
  const name='browser-fixture-'+Date.now();
  await page.getByLabel('Name',{exact:true}).fill(name);
  await page.getByLabel('Secret value').fill('local-fixture-secret');
  await page.getByLabel('Required scopes (comma separated)').fill('test:read');
  await page.getByRole('button',{name:'Save',exact:true}).click();
  await page.getByRole('button',{name:'Confirm',exact:true}).click();
  await expect(page.locator('#notice')).toHaveText('Secret saved.');
  await expect(page.getByText(name,{exact:true})).toBeVisible();
  await expect(page.getByLabel('Secret value')).toHaveValue('');
  expect(await page.content()).not.toContain('local-fixture-secret');
  await page.getByRole('link',{name:'Audit log'}).click();
  await expect(page.getByRole('cell',{name:'policies/publish.requested',exact:true})).toBeVisible();
  await expect(page.getByRole('cell',{name:'secrets.requested',exact:true})).toBeVisible();
});
