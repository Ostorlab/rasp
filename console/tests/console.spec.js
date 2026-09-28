import { test, expect } from "@playwright/test";
const summary = {
  tenantId: "tenant-a",
  appId: "com.example.app",
  installs: 12,
  builds: 2,
  events: 40,
  riskCounts: { none: 20, low: 10, medium: 7, high: 3, critical: 0 },
  activePolicyRevision: 2,
  candidatePolicyRevision: 3,
  rolloutPercent: 10,
  pendingDeliveries: 4,
};
async function setup(page, handler) {
  await page.route("**/v1/console/**", async (route) => {
    expect(route.request().headers().authorization).toBe(
      "Bearer private-test-credential",
    );
    if (handler && (await handler(route))) return;
    await route.fulfill({
      json: route.request().url().includes("/summary")
        ? summary
        : { items: [], nextCursor: null },
    });
  });
  await page.goto("/");
  await page.getByLabel("Application ID").fill("com.example.app");
  await page.getByLabel("Console credential").fill("private-test-credential");
  await page.getByRole("button", { name: "Connect", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Overview", exact: true }),
  ).toBeVisible();
}
test("renders API counts, keeps credential out of storage, and clears on disconnect", async ({
  page,
}) => {
  await setup(page);
  await expect(page.getByText("Bound installs", { exact: true })).toBeVisible();
  await expect(page.locator(".metric-value").first()).toHaveText("12");
  expect(
    await page.evaluate(() => [localStorage.length, sessionStorage.length]),
  ).toEqual([0, 0]);
  expect(await page.content()).not.toContain("private-test-credential");
  await page.getByRole("button", { name: "Disconnect" }).click();
  await expect(page.getByLabel("Console credential")).toHaveValue("");
  await expect(
    page.getByRole("heading", { name: "Connect to your application" }),
  ).toBeVisible();
  await expect(page.locator("#content")).toBeHidden();
});
test("server strings render as text and an install opens its timeline", async ({
  page,
}) => {
  await setup(page, async (route) => {
    if (new URL(route.request().url()).pathname.endsWith("/installs")) {
      await route.fulfill({
        json: {
          items: [
            {
              installId: "<img src=x onerror=alert(1)>",
              platform: "android",
              securityLevel: "hardware",
              boundAt: 1700000000,
            },
          ],
          nextCursor: null,
        },
      });
      return true;
    }
  });
  await page.getByRole("link", { name: "Installs", exact: true }).click();
  await page
    .getByRole("button", { name: "<img src=x onerror=alert(1)>", exact: true })
    .click();
  await expect(
    page.getByRole("heading", { name: "Install timeline" }),
  ).toBeVisible();
  await expect(page.locator("#content img")).toHaveCount(0);
  await expect(page.getByText("No records yet")).toBeVisible();
});
test("policy draft is reviewed and publication requires explicit confirmation", async ({
  page,
}) => {
  const writes = [];
  await setup(page, async (route) => {
    if (route.request().method() === "POST") {
      writes.push([
        new URL(route.request().url()).pathname,
        route.request().postDataJSON(),
      ]);
      await route.fulfill({
        json: route.request().url().endsWith("/drafts")
          ? {
              draftId: "draft-1",
              config: { checkIntervalSeconds: 30 },
              ttlSeconds: 86400,
            }
          : { revision: 4, percent: 10 },
      });
      return true;
    }
  });
  await page.getByRole("link", { name: "Policies", exact: true }).click();
  await page
    .getByLabel("Protection configuration (JSON)")
    .fill('{"checkIntervalSeconds":30}');
  await page.getByRole("button", { name: "Create draft" }).click();
  await expect(
    page.getByRole("heading", { name: "Review draft" }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Publish", exact: true }).click();
  expect(writes.length).toBe(1);
  await page.getByRole("button", { name: "Cancel", exact: true }).click();
  expect(writes.length).toBe(1);
  await page.getByRole("button", { name: "Publish", exact: true }).click();
  await page.getByRole("button", { name: "Confirm", exact: true }).click();
  await expect(page.getByRole("status")).toHaveText("Policy published.");
  expect(writes[1][1]).toEqual({ draftId: "draft-1", percent: 10 });
});
test("permission errors are shown without claiming success", async ({
  page,
}) => {
  await setup(page, async (route) => {
    if (route.request().url().includes("/secrets")) {
      await route.fulfill({ status: 403, json: { error: "forbidden" } });
      return true;
    }
  });
  await page.getByRole("link", { name: "Secrets & keys" }).click();
  await expect(page.getByRole("status")).toHaveText(
    "Your credential does not grant access to this action.",
  );
  await expect(
    page.getByRole("button", { name: "Save", exact: true }),
  ).toHaveCount(0);
});
test("pagination uses opaque cursor and refresh returns to the first page", async ({
  page,
}) => {
  const cursors = [];
  await setup(page, async (route) => {
    const url = new URL(route.request().url());
    if (url.pathname.endsWith("/audit")) {
      const cursor = url.searchParams.get("cursor");
      cursors.push(cursor);
      await route.fulfill({
        json: {
          items: [
            {
              eventId: "e1",
              receivedAt: 1700000000,
              actor: "operator",
              action: "policy.publish",
              target: "2",
            },
          ],
          nextCursor: cursor ? null : "opaque/+ cursor",
        },
      });
      return true;
    }
  });
  await page.getByRole("link", { name: "Audit log" }).click();
  await page.getByRole("button", { name: "Next page" }).click();
  await expect(page.getByRole("button", { name: "First page" })).toBeVisible();
  await page.getByRole("button", { name: "Refresh" }).click();
  await expect(page.getByRole("button", { name: "Next page" })).toBeVisible();
  expect(cursors).toEqual([null, "opaque/+ cursor", null]);
});
test("narrow viewport keeps navigation and forms accessible", async ({
  page,
}) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await setup(page);
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true);
  await page.getByRole("link", { name: "Policies", exact: true }).click();
  await expect(
    page.getByLabel("Protection configuration (JSON)"),
  ).toBeVisible();
  await page.screenshot({
    path: "test-results/console-mobile.png",
    fullPage: true,
  });
});
test("desktop overview contains no browser errors", async ({ page }) => {
  const errors = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.setViewportSize({ width: 1440, height: 1000 });
  await setup(page);
  await expect(page.locator(".metric-value").first()).toHaveText("12");
  await page.screenshot({
    path: "test-results/console-desktop.png",
    fullPage: true,
  });
  expect(errors).toEqual([]);
});

test("an old mutation's 401 cannot disconnect a replacement session", async ({ page }) => {
  let pending;
  await setup(page, async route => {
    if (route.request().url().endsWith('/keys/rotate')) {
      pending = route;
      return true;
    }
  });
  await page.getByRole('link', {name:'Secrets & keys'}).click();
  await page.getByRole('button', {name:'Rotate token key'}).click();
  await page.getByRole('button', {name:'Confirm', exact:true}).click();
  await expect.poll(() => pending !== undefined).toBe(true);
  await page.getByRole('button', {name:'Disconnect'}).click();
  await page.getByLabel('Application ID').fill('com.example.app');
  await page.getByLabel('Console credential').fill('private-test-credential');
  await page.getByRole('button', {name:'Connect', exact:true}).click();
  await expect(page.getByRole('heading', {name:'Secrets & keys', exact:true})).toBeVisible();
  const received = page.waitForResponse(response => response.url().endsWith('/keys/rotate'));
  await pending.fulfill({status:401,json:{error:'expired'}});
  await received;
  // A following request proves the new session is still usable after the old response.
  await page.getByRole('button', {name:'Refresh'}).click();
  await expect(page.getByRole('button', {name:'Rotate token key'})).toBeVisible();
  await expect(page.getByRole('button', {name:'Disconnect'})).toBeVisible();
  await expect(page.locator('#notice')).toBeHidden();
});


test("absent candidate rollout displays an empty value", async ({ page }) => {
  await setup(page, async route => {
    if (route.request().url().endsWith("/summary")) {
      await route.fulfill({ json: { ...summary, candidatePolicyRevision: null, rolloutPercent: null } });
      return true;
    }
  });
  await expect(page.locator(".detail").filter({ hasText: "Candidate rollout" }).locator("strong")).toHaveText("—");
  await expect(page.getByText("null%", { exact: true })).toHaveCount(0);
  await expect(page.getByText("undefined%", { exact: true })).toHaveCount(0);
});

test("malformed timeline hash falls back to installs", async ({ page }) => {
  await setup(page);
  await page.evaluate(() => { location.hash = "timeline/%"; });
  await expect(page.getByRole("heading", { name: "Installs", exact: true })).toBeVisible();
  await expect(page.getByText("No records yet")).toBeVisible();
  await expect(page.getByText("URI malformed", { exact: true })).toHaveCount(0);
});
