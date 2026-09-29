import { defineConfig } from "@playwright/test";
export default defineConfig({
  testDir: "./tests",
  timeout: 15000,
  use: { baseURL: "http://127.0.0.1:49187" },
  webServer: {
    command: "python3 -m http.server 49187 --bind 127.0.0.1",
    url: "http://127.0.0.1:49187",
    reuseExistingServer: false,
  },
});
