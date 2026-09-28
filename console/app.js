const $ = (selector) => document.querySelector(selector);
const pages = {
  overview: ["Overview", "A clear view of your application’s protection."],
  installs: ["Installs", "Bound devices and their attestation history."],
  "bypass-watch": [
    "Bypass watch",
    "High-risk signals and failed attestation outcomes.",
  ],
  policies: ["Policies", "Publish protection changes in controlled stages."],
  secrets: [
    "Secrets & keys",
    "Manage runtime entitlements and signing-key rotation.",
  ],
  deliveries: ["SIEM deliveries", "Track event delivery and retry outcomes."],
  audit: ["Audit log", "Administrative changes, with an accountable trail."],
};
let credential = "",
  appId = "",
  epoch = 0,
  controller,
  draft = null;
const content = $("#content");
const format = (value) =>
  value === null || value === undefined ? "—" : String(value);
const time = (value) =>
  Number.isFinite(value) ? new Date(value * 1000).toLocaleString() : "—";
const number = (value) =>
  Number.isFinite(value) ? new Intl.NumberFormat().format(value) : "—";
function el(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = format(text);
  if (className) node.className = className;
  return node;
}
function button(text, handler, className = "secondary") {
  const node = el("button", text, className);
  node.type = "button";
  node.addEventListener("click", handler);
  return node;
}
function notify(message, success = false) {
  const notice = $("#notice");
  notice.textContent = message;
  notice.className = success ? "success-notice" : "";
  notice.hidden = false;
}
function disconnect() {
  credential = "";
  appId = "";
  draft = null;
  epoch++;
  controller?.abort();
  content.replaceChildren();
  content.hidden = true;
  $("#connection").hidden = false;
  $("#disconnect").hidden = true;
  $("#identity").textContent = "Protection console";
  $("#connect-form").reset();
  $("#notice").hidden = true;
  document
    .querySelectorAll("nav a")
    .forEach((node) => node.removeAttribute("aria-current"));
}
const errors = {
  400: "Check the values and try again.",
  401: "Your credential was rejected. Connect again.",
  403: "Your credential does not grant access to this action.",
  404: "This record could not be found.",
  409: "This record changed. Refresh before trying again.",
};
async function api(path, body, signal) {
  const response = await fetch(
    `/v1/console/apps/${encodeURIComponent(appId)}${path}`,
    {
      method: body === undefined ? "GET" : "POST",
      headers: {
        Authorization: `Bearer ${credential}`,
        ...(body === undefined ? {} : { "Content-Type": "application/json" }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
      cache: "no-store",
      credentials: "omit",
      redirect: "error",
      signal,
    },
  );
  if (!response.ok) {
    if (response.status === 401) disconnect();
    throw new Error(
      errors[response.status] ||
        `Request failed (${response.status}). Try again.`,
    );
  }
  return response.json();
}
function showError(error) {
  if (error.name !== "AbortError")
    notify(
      error instanceof TypeError
        ? "Cannot reach the console service. Check the connection and try again."
        : error.message,
    );
}
function confirmAction(title, message, destructive = false) {
  const dialog = $("#confirm-dialog");
  $("#confirm-title").textContent = title;
  $("#confirm-message").textContent = message;
  $("#confirm-button").className = destructive ? "danger" : "success";
  dialog.returnValue = "cancel";
  dialog.showModal();
  return new Promise((resolve) =>
    dialog.addEventListener(
      "close",
      () => resolve(dialog.returnValue === "confirm"),
      { once: true },
    ),
  );
}
async function mutate(node, operation, success) {
  node.disabled = true;
  const generation = epoch;
  try {
    await operation();
    if (generation === epoch) {
      await render();
      notify(success, true);
    }
  } catch (error) {
    showError(error);
  } finally {
    node.disabled = false;
  }
}
function field(label, name, value = "", type = "text") {
  const wrapper = el("label", label);
  const input = el(type === "textarea" ? "textarea" : "input");
  input.name = name;
  input.value = value;
  if (type !== "textarea") input.type = type;
  input.required = true;
  wrapper.append(input);
  return wrapper;
}
function submit(text) {
  const node = el("button", text, "success");
  node.type = "submit";
  return node;
}
function badge(value) {
  return el(
    "span",
    value,
    `badge ${["high", "critical", "medium", "pending", "leased", "dead"].includes(value) ? value : ""}`,
  );
}
function header(key, title, subtitle) {
  const head = el("div", undefined, "page-head");
  const text = el("div");
  text.append(
    el("div", "APPLICATION / " + appId, "page-kicker"),
    el("h1", title || pages[key][0]),
    el("p", subtitle || pages[key][1]),
  );
  head.append(
    text,
    button("Refresh", () => render()),
  );
  content.append(head);
}
function table(
  columns,
  rows,
  emptyText = "New records will appear here when they are available.",
) {
  if (rows.length === 0) {
    const empty = el("div", undefined, "empty");
    empty.append(el("h2", "No records yet"), el("p", emptyText));
    content.append(empty);
    return;
  }
  const wrapper = el("div", undefined, "table-wrap"),
    table = el("table"),
    head = el("thead"),
    titles = el("tr"),
    body = el("tbody");
  for (const column of columns) {
    const th = el("th", column.title);
    th.scope = "col";
    titles.append(th);
  }
  head.append(titles);
  for (const row of rows) {
    const tr = el("tr");
    for (const column of columns) {
      const td = el("td");
      const value = column.render
        ? column.render(row)
        : format(row[column.key]);
      if (value instanceof Node) td.append(value);
      else td.textContent = value;
      tr.append(td);
    }
    body.append(tr);
  }
  table.append(head, body);
  wrapper.append(table);
  content.append(wrapper);
}
async function list(path, columns, signal, generation, cursor = null) {
  const query = new URLSearchParams({ limit: "50" });
  if (cursor) query.set("cursor", cursor);
  const data = await api(`${path}?${query}`, undefined, signal);
  if (generation !== epoch) return;
  table(columns, data.items);
  const controls = el("div", undefined, "pagination");
  controls.append(el("span", `${data.items.length} records on this page`));
  const actions = el("div", undefined, "actions");
  if (cursor) actions.append(button("First page", () => render(null)));
  if (data.nextCursor)
    actions.append(button("Next page", () => render(data.nextCursor)));
  controls.append(actions);
  content.append(controls);
}
const eventColumns = [
  { title: "Received", render: (row) => time(row.receivedAt) },
  {
    title: "Install",
    render: (row) =>
      button(
        row.installId,
        () => {
          location.hash = "timeline/" + encodeURIComponent(row.installId);
        },
        "text-button",
      ),
  },
  { title: "Risk", render: (row) => badge(row.risk) },
  { title: "Outcome", key: "kind" },
  { title: "Signals", render: (row) => (row.signals || []).join(", ") || "—" },
  { title: "Source", key: "source" },
  { title: "Policy", key: "policyRevision" },
];
async function overview(signal, generation) {
  const data = await api("/summary", undefined, signal);
  if (generation !== epoch) return;
  $("#identity").textContent = `${data.tenantId} / ${data.appId}`;
  const metrics = el("div", undefined, "metrics");
  for (const [label, value] of [
    ["Bound installs", data.installs],
    ["Registered builds", data.builds],
    ["Security events", data.events],
    ["Pending deliveries", data.pendingDeliveries],
  ]) {
    const metric = el("div", undefined, "metric");
    metric.append(
      el("div", label, "metric-label"),
      el("div", number(value), "metric-value"),
    );
    metrics.append(metric);
  }
  content.append(metrics);
  const columns = el("div", undefined, "columns"),
    risk = el("section", undefined, "panel"),
    policy = el("section", undefined, "panel");
  risk.append(
    el("h2", "Recorded risk distribution"),
    el("p", "All stored events, grouped by assessed risk.", "hint"),
  );
  const total = Object.values(data.riskCounts).reduce(
    (sum, value) => sum + value,
    0,
  );
  for (const name of ["none", "low", "medium", "high", "critical"]) {
    const row = el("div", undefined, `risk-row ${name}`),
      meter = el("progress");
    const value = data.riskCounts[name] || 0;
    meter.max = Math.max(total, 1);
    meter.value = value;
    meter.setAttribute("aria-label", `${name} risk: ${number(value)} events`);
    row.append(
      el("span", name[0].toUpperCase() + name.slice(1)),
      meter,
      el("span", number(value), "risk-count"),
    );
    risk.append(row);
  }
  policy.append(el("h2", "Policy deployment"));
  for (const [label, value] of [
    ["Stable revision", data.activePolicyRevision],
    ["Candidate revision", data.candidatePolicyRevision],
    ["Candidate rollout", `${data.rolloutPercent}%`],
  ]) {
    const row = el("div", undefined, "detail");
    row.append(el("span", label), el("strong", value));
    policy.append(row);
  }
  policy.append(
    button(
      "View policies",
      () => {
        location.hash = "policies";
      },
      "text-button",
    ),
  );
  columns.append(risk, policy);
  content.append(columns);
}
function policyActions(row) {
  const actions = el("div", undefined, "actions");
  actions.append(
    button(
      "Inspect",
      () => {
        const existing = $("#policy-detail");
        existing?.remove();
        const section = el("section");
        section.id = "policy-detail";
        section.tabIndex = -1;
        section.append(
          el("h2", `Revision ${row.revision}`, "subhead"),
          el("pre", JSON.stringify(row.config, null, 2), "config"),
        );
        content.append(section);
        section.focus();
      },
      "text-button",
    ),
  );
  if (row.status === "candidate")
    actions.append(button("Roll out", () => rolloutForm(row), "text-button"));
  if (row.status === "historical")
    actions.append(
      button(
        "Restore",
        async (event) => {
          const target = event.currentTarget;
          if (
            await confirmAction(
              "Restore policy content?",
              `Publish the content of revision ${row.revision} as a new revision for every install.`,
              true,
            )
          ) {
            await mutate(
              target,
              () => api("/policies/rollback", { revision: row.revision }),
              "Restored policy content as a new revision.",
            );
          }
        },
        "text-button",
      ),
    );
  return actions;
}
function rolloutForm(row) {
  $("#rollout-form")?.remove();
  const form = el("form", undefined, "form-panel");
  form.id = "rollout-form";
  const percent = field("Rollout percentage", "percent", "10", "number");
  percent.firstElementChild.min = 0;
  percent.firstElementChild.max = 100;
  const save = submit("Update");
  form.append(el("h2", `Roll out revision ${row.revision}`), percent, save);
  content.append(form);
  percent.firstElementChild.focus();
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const value = Number(new FormData(form).get("percent"));
    if (
      await confirmAction(
        "Update rollout?",
        `Revision ${row.revision} will be assigned to ${value}% of eligible installs.`,
      )
    )
      await mutate(
        save,
        () =>
          api("/policies/rollout", { revision: row.revision, percent: value }),
        "Rollout updated.",
      );
  });
}
function policyForm() {
  const form = el("form", undefined, "form-panel");
  const ttl = field("Validity (seconds)", "ttlSeconds", "86400", "number");
  ttl.firstElementChild.min = 60;
  const save = submit("Create draft");
  form.append(
    el("h2", "Draft a policy"),
    el(
      "p",
      "Only supported protection settings are accepted. Review the draft before publishing.",
      "hint",
    ),
    field("Protection configuration (JSON)", "config", "{}", "textarea"),
    ttl,
    save,
  );
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    save.disabled = true;
    const generation = epoch;
    try {
      const values = new FormData(form);
      let config;
      try {
        config = JSON.parse(values.get("config"));
      } catch {
        throw new Error("Configuration must be valid JSON.");
      }
      const created = await api("/policies/drafts", {
        config,
        ttlSeconds: Number(values.get("ttlSeconds")),
      });
      if (generation === epoch) {
        draft = created;
        await render();
        notify("Draft created. Review it before publishing.", true);
      }
    } catch (error) {
      showError(error);
    } finally {
      save.disabled = false;
    }
  });
  content.append(form);
  if (draft) {
    const review = el("form", undefined, "form-panel");
    const percent = field(
      "Initial rollout percentage",
      "percent",
      "10",
      "number",
    );
    percent.firstElementChild.min = 0;
    percent.firstElementChild.max = 100;
    const publish = submit("Publish");
    review.append(
      el("h2", "Review draft"),
      el("pre", JSON.stringify(draft.config, null, 2), "config"),
      el("p", `Validity: ${draft.ttlSeconds} seconds`, "hint"),
      percent,
      publish,
    );
    review.addEventListener("submit", async (event) => {
      event.preventDefault();
      const selected = draft,
        value = Number(new FormData(review).get("percent"));
      if (
        await confirmAction(
          "Publish policy?",
          `Publish this signed policy to ${value}% of eligible installs.`,
        )
      )
        await mutate(
          publish,
          async () => {
            await api("/policies/publish", {
              draftId: selected.draftId,
              percent: value,
            });
            draft = null;
          },
          "Policy published.",
        );
    });
    content.append(review);
  }
}
function secretForms() {
  const form = el("form", undefined, "form-panel"),
    save = submit("Save");
  const value = field("Secret value", "value", "", "password");
  value.firstElementChild.autocomplete = "off";
  const risk = el("label", "Maximum allowed risk"),
    select = el("select");
  select.name = "maxRisk";
  for (const name of ["none", "low", "medium", "high"]) {
    const option = el("option", name);
    option.value = name;
    select.append(option);
  }
  risk.append(select);
  const ttl = field("Grant lifetime (seconds)", "ttlSeconds", "300", "number");
  ttl.firstElementChild.min = 1;
  form.append(
    el("h2", "Create or replace a secret"),
    field("Name", "name"),
    value,
    field("Required scopes (comma separated)", "scopes"),
    risk,
    ttl,
    save,
  );
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const values = new FormData(form);
    if (
      await confirmAction(
        "Save secret?",
        "Create a new secret version with these entitlement limits.",
      )
    )
      await mutate(
        save,
        async () => {
          try {
            await api("/secrets", {
              name: values.get("name"),
              value: values.get("value"),
              scopes: values
                .get("scopes")
                .split(",")
                .map((x) => x.trim())
                .filter(Boolean),
              maxRisk: values.get("maxRisk"),
              ttlSeconds: Number(values.get("ttlSeconds")),
            });
          } finally {
            value.firstElementChild.value = "";
            values.delete("value");
          }
        },
        "Secret saved.",
      );
  });
  content.append(form);
  const keys = el("section", undefined, "form-panel");
  keys.append(
    el("h2", "Rotate signing keys"),
    el(
      "p",
      "Publish updated policy verification keys to clients before rotating policy signing keys. Existing token verification keys remain available for the configured overlap.",
      "hint",
    ),
  );
  const actions = el("div", undefined, "actions");
  for (const purpose of ["token", "policy"])
    actions.append(
      button(`Rotate ${purpose} key`, async (event) => {
        const target = event.currentTarget;
        if (
          await confirmAction(
            "Rotate signing key?",
            `Activate a new ${purpose} signing key for this application.`,
          )
        )
          await mutate(
            target,
            () => api("/keys/rotate", { purpose }),
            "Signing key rotated.",
          );
      }),
    );
  keys.append(actions);
  content.append(keys);
}
async function render(cursor = null) {
  if (!credential) return;
  controller?.abort();
  controller = new AbortController();
  const generation = ++epoch,
    signal = controller.signal;
  let [key, install] = location.hash.slice(1).split("/");
  if (!pages[key] && key !== "timeline") key = "overview";
  content.hidden = false;
  content.replaceChildren();
  content.setAttribute("aria-busy", "true");
  $("#notice").hidden = true;
  document.querySelectorAll("nav a").forEach((node) => {
    if (node.hash === `#${key}`) node.setAttribute("aria-current", "page");
    else node.removeAttribute("aria-current");
  });
  try {
    if (key === "timeline") {
      install = decodeURIComponent(install || "");
      header("installs", "Install timeline", install);
      await list(
        `/installs/${encodeURIComponent(install)}/timeline`,
        eventColumns,
        signal,
        generation,
        cursor,
      );
    } else {
      header(key);
      if (key === "overview") await overview(signal, generation);
      if (key === "installs")
        await list(
          "/installs",
          [
            {
              title: "Install",
              render: (row) =>
                button(
                  row.installId,
                  () => {
                    location.hash =
                      "timeline/" + encodeURIComponent(row.installId);
                  },
                  "text-button",
                ),
            },
            { title: "Platform", key: "platform" },
            { title: "Security level", key: "securityLevel" },
            { title: "Bound", render: (row) => time(row.boundAt) },
          ],
          signal,
          generation,
          cursor,
        );
      if (key === "bypass-watch")
        await list("/bypass-watch", eventColumns, signal, generation, cursor);
      if (key === "policies") {
        await list(
          "/policies",
          [
            { title: "Revision", key: "revision" },
            { title: "Status", render: (row) => badge(row.status) },
            { title: "Issued", render: (row) => time(row.issuedAt) },
            { title: "Expires", render: (row) => time(row.expiresAt) },
            { title: "Actions", render: policyActions },
          ],
          signal,
          generation,
          cursor,
        );
        if (generation === epoch) policyForm();
      }
      if (key === "secrets") {
        await list(
          "/secrets",
          [
            { title: "Name", key: "name" },
            { title: "Version", key: "version" },
            { title: "Scopes", render: (row) => row.scopes.join(", ") },
            { title: "Max risk", render: (row) => badge(row.maxRisk) },
            { title: "Lifetime (s)", key: "ttlSeconds" },
          ],
          signal,
          generation,
          cursor,
        );
        if (generation === epoch) secretForms();
      }
      if (key === "deliveries")
        await list(
          "/deliveries",
          [
            { title: "Event", key: "eventId" },
            { title: "Status", render: (row) => badge(row.status) },
            { title: "Attempts", key: "attempts" },
            { title: "Next attempt", render: (row) => time(row.nextAttemptAt) },
            { title: "Last error", key: "lastError" },
          ],
          signal,
          generation,
          cursor,
        );
      if (key === "audit")
        await list(
          "/audit",
          [
            { title: "Received", render: (row) => time(row.receivedAt) },
            { title: "Actor", key: "actor" },
            { title: "Action", key: "action" },
            { title: "Target", key: "target" },
          ],
          signal,
          generation,
          cursor,
        );
    }
  } catch (error) {
    if (generation === epoch || !credential) showError(error);
  } finally {
    if (generation === epoch) content.setAttribute("aria-busy", "false");
  }
}
for (const [key, [title]] of Object.entries(pages)) {
  const link = el("a", title);
  link.href = "#" + key;
  $("#navigation").append(link);
}
$("#disconnect").addEventListener("click", disconnect);
$(".skip").addEventListener("click", (event) => {
  event.preventDefault();
  $("#main").focus();
});
window.addEventListener("hashchange", () => render());
$("#connect-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget,
    values = new FormData(form),
    save = form.querySelector("button");
  save.disabled = true;
  credential = String(values.get("credential"));
  appId = String(values.get("appId")).trim();
  try {
    await api("/summary");
    form.reset();
    $("#connection").hidden = true;
    $("#disconnect").hidden = false;
    await render();
  } catch (error) {
    disconnect();
    showError(error);
  } finally {
    save.disabled = false;
  }
});
