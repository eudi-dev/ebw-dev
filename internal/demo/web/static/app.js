"use strict";

const api = (path) => new URL(path, document.baseURI);
const byId = (id) => document.getElementById(id);

async function call(method, path, body) {
  const response = await fetch(api(path), {
    method,
    headers: body ? { "Content-Type": "application/json" } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  let data = {};
  try {
    data = await response.json();
  } catch (error) {
    data = {};
  }
  if (!response.ok) {
    const failure = new Error(data.error_description || data.error || response.statusText);
    failure.status = response.status;
    throw failure;
  }
  return data;
}

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function para(...children) {
  const node = element("p");
  node.append(...children);
  return node;
}

function link(href, text, className) {
  const node = element("a", className, text);
  node.href = href;
  return node;
}

function fact(list, name, value, code) {
  if (value === undefined || value === null || value === "") return;
  list.append(element("dt", "", name));
  const dd = element("dd");
  dd.append(code ? element("code", "", String(value)) : String(value));
  list.append(dd);
}

function instant(value) {
  if (!value) return "";
  const date = typeof value === "number" ? new Date(value * 1000) : new Date(value);
  return date.toISOString().replace(".000Z", "Z");
}

function time(value) {
  return new Date(value).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" });
}

function day(value) {
  return new Date(value).toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric" });
}

function sameDay(a, b) {
  return new Date(a).toDateString() === new Date(b).toDateString();
}

function moment(value) {
  return sameDay(value, Date.now()) ? time(value) : day(value) + ", " + time(value);
}

function disclosure(title, ...content) {
  const details = element("details");
  details.append(element("summary", "", title), ...content);
  return details;
}

function codeBlock(text, href, label) {
  const box = element("div");
  if (href) {
    const decoder = link(href, label, "decoder");
    decoder.target = "_blank";
    decoder.rel = "noopener";
    box.append(decoder);
  }
  box.append(element("pre", "token", text));
  return box;
}

function remembered(key) {
  try {
    return JSON.parse(sessionStorage.getItem(key)) || {};
  } catch (error) {
    return {};
  }
}

function remember(key, value) {
  try {
    sessionStorage.setItem(key, JSON.stringify(value));
  } catch (error) {
    // Without the storage the page finds the request in its address.
  }
}

let config = {};

/* Progress rail, steps and banners */

function rail(node, state, who) {
  const item = document.querySelector('.rail li[data-node="' + node + '"]');
  if (!item) return;
  if (state) item.dataset.state = state;
  else delete item.dataset.state;
  if (who !== undefined) item.querySelector(".who").textContent = who;
}

function step(name, state, who) {
  const node = document.querySelector('[data-step="' + name + '"]');
  if (node) node.dataset.state = state;
  rail(name, state, who);
}

function banner(node, kind, title, text, ...extra) {
  node.hidden = false;
  node.className = (node.classList.contains("outcome") ? "outcome " : "") + "banner " + kind;
  node.replaceChildren(element("strong", "", title));
  if (text) node.append(typeof text === "string" ? element("span", "", text) : text);
  node.append(...extra.filter(Boolean));
}

function running(button, label) {
  button.disabled = true;
  button.replaceChildren(element("span", "spinner"), label);
  button.querySelector(".spinner").setAttribute("aria-hidden", "true");
}

function idle(button, label) {
  button.disabled = false;
  button.textContent = label;
}

function reasons(list) {
  if (!list || !list.length) return null;
  if (list.length === 1) return element("span", "", list[0]);
  const node = element("ul", "reasons");
  for (const reason of list) node.append(element("li", "", reason));
  return node;
}

function walletAnswer(answer) {
  const node = element("p", "muted");
  node.append("Answer of the wallet: ", element("code", "", answer.error));
  if (answer.error_description) node.append(", " + answer.error_description.replace(/[.\s]+$/, ""));
  node.append(".");
  return node;
}

function show(node) {
  if (node) node.scrollIntoView({ behavior: "smooth", block: "start" });
}

function poll(path, update) {
  setTimeout(async () => {
    let next;
    try {
      next = await call("GET", path);
    } catch (error) {
      if (error.status !== 404) poll(path, update);
      return;
    }
    await update(next);
    if (next.status === "pending") poll(path, update);
  }, 2000);
}

function refusalCount(cards, active) {
  const visible = cards.filter((card) => !card.hidden);
  const done = visible.filter((card) => card.dataset.state === "done" || card.dataset.state === "unexpected").length;
  const total = visible.length;
  if (!total) return;
  const state = done === total ? "done" : active ? "now" : null;
  rail("refusals", state, done ? done + " of " + total + " done" : total + " refusals");
  const label = document.querySelector('.rail li[data-node="refusals"] b');
  if (label) label.dataset.count = done + "/" + total;
}

/* Check reports */

const linkTitles = {
  credential: "Credential",
  mandate: "Delegation",
  presentation: "Presentation of the agent",
};

const walletLinkTitles = {
  credential: "Credential",
  presentation: "Presentation of the wallet",
};

function linkFacts(list, item, report) {
  const claims = item.claims || {};
  const links = report.links || [];
  if (item.kind === "credential") {
    const delegation = links.find((other) => other.kind === "mandate");
    fact(list, "Issuer", item.signer);
    fact(list, "Type", (report.credential || {}).vct, true);
    fact(list, "Issuer key", item.key_thumbprint, true);
    fact(list, "Holder key", delegation && delegation.key_thumbprint, true);
  } else if (item.kind === "mandate") {
    const delegation = report.mandate || {};
    const presentation = links.find((other) => other.kind === "presentation");
    fact(list, "Signed by", item.signer);
    fact(list, "Holder key", item.key_thumbprint, true);
    fact(list, "Agent", delegation.agent && delegation.agent.name);
    fact(list, "Agent key", presentation && presentation.key_thumbprint, true);
    fact(list, "Actions", (delegation.actions || []).join(", "), true);
    fact(list, "Limit", delegation.limit && delegation.limit.amount + " " + delegation.limit.currency);
    fact(list, "Expires", instant(delegation.expires));
    for (const audience of delegation.audiences || []) fact(list, "Disclosed audience", audience, true);
  } else {
    fact(list, "Signed by", item.signer);
    fact(list, "Agent key", item.key_thumbprint, true);
    fact(list, "Audience", claims.aud, true);
    fact(list, "Nonce", claims.nonce, true);
    fact(list, "Issued at", instant(claims.iat));
  }
}

function checkList(checks) {
  const labels = config.check_labels || {};
  const list = element("ul", "checks");
  for (const check of checks) {
    const row = element("li", check.result);
    row.append(element("span", "mark", check.result));
    const text = element("span", "", labels[check.name] || check.name);
    if (check.detail) text.append(element("span", "detail", check.detail));
    row.append(text);
    list.append(row);
  }
  return list;
}

function failedChecks(item) {
  return item.checks.filter((check) => check.result === "fail").length;
}

function countText(item) {
  const failed = failedChecks(item);
  return failed ? failed + " of " + item.checks.length + " checks failed" : item.checks.length + " checks passed";
}

function renderChain(report, technical, titles) {
  const container = element("div", "chain");
  if (!report) return container;
  if (report.structure && report.structure.result === "fail") {
    const block = element("div", "link fail");
    block.append(element("p", "link-title", "Token"), element("p", "", report.structure.detail));
    container.append(block);
  }
  for (const item of report.links || []) {
    const block = element("details", "link " + (failedChecks(item) ? "fail" : "pass"));
    const summary = element("summary");
    summary.append(element("span", "link-title", (titles || linkTitles)[item.kind] || item.kind));
    summary.append(element("span", "count", countText(item)));
    block.append(summary, checkList(item.checks));
    if (technical) {
      const facts = element("dl", "facts");
      linkFacts(facts, item, report);
      block.append(facts, element("pre", "", JSON.stringify({ header: item.header, claims: item.claims }, null, 2)));
    }
    container.append(block);
  }
  return container;
}

function miniChecks(report, titles) {
  const list = element("ul", "mini-checks");
  for (const item of (report && report.links) || []) {
    const row = element("li", failedChecks(item) ? "fail" : "pass");
    row.append(element("b", "", (titles || linkTitles)[item.kind] || item.kind), " " + countText(item) + ".");
    list.append(row);
  }
  return list;
}

function runLog(run) {
  const log = element("ol", "log");
  for (const entry of run.steps || []) {
    const row = element("li");
    row.append(element("span", "actor " + entry.actor, entry.actor === "agent" ? "Agent" : entry.actor === "wallet" ? "Business wallet" : run.verifier.name));
    row.append(entry.text);
    if (entry.detail) row.append(element("pre", "", JSON.stringify(entry.detail, null, 2)));
    log.append(row);
  }
  return log;
}

function runDetails(run) {
  const parts = [];
  if (run.report) parts.push(disclosure("Technical details: checks of the verifier", renderChain(run.report, true)));
  parts.push(disclosure("Technical details: messages between the agent and the verifier", runLog(run)));
  if (run.token) parts.push(disclosure("Technical details: raw token of the agent", element("pre", "token", run.token)));
  return parts;
}

/* Case page */

function casePage(caseID) {
  const selected = (config.cases || []).find((entry) => entry.id === caseID) || {};
  const storageKey = "ebw-dev:" + caseID;
  const cards = [...document.querySelectorAll(".refusal")];
  const requestButton = byId("request");
  const actButton = byId("act");
  const actResult = byId("act-result");
  const lock = byId("refusals-lock");
  const lockText = lock.querySelector("span").cloneNode(true);
  const acceptedText = actResult.dataset.accepted;

  let mandate = null;
  const runs = {};

  function store() {
    remember(storageKey, { main: mandate && mandate.id });
  }

  async function goToWallet(button) {
    running(button, "Opening the wallet");
    rail("request", "busy", "Opening the wallet");
    let created;
    try {
      created = await call("POST", "api/mandates", { case: caseID });
    } catch (error) {
      idle(button, "Ask the wallet for a delegation");
      rail("request", "now", "Business wallet");
      const node = byId("request-result");
      node.hidden = false;
      node.className = "result fail";
      node.textContent = "The demo server returned an error. " + error.message;
      return;
    }
    mandate = created;
    store();
    location.assign(created.request.wallet_url);
  }

  function approval() {
    const node = byId("approval-result");
    const status = mandate.status;
    if (status === "pending") {
      step("approval", "now", "Waiting");
      banner(node, "wait", "The wallet waits for your answer.", "You have not answered the request yet.",
        para(link(mandate.request.wallet_url, "Open the wallet", "button small")));
      return;
    }
    if (status === "refused") {
      step("approval", "failed", "No delegation");
      const again = element("p");
      const button = element("button", "small", "Ask again");
      button.type = "button";
      button.addEventListener("click", () => goToWallet(button));
      again.append(button);
      let title = "The wallet refused the request.";
      if (mandate.error === "access_denied") {
        title = "You declined the request in the wallet.";
        rail("approval", "failed", "Declined");
      }
      banner(node, "fail", title, "The agent has no delegation.", mandate.error ? walletAnswer(mandate) : null, again);
      return;
    }
    step("approval", "done", "Approved");
    const delegation = (mandate.report && mandate.report.mandate) || {};
    const limit = delegation.limit ? " up to " + delegation.limit.amount + " " + delegation.limit.currency : "";
    const allowed = element("span");
    allowed.append("The agent may use ", element("code", "", (delegation.actions || []).join(", ")), limit + " until " + moment(mandate.expires) + ".");
    const facts = element("dl", "facts");
    if (delegation.agent) fact(facts, "Agent", delegation.agent.name + " of " + delegation.agent.operator);
    fact(facts, "Purpose", delegation.purpose);
    fact(facts, "Credential", selected.credential_name);
    fact(facts, "Signed at", moment(mandate.created));
    banner(node, "pass", "You approved the delegation in the wallet.", allowed,
      disclosure("Technical details: delegation and signature chain", facts, renderChain(mandate.report, true),
        element("p", "label", "Raw token of the wallet"), element("pre", "token", mandate.token || "")));
  }

  function showAction(scroll) {
    const run = runs.ok;
    if (!run) {
      actButton.hidden = false;
      actResult.hidden = true;
      step("action", "now");
      return;
    }
    actButton.hidden = true;
    if (run.outcome === "accepted") {
      step("action", "done", "Accepted");
      banner(actResult, "pass", acceptedText, "The verifier checked all 3 signatures.", miniChecks(run.report), ...runDetails(run));
    } else {
      step("action", "failed", "Refused");
      banner(actResult, "fail", run.verifier.name + " refused the request.", reasons(run.reasons), miniChecks(run.report), ...runDetails(run));
      actButton.hidden = false;
      idle(actButton, actButton.dataset.label);
    }
    if (scroll) actResult.scrollIntoView({ behavior: "smooth", block: "center" });
  }

  function showRefusal(card) {
    const run = runs[card.dataset.variant];
    const button = card.querySelector("button");
    const node = card.querySelector(".outcome");
    if (!run) return;
    idle(button, "Run again");
    if (run.outcome === "refused") {
      card.dataset.state = "done";
      banner(node, "fail", "Refused as expected", reasons(run.reasons), ...runDetails(run));
    } else if (run.outcome === "accepted") {
      card.dataset.state = "unexpected";
      banner(node, "fail", "Accepted. The verifier should have refused it.", "", ...runDetails(run));
    } else {
      delete card.dataset.state;
      banner(node, "wait", "The run stopped before the verifier decided.", reasons(run.reasons), ...runDetails(run));
    }
  }

  // revoked reports whether a run revoked the credential behind the
  // delegation. Every later run would then fail for that reason.
  function revoked() {
    return runs.revoked && runs.revoked.outcome === "refused";
  }

  function showLock() {
    const granted = mandate && mandate.status === "granted";
    if (!granted) {
      lock.hidden = false;
      lock.replaceChildren(lockText.cloneNode(true));
    } else if (revoked()) {
      lock.hidden = false;
      const text = element("span", "", "The credential behind this delegation is revoked. ");
      const again = link("cases/" + caseID, "Start again for a new delegation");
      again.addEventListener("click", (event) => {
        event.preventDefault();
        restart();
      });
      text.append(again, ".");
      lock.replaceChildren(text);
    } else {
      lock.hidden = true;
    }
    for (const card of cards) card.querySelector("button").disabled = !granted || revoked();
    actButton.disabled = !granted || revoked();
  }

  function render(scroll) {
    const finished = !mandate || mandate.status !== "pending";
    requestButton.hidden = mandate !== null;
    byId("request-hint").hidden = mandate !== null;
    byId("restart").hidden = mandate === null;
    if (!mandate) {
      step("request", "now", "Business wallet");
      step("approval", "todo", "In the wallet");
      step("action", "todo");
      showLock();
      refusalCount(cards, false);
      return;
    }
    const result = byId("request-result");
    result.className = "result pass";
    result.textContent = "The agent asked the wallet at " + moment(mandate.created) + ".";
    step("request", "done", "Sent at " + time(mandate.created));
    approval();
    if (mandate.status === "granted") {
      showAction(false);
      for (const card of cards) showRefusal(card);
      showLock();
      refusalCount(cards, Boolean(runs.ok));
    } else {
      showLock();
      step("action", "todo");
      refusalCount(cards, false);
    }
    if (scroll && finished) show(mandate.status === "granted" && !runs.ok ? byId("step-action") : byId("step-approval"));
  }

  function restart() {
    remember(storageKey, {});
    location.assign(api("cases/" + caseID));
  }

  function watch() {
    if (!mandate || mandate.status !== "pending") return;
    poll("api/mandates/" + encodeURIComponent(mandate.id), async (next) => {
      mandate = next;
      if (next.status === "pending") return;
      await loadRuns();
      render(false);
    });
  }

  async function load(id) {
    if (!id) return null;
    try {
      return await call("GET", "api/mandates/" + encodeURIComponent(id));
    } catch (error) {
      return null;
    }
  }

  async function loadRuns() {
    for (const id of mandate.runs || []) {
      try {
        const run = await call("GET", "api/runs/" + encodeURIComponent(id));
        runs[run.variant] = run;
      } catch {
        continue;
      }
    }
  }

  async function run(variant) {
    try {
      return await call("POST", "api/mandates/" + encodeURIComponent(mandate.id) + "/runs", { variant });
    } catch (error) {
      return { variant, outcome: "error", reasons: ["The demo server returned an error. " + error.message], verifier: { name: "" }, steps: [] };
    }
  }

  requestButton.addEventListener("click", () => goToWallet(requestButton));

  actButton.dataset.label = actButton.textContent;
  actButton.addEventListener("click", async () => {
    running(actButton, "The agent is working");
    rail("action", "busy", "Agent at work");
    banner(actResult, "wait", "The agent shows the delegation to the verifier.", "");
    runs.ok = await run("ok");
    render(false);
    showAction(true);
  });

  for (const card of cards) {
    const button = card.querySelector("button");
    button.addEventListener("click", async () => {
      running(button, "Running");
      rail("refusals", "busy");
      runs[card.dataset.variant] = await run(card.dataset.variant);
      render(false);
    });
  }

  byId("restart").addEventListener("click", (event) => {
    event.preventDefault();
    restart();
  });

  (async () => {
    const returned = new URL(location.href).searchParams.get("mandate");
    mandate = await load(returned || remembered(storageKey).main);
    if (mandate && mandate.status === "granted") await loadRuns();
    store();
    render(Boolean(returned));
    if (!mandate && location.hash.startsWith("#refusal-")) {
      const target = document.querySelector(location.hash);
      if (target && target.dataset.variant) {
        const note = target.querySelector(".outcome");
        note.hidden = false;
        note.className = "outcome lock";
        const text = element("span", "", "This refusal runs after steps 1 and 2. ");
        text.append(link("#step-request", "Start with step 1"), ".");
        note.replaceChildren(text);
      }
    }
    watch();
  })();
}

/* Scenario page */

function scenarioPage(scenarioID) {
  const storageKey = "ebw-dev:scenario:" + scenarioID;
  const known = remembered(storageKey);
  const cards = [...document.querySelectorAll(".refusal")];
  const requests = {};
  const base = "api/scenarios/" + encodeURIComponent(scenarioID) + "/requests";
  const asker = document.body.dataset.asker;
  const accepted = byId("act-result").dataset.accepted;
  const done = byId("act-result").dataset.done;

  async function load(id) {
    try {
      return await call("GET", base + "/" + encodeURIComponent(id));
    } catch (error) {
      if (error.status === 404) return null;
      throw error;
    }
  }

  async function goToWallet(button, variant) {
    running(button, "Opening the wallet");
    if (variant === "ok") rail("request", "busy", "Opening the wallet");
    else rail("refusals", "busy");
    let request;
    try {
      request = await call("POST", base, { variant });
    } catch (error) {
      idle(button, "Ask the wallet");
      const node = variant === "ok" ? byId("request-result") : document.querySelector('.refusal[data-variant="' + variant + '"] .outcome');
      node.hidden = false;
      node.className = (variant === "ok" ? "result" : "outcome") + " fail";
      node.textContent = "The demo server returned an error. " + error.message;
      render(false);
      return;
    }
    known[variant] = request.id;
    remember(storageKey, known);
    location.assign(request.request.wallet_url);
  }

  function details(request) {
    const parts = [];
    for (const presentation of request.presentations || []) {
      parts.push(disclosure("Technical details: checks of " + inSentence(presentation.name), renderChain(presentation.report, true, walletLinkTitles)));
    }
    parts.push(disclosure("Technical details: request object",
      codeBlock(JSON.stringify(request.request.decoded, null, 2), request.request_decoder_url, "Open the request in the decoder"),
      element("p", "label", "Signed request object"), element("pre", "token", request.request.request_object)));
    for (const presentation of request.presentations || []) {
      parts.push(disclosure("Technical details: presented " + inSentence(presentation.name),
        codeBlock(JSON.stringify(presentation.report.credential || {}, null, 2)),
        element("p", "label", "Raw token"),
        codeBlock(presentation.token, presentation.decoder_url, "Open the token in the decoder")));
    }
    return parts;
  }

  function learned(request) {
    const list = element("dl", "learned");
    for (const entry of request.learned || []) fact(list, entry.name, entry.value);
    return list;
  }

  function notes(request) {
    return (request.notes || []).map((note) => element("p", "", note));
  }

  function checks(request) {
    const list = element("div");
    for (const presentation of request.presentations || []) {
      if ((request.presentations || []).length > 1) list.append(element("p", "label", presentation.name));
      list.append(miniChecks(presentation.report, walletLinkTitles));
    }
    return list;
  }

  function again(variant, label) {
    const box = element("p");
    const button = element("button", "small", label);
    button.type = "button";
    button.addEventListener("click", () => goToWallet(button, variant));
    box.append(button);
    return box;
  }

  function showMain() {
    const request = requests.ok;
    const approvalNode = byId("approval-result");
    const actNode = byId("act-result");
    byId("request").hidden = Boolean(request);
    byId("request-hint").hidden = Boolean(request);
    byId("restart").hidden = !Object.keys(requests).length;
    if (!request) {
      step("request", "now", "Business wallet");
      step("approval", "todo", "In the wallet");
      step("action", "todo");
      return;
    }
    const result = byId("request-result");
    result.className = "result pass";
    result.textContent = asker + " asked the wallet at " + moment(request.created) + ".";
    step("request", "done", "Sent at " + time(request.created));
    if (request.status === "pending") {
      step("approval", "now", "Waiting");
      step("action", "todo");
      banner(approvalNode, "wait", "The wallet waits for your answer.", "You have not answered the request yet.",
        link(request.request.wallet_url, "Open the wallet", "button small"));
      return;
    }
    if (request.error) {
      step("approval", "failed", request.error === "access_denied" ? "Declined" : "Error");
      step("action", "todo");
      const title = request.error === "access_denied" ? "You declined the request in the wallet." : "The wallet returned an error.";
      banner(approvalNode, "fail", title, asker + " got no credential.", walletAnswer(request), again("ok", "Ask again"));
      return;
    }
    step("approval", "done", "Approved");
    banner(approvalNode, "pass", "You approved the presentation in the wallet.", "");
    if (request.status === "accepted") {
      step("action", "done", done);
      banner(actNode, "pass", accepted, learned(request), checks(request), ...notes(request), ...details(request));
    } else {
      step("action", "failed", "Refused");
      banner(actNode, "fail", asker + " refused the presentation.", reasons(request.reasons), checks(request), ...notes(request), ...details(request));
    }
  }

  function showRefusal(card) {
    const request = requests[card.dataset.variant];
    const node = card.querySelector(".outcome");
    const button = card.querySelector("button");
    if (!request) return;
    idle(button, "Ask the wallet again");
    if (request.status === "pending") {
      delete card.dataset.state;
      banner(node, "wait", "The wallet waits for your answer.", "", link(request.request.wallet_url, "Open the wallet", "button small"));
    } else if (request.error === "access_denied") {
      card.dataset.state = "failed";
      banner(node, "fail", "You declined the request in the wallet.", asker + " got nothing. This refusal did not run.", walletAnswer(request));
    } else if (request.error) {
      card.dataset.state = "failed";
      banner(node, "fail", "The wallet returned an error.", walletAnswer(request));
    } else if (request.status === "refused") {
      card.dataset.state = "done";
      banner(node, "fail", "Refused as expected", reasons(request.reasons), ...notes(request), ...details(request));
    } else if (request.status === "stopped") {
      delete card.dataset.state;
      banner(node, "wait", "The request stopped before " + asker + " decided.", reasons(request.reasons), ...notes(request), ...details(request));
    } else {
      card.dataset.state = "unexpected";
      banner(node, "fail", "Accepted. " + asker + " should have refused it.", "", ...notes(request), ...details(request));
    }
  }

  function render(scrollTo) {
    showMain();
    for (const card of cards) showRefusal(card);
    refusalCount(cards, requests.ok && requests.ok.status === "accepted");
    if (scrollTo === "ok" && requests.ok) show(byId(requests.ok.status === "accepted" ? "step-action" : "step-approval"));
    else if (scrollTo) show(document.querySelector('.refusal[data-variant="' + scrollTo + '"]'));
  }

  function watch(variant) {
    const request = requests[variant];
    if (!request || request.status !== "pending") return;
    poll(base + "/" + encodeURIComponent(request.id), (next) => {
      requests[variant] = next;
      if (next.status !== "pending") render(false);
    });
  }

  byId("request").addEventListener("click", (event) => goToWallet(event.currentTarget, "ok"));
  for (const card of cards) {
    const button = card.querySelector("button");
    button.addEventListener("click", () => goToWallet(button, card.dataset.variant));
  }
  byId("restart").addEventListener("click", (event) => {
    event.preventDefault();
    remember(storageKey, {});
    location.assign(api("scenarios/" + scenarioID));
  });

  (async () => {
    const returned = new URL(location.href).searchParams.get("request");
    let scrollTo = null;
    if (returned) {
      const request = await load(returned).catch(() => null);
      if (request) {
        known[request.variant] = request.id;
        requests[request.variant] = request;
        scrollTo = request.variant;
      }
    }
    for (const [variant, id] of Object.entries(known)) {
      if (requests[variant]) continue;
      let request;
      try {
        request = await load(id);
      } catch (error) {
        continue;
      }
      if (request) requests[variant] = request;
      else delete known[variant];
    }
    remember(storageKey, known);
    render(scrollTo);
    for (const variant of Object.keys(requests)) watch(variant);
  })();
}

/* Wallet holdings: map and issuer page */

// inSentence writes a credential name for the middle of a sentence. Only the
// abbreviation EU keeps its capitals.
function inSentence(name) {
  return /^[A-Z][a-z]/.test(name) ? name[0].toLowerCase() + name.slice(1) : name;
}

function missingNames(list) {
  return list.map((holding) => inSentence(holding.name)).join(" and ");
}

function validCopies(holding) {
  return holding.credentials.filter((credential) => credential.valid);
}

// latestExpiry returns "" when a copy has no end date, because that copy never
// expires.
function latestExpiry(credentials) {
  if (!credentials.length || credentials.some((credential) => !credential.expires_at)) return "";
  return credentials.map((credential) => credential.expires_at).sort().pop();
}

async function holdings() {
  return call("GET", "api/wallet/credentials");
}

async function mapPage() {
  const node = byId("holdings");
  let list;
  try {
    list = await holdings();
  } catch (error) {
    node.className = "holdings missing";
    node.textContent = "The wallet is not reachable";
    return;
  }
  const missing = list.filter((holding) => !validCopies(holding).length);
  if (!missing.length) {
    node.className = "holdings ok";
    node.textContent = "Holds all " + list.length + " credentials";
    return;
  }
  node.className = "holdings missing";
  node.textContent = "No valid " + missingNames(missing);
  const issuer = byId("issuer-node");
  issuer.querySelector(".tag").textContent = "Needed now";
  issuer.querySelector("p").textContent = "The wallet has no valid " + missingNames(missing) + (missing.length === 1 ? ". The issuer adds it again." : ". The issuer adds them again.");
}

function issuerPage() {
  const cards = [...document.querySelectorAll(".offer")];
  const lead = byId("issuer-lead");
  const waiting = {};
  let polling = null;
  let deadline = 0;

  function cardOf(configuration) {
    return cards.find((card) => card.dataset.configuration === configuration);
  }

  function heldText(card, holding) {
    const node = card.querySelector(".held");
    node.hidden = false;
    const valid = validCopies(holding);
    if (valid.length) {
      node.className = "held ok";
      const expiry = latestExpiry(valid);
      node.textContent = expiry ? "In the wallet. Valid until " + day(expiry) + "." : "In the wallet.";
    } else if (holding.credentials.length) {
      node.className = "held missing";
      node.textContent = "The wallet holds no valid copy.";
    } else {
      node.className = "held missing";
      node.textContent = "Not in the wallet.";
    }
  }

  function showLead(list) {
    const missing = list.filter((holding) => !validCopies(holding).length);
    lead.textContent = missing.length
      ? "The wallet has no valid " + missingNames(missing) + (missing.length === 1 ? ". Add it here." : ". Add them here.")
      : "The wallet holds all " + list.length + " credentials. You need the issuer only after you delete one in the wallet.";
  }

  async function refresh() {
    let list;
    try {
      list = await holdings();
    } catch (error) {
      lead.textContent = "The wallet is not reachable. " + error.message;
      return;
    }
    showLead(list);
    for (const holding of list) {
      const card = cardOf(holding.configuration);
      if (!card) continue;
      heldText(card, holding);
      const before = waiting[holding.configuration];
      if (!before) continue;
      const added = holding.credentials.filter((credential) => !before.ids.includes(credential.id));
      if (!added.length) continue;
      delete waiting[holding.configuration];
      card.dataset.state = "done";
      idle(card.querySelector("button"), "Add to the wallet");
      const expiry = latestExpiry(added);
      banner(card.querySelector(".outcome"), "pass", "The wallet holds the new credential.",
        expiry ? "Valid until " + day(expiry) + ". You find it in the wallet under Credentials." : "You find it in the wallet under Credentials.",
        ...before.details);
      card.scrollIntoView({ behavior: "smooth", block: "nearest" });
    }
    if (!Object.keys(waiting).length) stop();
  }

  function stop() {
    clearInterval(polling);
    polling = null;
  }

  function poll() {
    deadline = Date.now() + 10 * 60 * 1000;
    if (polling) return;
    polling = setInterval(() => {
      if (Date.now() > deadline) {
        for (const configuration of Object.keys(waiting)) {
          const card = cardOf(configuration);
          idle(card.querySelector("button"), "Add to the wallet");
          banner(card.querySelector(".outcome"), "fail", "The wallet did not add the credential in 10 minutes.", "Create a new offer to try again.", ...waiting[configuration].details);
          delete waiting[configuration];
        }
        stop();
        return;
      }
      refresh();
    }, 2000);
  }

  for (const card of cards) {
    const button = card.querySelector("button");
    button.addEventListener("click", async () => {
      const configuration = card.dataset.configuration;
      // Browsers block a tab that opens after the offer request, because it
      // does not count as a user action. So the tab opens in the click handler.
      const tab = window.open("", "_blank");
      running(button, "Opening the wallet");
      let list;
      let offer;
      try {
        list = await holdings();
        offer = await call("POST", "api/offers", { configuration });
      } catch (error) {
        if (tab) tab.close();
        idle(button, "Add to the wallet");
        banner(card.querySelector(".outcome"), "fail", "The demo server returned an error.", error.message);
        return;
      }
      const holding = list.find((entry) => entry.configuration === configuration) || { credentials: [] };
      const open = link(offer.wallet_url, "Open the offer in the wallet", "button small");
      open.target = "_blank";
      const details = [disclosure("Technical details: credential offer",
        element("p", "label", "Offer URI"), element("pre", "token", offer.scheme_uri),
        codeBlock(JSON.stringify(offer.offer, null, 2), offer.decoder_url, "Open the offer in the decoder"))];
      waiting[configuration] = { ids: holding.credentials.map((credential) => credential.id), details };
      if (tab) {
        tab.opener = null;
        tab.location.href = offer.wallet_url;
      }
      delete card.dataset.state;
      button.replaceChildren(element("span", "spinner"), "Waiting for the wallet");
      banner(card.querySelector(".outcome"), "wait",
        tab ? "The offer is open in the wallet tab." : "Your browser blocked the new tab.",
        tab ? "Add the credential there. This page shows when it arrives." : "Open the offer with this button. This page shows when the credential arrives.",
        para(open), ...details);
      poll();
    });
  }

  addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible" && Object.keys(waiting).length) refresh();
  });
  refresh();
}

async function trustPanel() {
  const panel = byId("trust");
  try {
    const summary = await call("GET", "api/trust");
    const list = element("dl", "facts");
    fact(list, "Source", summary.source, true);
    fact(list, "Loaded at", instant(summary.loaded_at));
    for (const entry of summary.lists) {
      fact(list, entry.id, entry.issuers.length ? entry.issuers.join(", ") : "No issuers");
    }
    panel.replaceChildren(list);
  } catch {
    panel.textContent = "The trusted lists of the wallet did not load. Reload the page to try again.";
  }
}

// A page from the back and forward cache shows an old state. The wallet
// answered in the meantime, so the page loads again.
addEventListener("pageshow", (event) => {
  if (event.persisted) location.reload();
});

(async () => {
  try {
    config = await call("GET", "api/config");
  } catch (error) {
    config = {};
  }
  const page = document.body.dataset.page;
  if (page === "case") casePage(document.body.dataset.case);
  if (page === "scenario") scenarioPage(document.body.dataset.scenario);
  if (page === "issuer") issuerPage();
  if (page === "map") mapPage();
  if (byId("trust")) trustPanel();
})();
