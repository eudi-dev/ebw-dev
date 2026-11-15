// Walks the business wallet and the demo in a real browser.
// Usage: node scripts/browser-check.cjs <screenshot directory>
// It fails on a console error, on an HTTP error status and on a failed step.
const fs = require("node:fs");
const path = require("node:path");

const { chromium } = require(process.env.PLAYWRIGHT_MODULE || "playwright");

const WALLET = process.env.EBW_DEV_WALLET_URL || "http://localhost:28085";
const DEMO = process.env.EBW_DEV_PUBLIC_URL || "http://localhost:28090";
const shots = process.argv[2];
if (!shots) {
  console.error("usage: browser-check.cjs <screenshot directory>");
  process.exit(2);
}
fs.mkdirSync(shots, { recursive: true });

const CATALOGUE = ["Business wallet owner identification data", "EU power of attorney", "Employee authorisation"];
const STATUS_CHECK = "status";

const problems = [];
let context;
let shot = 0;

function check(condition, message) {
  if (!condition) throw new Error(message);
}

async function open(url) {
  const page = await context.newPage();
  page.setDefaultTimeout(10000);
  page.on("console", (message) => {
    if (message.type() === "error") problems.push(`console error on ${page.url()}: ${message.text()}`);
  });
  page.on("pageerror", (error) => problems.push(`script error on ${page.url()}: ${error.message}`));
  page.on("response", (response) => {
    if (response.status() >= 400) problems.push(`HTTP ${response.status()} for ${response.request().method()} ${response.url()}`);
  });
  if (url) await page.goto(url);
  return page;
}

async function capture(page, name) {
  shot += 1;
  await page.screenshot({ path: path.join(shots, `${String(shot).padStart(2, "0")}-${name}.png`) });
}

async function api(method, url, data) {
  const response = await context.request.fetch(url, { method, data });
  check(response.ok(), `${method} ${url} answered ${response.status()}: ${await response.text()}`);
  return response.json();
}

// registrar checks that the registrar of the wallet lists the parties of the
// demo and that the catalogue holds the 3 credential types.
async function registrar() {
  const list = await context.request.get(WALLET + "/api/registrar/wrp");
  check(list.ok(), `GET /api/registrar/wrp answered ${list.status()}`);
  const payload = JSON.parse(Buffer.from((await list.text()).split(".")[1], "base64url"));
  const parties = payload.data.map((party) => party.tradeName);
  for (const name of ["Acme Logistics", "Bolt Supplies"]) check(parties.includes(name), `the registrar lists ${parties.join(", ")}`);
  const listed = (await api("GET", WALLET + "/api/catalog/attestations")).map((entry) => entry.name).sort();
  check(JSON.stringify(listed) === JSON.stringify([...CATALOGUE].sort()), `the catalogue lists ${listed.join(", ")}`);
}

async function run(mandateID, variant) {
  return api("POST", `${DEMO}/api/mandates/${mandateID}/runs`, { variant });
}

function failedChecks(run) {
  if (!run.report) return [];
  return run.report.links
    .flatMap((link) => link.checks)
    .filter((item) => item.result === "fail")
    .map((item) => item.name);
}

// revokeInWallet revokes the credential behind the delegation, which the
// wallet finds by its status list entry, with the button on its card.
async function revokeInWallet(credential) {
  const entry = credential.status.status_list;
  const credentials = await api("GET", WALLET + "/api/credentials");
  const presented = credentials.find((held) => held.status && held.status.uri === entry.uri && held.status.idx === entry.idx);
  check(presented && presented.status.status === 0, `the wallet holds no valid credential at ${entry.uri} ${entry.idx}`);
  const page = await open(WALLET);
  // With a long list the activity panel of the wallet covers the card, and
  // a pointer click would hit the panel.
  await page.locator(`#revoke-${presented.id}`).dispatchEvent("click");
  // The wallet asks first when the credential has active delegations.
  const dialog = page.locator("div", { has: page.getByText(/^Revoke .+\?$/) }).filter({ has: page.getByRole("button", { name: "Cancel" }) }).last();
  const confirm = dialog.getByRole("button", { name: "Revoke", exact: true });
  if (await confirm.waitFor({ timeout: 3000 }).then(() => true, () => false)) await confirm.click();
  for (let i = 0; i < 40; i += 1) {
    const now = (await api("GET", WALLET + "/api/credentials")).find((credential) => credential.id === presented.id);
    if (now.status.status === 1) break;
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  await capture(page, "revoked-in-wallet");
  await page.close();
  const now = (await api("GET", WALLET + "/api/credentials")).find((credential) => credential.id === presented.id);
  check(now.status.status === 1, `the wallet did not revoke ${presented.id}`);
}

const WIDTHS = [360, 420, 768, 1280];
const SCHEMES = ["light", "dark"];

// overflow lists the elements wider than their box. Every details element
// is open, because the technical details hold the longest text.
async function overflow(page) {
  return page.evaluate(() => {
    const opened = [...document.querySelectorAll("details:not([open])")];
    for (const details of opened) details.open = true;
    const found = [];
    const root = document.documentElement;
    if (root.scrollWidth > root.clientWidth) found.push(`page ${root.scrollWidth} > ${root.clientWidth}`);
    for (const node of document.querySelectorAll("body *")) {
      const style = getComputedStyle(node);
      // A pre with its own scroll bar may be wider than its box.
      if (style.overflowX !== "visible" || style.display === "inline" || style.display === "none" || !node.clientWidth) continue;
      if (node.scrollWidth > node.clientWidth + 1) {
        const name = node.tagName.toLowerCase() + (node.id ? "#" + node.id : "") + (node.className ? "." + String(node.className).trim().split(/\s+/).join(".") : "");
        found.push(`${name} ${node.scrollWidth} > ${node.clientWidth}: ${node.textContent.trim().slice(0, 60)}`);
      }
    }
    for (const details of opened) details.open = false;
    return found.slice(0, 5);
  });
}

// states takes a full page screenshot of a demo page in every width and
// colour scheme and checks each for overflowing text.
async function states(page, name) {
  for (const scheme of SCHEMES) {
    await page.emulateMedia({ colorScheme: scheme });
    for (const width of WIDTHS) {
      await page.setViewportSize({ width, height: 900 });
      await page.waitForTimeout(150);
      for (const problem of await overflow(page)) problems.push(`overflow on ${name} at ${width} ${scheme}: ${problem}`);
      // A full page shot keeps the scroll offset, so a sticky element would
      // show at that offset instead of its place in the layout.
      await page.evaluate(() => scrollTo(0, 0));
      await page.screenshot({ path: path.join(shots, `${name}-${width}-${scheme}.png`), fullPage: true });
    }
  }
  await page.emulateMedia({ colorScheme: "light" });
  await page.setViewportSize({ width: 1280, height: 1000 });
}

// answer approves or declines the open request in the wallet and waits for
// the way back to the demo page.
async function answer(page, choice, back) {
  await page.locator("#consent-approve").waitFor();
  await page.locator(`#consent-${choice}`).click();
  await page.waitForURL((url) => url.href.startsWith(back));
}

// caseRequest asks the wallet for the delegation with the given button of the
// case page and answers in the wallet.
async function caseRequest(page, caseID, choice, button = page.locator("#request")) {
  await button.click();
  await page.locator("#consent-overlay").getByText("Acme agent service", { exact: true }).waitFor();
  await capture(page, `consent-${caseID}-${choice}`);
  await answer(page, choice, `${DEMO}/cases/${caseID}?mandate=`);
  await page.locator("#approval-result:not([hidden])").waitFor();
  const id = new URL(page.url()).searchParams.get("mandate");
  return api("GET", `${DEMO}/api/mandates/${id}`);
}

async function text(locator) {
  return (await locator.innerText()).replace(/\s+/g, " ");
}

async function runRefusal(card) {
  await card.locator("button").click();
  await card.locator("button", { hasText: "Run again" }).waitFor({ timeout: 30000 });
  check((await card.getAttribute("data-state")) === "done", `refusal ${await card.getAttribute("data-variant")}: ${await text(card.locator(".outcome"))}`);
}

async function caseFlow(caseID) {
  const page = await open(`${DEMO}/cases/${caseID}`);
  await states(page, `case-${caseID}-start`);
  const declined = await caseRequest(page, caseID, "deny");
  check(declined.status === "refused" && declined.error === "access_denied", `declined delegation: ${declined.status} ${declined.error}`);
  check((await text(page.locator("#approval-result"))).includes("You declined the request in the wallet."), "the case page does not show the decline");
  await states(page, `case-${caseID}-declined`);
  const granted = await caseRequest(page, caseID, "approve", page.locator("#approval-result button", { hasText: "Ask again" }));
  check(granted.status === "granted", `delegation of ${caseID}: ${granted.status} ${granted.error_description}`);
  check((await text(page.locator("#approval-result"))).includes("You approved the delegation in the wallet."), "the case page does not show the approval");
  check((await text(page.locator('.rail li[data-node="refusals"] .who'))) === "5 refusals", "the rail does not count 5 refusals");
  await states(page, `case-${caseID}-approved`);

  await page.locator("#act").click();
  await page.locator("#act-result.pass, #act-result.fail").waitFor({ timeout: 30000 });
  check(await page.locator("#act-result.pass").isVisible(), `run of ${caseID}: ${await text(page.locator("#act-result"))}`);
  await states(page, `case-${caseID}-accepted`);

  for (const variant of ["over_limit", "expired", "wrong_verifier", "tampered"]) {
    await runRefusal(page.locator(`#refusal-${variant}`));
  }
  check((await text(page.locator('.rail li[data-node="refusals"] .who'))) === "4 of 5 done", "the rail does not count 4 of 5 refusals as done");
  await runRefusal(page.locator("#refusal-revoked"));
  check(await page.locator("#refusals-lock").isVisible(), "no lock after the revoked run");
  check(await page.locator("#act").isDisabled(), "the action stays open after the revoked run");
  check(await page.locator("#refusal-over_limit button").isDisabled(), "the refusals stay open after the revoked run");
  await states(page, `case-${caseID}-refusals`);

  await page.locator("#restart").click();
  await page.waitForURL(`${DEMO}/cases/${caseID}`);
  const again = await caseRequest(page, caseID, "approve");
  check(again.status === "granted", `delegation of ${caseID} on the new credential: ${again.status} ${again.error_description}`);
  await page.locator("#act").click();
  await page.locator("#act-result.pass").waitFor({ timeout: 30000 });
  await page.close();
}

async function demo() {
  const home = await open(DEMO + "/");
  await home.locator("#holdings.ok, #holdings.missing").waitFor();
  await states(home, "map");
  const config = await home.evaluate(async () => (await fetch("api/config")).json());
  check(config.agent_client_id.startsWith("x509_hash:"), `agent_client_id is ${config.agent_client_id}`);
  check((await home.locator(".to-wallet").count()) === 0, "the map has the wallet pill in the header");
  await home.locator(".node.first").click();
  await home.waitForURL(`${DEMO}/cases/supplier`);
  await home.close();

  for (const caseID of ["supplier", "internal"]) await caseFlow(caseID);

  const lost = await open(`${DEMO}/cases/supplier#refusal-wrong_verifier`);
  await lost.locator("#refusal-wrong_verifier .outcome.lock").waitFor();
  await states(lost, "case-supplier-refusal-link");
  await lost.close();

  const page = await open(`${DEMO}/cases/supplier`);
  const granted = await caseRequest(page, "supplier", "approve");
  await page.close();
  await revokeInWallet(granted.report.credential);
  const refusedRun = await run(granted.id, "ok");
  check(refusedRun.outcome === "refused" && failedChecks(refusedRun).includes(STATUS_CHECK), `run after the revocation in the wallet: ${refusedRun.outcome} ${refusedRun.reasons}`);
  // The revoked run leaves the wallet with a fresh credential.
  await run(granted.id, "revoked");
}

// issuer adds each credential with the button of the issuer page. The offer
// opens in a new tab and the page waits for the credential.
async function issuer() {
  const page = await open(`${DEMO}/issuer`);
  await page.locator(".offer .held:not([hidden])").first().waitFor();
  await states(page, "issuer");
  for (const configuration of ["ebwoid", "eu-poa", "employee-authorisation"]) {
    const card = page.locator(`.offer[data-configuration="${configuration}"]`);
    const [tab] = await Promise.all([page.waitForEvent("popup"), card.locator("button").click()]);
    await tab.locator("#consent-approve").waitFor();
    if (configuration === "eu-poa") {
      await capture(tab, "issuer-consent");
      await states(page, "issuer-waiting");
    }
    await tab.locator("#consent-approve").click();
    await card.locator(".outcome.pass").waitFor({ timeout: 30000 });
    await tab.close();
  }
  await states(page, "issuer-added");
  await page.close();
}

// scenarioRequest asks the wallet with a button of the scenario page and
// answers in the wallet.
async function scenarioRequest(page, id, button, choice) {
  await button.click();
  await page.locator("#consent-overlay").waitFor();
  await capture(page, `consent-${id}-${choice}`);
  await answer(page, choice, `${DEMO}/scenarios/${id}?request=`);
  const request = new URL(page.url()).searchParams.get("request");
  return api("GET", `${DEMO}/api/scenarios/${id}/requests/${request}`);
}

async function scenarioFlow(id) {
  const page = await open(`${DEMO}/scenarios/${id}`);
  await states(page, `scenario-${id}-start`);
  const declined = await scenarioRequest(page, id, page.locator("#request"), "deny");
  check(declined.error === "access_denied", `${id} declined: ${declined.status} ${declined.error}`);
  await page.locator("#approval-result.fail").waitFor();
  await states(page, `scenario-${id}-declined`);
  const accepted = await scenarioRequest(page, id, page.locator("#approval-result button", { hasText: "Ask again" }), "approve");
  check(accepted.status === "accepted", `${id} ok: ${accepted.status} ${accepted.reasons}`);
  await page.locator("#act-result.pass").waitFor();
  await states(page, `scenario-${id}-accepted`);
  const variants = await page.locator(".refusal").evaluateAll((all) => all.map((card) => card.dataset.variant));
  for (const [index, variant] of variants.entries()) {
    const card = page.locator(`.refusal[data-variant="${variant}"]`);
    if (index === 0) {
      const skipped = await scenarioRequest(page, id, card.locator("button"), "deny");
      check(skipped.error === "access_denied", `${id} ${variant} declined: ${skipped.status}`);
      await card.locator(".outcome.fail").waitFor();
      check((await text(card.locator(".outcome"))).includes("This refusal did not run."), `${id} ${variant}: the declined refusal shows ${await text(card.locator(".outcome"))}`);
    }
    const refused = await scenarioRequest(page, id, card.locator("button"), "approve");
    check(refused.status === "refused", `${id} ${variant}: ${refused.status} ${refused.reasons}`);
    await page.waitForFunction((name) => document.querySelector(`.refusal[data-variant="${name}"]`).dataset.state === "done", variant);
  }
  check(await page.locator("#act-result.pass").isVisible(), `${id}: the main result is gone after the refusals`);
  if (variants.length) await states(page, `scenario-${id}-refusals`);
  await page.close();
}

// missing shows the map and the issuer page for a wallet without a valid EU
// power of attorney. The check takes the copies out of the real answer,
// because the demo keeps a valid copy in the wallet.
async function missing() {
  for (const [url, name] of [[DEMO + "/", "map-missing"], [DEMO + "/issuer", "issuer-missing"]]) {
    const page = await open();
    await page.route("**/api/wallet/credentials", async (route) => {
      const response = await route.fetch();
      const holdings = await response.json();
      for (const holding of holdings) if (holding.configuration === "eu-poa") holding.credentials = [];
      await route.fulfill({ response, json: holdings });
    });
    await page.goto(url);
    await page.locator("#holdings.missing, .offer .held.missing").first().waitFor();
    await states(page, name);
    await page.close();
  }
}

async function scenarios() {
  await issuer();
  await scenarioFlow("poa");
  await scenarioFlow("kyb");
  await missing();
  const home = await open(DEMO + "/");
  await home.locator("#holdings.ok").waitFor();
  await home.close();
}

async function main() {
  const browser = await chromium.launch();
  // The links of the wallet point at its HTTPS port with a certificate of the
  // wallet CA.
  context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1280, height: 1000 } });
  const steps = [
    ["registrar", registrar],
    ["cases", demo],
    ["issuer and scenarios", scenarios],
  ];
  for (const [name, step] of steps) {
    try {
      await step();
      console.log(`ok      ${name}`);
    } catch (error) {
      problems.push(`${name}: ${error.message.split("\n")[0]}`);
      console.log(`FAILED  ${name}`);
      for (const page of context.pages()) await capture(page, "failed").catch(() => {});
    }
    for (const page of context.pages()) await page.close();
  }
  await browser.close();
  if (problems.length > 0) {
    console.error(`\n${problems.length} problems:\n- ${problems.join("\n- ")}`);
    process.exit(1);
  }
  console.log(`\nNo problems. Screenshots are in ${shots}.`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
