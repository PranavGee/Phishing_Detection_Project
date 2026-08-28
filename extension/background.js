/**
 * PhishGuard service worker.
 *
 * Responsibilities:
 *   1. Score every top-level navigation before the page is shown, on-device.
 *   2. Redirect flagged navigations to the full-page warning interstitial.
 *   3. Answer scoring requests from the content script, popup and warning page.
 *
 * Nothing is sent anywhere: the model runs locally from lib/model.json. An
 * optional API endpoint can be enabled in Options for a second opinion from
 * the larger Random Forest model.
 */

importScripts("lib/features.js", "lib/model.js", "lib/allowlist.js");

/* --------------------------------------------------------------------- */
/* settings                                                               */
/* --------------------------------------------------------------------- */
const DEFAULTS = {
  enabled: true,
  // Blocking threshold. Deliberately stricter than the 0.5 used for reporting:
  // at 0.70 the model's precision is ~93% on the held-out set, so far fewer
  // real sites are interrupted. Tunable in Options.
  threshold: 0.7,
  useAllowlist: true,
  highlightLinks: true,
  userAllowlist: [],
  apiUrl: "",
  useApi: false,
  stats: { scanned: 0, blocked: 0, proceeded: 0 }
};

let settings = { ...DEFAULTS };

async function loadSettings() {
  const stored = await chrome.storage.local.get(DEFAULTS);
  settings = { ...DEFAULTS, ...stored };
  return settings;
}

async function saveSettings(patch) {
  settings = { ...settings, ...patch };
  await chrome.storage.local.set(patch);
  return settings;
}

async function bumpStat(key, by = 1) {
  // Read straight from storage rather than from the in-memory copy: several
  // navigation events can be in flight at once, and a stale copy would drop
  // the other handlers' increments.
  const { stats } = await chrome.storage.local.get({ stats: DEFAULTS.stats });
  const next = { ...stats, [key]: (stats[key] || 0) + by };
  await saveSettings({ stats: next });
}

/* --------------------------------------------------------------------- */
/* scoring                                                                */
/* --------------------------------------------------------------------- */
const SKIP_SCHEMES = /^(chrome|chrome-extension|about|edge|moz-extension|file|data|blob|view-source|devtools):/i;
const LOCAL_HOSTS = /^(localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|\[::1\]|.*\.local)$/i;

function isScannable(url) {
  return typeof url === "string" && url.length > 0 && !SKIP_SCHEMES.test(url);
}

function isAllowlisted(hostname) {
  if (!settings.useAllowlist) return false;
  if (!hostname) return false;
  if (LOCAL_HOSTS.test(hostname)) return true;
  if (self.PhishAllowlist.isBuiltInTrusted(hostname)) return true;
  const registrable = self.PhishAllowlist.registrableDomain(hostname);
  return (settings.userAllowlist || []).some(
    (d) => d === hostname || d === registrable
  );
}

/** Score one URL and return a verdict object. */
async function scoreUrl(url) {
  await self.PhishModel.load();
  const verdict = self.PhishModel.scoreUrl(url, settings.threshold);
  verdict.allowlisted = isAllowlisted(verdict.hostname);
  if (verdict.allowlisted) {
    verdict.is_phishing = false;
    verdict.reason_skipped = "allowlisted";
  }
  verdict.risk_score = Math.round(verdict.probability * 100);
  return verdict;
}

/**
 * Optional second opinion from the web app's Random Forest model.
 * Never blocks the local verdict — if the server is slow or down we keep
 * whatever the on-device model decided.
 */
async function scoreWithApi(url) {
  if (!settings.useApi || !settings.apiUrl) return null;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 2500);
  try {
    const res = await fetch(settings.apiUrl.replace(/\/$/, "") + "/api/predict", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, threshold: settings.threshold }),
      signal: controller.signal
    });
    if (!res.ok) return null;
    const body = await res.json();
    body.source = "api";
    return body;
  } catch (e) {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

/* --------------------------------------------------------------------- */
/* bypass list ("Proceed with this Website")                              */
/* --------------------------------------------------------------------- */
/** Session-scoped so a bypass never outlives the browser session. */
async function getBypassed() {
  const { bypassed } = await chrome.storage.session.get({ bypassed: [] });
  return new Set(bypassed);
}

async function addBypass(url) {
  const set = await getBypassed();
  set.add(url);
  set.add(self.PhishFeatures.getHostname(url));
  await chrome.storage.session.set({ bypassed: [...set] });
}

async function isBypassed(url) {
  const set = await getBypassed();
  return set.has(url) || set.has(self.PhishFeatures.getHostname(url));
}

/* --------------------------------------------------------------------- */
/* badge                                                                  */
/* --------------------------------------------------------------------- */
function setBadge(tabId, verdict) {
  if (!verdict || verdict.allowlisted) {
    chrome.action.setBadgeText({ tabId, text: "" }).catch(() => {});
    return;
  }
  const risky = verdict.probability >= settings.threshold;
  const warn = !risky && verdict.probability >= 0.5;
  chrome.action.setBadgeText({
    tabId, text: risky ? "!" : warn ? "?" : ""
  }).catch(() => {});
  chrome.action.setBadgeBackgroundColor({
    tabId, color: risky ? "#e02424" : "#e8a33d"
  }).catch(() => {});
}

/* --------------------------------------------------------------------- */
/* navigation interception                                                */
/* --------------------------------------------------------------------- */
function warningPageUrl(verdict) {
  const params = new URLSearchParams({
    url: verdict.url,
    score: String(verdict.risk_score),
    probability: verdict.probability.toFixed(4),
    level: verdict.risk_level,
    features: JSON.stringify(verdict.features)
  });
  return chrome.runtime.getURL("warning.html") + "?" + params.toString();
}

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return;                 // top-level only
  const url = details.url;
  if (!isScannable(url)) return;

  await loadSettings();
  if (!settings.enabled) return;
  if (await isBypassed(url)) return;

  const verdict = await scoreUrl(url);
  await bumpStat("scanned");
  setBadge(details.tabId, verdict);

  if (!verdict.is_phishing) return;

  await bumpStat("blocked");
  chrome.tabs.update(details.tabId, { url: warningPageUrl(verdict) })
    .catch(() => { /* tab closed mid-navigation */ });
});

/* Re-badge on completed navigations that were never intercepted. */
chrome.webNavigation.onCommitted.addListener(async (details) => {
  if (details.frameId !== 0 || !isScannable(details.url)) return;
  await loadSettings();
  if (!settings.enabled) {
    chrome.action.setBadgeText({ tabId: details.tabId, text: "" }).catch(() => {});
    return;
  }
  setBadge(details.tabId, await scoreUrl(details.url));
});

/* --------------------------------------------------------------------- */
/* messaging                                                              */
/* --------------------------------------------------------------------- */
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    await loadSettings();

    switch (msg && msg.type) {
      case "score": {
        sendResponse(await scoreUrl(msg.url));
        break;
      }

      case "scoreDetailed": {
        // Local verdict first, then upgrade with the API if it is enabled.
        const local = await scoreUrl(msg.url);
        const api = await scoreWithApi(msg.url);
        sendResponse(api ? { ...local, ...api, local_probability: local.probability,
                             allowlisted: local.allowlisted,
                             is_phishing: local.allowlisted ? false : api.is_phishing }
                         : local);
        break;
      }

      case "scoreMany": {
        await self.PhishModel.load();
        const out = {};
        for (const url of (msg.urls || []).slice(0, 400)) {
          if (!isScannable(url)) continue;
          const v = self.PhishModel.scoreUrl(url, settings.threshold);
          if (isAllowlisted(v.hostname)) continue;
          out[url] = {
            probability: v.probability,
            is_phishing: v.is_phishing,
            risk_level: v.risk_level
          };
        }
        sendResponse(out);
        break;
      }

      case "proceed": {
        await addBypass(msg.url);
        await bumpStat("proceeded");
        const tabId = msg.tabId || (sender.tab && sender.tab.id);
        if (tabId) chrome.tabs.update(tabId, { url: msg.url }).catch(() => {});
        sendResponse({ ok: true });
        break;
      }

      case "returnToSafety": {
        const tabId = msg.tabId || (sender.tab && sender.tab.id);
        if (!tabId) { sendResponse({ ok: false }); break; }
        // Prefer stepping back to whatever the user was looking at before.
        try {
          await chrome.tabs.goBack(tabId);
        } catch (e) {
          await chrome.tabs.update(tabId, {
            url: chrome.runtime.getURL("safe.html")
          }).catch(() => {});
        }
        sendResponse({ ok: true });
        break;
      }

      case "getSettings": {
        sendResponse(settings);
        break;
      }

      case "setSettings": {
        sendResponse(await saveSettings(msg.patch || {}));
        break;
      }

      case "allowSite": {
        const domain = self.PhishAllowlist.registrableDomain(msg.hostname);
        const list = new Set(settings.userAllowlist || []);
        list.add(domain);
        await saveSettings({ userAllowlist: [...list] });
        sendResponse({ ok: true, userAllowlist: [...list] });
        break;
      }

      case "removeAllowSite": {
        const list = (settings.userAllowlist || [])
          .filter((d) => d !== msg.domain);
        await saveSettings({ userAllowlist: list });
        sendResponse({ ok: true, userAllowlist: list });
        break;
      }

      case "testApi": {
        try {
          const res = await fetch(
            settings.apiUrl.replace(/\/$/, "") + "/api/health");
          sendResponse(res.ok ? await res.json() : { status: "error" });
        } catch (e) {
          sendResponse({ status: "error", detail: String(e) });
        }
        break;
      }

      default:
        sendResponse({ error: "unknown message type" });
    }
  })();
  return true;   // keep the channel open for the async reply
});

/* --------------------------------------------------------------------- */
/* lifecycle                                                              */
/* --------------------------------------------------------------------- */
chrome.runtime.onInstalled.addListener(async (details) => {
  await loadSettings();
  await self.PhishModel.load();
  if (details.reason === "install") {
    chrome.tabs.create({ url: chrome.runtime.getURL("options.html?welcome=1") });
  }
});

chrome.runtime.onStartup.addListener(() => {
  loadSettings().then(() => self.PhishModel.load());
});

loadSettings().then(() => self.PhishModel.load());
