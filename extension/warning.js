/* PhishGuard — warning interstitial logic */
(function () {
  "use strict";

  var params = new URLSearchParams(location.search);
  var blockedUrl = params.get("url") || "";
  var score = parseInt(params.get("score") || "0", 10);
  var features = {};
  try { features = JSON.parse(params.get("features") || "{}"); } catch (e) {}

  var LABELS = self.PhishFeatures.FEATURE_LABELS;

  /* ------------------------------------------------------------------ */
  /* explanation                                                         */
  /* ------------------------------------------------------------------ */
  function buildReasons(f) {
    var out = [];
    if (f.ip) {
      out.push(["bad", "The address contains a raw IP or a long random-looking " +
        "token instead of a clean, readable path. Real companies use readable " +
        "domain names."]);
    }
    if (f.nb_at) {
      out.push(["bad", "The address contains '@'. Browsers ignore everything " +
        "before it, so the site you actually land on is not the one you read."]);
    }
    if (f.length_url > 75) {
      out.push(["warn", "The address is unusually long (" + f.length_url +
        " characters) — a common way to push the real domain out of sight."]);
    }
    if (f.nb_dots >= 4) {
      out.push(["warn", "It has " + f.nb_dots + " dots, suggesting a long " +
        "subdomain chain such as yourbank.com.attacker-site.net."]);
    }
    if (f.nb_hyphens >= 3) {
      out.push(["warn", "It has " + f.nb_hyphens + " hyphens. Fake login pages " +
        "often look like secure-account-verify-login.com."]);
    }
    if (f.length_hostname > 30) {
      out.push(["warn", "The domain name is long (" + f.length_hostname +
        " characters), which makes it easy to miss what it really says."]);
    }
    if (f.nb_qm + f.nb_and >= 4) {
      out.push(["info", "The link carries a lot of query parameters, sometimes " +
        "used to smuggle tracking or redirect data."]);
    }
    if (!out.length) {
      out.push(["info", "No single property is damning, but the combination of " +
        "this address's length, structure and punctuation closely matches " +
        "phishing URLs in the training data."]);
    }
    return out;
  }

  /* ------------------------------------------------------------------ */
  /* render                                                              */
  /* ------------------------------------------------------------------ */
  document.getElementById("blocked-url").textContent = blockedUrl;

  var host = self.PhishFeatures.getHostname(blockedUrl);
  document.getElementById("blocked-host").innerHTML =
    "This page would be served by <b></b>";
  document.getElementById("blocked-host").querySelector("b").textContent = host;

  document.getElementById("risk-score").textContent = score + "%";
  document.getElementById("risk-note").textContent =
    score >= 80 ? "Very close match to known phishing patterns."
                : "Above the threshold at which PhishGuard interrupts you.";
  requestAnimationFrame(function () {
    document.getElementById("risk-fill").style.width = score + "%";
  });

  var list = document.getElementById("reasons");
  buildReasons(features).forEach(function (pair) {
    var li = document.createElement("li");
    li.className = pair[0];
    li.textContent = pair[1];
    list.appendChild(li);
  });

  var table = document.getElementById("feature-table");
  self.PhishFeatures.FEATURE_NAMES.forEach(function (name) {
    var value = features[name];
    if (value === undefined) return;
    var flag = (name === "ip" && value === 1) || (name === "nb_at" && value > 0) ||
               (name === "length_url" && value > 75) ||
               (name === "nb_dots" && value >= 4) ||
               (name === "nb_hyphens" && value >= 3);
    var tr = document.createElement("tr");
    if (flag) tr.className = "flag";
    var td1 = document.createElement("td");
    td1.textContent = LABELS[name] || name;
    var td2 = document.createElement("td");
    td2.textContent = value;
    tr.appendChild(td1);
    tr.appendChild(td2);
    table.appendChild(tr);
  });

  /* ------------------------------------------------------------------ */
  /* actions                                                             */
  /* ------------------------------------------------------------------ */
  document.getElementById("btn-proceed").addEventListener("click", function () {
    var ok = window.confirm(
      "PhishGuard flagged this site as phishing.\n\n" + blockedUrl +
      "\n\nDo not enter passwords, card numbers or personal details there.\n\n" +
      "Continue anyway?");
    if (!ok) return;
    chrome.runtime.sendMessage({ type: "proceed", url: blockedUrl });
  });

  document.getElementById("btn-safety").addEventListener("click", function () {
    // history.back() covers the normal case; the background script falls back
    // to a safe page when this tab has nowhere to go back to.
    if (history.length > 1) {
      history.back();
      setTimeout(function () {
        chrome.runtime.sendMessage({ type: "returnToSafety" });
      }, 250);
    } else {
      chrome.runtime.sendMessage({ type: "returnToSafety" });
    }
  });

  document.getElementById("btn-trust").addEventListener("click", function () {
    chrome.runtime.sendMessage({ type: "allowSite", hostname: host },
      function () {
        chrome.runtime.sendMessage({ type: "proceed", url: blockedUrl });
      });
  });

  document.getElementById("btn-safety").focus();
})();
