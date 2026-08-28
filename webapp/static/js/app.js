/* PhishGuard — scanner UI logic */
(function () {
  "use strict";

  var form = document.getElementById("scan-form");
  var input = document.getElementById("url-input");
  var scanBtn = document.getElementById("scan-btn");
  var resultEl = document.getElementById("result");
  var historyEl = document.getElementById("history");
  var overlay = document.getElementById("warning");

  var HISTORY_KEY = "phishguard.history";
  var lastResult = null;

  /* ------------------------------------------------------------------ */
  /* helpers                                                             */
  /* ------------------------------------------------------------------ */
  function esc(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;",
               '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  function readHistory() {
    try { return JSON.parse(localStorage.getItem(HISTORY_KEY)) || []; }
    catch (e) { return []; }
  }

  function writeHistory(items) {
    try { localStorage.setItem(HISTORY_KEY, JSON.stringify(items.slice(0, 25))); }
    catch (e) { /* private mode — history is a convenience, not a requirement */ }
  }

  function renderHistory() {
    var items = readHistory();
    if (!items.length) {
      historyEl.innerHTML = '<li class="empty">Nothing scanned yet.</li>';
      return;
    }
    historyEl.innerHTML = items.map(function (it) {
      return '<li><span class="dot ' + (it.phish ? "bad" : "ok") + '"></span>' +
        '<span class="h-url" title="' + esc(it.url) + '">' + esc(it.url) + "</span>" +
        '<span class="h-score" style="color:' + (it.phish ? "#ff6b6b" : "#4ad991") +
        '">' + it.score + "%</span></li>";
    }).join("");
  }

  function pushHistory(res) {
    var items = readHistory().filter(function (i) { return i.url !== res.url; });
    items.unshift({ url: res.url, score: res.risk_score, phish: res.is_phishing });
    writeHistory(items);
    renderHistory();
  }

  /* ------------------------------------------------------------------ */
  /* result card                                                         */
  /* ------------------------------------------------------------------ */
  function gauge(score, colour) {
    var r = 42, c = 2 * Math.PI * r, filled = c * (score / 100);
    return '<div class="gauge"><svg width="96" height="96">' +
      '<circle cx="48" cy="48" r="' + r + '" fill="none" stroke="#26325a" stroke-width="9"/>' +
      '<circle cx="48" cy="48" r="' + r + '" fill="none" stroke="' + colour +
      '" stroke-width="9" stroke-linecap="round" stroke-dasharray="' +
      filled + " " + (c - filled) + '"/></svg>' +
      '<div class="gauge-num" style="color:' + colour + '">' + score + "%</div></div>";
  }

  // Canonical model input order — the API returns JSON with sorted keys, and
  // showing them in training order reads better than alphabetically.
  var FEATURE_ORDER = ["length_url", "length_hostname", "ip", "nb_dots",
    "nb_hyphens", "nb_at", "nb_qm", "nb_and", "nb_or"];

  var HEADLINE = {
    high: "Phishing website — high risk",
    elevated: "Likely phishing website",
    low: "Probably safe, with a few odd signs",
    minimal: "No phishing indicators found"
  };

  function renderResult(res) {
    var phish = res.is_phishing;
    var colour = phish ? "#e02424" : (res.risk_level === "low" ? "#e8a33d" : "#10a45c");

    var reasons = res.reasons.map(function (r) {
      return '<li class="' + r.level + '"><span>' + esc(r.text) + "</span></li>";
    }).join("");

    var rows = FEATURE_ORDER.filter(function (k) {
      return res.features[k] !== undefined;
    }).map(function (k) {
      var v = res.features[k];
      var flag = (k === "ip" && v === 1) || (k === "nb_at" && v > 0) ||
                 (k === "length_url" && v > 75) || (k === "nb_dots" && v >= 4) ||
                 (k === "nb_hyphens" && v >= 3);
      return '<tr class="' + (flag ? "flag" : "") + '"><td>' +
        esc(res.feature_labels[k] || k) + "</td><td>" + v + "</td></tr>";
    }).join("");

    resultEl.className = "result";
    resultEl.innerHTML =
      '<div class="card ' + (phish ? "is-phishing" : "is-safe") + '">' +
        '<div class="card-head">' + gauge(res.risk_score, colour) +
          '<div class="verdict"><h2 style="color:' + colour + '">' +
            esc(HEADLINE[res.risk_level]) + "</h2>" +
            "<p>" + esc(res.model) + " &middot; " + res.confidence +
            "% confidence &middot; flagged at a threshold of " + res.threshold + "</p>" +
            '<div class="url">' + esc(res.url) + "</div>" +
          "</div>" +
        "</div>" +
        '<div class="card-body">' +
          "<div><h3>Why</h3><ul class=\"reasons\">" + reasons + "</ul></div>" +
          '<div><h3>Extracted features</h3><table class="ftable">' + rows +
          "</table></div>" +
        "</div>" +
        '<div class="card-actions">' +
          (phish
            ? '<button class="btn btn-danger" data-act="proceed">Proceed with this Website</button>' +
              '<button class="btn btn-safe" data-act="safety">Return to Safety</button>'
            : '<button class="btn btn-safe" data-act="open">Open this website</button>' +
              '<button class="btn btn-ghost" data-act="again">Scan another URL</button>') +
        "</div>" +
      "</div>";

    resultEl.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }

  /* ------------------------------------------------------------------ */
  /* full-screen warning                                                 */
  /* ------------------------------------------------------------------ */
  function showWarning(res) {
    window.scrollTo(0, 0);   // the overlay is fixed; start from the top
    document.getElementById("warning-url").textContent = res.url;
    document.getElementById("warning-score").textContent = res.risk_score + "%";
    document.getElementById("warning-reasons").innerHTML =
      res.reasons.filter(function (r) { return r.level !== "good"; })
        .slice(0, 4)
        .map(function (r) { return "<li>" + esc(r.text) + "</li>"; }).join("");
    overlay.classList.remove("hidden");
    document.body.style.overflow = "hidden";
    requestAnimationFrame(function () {
      document.getElementById("warning-fill").style.width = res.risk_score + "%";
    });
    document.getElementById("btn-safety").focus();
  }

  function hideWarning() {
    overlay.classList.add("hidden");
    document.getElementById("warning-fill").style.width = "0";
    document.body.style.overflow = "";
  }

  function returnToSafety() {
    hideWarning();
    input.value = "";
    input.focus();
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  function proceedAnyway(url) {
    var ok = window.confirm(
      "This site was flagged as phishing.\n\n" + url +
      "\n\nNever enter passwords, card numbers or personal details here.\n\n" +
      "Open it anyway?");
    if (!ok) return;
    hideWarning();
    window.open(url, "_blank", "noopener,noreferrer");
  }

  /* ------------------------------------------------------------------ */
  /* scanning                                                            */
  /* ------------------------------------------------------------------ */
  function scan(url) {
    scanBtn.disabled = true;
    scanBtn.textContent = "Scanning...";
    return fetch("/api/predict", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: url })
    })
      .then(function (r) {
        return r.json().then(function (body) {
          if (!r.ok) throw new Error(body.error || "Request failed");
          return body;
        });
      })
      .then(function (res) {
        lastResult = res;
        renderResult(res);
        pushHistory(res);
        if (res.is_phishing) showWarning(res);
      })
      .catch(function (err) {
        resultEl.className = "result";
        resultEl.innerHTML =
          '<div class="card"><div class="card-head"><div class="verdict">' +
          "<h2>Could not scan that URL</h2><p>" + esc(err.message) +
          "</p></div></div></div>";
      })
      .then(function () {
        scanBtn.disabled = false;
        scanBtn.textContent = "Scan URL";
      });
  }

  /* ------------------------------------------------------------------ */
  /* events                                                              */
  /* ------------------------------------------------------------------ */
  form.addEventListener("submit", function (e) {
    e.preventDefault();
    var url = input.value.trim();
    if (!url) { input.focus(); return; }
    scan(url);
  });

  document.querySelectorAll(".chip").forEach(function (chip) {
    chip.addEventListener("click", function () {
      input.value = chip.dataset.url;
      scan(chip.dataset.url);
    });
  });

  resultEl.addEventListener("click", function (e) {
    var btn = e.target.closest("[data-act]");
    if (!btn || !lastResult) return;
    var act = btn.dataset.act;
    if (act === "proceed") proceedAnyway(lastResult.url);
    if (act === "safety") returnToSafety();
    if (act === "open") window.open(lastResult.url, "_blank", "noopener,noreferrer");
    if (act === "again") { input.value = ""; input.focus(); }
  });

  document.getElementById("btn-proceed")
    .addEventListener("click", function () { proceedAnyway(lastResult.url); });
  document.getElementById("btn-safety")
    .addEventListener("click", returnToSafety);
  overlay.addEventListener("click", function (e) {
    if (e.target === overlay) returnToSafety();
  });
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape" && !overlay.classList.contains("hidden")) returnToSafety();
  });

  document.getElementById("clear-history").addEventListener("click", function () {
    writeHistory([]);
    renderHistory();
  });

  renderHistory();
  input.focus();

  // Shareable scan links: /?url=https://example.com scans on load, which is
  // also how the browser extension can hand a URL over to the web app.
  var preset = new URLSearchParams(location.search).get("url");
  if (preset) {
    input.value = preset;
    scan(preset);
  }
})();
