/* PhishGuard — toolbar popup */
(function () {
  "use strict";

  var els = {
    enabled: document.getElementById("toggle-enabled"),
    ringFill: document.getElementById("ring-fill"),
    ringScore: document.getElementById("ring-score"),
    title: document.getElementById("verdict-title"),
    host: document.getElementById("verdict-host"),
    note: document.getElementById("verdict-note"),
    manualUrl: document.getElementById("manual-url"),
    manualBtn: document.getElementById("manual-btn"),
    manualResult: document.getElementById("manual-result"),
    trust: document.getElementById("btn-trust"),
    threshold: document.getElementById("threshold"),
    thresholdValue: document.getElementById("threshold-value"),
    modelNote: document.getElementById("model-note")
  };

  var currentHost = null;
  var CIRC = 2 * Math.PI * 31;

  function send(msg) {
    return new Promise(function (resolve) {
      chrome.runtime.sendMessage(msg, function (res) {
        resolve(chrome.runtime.lastError ? null : res);
      });
    });
  }

  function setRing(score, colour) {
    var filled = CIRC * (score / 100);
    els.ringFill.setAttribute("stroke-dasharray", filled + " " + (CIRC - filled));
    els.ringFill.setAttribute("stroke", colour);
    els.ringScore.textContent = score + "%";
    els.ringScore.style.color = colour;
  }

  function colourFor(verdict) {
    // A trusted site is never interrupted, so its raw score must not be
    // painted like a warning — an amber 98% under the words "Trusted site"
    // reads as a contradiction.
    if (verdict.allowlisted) return "#7d88ad";
    if (verdict.is_phishing) return "#e02424";
    if (verdict.probability >= 0.5) return "#e8a33d";
    return "#10a45c";
  }

  function titleFor(verdict) {
    if (verdict.allowlisted) return "Trusted site";
    if (verdict.is_phishing) return "Phishing risk";
    if (verdict.probability >= 0.5) return "Slightly unusual";
    return "Looks safe";
  }

  function noteFor(verdict, enabled) {
    if (!enabled) {
      return "Protection is off — nothing is being checked.";
    }
    if (verdict.allowlisted) {
      // Say the quiet part out loud: the number above is the raw structural
      // score, and it is being deliberately ignored for this domain.
      return "Its address scores " + Math.round(verdict.probability * 100) +
        "%, but this domain is trusted, so you are never interrupted.";
    }
    return "Scored on-device from the address alone.";
  }

  /* ---------------- current tab ---------------- */
  function showCurrentTab() {
    chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
      var tab = tabs && tabs[0];
      if (!tab || !tab.url || !/^https?:/i.test(tab.url)) {
        els.title.textContent = "Nothing to check here";
        els.host.textContent = "";
        els.note.textContent = "Open a website to see its score.";
        els.trust.disabled = true;
        setRing(0, "#3a4470");
        return;
      }
      currentHost = self.PhishFeatures.getHostname(tab.url);
      els.host.textContent = currentHost;

      send({ type: "score", url: tab.url }).then(function (verdict) {
        if (!verdict) return;
        var score = Math.round(verdict.probability * 100);
        setRing(score, colourFor(verdict));
        els.title.textContent = titleFor(verdict);
        els.title.style.color = colourFor(verdict);
        els.note.textContent = noteFor(verdict, els.enabled.checked);
        els.trust.disabled = !!verdict.allowlisted;
        if (verdict.allowlisted) els.trust.textContent = "Already trusted";
      });
    });
  }

  /* ---------------- manual scan ---------------- */
  function manualScan() {
    var url = els.manualUrl.value.trim();
    if (!url) return;
    els.manualBtn.disabled = true;
    send({ type: "scoreDetailed", url: url }).then(function (verdict) {
      els.manualBtn.disabled = false;
      if (!verdict) return;
      var score = Math.round(verdict.probability * 100);
      els.manualResult.className = "manual-result " +
        (verdict.is_phishing ? "bad" : "ok");
      els.manualResult.innerHTML =
        "<strong>" + (verdict.is_phishing
          ? "Phishing — " + score + "% risk"
          : "Looks safe — " + score + "% risk") + "</strong>" +
        '<span class="u"></span>';
      els.manualResult.querySelector(".u").textContent = url;
      if (verdict.source === "api") {
        els.modelNote.textContent = "verified via API";
      }
    });
  }

  /* ---------------- settings ---------------- */
  send({ type: "getSettings" }).then(function (settings) {
    if (!settings) return;
    els.enabled.checked = settings.enabled;
    els.threshold.value = settings.threshold;
    els.thresholdValue.textContent = Number(settings.threshold).toFixed(2);
    document.getElementById("stat-scanned").textContent =
      settings.stats.scanned || 0;
    document.getElementById("stat-blocked").textContent =
      settings.stats.blocked || 0;
    document.getElementById("stat-proceeded").textContent =
      settings.stats.proceeded || 0;
    if (settings.useApi && settings.apiUrl) {
      els.modelNote.textContent = "on-device + API";
    }
    // Re-render now that we know whether protection is actually on: the first
    // paint runs before this reply arrives and assumes the HTML default.
    showCurrentTab();
  });

  els.enabled.addEventListener("change", function () {
    send({ type: "setSettings", patch: { enabled: els.enabled.checked } })
      .then(showCurrentTab);
  });

  els.threshold.addEventListener("input", function () {
    els.thresholdValue.textContent = Number(els.threshold.value).toFixed(2);
  });

  els.threshold.addEventListener("change", function () {
    send({ type: "setSettings",
           patch: { threshold: Number(els.threshold.value) } })
      .then(showCurrentTab);
  });

  els.trust.addEventListener("click", function () {
    if (!currentHost) return;
    send({ type: "allowSite", hostname: currentHost }).then(function () {
      els.trust.textContent = "Added to trusted sites";
      els.trust.disabled = true;
      showCurrentTab();
    });
  });

  els.manualBtn.addEventListener("click", manualScan);
  els.manualUrl.addEventListener("keydown", function (e) {
    if (e.key === "Enter") manualScan();
  });

  document.getElementById("open-options").addEventListener("click", function (e) {
    e.preventDefault();
    chrome.runtime.openOptionsPage();
  });

  showCurrentTab();
})();
