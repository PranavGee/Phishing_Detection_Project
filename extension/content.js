/**
 * PhishGuard content script.
 *
 * Catches the click itself: links on the page are scored in the background as
 * soon as the page settles, so when a risky one is clicked the warning appears
 * instantly instead of after the phishing page has already started loading.
 *
 * The modal lives in a shadow root so the host page's CSS cannot restyle,
 * hide or fake it.
 */
(function () {
  "use strict";

  var risky = new Map();       // href -> verdict
  var scanned = new Set();
  var settings = { enabled: true, highlightLinks: true };
  var overlayHost = null;
  var scanTimer = null;

  /* ------------------------------------------------------------------ */
  /* link scanning                                                       */
  /* ------------------------------------------------------------------ */
  function collectLinks() {
    var out = [];
    var anchors = document.querySelectorAll('a[href^="http"]');
    for (var i = 0; i < anchors.length && out.length < 400; i++) {
      var href = anchors[i].href;
      if (href && !scanned.has(href)) {
        scanned.add(href);
        out.push(href);
      }
    }
    return out;
  }

  function markLinks() {
    if (!settings.highlightLinks) return;
    document.querySelectorAll('a[href^="http"]').forEach(function (a) {
      if (risky.has(a.href) && !a.dataset.phishguard) {
        a.dataset.phishguard = "risky";
        a.title = "PhishGuard: this link looks like a phishing site";
      }
    });
  }

  function scanLinks() {
    if (!settings.enabled) return;
    var urls = collectLinks();
    if (!urls.length) return;
    chrome.runtime.sendMessage({ type: "scoreMany", urls: urls },
      function (results) {
        if (chrome.runtime.lastError || !results) return;
        Object.keys(results).forEach(function (url) {
          if (results[url].is_phishing) risky.set(url, results[url]);
        });
        markLinks();
      });
  }

  function scheduleScan() {
    clearTimeout(scanTimer);
    scanTimer = setTimeout(scanLinks, 400);
  }

  /* ------------------------------------------------------------------ */
  /* modal                                                               */
  /* ------------------------------------------------------------------ */
  var MODAL_CSS = [
    ":host{all:initial}",
    ".backdrop{position:fixed;inset:0;z-index:2147483647;background:rgba(6,4,8,.85);",
      "backdrop-filter:blur(5px);display:grid;place-items:center;padding:20px;",
      "font-family:'Segoe UI',system-ui,-apple-system,Roboto,Arial,sans-serif;",
      "animation:pg-fade .16s ease}",
    "@keyframes pg-fade{from{opacity:0}to{opacity:1}}",
    ".card{width:min(620px,100%);background:#1b1116;border:1px solid #6d2028;",
      "border-radius:18px;overflow:hidden;box-shadow:0 30px 80px rgba(0,0,0,.7);",
      "animation:pg-pop .2s cubic-bezier(.2,.9,.3,1.2);max-height:92vh;overflow-y:auto}",
    "@keyframes pg-pop{from{transform:scale(.95);opacity:0}to{transform:scale(1);opacity:1}}",
    ".stripe{height:6px;background:repeating-linear-gradient(45deg,#e02424 0 14px,#8f1414 14px 28px)}",
    ".body{padding:30px 34px 32px;text-align:center;color:#f0e5e5}",
    ".icon{font-size:44px;line-height:1;color:#ff6b6b;margin-bottom:6px}",
    "h2{margin:0 0 10px;font-size:25px;color:#ff6b6b;font-weight:700;letter-spacing:-.3px}",
    "p{margin:0 0 16px;font-size:15px;color:#d9c7c7;line-height:1.55}",
    "strong{color:#ff8f8f}",
    ".url{font-family:ui-monospace,Consolas,monospace;font-size:12.5px;background:#241419;",
      "border:1px solid #57202a;color:#ffbdbd;border-radius:9px;padding:11px 13px;",
      "word-break:break-all;text-align:left;margin-bottom:16px}",
    ".meter{text-align:left;margin-bottom:18px}",
    ".mhead{display:flex;justify-content:space-between;font-size:11px;color:#b9a5a5;",
      "text-transform:uppercase;letter-spacing:.1em;margin-bottom:6px}",
    ".mhead b{color:#ff6b6b;font-size:15px}",
    ".bar{height:9px;background:#2c1a1f;border-radius:999px;overflow:hidden}",
    ".bar i{display:block;height:100%;background:linear-gradient(90deg,#e8a33d,#e02424);",
      "transition:width .6s cubic-bezier(.2,.8,.3,1)}",
    ".actions{display:flex;gap:13px;justify-content:center;flex-wrap:wrap;margin-bottom:14px}",
    "button{border:0;border-radius:11px;padding:15px 24px;cursor:pointer;font-size:15.5px;",
      "font-weight:700;color:#fff;min-width:235px;font-family:inherit;",
      "transition:transform .12s ease,background .12s ease}",
    "button:hover{transform:translateY(-2px)}",
    "button:focus-visible{outline:3px solid #fff;outline-offset:3px}",
    ".danger{background:#e02424;box-shadow:0 9px 22px rgba(224,36,36,.3)}",
    ".danger:hover{background:#c31d1d}",
    ".safe{background:#10a45c;box-shadow:0 9px 22px rgba(16,164,92,.3)}",
    ".safe:hover{background:#0b8c4d}",
    ".hint{font-size:12.5px;color:#9b8b8b;margin:0}",
    "@media(max-width:560px){button{min-width:100%}.body{padding:24px 20px}}"
  ].join("");

  function closeModal() {
    if (overlayHost) {
      overlayHost.remove();
      overlayHost = null;
      document.documentElement.style.overflow = "";
    }
  }

  function showModal(url, verdict) {
    closeModal();
    var score = Math.round((verdict.probability || 0) * 100);

    overlayHost = document.createElement("div");
    overlayHost.id = "phishguard-overlay-host";
    var shadow = overlayHost.attachShadow({ mode: "closed" });

    var style = document.createElement("style");
    style.textContent = MODAL_CSS;
    shadow.appendChild(style);

    var backdrop = document.createElement("div");
    backdrop.className = "backdrop";
    backdrop.innerHTML =
      '<div class="card" role="alertdialog" aria-modal="true">' +
        '<div class="stripe"></div>' +
        '<div class="body">' +
          '<div class="icon">&#9888;</div>' +
          "<h2>Phishing website detected</h2>" +
          "<p>The link you clicked leads to what our model predicts is a " +
            "<strong>phishing website</strong>, built to steal passwords or " +
            "personal information.</p>" +
          '<div class="url"></div>' +
          '<div class="meter"><div class="mhead"><span>Phishing risk</span>' +
            "<b></b></div><div class=\"bar\"><i></i></div></div>" +
          '<div class="actions">' +
            '<button class="danger" data-act="proceed">Proceed with this Website</button>' +
            '<button class="safe" data-act="safety">Return to Safety</button>' +
          "</div>" +
          '<p class="hint">&ldquo;Return to Safety&rdquo; keeps you on this page. ' +
            "Proceeding opens the site at your own risk.</p>" +
        "</div>" +
      "</div>";

    backdrop.querySelector(".url").textContent = url;
    backdrop.querySelector(".mhead b").textContent = score + "%";
    shadow.appendChild(backdrop);

    document.documentElement.appendChild(overlayHost);
    document.documentElement.style.overflow = "hidden";

    requestAnimationFrame(function () {
      backdrop.querySelector(".bar i").style.width = score + "%";
    });

    backdrop.addEventListener("click", function (e) {
      var btn = e.target.closest("button[data-act]");
      if (!btn) {
        if (e.target === backdrop) closeModal();
        return;
      }
      if (btn.dataset.act === "safety") {
        closeModal();
        return;
      }
      var ok = window.confirm(
        "PhishGuard flagged this link as phishing.\n\n" + url +
        "\n\nNever enter passwords or card details there.\n\nOpen it anyway?");
      if (!ok) return;
      closeModal();
      chrome.runtime.sendMessage({ type: "proceed", url: url }, function () {
        // The background script clears the block for this URL, then we go.
        window.location.href = url;
      });
    });

    backdrop.querySelector('button[data-act="safety"]').focus();
  }

  /* ------------------------------------------------------------------ */
  /* click interception                                                  */
  /* ------------------------------------------------------------------ */
  document.addEventListener("click", function (e) {
    if (!settings.enabled) return;
    if (e.defaultPrevented || e.button !== 0) return;
    if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;

    var anchor = e.target.closest && e.target.closest('a[href^="http"]');
    if (!anchor) return;

    var verdict = risky.get(anchor.href);
    if (!verdict) return;              // not flagged — behave normally

    e.preventDefault();
    e.stopPropagation();
    showModal(anchor.href, verdict);
  }, true);

  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape") closeModal();
  }, true);

  /* ------------------------------------------------------------------ */
  /* boot                                                                */
  /* ------------------------------------------------------------------ */
  chrome.runtime.sendMessage({ type: "getSettings" }, function (loaded) {
    if (chrome.runtime.lastError || !loaded) return;
    settings = loaded;
    if (!settings.enabled) return;

    scanLinks();

    var observer = new MutationObserver(scheduleScan);
    observer.observe(document.documentElement, {
      childList: true, subtree: true
    });
  });
})();
