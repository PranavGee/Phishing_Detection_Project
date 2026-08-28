/* PhishGuard — options page */
(function () {
  "use strict";

  var saveNote = document.getElementById("saveNote");
  var saveTimer = null;

  function send(msg) {
    return new Promise(function (resolve) {
      chrome.runtime.sendMessage(msg, function (res) {
        resolve(chrome.runtime.lastError ? null : res);
      });
    });
  }

  function flashSaved() {
    saveNote.classList.add("show");
    clearTimeout(saveTimer);
    saveTimer = setTimeout(function () {
      saveNote.classList.remove("show");
    }, 1300);
  }

  function save(patch) {
    return send({ type: "setSettings", patch: patch }).then(function (s) {
      flashSaved();
      return s;
    });
  }

  /* ---------------- allowlist ---------------- */
  function renderAllowlist(list) {
    var ul = document.getElementById("allowlist");
    ul.innerHTML = "";
    if (!list || !list.length) {
      var empty = document.createElement("li");
      empty.className = "empty";
      empty.textContent = "No custom trusted sites yet.";
      ul.appendChild(empty);
      return;
    }
    list.forEach(function (domain) {
      var li = document.createElement("li");
      var span = document.createElement("span");
      span.textContent = domain;
      var btn = document.createElement("button");
      btn.type = "button";
      btn.textContent = "×";
      btn.title = "Remove " + domain;
      btn.addEventListener("click", function () {
        send({ type: "removeAllowSite", domain: domain }).then(function (res) {
          if (res) renderAllowlist(res.userAllowlist);
          flashSaved();
        });
      });
      li.appendChild(span);
      li.appendChild(btn);
      ul.appendChild(li);
    });
  }

  function addDomain() {
    var input = document.getElementById("newDomain");
    var value = input.value.trim().toLowerCase()
      .replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/^www\./, "");
    if (!value) return;
    send({ type: "allowSite", hostname: value }).then(function (res) {
      if (res) renderAllowlist(res.userAllowlist);
      input.value = "";
      flashSaved();
    });
  }

  /* ---------------- load ---------------- */
  send({ type: "getSettings" }).then(function (s) {
    if (!s) return;
    document.getElementById("enabled").checked = s.enabled;
    document.getElementById("highlightLinks").checked = s.highlightLinks;
    document.getElementById("useAllowlist").checked = s.useAllowlist;
    document.getElementById("threshold").value = s.threshold;
    document.getElementById("thresholdValue").textContent =
      Number(s.threshold).toFixed(2);
    document.getElementById("useApi").checked = s.useApi;
    document.getElementById("apiUrl").value = s.apiUrl || "";
    document.getElementById("statScanned").textContent = s.stats.scanned || 0;
    document.getElementById("statBlocked").textContent = s.stats.blocked || 0;
    document.getElementById("statProceeded").textContent = s.stats.proceeded || 0;
    renderAllowlist(s.userAllowlist);
  });

  /* ---------------- wiring ---------------- */
  ["enabled", "highlightLinks", "useAllowlist", "useApi"].forEach(function (id) {
    document.getElementById(id).addEventListener("change", function (e) {
      var patch = {};
      patch[id] = e.target.checked;
      save(patch);
    });
  });

  var threshold = document.getElementById("threshold");
  threshold.addEventListener("input", function () {
    document.getElementById("thresholdValue").textContent =
      Number(threshold.value).toFixed(2);
  });
  threshold.addEventListener("change", function () {
    save({ threshold: Number(threshold.value) });
  });

  document.getElementById("addDomain").addEventListener("click", addDomain);
  document.getElementById("newDomain").addEventListener("keydown", function (e) {
    if (e.key === "Enter") addDomain();
  });

  var apiUrl = document.getElementById("apiUrl");
  apiUrl.addEventListener("change", function () {
    save({ apiUrl: apiUrl.value.trim() });
  });

  document.getElementById("testApi").addEventListener("click", function () {
    var status = document.getElementById("apiStatus");
    status.className = "status";
    status.textContent = "Testing…";
    save({ apiUrl: apiUrl.value.trim() }).then(function () {
      return send({ type: "testApi" });
    }).then(function (res) {
      if (res && res.status === "ok") {
        status.className = "status ok";
        status.textContent = "Connected — serving the " + res.model + " model.";
      } else {
        status.className = "status err";
        status.textContent = "Could not reach that address. Is the web app "
          + "running (python webapp/app.py)?";
      }
    });
  });

  document.getElementById("resetStats").addEventListener("click", function () {
    save({ stats: { scanned: 0, blocked: 0, proceeded: 0 } }).then(function () {
      document.getElementById("statScanned").textContent = "0";
      document.getElementById("statBlocked").textContent = "0";
      document.getElementById("statProceeded").textContent = "0";
    });
  });

  if (new URLSearchParams(location.search).get("welcome")) {
    document.getElementById("welcome").classList.remove("hidden");
  }
})();
