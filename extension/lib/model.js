/**
 * Offline scorer for the exported Gradient Boosting model.
 *
 * The model ships as `lib/model.json` (produced by ml/export_js_model.py), so a
 * verdict is available before the page starts loading and no URL ever leaves
 * the browser. Scoring is:
 *
 *     P(phishing) = sigmoid(base_score + learning_rate * SUM over trees)
 */
(function (root) {
  "use strict";

  var model = null;
  var loading = null;

  /** Fetch and cache lib/model.json (idempotent). */
  function load(url) {
    if (model) return Promise.resolve(model);
    if (loading) return loading;
    var src = url || (typeof chrome !== "undefined" && chrome.runtime
      ? chrome.runtime.getURL("lib/model.json")
      : "lib/model.json");
    loading = fetch(src)
      .then(function (r) { return r.json(); })
      .then(function (json) { model = json; loading = null; return model; });
    return loading;
  }

  function setModel(json) { model = json; return model; }
  function isLoaded() { return model !== null; }

  function walk(tree, row) {
    var node = 0;
    while (tree.f[node] >= 0) {
      node = row[tree.f[node]] <= tree.t[node] ? tree.l[node] : tree.r[node];
    }
    return tree.v[node];
  }

  /** P(phishing) for a feature row ordered like model.feature_names. */
  function scoreVector(row) {
    if (!model) throw new Error("model.json is not loaded yet");
    var total = 0;
    for (var i = 0; i < model.trees.length; i++) {
      total += walk(model.trees[i], row);
    }
    var raw = model.base_score + model.learning_rate * total;
    return 1 / (1 + Math.exp(-raw));
  }

  /**
   * Full verdict for a URL.
   * `threshold` is the probability at or above which we call it phishing.
   */
  function scoreUrl(url, threshold) {
    var t = typeof threshold === "number" ? threshold : 0.5;
    var features = root.PhishFeatures.extractFeatures(url);
    var vector = model.feature_names.map(function (n) { return features[n]; });
    var probability = scoreVector(vector);
    return {
      url: url,
      hostname: root.PhishFeatures.getHostname(url),
      probability: probability,
      threshold: t,
      is_phishing: probability >= t,
      risk_level: riskLevel(probability),
      features: features,
      source: "on-device"
    };
  }

  /** Four bands used for the colour of the badge and the warning copy. */
  function riskLevel(p) {
    if (p >= 0.8) return "high";
    if (p >= 0.5) return "elevated";
    if (p >= 0.3) return "low";
    return "minimal";
  }

  root.PhishModel = {
    load: load,
    setModel: setModel,
    isLoaded: isLoaded,
    scoreVector: scoreVector,
    scoreUrl: scoreUrl,
    riskLevel: riskLevel
  };

  if (typeof module !== "undefined" && module.exports) {
    module.exports = root.PhishModel;
  }
})(typeof self !== "undefined" ? self : this);
