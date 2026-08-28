/**
 * URL feature extraction — the JavaScript mirror of ml/features.py.
 *
 * The nine values produced here must match the columns the model was trained
 * on, otherwise the extension would score URLs differently from the way the
 * model learned them. `ml/parity_check.py` runs both implementations over a
 * sample of the dataset and fails if they ever disagree.
 *
 * Loaded as a classic script (no modules) so the same file works in the
 * service worker, the warning page and the popup.
 */
(function (root) {
  "use strict";

  var FEATURE_NAMES = [
    "length_url",
    "length_hostname",
    "ip",
    "nb_dots",
    "nb_hyphens",
    "nb_at",
    "nb_qm",
    "nb_and",
    "nb_or"
  ];

  var FEATURE_LABELS = {
    length_url: "Total URL length",
    length_hostname: "Hostname length",
    ip: "Raw IP address / long hex token in URL",
    nb_dots: "Number of dots ( . )",
    nb_hyphens: "Number of hyphens ( - )",
    nb_at: "Number of at signs ( @ )",
    nb_qm: "Number of question marks ( ? )",
    nb_and: "Number of ampersands ( & )",
    nb_or: "Number of pipes ( | )"
  };

  var OCTET = "([01]?\\d\\d?|2[0-4]\\d|25[0-5])";
  // Same rule as the dataset's `ip` column: an IPv4 host written straight into
  // the URL, or a long hexadecimal token (>= 7 hex chars).
  var IP_LIKE = new RegExp(
    "(?:(?:" + OCTET + "\\.){3}" + OCTET + "/)|(?:(?<![0-9a-fA-F])[0-9a-fA-F]{7,})"
  );

  function normalizeUrl(url) {
    url = (url || "").trim();
    if (url && !/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(url)) {
      url = "http://" + url;
    }
    return url;
  }

  /** Hostname without the port — matches the dataset's `length_hostname`. */
  function getHostname(url) {
    var netloc;
    try {
      netloc = new URL(normalizeUrl(url)).host;
    } catch (e) {
      // Fall back to manual parsing for inputs the URL parser rejects.
      var rest = normalizeUrl(url).split("://")[1] || "";
      netloc = rest.split("/")[0].split("?")[0].split("#")[0];
    }
    if (netloc.indexOf("@") !== -1) {
      netloc = netloc.substring(netloc.lastIndexOf("@") + 1);
    }
    if (netloc.charAt(0) === "[") {
      return netloc.split("]")[0] + "]";
    }
    return netloc.split(":")[0];
  }

  function countChar(str, ch) {
    var n = 0;
    for (var i = 0; i < str.length; i++) {
      if (str.charAt(i) === ch) n++;
    }
    return n;
  }

  function extractFeatures(url) {
    var normalized = normalizeUrl(url);
    var hostname = getHostname(normalized);
    return {
      length_url: normalized.length,
      length_hostname: hostname.length,
      ip: IP_LIKE.test(normalized) ? 1 : 0,
      nb_dots: countChar(normalized, "."),
      nb_hyphens: countChar(normalized, "-"),
      nb_at: countChar(normalized, "@"),
      nb_qm: countChar(normalized, "?"),
      nb_and: countChar(normalized, "&"),
      nb_or: countChar(normalized, "|")
    };
  }

  function extractVector(url) {
    var f = extractFeatures(url);
    return FEATURE_NAMES.map(function (name) { return f[name]; });
  }

  root.PhishFeatures = {
    FEATURE_NAMES: FEATURE_NAMES,
    FEATURE_LABELS: FEATURE_LABELS,
    normalizeUrl: normalizeUrl,
    getHostname: getHostname,
    extractFeatures: extractFeatures,
    extractVector: extractVector
  };

  if (typeof module !== "undefined" && module.exports) {
    module.exports = root.PhishFeatures;   // lets Node run the parity check
  }
})(typeof self !== "undefined" ? self : this);
