/**
 * Extension logic tests (Node, no browser required).
 *
 * Loads the extension's own lib/ files and exercises the decisions the service
 * worker makes: feature extraction, on-device scoring, the allowlist, and the
 * threshold that decides whether a warning is shown.
 *
 * Run:  node tests/test_extension.js
 */
"use strict";

const fs = require("fs");
const path = require("path");

const LIB = path.join(__dirname, "..", "extension", "lib");
global.self = global;
require(path.join(LIB, "features.js"));
require(path.join(LIB, "model.js"));
require(path.join(LIB, "allowlist.js"));

self.PhishModel.setModel(
  JSON.parse(fs.readFileSync(path.join(LIB, "model.json"), "utf8"))
);

let passed = 0;
let failed = 0;

function check(name, actual, expected) {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  if (ok) {
    passed++;
    console.log("  PASS  " + name);
  } else {
    failed++;
    console.log("  FAIL  " + name +
      "\n          expected " + JSON.stringify(expected) +
      "\n          actual   " + JSON.stringify(actual));
  }
}

function checkTrue(name, value) { check(name, !!value, true); }

/* --------------------------------------------------------------------- */
console.log("\nFeature extraction");

const f1 = self.PhishFeatures.extractFeatures(
  "http://www.crestonwood.com/router.php");
check("length_url on a known dataset row", f1.length_url, 37);
check("length_hostname on a known dataset row", f1.length_hostname, 19);
check("nb_dots on a known dataset row", f1.nb_dots, 3);
check("ip is 0 for a clean URL", f1.ip, 0);

const f2 = self.PhishFeatures.extractFeatures(
  "http://shadetreetechnology.com/V4/validation/a111aedc8ae390eabcfa130e041a10a4");
check("ip fires on a long hex token", f2.ip, 1);

const f3 = self.PhishFeatures.extractFeatures("http://179.185.89.94/");
check("ip fires on a raw IPv4 host", f3.ip, 1);

const f4 = self.PhishFeatures.extractFeatures(
  "https://user@evil.com:8443/a?b=1&c=2|3");
check("port is excluded from hostname length",
  f4.length_hostname, "evil.com".length);
check("nb_at counts the userinfo separator", f4.nb_at, 1);
check("nb_or counts pipes", f4.nb_or, 1);
check("nb_and counts ampersands", f4.nb_and, 1);

check("scheme-less input is normalised",
  self.PhishFeatures.getHostname("example.com/path"), "example.com");

/* --------------------------------------------------------------------- */
console.log("\nModel scoring");

const obviousPhish = self.PhishModel.scoreUrl(
  "http://secure-appleid.com.verify-login.duilawyeryork.com/ap/89e6a3b4b063b8d/" +
  "?cmd=_update&dispatch=89e6a3b4b063b8d1b&locale=_", 0.7);
checkTrue("a textbook phishing URL is flagged", obviousPhish.is_phishing);
checkTrue("its probability is high", obviousPhish.probability > 0.9);
check("risk level is reported", obviousPhish.risk_level, "high");

const clean = self.PhishModel.scoreUrl("https://www.google.com", 0.7);
check("a short clean URL is not flagged", clean.is_phishing, false);

const p = self.PhishModel.scoreUrl("https://example.com/x", 0.7).probability;
checkTrue("probability is a valid probability", p >= 0 && p <= 1);

const strict = self.PhishModel.scoreUrl("https://www.github.com/explore", 0.9);
const loose = self.PhishModel.scoreUrl("https://www.github.com/explore", 0.3);
check("the threshold actually changes the verdict",
  [strict.is_phishing, loose.is_phishing], [false, true]);
check("the probability itself does not depend on the threshold",
  strict.probability.toFixed(9), loose.probability.toFixed(9));

/* --------------------------------------------------------------------- */
console.log("\nAllowlist");

checkTrue("a bare well-known domain is trusted",
  self.PhishAllowlist.isBuiltInTrusted("github.com"));
checkTrue("a subdomain of a well-known domain is trusted",
  self.PhishAllowlist.isBuiltInTrusted("gist.github.com"));
checkTrue("a two-part TLD is handled",
  self.PhishAllowlist.isBuiltInTrusted("www.bbc.co.uk"));
check("a lookalike domain is NOT trusted",
  self.PhishAllowlist.isBuiltInTrusted("github.com.evil.tk"), false);
check("registrable domain of a deep subdomain",
  self.PhishAllowlist.registrableDomain("a.b.c.example.com"), "example.com");
check("registrable domain with a two-part suffix",
  self.PhishAllowlist.registrableDomain("news.bbc.co.uk"), "bbc.co.uk");

/* The allowlist is what keeps the extension usable: without it these
   real sites would interrupt the user at the default threshold. */
const REAL_SITES = [
  "https://stackoverflow.com/questions/tagged/python",
  "https://www.paypal.com/signin",
  "https://www.github.com/explore",
  "https://en.wikipedia.org/wiki/Phishing",
  "https://www.amazon.com/dp/B08N5WRWNW"
];
let interrupted = 0;
REAL_SITES.forEach((url) => {
  const v = self.PhishModel.scoreUrl(url, 0.7);
  const host = self.PhishFeatures.getHostname(url);
  if (v.is_phishing && !self.PhishAllowlist.isBuiltInTrusted(host)) interrupted++;
});
check("no well-known site is interrupted", interrupted, 0);

/* --------------------------------------------------------------------- */
console.log("\nDataset agreement (sample of labelled URLs)");

const csv = path.join(__dirname, "..", "data", "dataset_phishing.csv");
if (fs.existsSync(csv)) {
  const lines = fs.readFileSync(csv, "utf8").split("\n").slice(1);
  let correct = 0;
  let total = 0;
  for (let i = 0; i < lines.length; i += 7) {
    const line = lines[i];
    if (!line || !line.trim()) continue;
    const url = line.slice(0, line.indexOf(","));
    const label = line.trim().endsWith(",phishing") ? 1 : 0;
    const v = self.PhishModel.scoreUrl(url, 0.5);
    if ((v.is_phishing ? 1 : 0) === label) correct++;
    total++;
  }
  const acc = correct / total;
  console.log("  scored " + total + " URLs, accuracy " +
    (acc * 100).toFixed(2) + "%");
  checkTrue("accuracy on a dataset sample is above 70%", acc > 0.7);
} else {
  console.log("  SKIP  dataset not present");
}

/* --------------------------------------------------------------------- */
console.log("\n" + (failed === 0
  ? "All " + passed + " checks passed."
  : passed + " passed, " + failed + " FAILED."));
process.exit(failed === 0 ? 0 : 1);
