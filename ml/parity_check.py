"""
Cross-language parity check: Python model  vs  browser-extension JavaScript.

Runs the extension's own `lib/features.js` + `lib/model.js` under Node over a
sample of real dataset URLs and compares, per URL:

    * all nine extracted features        (must be identical)
    * P(phishing) from the JS scorer     (must match sklearn to < 1e-9)

This is what stops the extension from quietly drifting away from the trained
model. Requires Node.js on PATH.

Run:  python ml/parity_check.py [n_samples]
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile

import joblib
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from features import FEATURE_NAMES, extract_features  # noqa: E402

# The Windows console defaults to cp1252, which cannot print an
# internationalised URL. Without this, a report about a non-ASCII URL would
# crash instead of being shown.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXT_LIB = os.path.join(ROOT, "extension", "lib")

# Every dataset URL is plain ASCII, so the sampled rows alone would never
# exercise the places where Python's `urlparse` and JavaScript's `URL` disagree.
# These are checked on every run as well.
EDGE_CASES = [
    "http://пример.рф/login",       # Cyrillic IDN
    "https://例え.テスト/a/b?x=1",                      # Japanese IDN
    "http://аpple.com/signin",                                          # homograph: Cyrillic 'a'
    "http://xn--e1afmkfd.xn--p1ai/login",                                    # already punycoded
    "http://EXAMPLE.COM/Path",                                               # mixed case host
    "http://user:pass@evil.example.com:8443/a?b=1",                          # userinfo + port
    "http://[2001:db8::1]:8080/x",                                           # IPv6 literal
    "https://example.com:443/a",                                             # default port
    "http://example.com/a b c",                                              # spaces in path
    "  https://example.com/trim  ",                                          # needs trimming
    "example.com/no-scheme",                                                 # no scheme
    "http://a_b.example.com/x",                                              # underscore label
    "http://example.com./x",                                                 # trailing dot
    "https://sub.domain.co.uk/a?b=1&c=2|3",                                  # two-part TLD, pipe
]

RUNNER = r"""
const fs = require('fs');
const path = require('path');
const LIB = process.argv[2];
global.self = global;
require(path.join(LIB, 'features.js'));
require(path.join(LIB, 'model.js'));
const model = JSON.parse(fs.readFileSync(path.join(LIB, 'model.json'), 'utf8'));
self.PhishModel.setModel(model);
const urls = JSON.parse(fs.readFileSync(process.argv[3], 'utf8'));
const out = urls.map(function (u) {
  const f = self.PhishFeatures.extractFeatures(u);
  const row = model.feature_names.map(function (n) { return f[n]; });
  return { url: u, features: f, probability: self.PhishModel.scoreVector(row) };
});
fs.writeFileSync(process.argv[4], JSON.stringify(out));
"""


def main() -> int:
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 1500
    df = pd.read_csv(os.path.join(ROOT, "data", "dataset_phishing.csv"),
                     usecols=["url"])
    urls = df["url"].sample(n=min(n, len(df)), random_state=7).tolist()
    urls += EDGE_CASES

    tmp = tempfile.mkdtemp(prefix="parity_")
    runner_js = os.path.join(tmp, "runner.js")
    urls_json = os.path.join(tmp, "urls.json")
    out_json = os.path.join(tmp, "out.json")
    with open(runner_js, "w", encoding="utf-8") as fh:
        fh.write(RUNNER)
    with open(urls_json, "w", encoding="utf-8") as fh:
        json.dump(urls, fh, ensure_ascii=False)

    print("Running extension JavaScript under Node on " + str(len(urls))
          + " URLs (" + str(len(EDGE_CASES)) + " of them hand-picked edge cases)...")
    proc = subprocess.run(["node", runner_js, EXT_LIB, urls_json, out_json],
                          capture_output=True, text=True)
    if proc.returncode != 0:
        print(proc.stdout)
        print(proc.stderr)
        print("FAILED: could not run the JavaScript (is Node.js installed?)")
        return 1

    with open(out_json, encoding="utf-8") as fh:
        js_results = json.load(fh)

    model = joblib.load(os.path.join(ROOT, "models", "edge_model_gb.joblib"))
    rows = pd.DataFrame([extract_features(u) for u in urls])[FEATURE_NAMES]
    py_prob = model.predict_proba(rows)[:, 1]

    feature_mismatches, worst_prob_diff, worst_url = 0, 0.0, ""
    for i, res in enumerate(js_results):
        for name in FEATURE_NAMES:
            if res["features"][name] != int(rows.iloc[i][name]):
                feature_mismatches += 1
                if feature_mismatches <= 5:
                    print("  feature mismatch on " + name + ": js="
                          + str(res["features"][name]) + " py="
                          + str(int(rows.iloc[i][name])) + "  " + res["url"][:80])
        diff = abs(res["probability"] - float(py_prob[i]))
        if diff > worst_prob_diff:
            worst_prob_diff, worst_url = diff, res["url"]

    print("\nFeature mismatches      : " + str(feature_mismatches))
    print("Max probability delta   : " + format(worst_prob_diff, ".3e"))
    if worst_url:
        print("Worst URL               : " + worst_url[:90])

    ok = feature_mismatches == 0 and worst_prob_diff < 1e-9
    print("\n" + ("PASS - the extension scores URLs exactly like the Python model."
                  if ok else "FAIL - JavaScript and Python disagree."))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
