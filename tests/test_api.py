"""
Web app + API tests.

Uses Flask's test client, so no server needs to be running.

Run:  python tests/test_api.py
"""

from __future__ import annotations

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "webapp"))
sys.path.insert(0, os.path.join(ROOT, "ml"))

from app import app  # noqa: E402

passed = 0
failed = 0


def check(name, actual, expected):
    global passed, failed
    if actual == expected:
        passed += 1
        print("  PASS  " + name)
    else:
        failed += 1
        print("  FAIL  " + name + "\n          expected " + repr(expected)
              + "\n          actual   " + repr(actual))


def check_true(name, value):
    check(name, bool(value), True)


def main() -> int:
    client = app.test_client()

    print("\nPages")
    check("GET / returns 200", client.get("/").status_code, 200)
    check("GET /report returns 200", client.get("/report").status_code, 200)
    check_true("the scanner page renders both action buttons",
               b"Proceed with this Website" in client.get("/").data
               and b"Return to Safety" in client.get("/").data)

    print("\nHealth and model info")
    health = client.get("/api/health")
    check("GET /api/health returns 200", health.status_code, 200)
    check("health reports ok", health.get_json()["status"], "ok")

    info = client.get("/api/model-info").get_json()
    check("model-info lists exactly the nine requested features",
          info["features"],
          ["length_url", "length_hostname", "ip", "nb_dots", "nb_hyphens",
           "nb_at", "nb_qm", "nb_and", "nb_or"])
    check_true("model-info carries the test metrics",
               "roc_auc" in info["test_metrics"])

    print("\nPrediction")
    phish_url = ("http://secure-appleld.com.verify-login.duilawyeryork.com/"
                 "ap/89e6a3b4b063b8d/?cmd=_update&dispatch=89e6a3b4b063b8d1b")
    res = client.post("/api/predict", json={"url": phish_url}).get_json()
    check("a textbook phishing URL is called phishing", res["verdict"], "phishing")
    check_true("its probability is high", res["probability"] > 0.9)
    check("the hostname is parsed correctly", res["hostname"],
          "secure-appleld.com.verify-login.duilawyeryork.com")
    check("all nine features come back", sorted(res["features"].keys()),
          sorted(["length_url", "length_hostname", "ip", "nb_dots", "nb_hyphens",
                  "nb_at", "nb_qm", "nb_and", "nb_or"]))
    check_true("an explanation is included", len(res["reasons"]) > 0)
    check("risk_score matches the probability", res["risk_score"],
          int(round(res["probability"] * 100)))

    safe = client.post("/api/predict", json={"url": "https://www.google.com"}).get_json()
    check("a short clean URL is called legitimate", safe["verdict"], "legitimate")

    print("\nThresholds")
    strict = client.post("/api/predict",
                         json={"url": "https://www.github.com/explore",
                               "threshold": 0.95}).get_json()
    loose = client.post("/api/predict",
                        json={"url": "https://www.github.com/explore",
                              "threshold": 0.2}).get_json()
    check("a strict threshold clears it", strict["is_phishing"], False)
    check("a loose threshold flags it", loose["is_phishing"], True)
    check("the probability does not depend on the threshold",
          round(strict["probability"], 6), round(loose["probability"], 6))

    print("\nBatch")
    batch = client.post("/api/predict/batch", json={
        "urls": [phish_url, "https://www.google.com", "https://en.wikipedia.org"]
    }).get_json()
    check("batch returns one result per URL", batch["count"], 3)
    check_true("batch reports how many were flagged", batch["flagged"] >= 1)

    print("\nInput validation")
    check("empty body is rejected",
          client.post("/api/predict", json={}).status_code, 400)
    check("empty url is rejected",
          client.post("/api/predict", json={"url": "  "}).status_code, 400)
    check("out-of-range threshold is rejected",
          client.post("/api/predict",
                      json={"url": "https://a.com", "threshold": 5}).status_code, 400)
    check("non-numeric threshold is rejected",
          client.post("/api/predict",
                      json={"url": "https://a.com", "threshold": "high"}).status_code,
          400)
    check("an empty batch is rejected",
          client.post("/api/predict/batch", json={"urls": []}).status_code, 400)
    check("an oversized batch is rejected",
          client.post("/api/predict/batch",
                      json={"urls": ["https://a.com"] * 101}).status_code, 400)
    check("an unknown route 404s", client.get("/nope").status_code, 404)

    print("\nA URL with no scheme still works")
    bare = client.post("/api/predict", json={"url": "example.com/login"}).get_json()
    check("hostname resolved without a scheme", bare["hostname"], "example.com")

    print("\n" + ("All " + str(passed) + " checks passed."
                  if failed == 0 else
                  str(passed) + " passed, " + str(failed) + " FAILED."))
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
