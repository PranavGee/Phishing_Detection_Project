"""
Export the Gradient Boosting model to plain JSON so the browser extension can
score URLs entirely offline (no network round-trip, nothing leaves the device).

A boosted ensemble of shallow trees is small enough to ship inside an extension:
scoring is `sigmoid(base + lr * sum(tree(x)))`, which is ~30 lines of JavaScript
(see extension/lib/model.js).

The exporter re-derives the intercept empirically from `decision_function` and
then asserts that the exported representation reproduces sklearn's
`predict_proba` to within 1e-9 on the whole test set, so the JS scorer cannot
silently drift from the Python model.

Run (after train_model.py):  python ml/export_js_model.py
"""

from __future__ import annotations

import json
import os
import sys

import joblib
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from features import FEATURE_NAMES  # noqa: E402
from train_model import get_split  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_DIR = os.path.join(ROOT, "models")
TARGETS = [os.path.join(ROOT, "extension", "lib", "model.json")]
ROUND = 12


def export_tree(tree) -> dict:
    """Flatten a sklearn tree into parallel arrays (leaves have feature -1)."""
    t = tree.tree_
    return {
        "f": [int(v) for v in t.feature],
        "t": [round(float(v), ROUND) for v in t.threshold],
        "l": [int(v) for v in t.children_left],
        "r": [int(v) for v in t.children_right],
        "v": [round(float(v), ROUND) for v in t.value.reshape(-1)],
    }


def predict_raw(trees, base, lr, row):
    """Reference implementation of what model.js does, used for the parity check."""
    total = 0.0
    for tree in trees:
        node = 0
        while tree["f"][node] >= 0:
            node = (tree["l"][node] if row[tree["f"][node]] <= tree["t"][node]
                    else tree["r"][node])
        total += tree["v"][node]
    return base + lr * total


def main() -> int:
    model = joblib.load(os.path.join(MODEL_DIR, "edge_model_gb.joblib"))
    split = get_split()
    with open(os.path.join(MODEL_DIR, "model_meta.json"), encoding="utf-8") as fh:
        meta = json.load(fh)

    X_test = split["X_test"]
    lr = float(model.learning_rate)
    trees = [export_tree(est[0]) for est in model.estimators_]

    # Recover the constant init term without depending on sklearn internals:
    # decision_function = base + lr * sum(trees), so base is the leftover.
    probe = X_test.iloc[:200]
    leaves = np.array([[predict_raw([t], 0.0, lr, row) for t in trees]
                       for row in probe.to_numpy()]).sum(axis=1)
    base = float(np.median(model.decision_function(probe) - leaves))

    export = {
        "format": "gradient_boosting_binary_v1",
        "feature_names": FEATURE_NAMES,
        "learning_rate": lr,
        "base_score": round(base, 8),
        "n_trees": len(trees),
        "positive_class": "phishing",
        "default_threshold": 0.5,
        "trained_at": meta["trained_at"],
        "trees": trees,
    }

    # Parity check against sklearn on the full held-out set.
    mine = 1.0 / (1.0 + np.exp(-np.array(
        [predict_raw(trees, base, lr, row) for row in X_test.to_numpy()])))
    theirs = model.predict_proba(X_test)[:, 1]
    diff = float(np.max(np.abs(mine - theirs)))
    print("Exported " + str(len(trees)) + " trees, "
          + str(sum(len(t["f"]) for t in trees)) + " nodes")
    print("Max |exported - sklearn| probability difference: " + format(diff, ".3e"))
    if diff > 1e-9:
        print("ERROR: exported model does not match sklearn.")
        return 1

    payload = json.dumps(export, separators=(",", ":"))
    for target in TARGETS:
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "w", encoding="utf-8") as fh:
            fh.write(payload)
        print("Saved -> " + os.path.relpath(target, ROOT)
              + "  (" + format(len(payload) / 1024, ".0f") + " KB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
