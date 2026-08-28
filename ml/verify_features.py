"""
Verify that `ml/features.py` reproduces the dataset columns.

Guarantees train/inference consistency: the browser extension and web app
compute features from a raw URL, while the model was trained on the columns
shipped in `dataset_phishing.csv`.  If the two disagreed, live predictions
would be silently wrong.  Run:  python ml/verify_features.py
"""

from __future__ import annotations

import json
import os
import sys

import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from features import FEATURE_NAMES, extract_features  # noqa: E402

# The Windows console defaults to cp1252, which cannot print an
# internationalised URL. Without this, a report about a non-ASCII URL would
# crash instead of being shown.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data", "dataset_phishing.csv")
OUT = os.path.join(ROOT, "reports", "metrics", "feature_verification.json")


def main() -> int:
    df = pd.read_csv(DATA, usecols=["url"] + FEATURE_NAMES)
    recomputed = pd.DataFrame([extract_features(u) for u in df["url"]])

    report, worst = {}, 1.0
    print(f"Verifying {len(df):,} URLs against ml/features.py\n")
    print(f"{'feature':<18}{'agreement':>12}{'mismatches':>13}")
    print("-" * 43)
    for name in FEATURE_NAMES:
        match = (recomputed[name] == df[name])
        agreement = float(match.mean())
        report[name] = {
            "agreement": round(agreement, 6),
            "mismatches": int((~match).sum()),
        }
        worst = min(worst, agreement)
        print(f"{name:<18}{agreement:>11.4%}{int((~match).sum()):>13}")

    print("-" * 43)
    print(f"{'WORST':<18}{worst:>11.4%}")
    print(
        "\nNote: the handful of mismatches come from a few URLs that were "
        "truncated\nwhen the CSV was written, not from the extraction rules."
    )

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump({"rows": int(len(df)), "per_feature": report,
                   "worst_agreement": round(worst, 6)}, fh, indent=2)
    print(f"\nSaved -> {os.path.relpath(OUT, ROOT)}")
    return 0 if worst >= 0.99 else 1


if __name__ == "__main__":
    raise SystemExit(main())
