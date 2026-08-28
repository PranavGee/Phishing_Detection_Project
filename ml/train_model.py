"""
Train the phishing-URL classifier.

Uses ONLY the ten requested dataset columns:
    url, length_url, length_hostname, ip, nb_dots,
    nb_hyphens, nb_at, nb_qm, nb_and, nb_or
(`url` is the identifier; the other nine are the model inputs.)

Seven candidate models are compared with stratified 5-fold cross-validation on
the training split; the winner (by mean CV ROC-AUC) is refit and saved as the
production model.  A Gradient Boosting model is always trained as well because
it is the one exported to JSON for the browser extension's offline scorer.

Run:  python ml/train_model.py
"""

from __future__ import annotations

import json
import os
import sys
import time
import warnings

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import (ExtraTreesClassifier, GradientBoostingClassifier,
                              RandomForestClassifier)
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold, cross_validate, train_test_split
from sklearn.naive_bayes import GaussianNB
from sklearn.neighbors import KNeighborsClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from features import FEATURE_NAMES  # noqa: E402

warnings.filterwarnings("ignore")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data", "dataset_phishing.csv")
MODEL_DIR = os.path.join(ROOT, "models")
METRIC_DIR = os.path.join(ROOT, "reports", "metrics")

RANDOM_STATE = 42
TEST_SIZE = 0.20
TARGET = "status"
POSITIVE_LABEL = "phishing"   # class 1 == phishing


def load_dataset():
    """Load the ten requested columns and map the label to 0/1."""
    df = pd.read_csv(DATA, usecols=["url", TARGET] + FEATURE_NAMES)
    df = df.dropna(subset=FEATURE_NAMES + [TARGET]).reset_index(drop=True)
    X = df[FEATURE_NAMES].astype(float)
    y = (df[TARGET] == POSITIVE_LABEL).astype(int)
    return df, X, y


def get_split():
    """The deterministic train/test split, shared by every downstream script.

    Cached to disk by `main()`, but recreated identically from the seed when the
    cache is absent (it is derived data, so it is not committed to the repo).
    """
    cached = os.path.join(MODEL_DIR, "train_test_split.joblib")
    if os.path.exists(cached):
        return joblib.load(cached)
    _, X, y = load_dataset()
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, stratify=y, random_state=RANDOM_STATE)
    return {"X_train": X_train, "X_test": X_test,
            "y_train": y_train, "y_test": y_test}


def build_candidates():
    """Candidate models. Scale-sensitive ones are wrapped in a scaler pipeline."""
    def scaled(est):
        return Pipeline([("scaler", StandardScaler()), ("clf", est)])

    return {
        "Logistic Regression": scaled(
            LogisticRegression(max_iter=2000, random_state=RANDOM_STATE)),
        "K-Nearest Neighbors": scaled(
            KNeighborsClassifier(n_neighbors=15, weights="distance", n_jobs=-1)),
        "Gaussian Naive Bayes": scaled(GaussianNB()),
        "SVM (RBF)": scaled(
            SVC(C=10, gamma="scale", probability=True, random_state=RANDOM_STATE)),
        "Decision Tree": DecisionTreeClassifier(
            max_depth=12, min_samples_leaf=5, random_state=RANDOM_STATE),
        "Random Forest": RandomForestClassifier(
            n_estimators=500, max_depth=None, min_samples_leaf=3,
            n_jobs=-1, random_state=RANDOM_STATE),
        "Extra Trees": ExtraTreesClassifier(
            n_estimators=400, min_samples_leaf=2,
            n_jobs=-1, random_state=RANDOM_STATE),
        "Gradient Boosting": GradientBoostingClassifier(
            n_estimators=300, learning_rate=0.1, max_depth=4,
            random_state=RANDOM_STATE),
    }


def main() -> int:
    os.makedirs(MODEL_DIR, exist_ok=True)
    os.makedirs(METRIC_DIR, exist_ok=True)

    df, X, y = load_dataset()
    print(f"Dataset      : {len(df):,} URLs   ({int(y.sum()):,} phishing / "
          f"{int((1 - y).sum()):,} legitimate)")
    print(f"Features ({len(FEATURE_NAMES)}) : {', '.join(FEATURE_NAMES)}")

    zero_var = [c for c in FEATURE_NAMES if X[c].nunique() == 1]
    if zero_var:
        print(f"Note         : {', '.join(zero_var)} is constant in this dataset "
              f"(kept, contributes nothing)")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, stratify=y, random_state=RANDOM_STATE)
    print(f"Split        : {len(X_train):,} train / {len(X_test):,} test "
          f"(stratified, seed {RANDOM_STATE})\n")

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=RANDOM_STATE)
    scoring = ["accuracy", "precision", "recall", "f1", "roc_auc"]

    print("Cross-validating candidates (5-fold on the training split)...\n")
    print(f"{'model':<24}{'accuracy':>10}{'precision':>11}{'recall':>9}"
          f"{'f1':>9}{'roc_auc':>10}{'fit s':>8}")
    print("-" * 81)

    rows = []
    for name, model in build_candidates().items():
        t0 = time.time()
        res = cv_res = cross_validate(model, X_train, y_train, cv=cv,
                                      scoring=scoring, n_jobs=-1)
        row = {"model": name}
        for metric in scoring:
            row[metric] = float(np.mean(cv_res[f"test_{metric}"]))
            row[f"{metric}_std"] = float(np.std(cv_res[f"test_{metric}"]))
        row["fit_time_s"] = round(time.time() - t0, 2)
        rows.append(row)
        print(f"{name:<24}{row['accuracy']:>10.4f}{row['precision']:>11.4f}"
              f"{row['recall']:>9.4f}{row['f1']:>9.4f}{row['roc_auc']:>10.4f}"
              f"{row['fit_time_s']:>8.1f}")
        del res

    comparison = pd.DataFrame(rows).sort_values("roc_auc", ascending=False)
    comparison.to_csv(os.path.join(METRIC_DIR, "model_comparison.csv"), index=False)

    best_name = comparison.iloc[0]["model"]
    print("-" * 81)
    print(f"\nBest by CV ROC-AUC: {best_name}\n")

    # Refit the winner on the full training split and persist it.
    candidates = build_candidates()
    best_model = candidates[best_name]
    best_model.fit(X_train, y_train)
    joblib.dump(best_model, os.path.join(MODEL_DIR, "phishing_model.joblib"),
                compress=3)

    # Always fit + save Gradient Boosting: it is exported to JSON so that the
    # browser extension can score URLs offline, with no network round-trip.
    if best_name == "Gradient Boosting":
        gb_model = best_model
    else:
        gb_model = candidates["Gradient Boosting"]
        gb_model.fit(X_train, y_train)
    joblib.dump(gb_model, os.path.join(MODEL_DIR, "edge_model_gb.joblib"),
                compress=3)

    # Persist the exact split so evaluate.py scores on unseen data only.
    joblib.dump(
        {"X_train": X_train, "X_test": X_test, "y_train": y_train, "y_test": y_test},
        os.path.join(MODEL_DIR, "train_test_split.joblib"), compress=3)

    meta = {
        "best_model": best_name,
        "feature_names": FEATURE_NAMES,
        "positive_class": POSITIVE_LABEL,
        "n_rows": int(len(df)),
        "n_train": int(len(X_train)),
        "n_test": int(len(X_test)),
        "test_size": TEST_SIZE,
        "random_state": RANDOM_STATE,
        "constant_features": zero_var,
        "cv_results": rows,
        "trained_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "sklearn_version": __import__("sklearn").__version__,
    }
    with open(os.path.join(MODEL_DIR, "model_meta.json"), "w", encoding="utf-8") as fh:
        json.dump(meta, fh, indent=2)

    print(f"Saved -> models/phishing_model.joblib      ({best_name})")
    print("Saved -> models/edge_model_gb.joblib       (offline extension model)")
    print("Saved -> models/train_test_split.joblib")
    print("Saved -> models/model_meta.json")
    print("Saved -> reports/metrics/model_comparison.csv")
    print("\nNext: python ml/evaluate.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
