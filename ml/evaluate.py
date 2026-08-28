"""
Evaluate the trained phishing classifier and render every report figure.

Produces (in reports/):
    metrics/classification_report.txt   precision / recall / F1 per class
    metrics/test_metrics.json           headline metrics on the held-out split
    metrics/threshold_sweep.csv         metrics across decision thresholds
    figures/01_class_distribution.png
    figures/02_feature_distributions.png
    figures/03_correlation_heatmap.png
    figures/04_model_comparison.png
    figures/05_confusion_matrix.png
    figures/06_roc_curve.png
    figures/07_precision_recall_curve.png
    figures/08_feature_importance.png
    figures/09_learning_curve.png
    figures/10_threshold_analysis.png

Run (after train_model.py):  python ml/evaluate.py
"""

from __future__ import annotations

import json
import os
import sys
import warnings

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn.inspection import permutation_importance
from sklearn.metrics import (accuracy_score, auc, average_precision_score,
                             classification_report, confusion_matrix, f1_score,
                             matthews_corrcoef, precision_recall_curve,
                             precision_score, recall_score, roc_auc_score,
                             roc_curve)
from sklearn.model_selection import learning_curve

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from features import FEATURE_NAMES  # noqa: E402
from train_model import get_split  # noqa: E402

warnings.filterwarnings("ignore")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data", "dataset_phishing.csv")
MODEL_DIR = os.path.join(ROOT, "models")
FIG_DIR = os.path.join(ROOT, "reports", "figures")
METRIC_DIR = os.path.join(ROOT, "reports", "metrics")

PHISH = "#d92b2b"
SAFE = "#1a9e5c"
ACCENT = "#2b5fd9"
sns.set_theme(style="whitegrid", font_scale=1.0)
plt.rcParams.update({"figure.dpi": 130, "savefig.dpi": 130,
                     "axes.titleweight": "bold", "savefig.bbox": "tight"})


def save(fig, name):
    fig.savefig(os.path.join(FIG_DIR, name))
    plt.close(fig)
    print("  figure -> reports/figures/" + name)


# --------------------------------------------------------------------------- #
# Exploratory figures
# --------------------------------------------------------------------------- #
def fig_class_distribution(df):
    counts = df["status"].value_counts()
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.2))
    colors = [SAFE if s == "legitimate" else PHISH for s in counts.index]
    axes[0].bar(counts.index, counts.values, color=colors, width=0.55)
    for i, v in enumerate(counts.values):
        axes[0].text(i, v + 60, format(v, ","), ha="center", fontweight="bold")
    axes[0].set_title("Class distribution")
    axes[0].set_ylabel("URLs")
    axes[0].set_ylim(0, counts.max() * 1.15)
    axes[1].pie(counts.values, labels=counts.index, colors=colors,
                autopct="%1.1f%%", startangle=90,
                wedgeprops={"edgecolor": "white", "linewidth": 2})
    axes[1].set_title("Balance")
    fig.suptitle("Dataset composition", fontweight="bold")
    save(fig, "01_class_distribution.png")


def fig_feature_distributions(df):
    plot_feats = [f for f in FEATURE_NAMES if df[f].nunique() > 1]
    fig, axes = plt.subplots(2, 4, figsize=(17, 7.5))
    for ax, feat in zip(axes.ravel(), plot_feats):
        legit = df.loc[df.status == "legitimate", feat]
        phish = df.loc[df.status == "phishing", feat]
        if df[feat].nunique() <= 3:
            width = 0.38
            vals = sorted(df[feat].unique())
            idx = np.arange(len(vals))
            ax.bar(idx - width / 2, [int((legit == v).sum()) for v in vals],
                   width, color=SAFE, label="legitimate")
            ax.bar(idx + width / 2, [int((phish == v).sum()) for v in vals],
                   width, color=PHISH, label="phishing")
            ax.set_xticks(idx)
            ax.set_xticklabels(vals)
        else:
            hi = np.percentile(df[feat], 99)
            bins = np.linspace(0, max(hi, 1), 40)
            ax.hist(legit, bins=bins, color=SAFE, alpha=0.62, label="legitimate")
            ax.hist(phish, bins=bins, color=PHISH, alpha=0.62, label="phishing")
        ax.set_title(feat, fontsize=11)
        ax.set_ylabel("count")
    for ax in axes.ravel()[len(plot_feats):]:
        ax.axis("off")
    axes.ravel()[0].legend(loc="upper right", fontsize=9)
    fig.suptitle("Feature distributions by class (99th-percentile clipped)",
                 fontweight="bold", y=1.0)
    fig.tight_layout()
    save(fig, "02_feature_distributions.png")


def fig_correlation(df):
    corr = df[FEATURE_NAMES + ["label"]].corr()
    fig, ax = plt.subplots(figsize=(9, 7.2))
    sns.heatmap(corr, annot=True, fmt=".2f", cmap="RdBu_r", center=0,
                square=True, linewidths=0.5, cbar_kws={"shrink": 0.8}, ax=ax,
                annot_kws={"size": 8})
    ax.set_title("Feature correlation matrix (label: 1 = phishing)")
    save(fig, "03_correlation_heatmap.png")


def fig_model_comparison():
    comp = pd.read_csv(os.path.join(METRIC_DIR, "model_comparison.csv"))
    comp = comp.sort_values("roc_auc")
    fig, axes = plt.subplots(1, 2, figsize=(15, 5.6))
    y = np.arange(len(comp))
    bars = axes[0].barh(y, comp["roc_auc"], color=ACCENT, height=0.62)
    bars[-1].set_color(PHISH)
    axes[0].set_yticks(y)
    axes[0].set_yticklabels(comp["model"])
    axes[0].set_xlim(0.5, 1.0)
    axes[0].set_xlabel("mean CV ROC-AUC")
    axes[0].set_title("Model ranking (5-fold CV)")
    for i, v in enumerate(comp["roc_auc"]):
        axes[0].text(v + 0.004, i, format(v, ".4f"), va="center", fontsize=9)

    metrics = ["accuracy", "precision", "recall", "f1"]
    width = 0.2
    x = np.arange(len(comp))
    for i, m in enumerate(metrics):
        axes[1].bar(x + (i - 1.5) * width, comp[m], width, label=m)
    axes[1].set_xticks(x)
    axes[1].set_xticklabels(comp["model"], rotation=35, ha="right", fontsize=8)
    axes[1].set_ylim(0, 1)
    axes[1].legend(ncol=4, fontsize=9)
    axes[1].set_title("All metrics per model")
    fig.tight_layout()
    save(fig, "04_model_comparison.png")


# --------------------------------------------------------------------------- #
# Model figures
# --------------------------------------------------------------------------- #
def fig_confusion(y_true, y_pred):
    cm = confusion_matrix(y_true, y_pred)
    fig, axes = plt.subplots(1, 2, figsize=(12, 4.8))
    labels = ["legitimate", "phishing"]
    sns.heatmap(cm, annot=True, fmt=",d", cmap="Blues", square=True,
                xticklabels=labels, yticklabels=labels, cbar=False, ax=axes[0],
                annot_kws={"size": 14, "weight": "bold"})
    axes[0].set_title("Confusion matrix (counts)")
    cmn = cm / cm.sum(axis=1, keepdims=True)
    sns.heatmap(cmn, annot=True, fmt=".2%", cmap="Blues", square=True,
                xticklabels=labels, yticklabels=labels, cbar=False, ax=axes[1],
                annot_kws={"size": 14, "weight": "bold"}, vmin=0, vmax=1)
    axes[1].set_title("Normalised by true class")
    for ax in axes:
        ax.set_xlabel("predicted")
        ax.set_ylabel("actual")
    fig.suptitle("Held-out test set", fontweight="bold")
    fig.tight_layout()
    save(fig, "05_confusion_matrix.png")
    return cm


def fig_roc(y_true, y_prob, name):
    fpr, tpr, _ = roc_curve(y_true, y_prob)
    fig, ax = plt.subplots(figsize=(6.6, 5.6))
    ax.plot(fpr, tpr, color=PHISH, lw=2.4,
            label=name + " (AUC = " + format(auc(fpr, tpr), ".4f") + ")")
    ax.plot([0, 1], [0, 1], "--", color="grey", lw=1.2, label="random (0.50)")
    ax.fill_between(fpr, tpr, alpha=0.10, color=PHISH)
    ax.set_xlabel("false positive rate")
    ax.set_ylabel("true positive rate")
    ax.set_title("ROC curve")
    ax.legend(loc="lower right")
    save(fig, "06_roc_curve.png")


def fig_pr(y_true, y_prob, name):
    prec, rec, _ = precision_recall_curve(y_true, y_prob)
    ap = average_precision_score(y_true, y_prob)
    fig, ax = plt.subplots(figsize=(6.6, 5.6))
    ax.plot(rec, prec, color=ACCENT, lw=2.4,
            label=name + " (AP = " + format(ap, ".4f") + ")")
    ax.axhline(y_true.mean(), ls="--", color="grey", lw=1.2,
               label="baseline (" + format(y_true.mean(), ".2f") + ")")
    ax.fill_between(rec, prec, alpha=0.10, color=ACCENT)
    ax.set_xlabel("recall")
    ax.set_ylabel("precision")
    ax.set_title("Precision-Recall curve")
    ax.legend(loc="lower left")
    save(fig, "07_precision_recall_curve.png")


def fig_importance(model, X_test, y_test):
    est = model.named_steps["clf"] if hasattr(model, "named_steps") else model
    perm = permutation_importance(model, X_test, y_test, n_repeats=10,
                                  random_state=42, n_jobs=-1, scoring="roc_auc")
    has_native = hasattr(est, "feature_importances_")
    ncols = 2 if has_native else 1
    fig, axes = plt.subplots(1, ncols, figsize=(7.5 * ncols, 5.4), squeeze=False)
    axes = axes[0]

    if has_native:
        order = np.argsort(est.feature_importances_)
        axes[0].barh(np.array(FEATURE_NAMES)[order],
                     est.feature_importances_[order], color=ACCENT)
        axes[0].set_title("Impurity-based importance")
        axes[0].set_xlabel("mean decrease in impurity")

    ax = axes[-1]
    order = np.argsort(perm.importances_mean)
    ax.barh(np.array(FEATURE_NAMES)[order], perm.importances_mean[order],
            xerr=perm.importances_std[order], color=PHISH)
    ax.set_title("Permutation importance (test ROC-AUC drop)")
    ax.set_xlabel("mean AUC decrease")
    fig.suptitle("Which URL properties drive the prediction", fontweight="bold")
    fig.tight_layout()
    save(fig, "08_feature_importance.png")
    return {f: float(v) for f, v in zip(FEATURE_NAMES, perm.importances_mean)}


def fig_learning_curve(model, X, y):
    sizes, train_sc, test_sc = learning_curve(
        model, X, y, cv=5, scoring="roc_auc", n_jobs=-1,
        train_sizes=np.linspace(0.1, 1.0, 8), random_state=42)
    fig, ax = plt.subplots(figsize=(7.2, 5.2))
    for scores, colour, label in ((train_sc, ACCENT, "training"),
                                  (test_sc, PHISH, "cross-validation")):
        mean, std = scores.mean(1), scores.std(1)
        ax.plot(sizes, mean, "o-", color=colour, label=label)
        ax.fill_between(sizes, mean - std, mean + std, alpha=0.15, color=colour)
    ax.set_xlabel("training samples")
    ax.set_ylabel("ROC-AUC")
    ax.set_title("Learning curve")
    ax.legend(loc="best")
    save(fig, "09_learning_curve.png")


def fig_threshold(y_true, y_prob):
    rows = []
    for t in np.linspace(0.05, 0.95, 91):
        pred = (y_prob >= t).astype(int)
        rows.append({
            "threshold": round(float(t), 3),
            "accuracy": accuracy_score(y_true, pred),
            "precision": precision_score(y_true, pred, zero_division=0),
            "recall": recall_score(y_true, pred, zero_division=0),
            "f1": f1_score(y_true, pred, zero_division=0),
        })
    sweep = pd.DataFrame(rows)
    sweep.to_csv(os.path.join(METRIC_DIR, "threshold_sweep.csv"), index=False)

    best = sweep.loc[sweep["f1"].idxmax()]
    fig, ax = plt.subplots(figsize=(8.2, 5.2))
    for col, colour in (("accuracy", "#6b7280"), ("precision", ACCENT),
                        ("recall", PHISH), ("f1", SAFE)):
        ax.plot(sweep["threshold"], sweep[col], label=col, color=colour, lw=2)
    ax.axvline(0.5, ls="--", color="grey", lw=1, label="default 0.50")
    ax.axvline(best["threshold"], ls=":", color="black", lw=1.4,
               label="best F1 @ " + format(best["threshold"], ".2f"))
    ax.set_xlabel("decision threshold (P(phishing) >= t)")
    ax.set_ylabel("score")
    ax.set_title("Threshold analysis - how strict should the warning be?")
    ax.legend(loc="lower center", ncol=3, fontsize=9)
    save(fig, "10_threshold_analysis.png")
    return sweep, best


# --------------------------------------------------------------------------- #
def main() -> int:
    os.makedirs(FIG_DIR, exist_ok=True)
    os.makedirs(METRIC_DIR, exist_ok=True)

    with open(os.path.join(MODEL_DIR, "model_meta.json"), encoding="utf-8") as fh:
        meta = json.load(fh)
    model = joblib.load(os.path.join(MODEL_DIR, "phishing_model.joblib"))
    split = get_split()
    X_train, X_test = split["X_train"], split["X_test"]
    y_train, y_test = split["y_train"], split["y_test"]

    df = pd.read_csv(DATA, usecols=["url", "status"] + FEATURE_NAMES)
    df["label"] = (df["status"] == "phishing").astype(int)

    name = meta["best_model"]
    print("Evaluating: " + name + "\n")
    print("Exploratory figures")
    fig_class_distribution(df)
    fig_feature_distributions(df)
    fig_correlation(df)
    fig_model_comparison()

    y_prob = model.predict_proba(X_test)[:, 1]
    y_pred = (y_prob >= 0.5).astype(int)

    print("\nModel figures")
    cm = fig_confusion(y_test, y_pred)
    fig_roc(y_test, y_prob, name)
    fig_pr(y_test, y_prob, name)
    importance = fig_importance(model, X_test, y_test)
    fig_learning_curve(model, X_train, y_train)
    _, best_th = fig_threshold(y_test, y_prob)

    tn, fp, fn, tp = cm.ravel()
    metrics = {
        "model": name,
        "n_test": int(len(y_test)),
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "precision": float(precision_score(y_test, y_pred)),
        "recall": float(recall_score(y_test, y_pred)),
        "f1": float(f1_score(y_test, y_pred)),
        "roc_auc": float(roc_auc_score(y_test, y_prob)),
        "average_precision": float(average_precision_score(y_test, y_prob)),
        "mcc": float(matthews_corrcoef(y_test, y_pred)),
        "specificity": float(tn / (tn + fp)),
        "false_positive_rate": float(fp / (fp + tn)),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp),
                             "fn": int(fn), "tp": int(tp)},
        "best_f1_threshold": float(best_th["threshold"]),
        "best_f1_at_threshold": float(best_th["f1"]),
        "permutation_importance": importance,
    }
    with open(os.path.join(METRIC_DIR, "test_metrics.json"), "w",
              encoding="utf-8") as fh:
        json.dump(metrics, fh, indent=2)

    report = classification_report(y_test, y_pred,
                                   target_names=["legitimate", "phishing"],
                                   digits=4)
    header = ("Phishing URL Detection - held-out test set ("
              + format(len(y_test), ",") + " URLs)\n"
              "Model: " + name + "\n"
              "Features: " + ", ".join(FEATURE_NAMES) + "\n" + "=" * 64 + "\n")
    body = ("\nROC-AUC              " + format(metrics["roc_auc"], ".4f") + "\n"
            "Average precision    " + format(metrics["average_precision"], ".4f") + "\n"
            "Matthews corr coef   " + format(metrics["mcc"], ".4f") + "\n"
            "Specificity          " + format(metrics["specificity"], ".4f") + "\n"
            "False positive rate  " + format(metrics["false_positive_rate"], ".4f") + "\n")
    with open(os.path.join(METRIC_DIR, "classification_report.txt"), "w",
              encoding="utf-8") as fh:
        fh.write(header + report + body)

    print("\n" + header + report + body)
    print("  metrics -> reports/metrics/test_metrics.json")
    print("  metrics -> reports/metrics/classification_report.txt")
    print("  metrics -> reports/metrics/threshold_sweep.csv")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
