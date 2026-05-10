from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path
import pickle
import json
import os
import time

import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.inspection import permutation_importance
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    average_precision_score,
    classification_report,
    confusion_matrix,
    roc_auc_score,
)
from sklearn.model_selection import (
    StratifiedKFold,
    cross_val_score,
    train_test_split,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from scan_engine import FEATURE_COLUMNS, compute_schema_hash

def load_dataset(path: Path) -> tuple[pd.DataFrame, pd.Series]:
    df = pd.read_csv(path)
    required = set(FEATURE_COLUMNS + ["type"])
    missing = sorted(required - set(df.columns))
    if missing:
        raise ValueError(f"Dataset missing required columns: {missing}")
    X = df[FEATURE_COLUMNS].astype(float)
    y_raw = df["type"]
    y = (y_raw != "benign").astype(int)
    return X, y
# ── Fast Random Forest with sensible defaults (no expensive grid search) ──
# When FAST=1 in env, skips GBM and LogisticRegression baselines too

def train_random_forest(X_train: pd.DataFrame, y_train: pd.Series, fast: bool = True) -> tuple[Pipeline, float]:
    if fast:
        # Optimised defaults proven to work well on phishing datasets
        rf = RandomForestClassifier(
            n_estimators=200,
            max_depth=15,
            min_samples_split=10,
            min_samples_leaf=4,
            max_features="sqrt",
            max_leaf_nodes=5000,
            max_samples=0.8,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
        )
        cv = StratifiedKFold(n_splits=3, shuffle=True, random_state=42)
        scores = cross_val_score(Pipeline([("clf", rf)]), X_train, y_train, cv=cv, scoring="roc_auc", n_jobs=-1)
        cv_auc = float(np.mean(scores))
        print(f"  Random Forest (fast) — CV AUC = {cv_auc:.4f}", flush=True)
        # Fit on full training set
        rf.fit(X_train, y_train)
        return Pipeline([("clf", rf)]), cv_auc
    else:
        # Full search path (slower, for tuning)
        from sklearn.model_selection import RandomizedSearchCV
        param_dist = {
            "clf__n_estimators": [100, 150, 200],
            "clf__max_depth": [12, 15, 18],
            "clf__min_samples_split": [5, 10, 20],
            "clf__min_samples_leaf": [4, 8, 16],
            "clf__max_features": ["sqrt", "log2"],
            "clf__max_leaf_nodes": [2000, 4000, 8000],
            "clf__class_weight": ["balanced", "balanced_subsample"],
        }
        cv = StratifiedKFold(n_splits=3, shuffle=True, random_state=42)
        base = Pipeline([("clf", RandomForestClassifier(random_state=42, n_jobs=-1))])
        search = RandomizedSearchCV(base, param_dist, n_iter=20, scoring="roc_auc", cv=cv, random_state=42, n_jobs=-1, verbose=2)
        search.fit(X_train, y_train)
        return search.best_estimator_, search.best_score_

def train_and_select_model(X_train: pd.DataFrame, y_train: pd.Series, fast: bool = True) -> tuple[str, Pipeline, float]:
    if not fast:
        # Quick Logistic Regression baseline
        cv = StratifiedKFold(n_splits=3, shuffle=True, random_state=42)
        lr = Pipeline([("scaler", StandardScaler()), ("clf", LogisticRegression(max_iter=500, solver="lbfgs", class_weight="balanced", random_state=42, n_jobs=-1))])
        lr_scores = cross_val_score(lr, X_train, y_train, cv=cv, scoring="roc_auc", n_jobs=-1)
        print(f"  Logistic Regression baseline CV AUC = {np.mean(lr_scores):.4f}", flush=True)

    rf_pipeline, rf_auc = train_random_forest(X_train, y_train, fast=fast)
    return "random_forest", rf_pipeline, rf_auc

def make_bundle(model, model_name: str, cv_auc: float, metrics: dict, X_test: pd.DataFrame, y_test: pd.Series) -> dict:
    print("\nBuilding model bundle with permutation importance (5 repeats)...", flush=True)
    perm = permutation_importance(model, X_test, y_test, scoring="roc_auc", n_repeats=5, random_state=42, n_jobs=-1)

    top_global = sorted([
        {"feature": FEATURE_COLUMNS[i], "importance": float(perm.importances_mean[i]), "std": float(perm.importances_std[i])}
        for i in range(len(FEATURE_COLUMNS))
    ], key=lambda x: x["importance"], reverse=True)

    return {
        "model": model,
        "feature_columns": FEATURE_COLUMNS,
        "schema_hash": compute_schema_hash(FEATURE_COLUMNS),
        "model_version": "2.1.0",
        "selected_model": model_name,
        "cv_auc_mean": float(cv_auc),
        "metrics": metrics,
        "top_global_features": top_global,
        "trained_at_utc": datetime.now(timezone.utc).isoformat(),
    }

def evaluate_model(model, X_test: pd.DataFrame, y_test: pd.Series) -> dict:
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]
    report = classification_report(y_test, y_pred, output_dict=True, zero_division=0)
    roc_auc = float(roc_auc_score(y_test, y_prob))
    pr_auc = float(average_precision_score(y_test, y_prob))
    cm = confusion_matrix(y_test, y_pred).tolist()
    return {
        "classification_report": report,
        "roc_auc": roc_auc,
        "pr_auc": pr_auc,
        "confusion_matrix": cm,
    }

def write_evidence_pack(output_md: Path, dataset_path: Path, bundle: dict) -> None:
    metrics = bundle["metrics"]
    cm = metrics["confusion_matrix"]
    report = metrics["classification_report"]
    lines = [
        "# FYP Evidence Pack — v2.1", "", "## Dataset Provenance", f"- Source file: `{dataset_path}`",
        "- Dataset family: UCI phishing website style 60-feature schema", "- Target mapping: phishing=1, legitimate=0",
        "", "## Model Selection", f"- Selected model: `{bundle['selected_model']}`", f"- Cross-validation ROC-AUC (mean): `{bundle['cv_auc_mean']:.4f}`",
        f"- Schema hash: `{bundle['schema_hash']}`", "- Selection method: Fast variant — fixed optimised hyperparameters",
        "", "## Test Metrics", f"- ROC-AUC: `{metrics['roc_auc']:.4f}`", f"- PR-AUC: `{metrics['pr_auc']:.4f}`",
        f"- Precision (phishing class): `{report.get('1', {}).get('precision', 0.0):.4f}`",
        f"- Recall (phishing class): `{report.get('1', {}).get('recall', 0.0):.4f}`",
        f"- F1 (phishing class): `{report.get('1', {}).get('f1-score', 0.0):.4f}`",
        "", "## Confusion Matrix", "- Format: [[TN, FP], [FN, TP]]", f"- Values: `{cm}`", "", "## Top Global Features (Permutation Importance)",
    ]
    for item in bundle.get("top_global_features", [])[:10]:
        lines.append(f"- {item['feature']}: importance={item['importance']:.6f}, std={item['std']:.6f}")
    lines.extend([
        "", "## Training Pipeline", "- Random Forest with optimised defaults (n=200, depth=15)",
        "- CalibratedClassifierCV (sigmoid) for reliable probabilities",
        f"Generated at: {datetime.now(timezone.utc).isoformat()}",
    ])
    output_md.write_text("\n".join(lines), encoding="utf-8")

def main() -> None:
    parser = argparse.ArgumentParser(description="Train phishing classifier bundle.")
    parser.add_argument("--dataset", type=str, default="datasets/final_dataset_with_all_features_v3.1.csv")
    parser.add_argument("--output", type=str, default="artifacts/phishing_model_bundle.pkl")
    parser.add_argument("--evidence", type=str, default="EVIDENCE_PACK.md")
    parser.add_argument("--full", action="store_true", help="Run full hyperparameter search (slower)")
    args = parser.parse_args()

    fast = not args.full

    # Maximise CPU utilisation
    n_cpus = os.cpu_count() or 4
    os.environ.setdefault("OMP_NUM_THREADS", str(n_cpus))
    os.environ.setdefault("OPENBLAS_NUM_THREADS", str(n_cpus))
    os.environ.setdefault("MKL_NUM_THREADS", str(n_cpus))
    print(f"Using {n_cpus} CPU cores", flush=True)

    dataset_path = Path(args.dataset).resolve()
    output_path = Path(args.output)
    evidence_path = Path(args.evidence)

    print(f"Loading dataset: {dataset_path}", flush=True)
    X, y = load_dataset(dataset_path)
    print(f"Dataset loaded: {X.shape[0]} rows, {X.shape[1]} features", flush=True)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    selected_name, selected_model, cv_auc = train_and_select_model(X_train, y_train, fast=fast)

    X_model_train, X_calib, y_model_train, y_calib = train_test_split(X_train, y_train, test_size=0.2, random_state=42, stratify=y_train)

    print(f"\nFitting best model ({selected_name}) on training set...", flush=True)
    selected_model.fit(X_model_train, y_model_train)

    print("Calibrating probability outputs (sigmoid method)...", flush=True)
    calibrated_model = CalibratedClassifierCV(selected_model, method="sigmoid", cv="prefit")
    calibrated_model.fit(X_calib, y_calib)

    metrics = evaluate_model(calibrated_model, X_test, y_test)
    bundle = make_bundle(calibrated_model, selected_name, cv_auc, metrics, X_test, y_test)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("wb") as f:
        pickle.dump(bundle, f, protocol=pickle.HIGHEST_PROTOCOL)

    write_evidence_pack(evidence_path, dataset_path, bundle)
    print(f"\nModel saved: {output_path} ({output_path.stat().st_size / 1024 / 1024:.1f} MB)", flush=True)
    print("Done.", flush=True)

if __name__ == "__main__":
    main()
