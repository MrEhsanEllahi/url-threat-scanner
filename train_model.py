from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path
import pickle

import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.inspection import permutation_importance
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    average_precision_score,
    classification_report,
    confusion_matrix,
    roc_auc_score,
)
from sklearn.model_selection import (
    RandomizedSearchCV,
    StratifiedKFold,
    cross_val_score,
    train_test_split,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from scan_engine import FEATURE_COLUMNS, compute_schema_hash


def load_dataset(path: Path) -> tuple[pd.DataFrame, pd.Series]:
    df = pd.read_csv(path)

    required = set(FEATURE_COLUMNS + ["class"])
    missing = sorted(required - set(df.columns))
    if missing:
        raise ValueError(f"Dataset missing required columns: {missing}")

    X = df[FEATURE_COLUMNS].astype(float)
    y_raw = df["class"].astype(int)
    # Binary target: 1 => phishing, 0 => legitimate
    y = (y_raw == -1).astype(int)
    return X, y


def _tune_random_forest(X_train: pd.DataFrame, y_train: pd.Series, cv: StratifiedKFold) -> tuple[Pipeline, float]:
    """
    RandomizedSearchCV over Random Forest hyperparameters.
    Tests 30 random combinations — finds a much better model than hardcoded n_estimators=180.
    """
    print("  Tuning Random Forest with RandomizedSearchCV (30 iterations)...")

    param_dist = {
        "clf__n_estimators": [100, 150, 200, 250, 300],
        "clf__max_depth": [None, 10, 15, 20, 25],
        "clf__min_samples_split": [2, 5, 10],
        "clf__min_samples_leaf": [1, 2, 4],
        "clf__max_features": ["sqrt", "log2", 0.5],
        "clf__class_weight": ["balanced", "balanced_subsample"],
    }

    base_pipeline = Pipeline([
        ("clf", RandomForestClassifier(random_state=42, n_jobs=1)),
    ])

    search = RandomizedSearchCV(
        base_pipeline,
        param_distributions=param_dist,
        n_iter=30,
        scoring="roc_auc",
        cv=cv,
        random_state=42,
        n_jobs=1,
        verbose=0,
    )
    search.fit(X_train, y_train)
    best_score = float(search.best_score_)
    print(f"  RF best CV AUC: {best_score:.4f} | params: {search.best_params_}")
    return search.best_estimator_, best_score


def _tune_gradient_boosting(X_train: pd.DataFrame, y_train: pd.Series, cv: StratifiedKFold) -> tuple[Pipeline, float]:
    """
    RandomizedSearchCV over GradientBoostingClassifier hyperparameters.
    GBM almost always outperforms Random Forest on tabular data like this.
    """
    print("  Tuning Gradient Boosting with RandomizedSearchCV (30 iterations)...")

    param_dist = {
        "clf__n_estimators": [100, 150, 200, 250, 300],
        "clf__learning_rate": [0.01, 0.05, 0.1, 0.15, 0.2],
        "clf__max_depth": [3, 4, 5, 6],
        "clf__min_samples_split": [2, 5, 10],
        "clf__min_samples_leaf": [1, 2, 4],
        "clf__subsample": [0.7, 0.8, 0.9, 1.0],
        "clf__max_features": ["sqrt", "log2", None],
    }

    base_pipeline = Pipeline([
        ("clf", GradientBoostingClassifier(random_state=42)),
    ])

    search = RandomizedSearchCV(
        base_pipeline,
        param_distributions=param_dist,
        n_iter=30,
        scoring="roc_auc",
        cv=cv,
        random_state=42,
        n_jobs=1,
        verbose=0,
    )
    search.fit(X_train, y_train)
    best_score = float(search.best_score_)
    print(f"  GBM best CV AUC: {best_score:.4f} | params: {search.best_params_}")
    return search.best_estimator_, best_score


def _baseline_logistic_regression(X_train: pd.DataFrame, y_train: pd.Series, cv: StratifiedKFold) -> tuple[Pipeline, float]:
    """Logistic regression baseline — fast, no tuning needed."""
    print("  Evaluating Logistic Regression baseline...")
    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", LogisticRegression(max_iter=800, solver="lbfgs", class_weight="balanced", random_state=42)),
    ])
    scores = cross_val_score(pipeline, X_train, y_train, cv=cv, scoring="roc_auc", n_jobs=1)
    score_mean = float(np.mean(scores))
    print(f"  LR CV AUC: {score_mean:.4f}")
    return pipeline, score_mean


def train_and_select_model(X_train: pd.DataFrame, y_train: pd.Series) -> tuple[str, Pipeline, float]:
    """
    Trains 3 candidates:
    1. Logistic Regression (baseline)
    2. Random Forest with RandomizedSearchCV tuning
    3. Gradient Boosting with RandomizedSearchCV tuning

    Selects the one with the best cross-validated ROC-AUC score.
    """
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

    candidates: dict[str, tuple[Pipeline, float]] = {}

    # 1. Logistic Regression — fast baseline
    lr_pipeline, lr_score = _baseline_logistic_regression(X_train, y_train, cv)
    candidates["logistic_regression"] = (lr_pipeline, lr_score)

    # 2. Random Forest with hyperparameter search
    rf_pipeline, rf_score = _tune_random_forest(X_train, y_train, cv)
    candidates["random_forest_tuned"] = (rf_pipeline, rf_score)

    # 3. Gradient Boosting with hyperparameter search
    gbm_pipeline, gbm_score = _tune_gradient_boosting(X_train, y_train, cv)
    candidates["gradient_boosting_tuned"] = (gbm_pipeline, gbm_score)

    # Pick winner
    best_name = max(candidates, key=lambda k: candidates[k][1])
    best_model, best_cv_auc = candidates[best_name]

    print(f"\n  Winner: {best_name} (CV AUC = {best_cv_auc:.4f})")
    return best_name, best_model, best_cv_auc


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


def make_bundle(
    model,
    model_name: str,
    cv_auc: float,
    metrics: dict,
    X_test: pd.DataFrame,
    y_test: pd.Series,
) -> dict:
    perm = permutation_importance(
        model,
        X_test,
        y_test,
        scoring="roc_auc",
        n_repeats=10,
        random_state=42,
        n_jobs=1,
    )

    top_global = sorted(
        [
            {
                "feature": FEATURE_COLUMNS[i],
                "importance": float(perm.importances_mean[i]),
                "std": float(perm.importances_std[i]),
            }
            for i in range(len(FEATURE_COLUMNS))
        ],
        key=lambda x: x["importance"],
        reverse=True,
    )

    return {
        "model": model,
        "feature_columns": FEATURE_COLUMNS,
        "schema_hash": compute_schema_hash(FEATURE_COLUMNS),
        "model_version": "2.0.0",
        "selected_model": model_name,
        "cv_auc_mean": float(cv_auc),
        "metrics": metrics,
        "top_global_features": top_global,
        "trained_at_utc": datetime.now(timezone.utc).isoformat(),
    }


def write_evidence_pack(output_md: Path, dataset_path: Path, bundle: dict) -> None:
    metrics = bundle["metrics"]
    cm = metrics["confusion_matrix"]
    report = metrics["classification_report"]

    lines = [
        "# FYP Evidence Pack — v2.0",
        "",
        "## Dataset Provenance",
        f"- Source file: `{dataset_path}`",
        "- Dataset family: UCI phishing website style 30-feature schema",
        "- Target mapping: phishing=1 (from original class=-1), legitimate=0",
        "",
        "## Model Selection",
        f"- Selected model: `{bundle['selected_model']}`",
        f"- Cross-validation ROC-AUC (mean): `{bundle['cv_auc_mean']:.4f}`",
        f"- Schema hash: `{bundle['schema_hash']}`",
        "- Selection method: RandomizedSearchCV (30 iterations) over Random Forest + Gradient Boosting candidates",
        "",
        "## Test Metrics",
        f"- ROC-AUC: `{metrics['roc_auc']:.4f}`",
        f"- PR-AUC: `{metrics['pr_auc']:.4f}`",
        f"- Precision (phishing class): `{report.get('1', {}).get('precision', 0.0):.4f}`",
        f"- Recall (phishing class): `{report.get('1', {}).get('recall', 0.0):.4f}`",
        f"- F1 (phishing class): `{report.get('1', {}).get('f1-score', 0.0):.4f}`",
        "",
        "## Confusion Matrix",
        "- Format: [[TN, FP], [FN, TP]]",
        f"- Values: `{cm}`",
        "",
        "## Top Global Features (Permutation Importance)",
    ]

    for item in bundle.get("top_global_features", [])[:10]:
        lines.append(f"- {item['feature']}: importance={item['importance']:.6f}, std={item['std']:.6f}")

    lines.extend([
        "",
        "## Training Pipeline",
        "- Candidate 1: Logistic Regression with StandardScaler (baseline)",
        "- Candidate 2: Random Forest — tuned with RandomizedSearchCV (30 iterations, 5-fold CV)",
        "- Candidate 3: Gradient Boosting — tuned with RandomizedSearchCV (30 iterations, 5-fold CV)",
        "- Winner selected by highest mean ROC-AUC on cross-validation",
        "- Final model wrapped in CalibratedClassifierCV (sigmoid) for reliable probabilities",
        "",
        "## Known Limitations",
        "- WHOIS and DNS metadata may be unavailable for some domains or blocked networks.",
        "- Selenium environment setup is required for full DOM extraction.",
        "- Model quality depends on feature parity between training schema and live extraction heuristics.",
        "- Content-based threat detection (betting/scam/fraud) is handled by a separate rule-based layer.",
        "",
        f"Generated at: {datetime.now(timezone.utc).isoformat()}",
    ])

    output_md.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Train phishing classifier bundle (v2 — with hyperparameter tuning).")
    parser.add_argument(
        "--dataset",
        type=str,
        default="phishing.csv",
        help="Path to phishing CSV dataset",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="artifacts/phishing_model_bundle.pkl",
        help="Output model bundle path",
    )
    parser.add_argument(
        "--evidence",
        type=str,
        default="EVIDENCE_PACK.md",
        help="Output evidence markdown path",
    )
    args = parser.parse_args()

    dataset_path = Path(args.dataset).resolve()
    output_path = Path(args.output)
    evidence_path = Path(args.evidence)

    print(f"Loading dataset: {dataset_path}")
    X, y = load_dataset(dataset_path)
    print(f"Dataset loaded: {X.shape[0]} rows, {X.shape[1]} features")
    print(f"Class distribution — phishing: {y.sum()}, legitimate: {(y == 0).sum()}\n")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y,
    )

    print("=== Model Selection & Hyperparameter Tuning ===")
    selected_name, selected_model, cv_auc = train_and_select_model(X_train, y_train)

    # Split train further: 80% for fitting, 20% for calibration
    X_model_train, X_calib, y_model_train, y_calib = train_test_split(
        X_train, y_train, test_size=0.2, random_state=42, stratify=y_train,
    )

    print(f"\nFitting best model ({selected_name}) on training set...")
    selected_model.fit(X_model_train, y_model_train)

    print("Calibrating probability outputs (sigmoid method)...")
    calibrated_model = CalibratedClassifierCV(selected_model, method="sigmoid", cv="prefit")
    calibrated_model.fit(X_calib, y_calib)

    print("Evaluating on held-out test set...")
    metrics = evaluate_model(calibrated_model, X_test, y_test)

    print(f"\n=== Final Results ===")
    print(f"Selected model : {selected_name}")
    print(f"ROC-AUC        : {metrics['roc_auc']:.4f}")
    print(f"PR-AUC         : {metrics['pr_auc']:.4f}")
    cm = metrics["confusion_matrix"]
    print(f"Confusion Matrix: TN={cm[0][0]}, FP={cm[0][1]}, FN={cm[1][0]}, TP={cm[1][1]}")

    print("\nBuilding model bundle with permutation importance...")
    bundle = make_bundle(calibrated_model, selected_name, cv_auc, metrics, X_test, y_test)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("wb") as f:
        pickle.dump(bundle, f, protocol=pickle.HIGHEST_PROTOCOL)

    write_evidence_pack(evidence_path, dataset_path, bundle)

    print(f"\nModel bundle  : {output_path.resolve()}")
    print(f"Evidence pack : {evidence_path.resolve()}")
    print("Done.")


if __name__ == "__main__":
    main()
