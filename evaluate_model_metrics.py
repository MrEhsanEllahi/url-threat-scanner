"""
ShieldScan Model Metrics Extraction Script
==========================================
Ye script trained model bundle se test accuracy, ROC-AUC, PR-AUC,
classification report aur confusion matrix nikal kar JSON file mein save karta hai.

How it works:
1. scan_engine.py ka load_model_bundle() function model ko pickle file se memory mein load karta hai
2. Bundle mein pehle se saved metrics hoti hain (jo train_model.py ne evaluate karke save ki thin)
3. Hum woh metrics nikal kar print aur JSON file dono mein output karte hain

Run: python evaluate_model_metrics.py
"""

from scan_engine import load_model_bundle
import json
import os


def extract_and_save_metrics():
    # Step 1: Load trained model bundle from disk
    print("Loading model bundle...")
    bundle, error = load_model_bundle()
    
    if bundle is None:
        print(f"ERROR: Model load failed — {error}")
        return
    
    # Step 2: Extract stored metrics from bundle dict
    metrics = bundle["metrics"]                      # evaluate_model() se aya hua
    report = metrics["classification_report"]         # sklearn classification_report
    
    # Step 3: Build clean output
    output = {
        "model_info": {
            "type": bundle["selected_model"],         # e.g., "random_forest"
            "version": bundle["model_version"],        # e.g., "2.1.0"
            "cv_auc_mean": round(bundle["cv_auc_mean"], 4),  # Cross-validation AUC
            "trained_at": bundle.get("trained_at_utc", "")
        },
        "test_metrics": {
            "roc_auc": round(metrics["roc_auc"], 4),     # Area under ROC curve
            "pr_auc": round(metrics["pr_auc"], 4),       # Area under Precision-Recall curve
            "accuracy": round(report["accuracy"], 4),    # Overall accuracy
        },
        "per_class_metrics": {
            "benign_class": {                            # Class 0 = legitimate URLs
                "precision": round(report["0"]["precision"], 4),
                "recall": round(report["0"]["recall"], 4),
                "f1_score": round(report["0"]["f1-score"], 4),
                "support": int(report["0"]["support"])    # Number of benign samples
            },
            "phishing_class": {                          # Class 1 = phishing URLs
                "precision": round(report["1"]["precision"], 4),
                "recall": round(report["1"]["recall"], 4),
                "f1_score": round(report["1"]["f1-score"], 4),
                "support": int(report["1"]["support"])    # Number of phishing samples
            }
        },
        "confusion_matrix": {
            "format": "[[True Negatives, False Positives], [False Negatives, True Positives]]",
            "values": metrics["confusion_matrix"]
        },
        "top_10_features": []
    }
    
    # Step 4: Extract top 10 most important features
    for item in bundle.get("top_global_features", [])[:10]:
        output["top_10_features"].append({
            "feature": item["feature"],
            "importance": round(item["importance"], 6)
        })
    
    # Step 5: Print to console
    print("\n" + "=" * 60)
    print("SHIELDSCAN MODEL METRICS — TEST SET EVALUATION")
    print("=" * 60)
    print(f"\nModel: {output['model_info']['type']} v{output['model_info']['version']}")
    print(f"Cross-Validation AUC: {output['model_info']['cv_auc_mean']:.4f}")
    print(f"\nROC-AUC (test):  {output['test_metrics']['roc_auc']:.4f}")
    print(f"PR-AUC (test):   {output['test_metrics']['pr_auc']:.4f}")
    print(f"Accuracy (test): {output['test_metrics']['accuracy']:.4f}")
    
    print(f"\nPer-Class Metrics:")
    for cls_name, cls_metrics in output["per_class_metrics"].items():
        print(f"  {cls_name}:")
        print(f"    Precision: {cls_metrics['precision']:.4f}")
        print(f"    Recall:    {cls_metrics['recall']:.4f}")
        print(f"    F1-Score:  {cls_metrics['f1_score']:.4f}")
        print(f"    Support:   {cls_metrics['support']:,}")
    
    print(f"\nConfusion Matrix:")
    cm = output["confusion_matrix"]["values"]
    print(f"  TN={cm[0][0]:,}  FP={cm[0][1]:,}")
    print(f"  FN={cm[1][0]:,}  TP={cm[1][1]:,}")
    
    print(f"\nTop 10 Features (by importance):")
    for i, f in enumerate(output["top_10_features"], 1):
        print(f"  {i}. {f['feature']}: {f['importance']:.6f}")
    
    # Step 6: Save to JSON file
    output_path = "model_metrics.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    
    print(f"\nSaved to: {os.path.abspath(output_path)}")


if __name__ == "__main__":
    extract_and_save_metrics()
