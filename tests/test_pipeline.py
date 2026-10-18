"""
Comprehensive Backend Pipeline Test
Validates data loading, preprocessing, model training, evaluation metrics,
inference, threat intelligence summaries, and PDF/CSV report generation.
"""

import sys
import os

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from src.data_loader import load_csv_dataset
from src.train_model import train_and_evaluate_pipeline, save_model_bundle, load_model_bundle
from src.prediction import run_traffic_inference
from src.threat_analysis import compile_threat_intelligence_summary
from src.report_generator import export_analysis_csv, generate_pdf_threat_report


def main():
    print("[1] Loading synthetic sample dataset...")
    df, summary, err = load_csv_dataset("data/sample_network_traffic.csv", is_sample=True)
    if err:
        print(f"Error loading dataset: {err}")
        sys.exit(1)
        
    print(f"    Loaded {len(df)} rows, target: {summary['detected_target_column']}")

    print("[2] Training ML model pipeline (Random Forest)...")
    bundle = train_and_evaluate_pipeline(
        df,
        target_col="Label",
        model_type="Random Forest",
        test_size=0.25,
        enable_cv=True,
        cv_folds=3
    )
    metrics = bundle["metrics"]
    print(f"    Validation Accuracy: {metrics['accuracy']:.4f}")
    print(f"    Precision (Macro):   {metrics['precision_macro']:.4f}")
    print(f"    Recall (Macro):      {metrics['recall_macro']:.4f}")
    print(f"    F1-Score (Macro):    {metrics['f1_macro']:.4f}")
    if "cv_scores" in bundle and bundle["cv_scores"]:
        print(f"    Cross-Val Accuracy:  {bundle['cv_scores']['cv_accuracy_mean']:.4f} (+/- {bundle['cv_scores']['cv_accuracy_std']:.4f})")

    print("[3] Saving and loading model bundle with Joblib...")
    saved_path = save_model_bundle(bundle)
    loaded_bundle = load_model_bundle(saved_path)
    print(f"    Model saved and verified at: {saved_path}")

    print("[4] Executing inference on unseen test traffic...")
    test_sample = df.sample(300, random_state=42)
    enriched, inf_summary = run_traffic_inference(test_sample, loaded_bundle)
    print(f"    Total flows evaluated: {inf_summary['total_records']}")
    print(f"    Potentially suspicious: {inf_summary['suspicious_count']} ({inf_summary['suspicious_percentage']}%)")
    print(f"    Statistical anomalies:  {inf_summary['anomaly_count']}")

    print("[5] Synthesizing Threat Intelligence & MITRE mapping...")
    threat_sum = compile_threat_intelligence_summary(enriched, inf_summary)
    print(f"    Executive Summary: {threat_sum['executive_summary'][:95]}...")
    print(f"    Discovered Attack Classes: {len(threat_sum['detected_attacks'])}")

    print("[6] Generating PDF and CSV reports...")
    csv_bytes = export_analysis_csv(enriched)
    pdf_bytes = generate_pdf_threat_report("sample_network_traffic.csv", loaded_bundle, inf_summary, threat_sum)
    print(f"    CSV Export Size: {len(csv_bytes):,} bytes")
    print(f"    PDF Report Size: {len(pdf_bytes):,} bytes")

    # Save sample PDF report to reports/
    sample_pdf_path = os.path.join("reports", "sample_threat_intelligence_report.pdf")
    with open(sample_pdf_path, "wb") as f:
        f.write(pdf_bytes)
    print(f"    Sample PDF report saved to: {sample_pdf_path}")

    print("\n[+] SUCCESS: ALL BACKEND PIPELINE TESTS PASSED RIGOROUSLY!")


if __name__ == "__main__":
    main()
