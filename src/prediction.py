"""
Prediction Module for Cyber Threat Intelligence
Executes inference on incoming or uploaded traffic flows using trained models and anomaly detectors.
Labels predictions explicitly as 'Model Prediction' and 'Potentially Suspicious'.
"""

from typing import Dict, Any, Tuple, Optional
import numpy as np
import pandas as pd


def compute_threat_level(pred_label: str, confidence: float, anomaly_score: float) -> str:
    """
    Heuristic threat level categorization combining supervised predictions and anomaly indicators.
    Labels are explicitly estimates, not confirmed attacks.
    """
    is_benign = str(pred_label).strip().upper() in ['BENIGN', 'NORMAL', '0']
    
    if is_benign:
        if anomaly_score > 0.85:
            return "MEDIUM"  # High anomaly on benign label -> potential zero day
        elif anomaly_score > 0.70:
            return "LOW"
        return "SAFE"
    else:
        # Malicious prediction
        if confidence >= 0.85 and anomaly_score >= 0.60:
            return "CRITICAL"
        elif confidence >= 0.70:
            return "HIGH"
        else:
            return "MEDIUM"


def run_traffic_inference(
    df: pd.DataFrame,
    model_bundle: Dict[str, Any]
) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """
    Execute full inference pipeline on traffic records.
    
    Returns:
    - enriched_df: Original data augmented with prediction results, confidence scores,
                   anomaly status, and calculated threat levels.
    - inference_summary: Dictionary of aggregated findings.
    """
    preprocessor = model_bundle["preprocessor"]
    model = model_bundle["model"]
    anomaly_detector = model_bundle.get("anomaly_detector")

    # Transform features using pre-fitted preprocessor
    X_proc, _ = preprocessor.transform(df)

    # Supervised Predictions
    y_pred_numeric = model.predict(X_proc)
    y_pred_labels = preprocessor.inverse_transform_labels(y_pred_numeric)

    # Prediction Confidence (Probability of top class)
    confidences = np.full(len(df), 1.0)
    if hasattr(model, "predict_proba"):
        probas = model.predict_proba(X_proc)
        confidences = np.max(probas, axis=1)

    # Anomaly Detection
    if anomaly_detector and getattr(anomaly_detector, "is_fitted", False):
        anomaly_flags, anomaly_scores = anomaly_detector.predict_anomalies(X_proc)
    else:
        anomaly_flags = np.full(len(df), "Not Evaluated")
        anomaly_scores = np.zeros(len(df))

    # Build enriched result dataframe
    enriched_df = df.copy()
    enriched_df["Model Prediction"] = y_pred_labels
    enriched_df["Prediction Confidence (%)"] = np.round(confidences * 100, 1)
    
    # Classify traffic as potentially suspicious
    is_suspicious = [
        str(label).strip().upper() not in ['BENIGN', 'NORMAL', '0'] or score > 0.75
        for label, score in zip(y_pred_labels, anomaly_scores)
    ]
    enriched_df["Potentially Suspicious"] = np.where(is_suspicious, "Yes", "No")
    enriched_df["Anomaly Status"] = anomaly_flags
    enriched_df["Anomaly Score"] = anomaly_scores

    # Compute Threat Level
    threat_levels = [
        compute_threat_level(label, conf, score)
        for label, conf, score in zip(y_pred_labels, confidences, anomaly_scores)
    ]
    enriched_df["Threat Severity"] = threat_levels

    # Generate inference summary statistics
    total_records = len(df)
    suspicious_count = int(np.sum(is_suspicious))
    anomaly_count = int(np.sum(anomaly_flags == "Potentially Anomalous"))
    
    # Benign baseline is reduced by the number of statistical anomalies
    raw_normal_count = max(0, total_records - suspicious_count)
    clean_normal_count = max(0, raw_normal_count - anomaly_count)
    normal_count = clean_normal_count
    
    label_breakdown = enriched_df["Model Prediction"].value_counts().to_dict()
    severity_breakdown = enriched_df["Threat Severity"].value_counts().to_dict()

    summary = {
        "total_records": total_records,
        "normal_count": normal_count,
        "raw_normal_count": raw_normal_count,
        "clean_normal_count": clean_normal_count,
        "suspicious_count": suspicious_count,
        "suspicious_percentage": round((suspicious_count / total_records) * 100, 1) if total_records > 0 else 0,
        "anomaly_count": anomaly_count,
        "label_breakdown": label_breakdown,
        "severity_breakdown": severity_breakdown,
        "model_type": model_bundle.get("model_type", "Random Forest")
    }

    return enriched_df, summary
