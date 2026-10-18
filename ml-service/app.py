"""
CyberSleuth ML & DMV Microservice
Exposes REST endpoints for Network Flow Preprocessing, Random Forest Classification,
Isolation Forest Anomaly Detection, MITRE ATT&CK Threat Mapping, and DMV Visual Metrics.
Runs on Port 5000.
"""

import os
import sys
import json
from typing import Dict, Any, List
import pandas as pd
import numpy as np
from flask import Flask, request, jsonify
from flask_cors import CORS

# Add root directory to python path to access existing src/ modules
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.train_model import load_model_bundle, list_saved_models
from src.prediction import run_traffic_inference
from src.threat_analysis import compile_threat_intelligence_summary, get_mitre_mapping, explain_flagged_flow
from src.data_loader import clean_column_names

app = Flask(__name__)
CORS(app)

# Global model cache
ACTIVE_BUNDLE = None
ACTIVE_MODEL_NAME = None

def get_or_load_active_model():
    global ACTIVE_BUNDLE, ACTIVE_MODEL_NAME
    if ACTIVE_BUNDLE is not None:
        return ACTIVE_BUNDLE, ACTIVE_MODEL_NAME

    models = list_saved_models()
    if models:
        # Load the latest saved model
        latest_model = models[-1]
        ACTIVE_BUNDLE = load_model_bundle(latest_model["path"])
        ACTIVE_MODEL_NAME = latest_model["filename"]
        print(f"[*] Loaded model: {ACTIVE_MODEL_NAME}")
    return ACTIVE_BUNDLE, ACTIVE_MODEL_NAME


@app.route("/api/ml/health", methods=["GET"])
def health_check():
    """Health status and loaded model details."""
    bundle, model_name = get_or_load_active_model()
    saved_models = list_saved_models()
    return jsonify({
        "status": "UP",
        "service": "Python ML & DMV Microservice",
        "port": 5000,
        "active_model": model_name if model_name else "No model loaded",
        "model_type": bundle.get("model_type", "None") if bundle else "None",
        "num_classes": len(bundle.get("classes", [])) if bundle else 0,
        "classes": list(bundle.get("classes", [])) if bundle else [],
        "available_models_count": len(saved_models)
    })


@app.route("/api/ml/sample-data", methods=["GET"])
def get_sample_data():
    """Returns sample network traffic metadata and top records."""
    sample_csv_path = os.path.join(PROJECT_ROOT, "data", "sample_network_traffic.csv")
    if not os.path.exists(sample_csv_path):
        return jsonify({"error": "Sample data not found"}), 404
        
    df = pd.read_csv(sample_csv_path)
    preview = df.head(15).replace({np.nan: None}).to_dict(orient="records")
    return jsonify({
        "total_records": len(df),
        "columns": list(df.columns),
        "preview": preview
    })


def validate_traffic_records(df: pd.DataFrame, expected_features: List[str]):
    """
    Validates whether the incoming dataset matches network flow telemetry requirements.
    Prevents inference crashes on wrong datasets (e.g. employee records, sales data, student marks).
    """
    if df is None or len(df) == 0:
        return False, "The uploaded dataset is empty.", []

    if df.shape[0] < 2:
        return False, f"Dataset has too few records ({df.shape[0]} rows). At least 2 flow records required.", []

    if df.shape[1] < 2:
        return False, f"Dataset contains too few columns ({df.shape[1]}). Flow analysis requires multi-dimensional features.", []

    # Clean whitespace from column names
    clean_cols = [str(c).strip().lower() for c in df.columns]
    
    # Common signature network flow terms
    network_signatures = [
        "port", "proto", "protocol", "duration", "packet", "packets", 
        "byte", "bytes", "fwd", "bwd", "flow", "length", "flag", "syn", "ack", "iat"
    ]
    
    matching_network_cols = [
        orig for orig, c in zip(df.columns, clean_cols)
        if any(sig in c for sig in network_signatures)
    ]

    # Also check exact overlap with model's expected features
    expected_lower = {str(f).strip().lower() for f in expected_features}
    direct_feature_overlap = [
        orig for orig, c in zip(df.columns, clean_cols)
        if c in expected_lower
    ]

    if len(matching_network_cols) == 0 and len(direct_feature_overlap) == 0:
        found_sample = [str(c).strip() for c in list(df.columns[:8])]
        return (
            False,
            f"Invalid dataset schema. The uploaded file does not contain network flow telemetry. "
            f"Found columns: [{', '.join(found_sample)}]. Expected network flow features such as 'Destination Port', "
            f"'Flow Duration', 'Protocol', or Packet length metrics.",
            found_sample
        )

    # Check numeric content
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    if len(numeric_cols) == 0:
        return False, "Uploaded dataset contains no numeric telemetry measurements required for machine learning.", []

    return True, "Dataset validated successfully.", []


@app.route("/api/ml/triage", methods=["POST"])
def run_triage():
    """
    Executes ML inference and DMV analysis on network flow records.
    Can accept JSON array of records, or if empty, uses the built-in benchmark dataset.
    """
    bundle, model_name = get_or_load_active_model()
    if not bundle:
        return jsonify({"error": "No trained model bundle found in models directory."}), 500

    data = request.get_json(silent=True) or {}
    records = data.get("records")
    
    # If no records provided in request payload, use sample benchmark dataset
    if not records or len(records) == 0:
        sample_path = os.path.join(PROJECT_ROOT, "data", "sample_network_traffic.csv")
        df = pd.read_csv(sample_path)
    else:
        df = pd.DataFrame(records)

    # Clean leading/trailing column whitespaces
    df = clean_column_names(df)

    # Validate dataset before attempting inference
    is_valid, validation_msg, found_cols = validate_traffic_records(df, bundle.get("feature_names", []))
    if not is_valid:
        return jsonify({
            "status": "VALIDATION_ERROR",
            "error": validation_msg,
            "found_columns": found_cols,
            "sample_expected": ["Destination Port", "Flow Duration", "Total Fwd Packets", "Protocol", "Flow Packets/s"]
        }), 400

    # Run inference pipeline
    enriched_df, summary = run_traffic_inference(df, bundle)

    # MITRE ATT&CK Mapping
    mitre_summary = compile_threat_intelligence_summary(enriched_df, summary)

    # DMV (Data Mining & Visualization) Metrics Calculation
    # 1. Protocol Distribution
    protocol_counts = {}
    for col in ["Protocol", "protocol", "proto"]:
        if col in enriched_df.columns:
            protocol_counts = enriched_df[col].value_counts().head(5).to_dict()
            # Convert numeric protocols to strings if needed
            protocol_counts = {str(k): int(v) for k, v in protocol_counts.items()}
            break

    # 2. Targeted Ports
    port_counts = {}
    for col in ["Destination Port", "destination_port", "Dst Port"]:
        if col in enriched_df.columns:
            port_counts = {str(k): int(v) for k, v in enriched_df[col].value_counts().head(8).items()}
            break

    # 3. Anomaly Score Distribution (binned for histogram)
    anomaly_scores = enriched_df["Anomaly Score"].dropna().tolist()
    hist_counts, bin_edges = np.histogram(anomaly_scores, bins=10, range=(0.0, 1.0))
    anomaly_histogram = [
        {"range": f"{round(bin_edges[i], 1)}-{round(bin_edges[i+1], 1)}", "count": int(hist_counts[i])}
        for i in range(len(hist_counts))
    ]

    # 4. Feature Importances
    feature_importances = bundle.get("feature_importances", [])
    if isinstance(feature_importances, pd.DataFrame):
        top_features = feature_importances.head(8).to_dict(orient="records")
    elif isinstance(feature_importances, list):
        top_features = feature_importances[:8]
    else:
        top_features = []

    # Prepare sanitized records preview for the UI table (first 50 records)
    display_cols = [
        col for col in [
            "Destination Port", "Protocol", "Flow Duration", "Total Fwd Packets",
            "Model Prediction", "Prediction Confidence (%)", "Potentially Suspicious",
            "Anomaly Status", "Anomaly Score", "Threat Severity"
        ] if col in enriched_df.columns
    ]
    
    # Add record id
    table_records = enriched_df[display_cols].head(50).copy()
    table_records.insert(0, "Record_ID", [f"FLOW-{i+1:04d}" for i in range(len(table_records))])
    
    # Map MITRE tactic to each row for immediate forensic display
    def attach_tactic(pred):
        info = get_mitre_mapping(str(pred))
        return info.get("tactic", "N/A") if info else "Normal"
        
    table_records["MITRE_Tactic"] = table_records["Model Prediction"].apply(attach_tactic)
    
    records_json = table_records.replace({np.nan: None}).to_dict(orient="records")

    response_payload = {
        "model_used": model_name,
        "summary": summary,
        "mitre_summary": mitre_summary,
        "dmv_metrics": {
            "protocol_counts": protocol_counts,
            "port_counts": port_counts,
            "anomaly_histogram": anomaly_histogram,
            "feature_importances": top_features
        },
        "records": records_json
    }

    return jsonify(response_payload)


if __name__ == "__main__":
    print("=" * 60)
    print(" [+] CyberSleuth Python ML & DMV Microservice")
    print(" Running on http://127.0.0.1:5000")
    print("=" * 60)
    app.run(host="0.0.0.0", port=5000, debug=False)
