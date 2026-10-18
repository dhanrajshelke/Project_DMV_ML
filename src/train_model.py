"""
Model Training Module for Cyber Threat Intelligence
Implements supervised training, stratified validation, metric evaluation,
feature importance extraction, and pipeline persistence with Joblib.
"""

import os
from datetime import datetime
from typing import Dict, Any, Tuple, Optional, List
import numpy as np
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report
)

from src.preprocessing import NetworkDataPreprocessor
from src.anomaly_detection import NetworkAnomalyDetector


MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")
os.makedirs(MODEL_DIR, exist_ok=True)


def get_classifier(model_type: str = "Random Forest", **kwargs) -> Any:
    """Instantiate selected classifier."""
    if model_type == "Decision Tree":
        return DecisionTreeClassifier(
            max_depth=kwargs.get("max_depth", 15),
            min_samples_split=kwargs.get("min_samples_split", 5),
            class_weight="balanced",
            random_state=42
        )
    elif model_type == "Extra Trees":
        return ExtraTreesClassifier(
            n_estimators=kwargs.get("n_estimators", 100),
            max_depth=kwargs.get("max_depth", 15),
            class_weight="balanced",
            random_state=42,
            n_jobs=-1
        )
    else:  # Default: Random Forest
        return RandomForestClassifier(
            n_estimators=kwargs.get("n_estimators", 100),
            max_depth=kwargs.get("max_depth", 15),
            min_samples_split=kwargs.get("min_samples_split", 4),
            class_weight="balanced_subsample",
            random_state=42,
            n_jobs=-1
        )


def train_and_evaluate_pipeline(
    df: pd.DataFrame,
    target_col: str,
    model_type: str = "Random Forest",
    test_size: float = 0.25,
    enable_cv: bool = True,
    cv_folds: int = 5,
    train_anomaly_detector: bool = True,
    **model_params
) -> Dict[str, Any]:
    """
    Complete end-to-end training and evaluation pipeline with no data leakage.
    
    1. Splits raw data into train and test sets using stratified sampling.
    2. Fits Preprocessor strictly on train set.
    3. Transforms test set using fitted preprocessor.
    4. Trains classifier on X_train.
    5. Optionally runs Stratified K-Fold Cross-Validation on train set.
    6. Evaluates rigorously on unseen test set.
    7. Optionally fits an Isolation Forest anomaly detector.
    8. Extracts feature importance rankings.
    """
    if target_col not in df.columns:
        raise ValueError(f"Target column '{target_col}' not found in dataset.")

    # Drop rows where target is missing
    df_clean = df.dropna(subset=[target_col]).copy()
    
    # Check if classes have enough samples for stratified split
    value_counts = df_clean[target_col].value_counts()
    min_count = value_counts.min()
    
    # Train/Test Split (Stratified if classes have >= 2 records)
    stratify_target = df_clean[target_col] if min_count >= 2 else None
    train_df, test_df = train_test_split(
        df_clean,
        test_size=test_size,
        random_state=42,
        stratify=stratify_target
    )

    # Fit preprocessor strictly on train data
    preprocessor = NetworkDataPreprocessor()
    preprocessor.fit(train_df, target_col=target_col)

    X_train, y_train = preprocessor.transform(train_df)
    X_test, y_test = preprocessor.transform(test_df)

    # Initialize classifier
    clf = get_classifier(model_type, **model_params)

    # Cross-validation on training data
    cv_scores = {}
    if enable_cv and len(np.unique(y_train)) > 1:
        n_splits = min(cv_folds, int(min_count * (1 - test_size)))
        if n_splits >= 2:
            skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=42)
            cv_acc = cross_val_score(clf, X_train, y_train, cv=skf, scoring='accuracy', n_jobs=-1)
            cv_f1 = cross_val_score(clf, X_train, y_train, cv=skf, scoring='f1_macro', n_jobs=-1)
            cv_scores = {
                "cv_accuracy_mean": float(np.mean(cv_acc)),
                "cv_accuracy_std": float(np.std(cv_acc)),
                "cv_f1_macro_mean": float(np.mean(cv_f1)),
                "cv_f1_macro_std": float(np.std(cv_f1)),
                "folds": n_splits
            }

    # Train final model on entire training split
    clf.fit(X_train, y_train)

    # Predict on unseen test set
    y_pred = clf.predict(X_test)
    y_pred_proba = clf.predict_proba(X_test) if hasattr(clf, "predict_proba") else None

    # Calculate actual computed evaluation metrics
    acc = float(accuracy_score(y_test, y_pred))
    prec_macro = float(precision_score(y_test, y_pred, average='macro', zero_division=0))
    prec_weighted = float(precision_score(y_test, y_pred, average='weighted', zero_division=0))
    rec_macro = float(recall_score(y_test, y_pred, average='macro', zero_division=0))
    rec_weighted = float(recall_score(y_test, y_pred, average='weighted', zero_division=0))
    f1_macro = float(f1_score(y_test, y_pred, average='macro', zero_division=0))
    f1_weighted = float(f1_score(y_test, y_pred, average='weighted', zero_division=0))

    # Confusion Matrix
    class_names = preprocessor.classes_.tolist() if preprocessor.classes_ is not None else []
    cm = confusion_matrix(y_test, y_pred)
    
    # Classification Report
    report_dict = classification_report(
        y_test,
        y_pred,
        target_names=class_names,
        output_dict=True,
        zero_division=0
    )

    # Feature Importance
    feature_importances = []
    if hasattr(clf, "feature_importances_"):
        raw_imp = clf.feature_importances_
        features = preprocessor.feature_names
        feat_pairs = sorted(zip(features, raw_imp), key=lambda x: x[1], reverse=True)
        feature_importances = [{"feature": f, "importance": round(float(imp), 4)} for f, imp in feat_pairs]

    # Optional Anomaly Detector trained on benign/all training traffic
    anomaly_detector = None
    if train_anomaly_detector:
        anomaly_detector = NetworkAnomalyDetector()
        # Fit anomaly detector on train set
        anomaly_detector.fit(X_train)

    result_bundle = {
        "model": clf,
        "preprocessor": preprocessor,
        "anomaly_detector": anomaly_detector,
        "model_type": model_type,
        "target_col": target_col,
        "classes": class_names,
        "feature_names": preprocessor.feature_names,
        "metrics": {
            "accuracy": acc,
            "precision_macro": prec_macro,
            "precision_weighted": prec_weighted,
            "recall_macro": rec_macro,
            "recall_weighted": rec_weighted,
            "f1_macro": f1_macro,
            "f1_weighted": f1_weighted,
        },
        "cv_scores": cv_scores,
        "confusion_matrix": cm.tolist(),
        "classification_report": report_dict,
        "feature_importances": feature_importances,
        "train_rows": len(train_df),
        "test_rows": len(test_df),
        "test_df": test_df.reset_index(drop=True),
        "y_test": y_test,
        "y_pred": y_pred,
        "y_pred_proba": y_pred_proba,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    return result_bundle


def save_model_bundle(bundle: Dict[str, Any], filename: Optional[str] = None) -> str:
    """Save trained bundle to Joblib file."""
    if filename is None:
        timestamp_slug = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"cyber_model_{timestamp_slug}.joblib"
        
    save_path = os.path.join(MODEL_DIR, filename)
    # Exclude large DataFrames from serialised model bundle to keep file compact
    save_data = {
        "model": bundle["model"],
        "preprocessor": bundle["preprocessor"],
        "anomaly_detector": bundle.get("anomaly_detector"),
        "model_type": bundle["model_type"],
        "target_col": bundle["target_col"],
        "classes": bundle["classes"],
        "feature_names": bundle["feature_names"],
        "metrics": bundle["metrics"],
        "cv_scores": bundle.get("cv_scores", {}),
        "confusion_matrix": bundle.get("confusion_matrix", []),
        "classification_report": bundle.get("classification_report", {}),
        "feature_importances": bundle.get("feature_importances", []),
        "timestamp": bundle.get("timestamp")
    }
    joblib.dump(save_data, save_path)
    return save_path


def load_model_bundle(filepath: str) -> Dict[str, Any]:
    """Load trained bundle from Joblib file."""
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Model file not found at: {filepath}")
    return joblib.load(filepath)


def list_saved_models() -> List[Dict[str, Any]]:
    """List all persisted models in models directory."""
    if not os.path.exists(MODEL_DIR):
        return []
    models = []
    for f in os.listdir(MODEL_DIR):
        if f.endswith(".joblib"):
            path = os.path.join(MODEL_DIR, f)
            size_kb = round(os.path.getsize(path) / 1024, 1)
            modified = datetime.fromtimestamp(os.path.getmtime(path)).strftime("%Y-%m-%d %H:%M")
            models.append({"filename": f, "path": path, "size_kb": size_kb, "modified": modified})
    return models
