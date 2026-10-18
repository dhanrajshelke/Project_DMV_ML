"""
Data Loader Module for Cyber Threat Intelligence Project
Handles secure ingestion, validation, and metadata extraction of network traffic datasets (CSV).
"""

import os
from typing import Tuple, Dict, Any, Optional, Union
import pandas as pd
import numpy as np


MAX_FILE_SIZE_MB = 150  # Upper threshold for browser memory safety


def clean_column_names(df: pd.DataFrame) -> pd.DataFrame:
    """
    Standardize DataFrame column names by stripping leading/trailing whitespace,
    which is notorious in datasets like CIC-IDS2017 (e.g. ' Destination Port' -> 'Destination Port').
    """
    df = df.copy()
    df.columns = [str(col).strip() for col in df.columns]
    return df


def detect_target_column(df: pd.DataFrame) -> Optional[str]:
    """
    Auto-detect probable target label column based on common naming conventions in IDS datasets.
    """
    common_label_names = [
        'Label', 'label', 'attack_cat', 'Attack', 'class', 'Class',
        'target', 'Target', 'threat_category', 'Category', 'attack_type'
    ]
    for col in common_label_names:
        if col in df.columns:
            return col
            
    # Substring search if exact match not found
    for col in df.columns:
        if any(term in col.lower() for term in ['label', 'attack', 'class']):
            return col
            
    return None


def validate_network_dataset(df: pd.DataFrame) -> Tuple[bool, str]:
    """
    Validates whether an ingested dataset is appropriate for network traffic analysis.
    Checks:
    - Minimum row and column counts
    - Presence of numerical flow metrics
    """
    if df.empty:
        return False, "The uploaded dataset is empty."
        
    if df.shape[0] < 10:
        return False, f"Dataset has too few records ({df.shape[0]} rows). At least 10 rows required."
        
    if df.shape[1] < 3:
        return False, f"Dataset has too few columns ({df.shape[1]} columns). A valid flow dataset requires features."
        
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    if len(numeric_cols) < 2:
        return False, "Dataset contains fewer than 2 numeric features. Network flow data requires numerical measurements."
        
    return True, "Dataset validated successfully."


def get_dataset_summary(df: pd.DataFrame, filename: str, is_synthetic: bool = False) -> Dict[str, Any]:
    """
    Generate detailed structural summary and health metrics for the loaded dataset.
    """
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    categorical_cols = df.select_dtypes(include=['object', 'category']).columns.tolist()
    
    # Calculate missing values
    missing_counts = df.isnull().sum()
    total_missing = int(missing_counts.sum())
    missing_cols_dict = missing_counts[missing_counts > 0].to_dict()
    
    # Check for infinite values (common in CIC-IDS2017)
    inf_count = 0
    if len(numeric_cols) > 0:
        inf_mask = np.isinf(df[numeric_cols])
        inf_count = int(inf_mask.sum().sum())
        
    detected_target = detect_target_column(df)
    
    class_distribution = {}
    if detected_target and detected_target in df.columns:
        class_distribution = df[detected_target].value_counts().to_dict()
        
    memory_mb = round(df.memory_usage(deep=True).sum() / (1024 * 1024), 2)
    
    return {
        "filename": filename,
        "is_synthetic": is_synthetic,
        "rows": df.shape[0],
        "columns": df.shape[1],
        "column_names": df.columns.tolist(),
        "numeric_features_count": len(numeric_cols),
        "categorical_features_count": len(categorical_cols),
        "total_missing_values": total_missing,
        "missing_by_column": missing_cols_dict,
        "infinite_values_count": inf_count,
        "detected_target_column": detected_target,
        "class_distribution": class_distribution,
        "memory_mb": memory_mb
    }


def load_csv_dataset(
    file_or_path: Union[str, Any],
    is_sample: bool = False
) -> Tuple[Optional[pd.DataFrame], Optional[Dict[str, Any]], Optional[str]]:
    """
    Load, sanitize, and validate a CSV network traffic dataset.
    
    Supports:
    - File path string
    - Streamlit UploadedFile object
    
    Returns:
    - (DataFrame, summary_dict, error_message)
    """
    try:
        filename = "uploaded_traffic_data.csv"
        
        if isinstance(file_or_path, str):
            filename = os.path.basename(file_or_path)
            if not os.path.exists(file_or_path):
                return None, None, f"File not found: {file_or_path}"
            df = pd.read_csv(file_or_path, low_memory=False)
        else:
            # Streamlit UploadedFile
            filename = getattr(file_or_path, "name", "uploaded_data.csv")
            # Size check
            size_mb = file_or_path.size / (1024 * 1024)
            if size_mb > MAX_FILE_SIZE_MB:
                return None, None, f"File exceeds maximum allowed size of {MAX_FILE_SIZE_MB}MB (File size: {size_mb:.1f}MB)."
            df = pd.read_csv(file_or_path, low_memory=False)
            
        # Clean column headers
        df = clean_column_names(df)
        
        # Validate
        valid, msg = validate_network_dataset(df)
        if not valid:
            return None, None, msg
            
        summary = get_dataset_summary(df, filename=filename, is_synthetic=is_sample)
        return df, summary, None
        
    except Exception as e:
        return None, None, f"Failed to parse CSV dataset: {str(e)}"
