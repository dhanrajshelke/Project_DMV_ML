"""
Preprocessing Module for Cyber Threat Intelligence and Attack Pattern Discovery
Handles clean data transformation, identifier dropping, infinite/missing value imputation,
categorical encoding, and strict data-leakage prevention.
"""

from typing import Tuple, List, Dict, Any, Optional
import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.impute import SimpleImputer


# Non-predictive identifier columns that should not be used as features to avoid shortcut learning
IDENTIFIER_COLUMNS_PATTERNS = [
    'flow id', 'flow_id', 'source ip', 'destination ip', 'src ip', 'dst ip',
    'source_ip', 'destination_ip', 'timestamp', 'date', 'time', 'flow_by_hour',
    'unnamed', 'index', 'id'
]


class NetworkDataPreprocessor:
    """
    Stateful preprocessor for network flow datasets.
    Ensures that imputers, encoders, and scalers are fitted ONLY on training data.
    """
    def __init__(self, scale_features: bool = False):
        self.scale_features = scale_features
        self.numeric_imputer: Optional[SimpleImputer] = None
        self.categorical_imputers: Dict[str, SimpleImputer] = {}
        self.scaler: Optional[StandardScaler] = None
        self.feature_names: List[str] = []
        self.numeric_cols: List[str] = []
        self.categorical_cols: List[str] = []
        self.label_encoder: Optional[LabelEncoder] = None
        self.classes_: Optional[np.ndarray] = None
        self.dropped_cols: List[str] = []
        self.target_col: Optional[str] = None
        self.categorical_mappings: Dict[str, Dict[str, int]] = {}

    def _identify_identifier_cols(self, df: pd.DataFrame, target_col: Optional[str] = None) -> List[str]:
        """Detect columns that are identifiers rather than behavioral traffic features."""
        dropped = []
        for col in df.columns:
            if target_col and col == target_col:
                continue
            col_lower = str(col).lower().strip()
            if any(pattern in col_lower for pattern in IDENTIFIER_COLUMNS_PATTERNS):
                dropped.append(col)
        return dropped

    def fit(self, df: pd.DataFrame, target_col: Optional[str] = None) -> 'NetworkDataPreprocessor':
        """
        Fit all imputation, encoding, and scaling components exclusively on training data.
        """
        self.target_col = target_col
        X = df.copy()

        # Separate target if present
        if target_col and target_col in X.columns:
            y = X[target_col].astype(str)
            X = X.drop(columns=[target_col])
            self.label_encoder = LabelEncoder()
            self.label_encoder.fit(y)
            self.classes_ = self.label_encoder.classes_

        # Detect and drop identifier columns
        self.dropped_cols = self._identify_identifier_cols(X, target_col)
        X = X.drop(columns=self.dropped_cols, errors='ignore')

        # Replace inf with nan
        X = X.replace([np.inf, -np.inf], np.nan)

        # Drop columns with 100% missing values or zero variance
        valid_cols = []
        for col in X.columns:
            if X[col].isnull().all():
                self.dropped_cols.append(col)
                continue
            # Drop constant columns (zero variance)
            if X[col].nunique() <= 1:
                self.dropped_cols.append(col)
                continue
            valid_cols.append(col)

        X = X[valid_cols]

        # Categorize features
        self.numeric_cols = X.select_dtypes(include=[np.number]).columns.tolist()
        self.categorical_cols = X.select_dtypes(exclude=[np.number]).columns.tolist()

        # Numeric Imputer (Median strategy handles skewed network flows best)
        if len(self.numeric_cols) > 0:
            self.numeric_imputer = SimpleImputer(strategy='median')
            self.numeric_imputer.fit(X[self.numeric_cols])

        # Categorical Encodings (Frequency/Ordinal mapping)
        for col in self.categorical_cols:
            unique_vals = X[col].dropna().unique().tolist()
            mapping = {val: idx for idx, val in enumerate(unique_vals)}
            self.categorical_mappings[col] = mapping

        # Final feature names
        self.feature_names = self.numeric_cols + self.categorical_cols

        # Optional Feature Scaler
        if self.scale_features and len(self.numeric_cols) > 0:
            self.scaler = StandardScaler()
            X_num = self.numeric_imputer.transform(X[self.numeric_cols])
            self.scaler.fit(X_num)

        return self

    def transform(self, df: pd.DataFrame) -> Tuple[np.ndarray, Optional[np.ndarray]]:
        """
        Transform a feature DataFrame using the parameters learned during fit().
        """
        X = df.copy()
        y_encoded = None

        if self.target_col and self.target_col in X.columns:
            y_raw = X[self.target_col].astype(str)
            if self.label_encoder:
                # Handle unseen labels gracefully
                known_classes = set(self.label_encoder.classes_)
                y_raw = y_raw.map(lambda s: s if s in known_classes else known_classes[0] if len(known_classes) > 0 else 'Unknown')
                y_encoded = self.label_encoder.transform(y_raw)
            X = X.drop(columns=[self.target_col])

        # Drop identifiers and columns flagged during fit
        X = X.drop(columns=[c for c in self.dropped_cols if c in X.columns], errors='ignore')

        # Replace inf with nan
        X = X.replace([np.inf, -np.inf], np.nan)

        processed_parts = []

        # Process numeric columns
        if len(self.numeric_cols) > 0:
            # Reindex to ensure identical column ordering
            num_df = X.reindex(columns=self.numeric_cols)
            if self.numeric_imputer:
                num_arr = self.numeric_imputer.transform(num_df)
            else:
                num_arr = num_df.fillna(0).to_numpy()

            if self.scale_features and self.scaler:
                num_arr = self.scaler.transform(num_arr)

            processed_parts.append(num_arr)

        # Process categorical columns
        if len(self.categorical_cols) > 0:
            cat_dfs = []
            for col in self.categorical_cols:
                mapping = self.categorical_mappings.get(col, {})
                col_series = X[col] if col in X.columns else pd.Series([np.nan] * len(X))
                encoded_col = col_series.map(mapping).fillna(-1).to_numpy().reshape(-1, 1)
                cat_dfs.append(encoded_col)
            cat_arr = np.hstack(cat_dfs)
            processed_parts.append(cat_arr)

        if len(processed_parts) == 0:
            raise ValueError("No valid features remained after preprocessing.")

        X_processed = np.hstack(processed_parts)
        return X_processed, y_encoded

    def fit_transform(self, df: pd.DataFrame, target_col: Optional[str] = None) -> Tuple[np.ndarray, Optional[np.ndarray]]:
        """Fit on data and transform in one step."""
        self.fit(df, target_col=target_col)
        return self.transform(df)

    def inverse_transform_labels(self, y_pred: np.ndarray) -> np.ndarray:
        """Decode integer class predictions back into original human-readable attack labels."""
        if self.label_encoder is not None:
            return self.label_encoder.inverse_transform(y_pred)
        return y_pred.astype(str)
