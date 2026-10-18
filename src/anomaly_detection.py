"""
Anomaly Detection Module
Provides unsupervised network traffic anomaly detection using Isolation Forest.
Calculates continuous anomaly scores, isolates zero-day behavior, and discovers unknown attack vectors.
"""

from typing import Tuple, Dict, Any, Optional
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest


class NetworkAnomalyDetector:
    """
    Unsupervised anomaly detector for network flow data using Isolation Forest.
    """
    def __init__(self, contamination: float = 0.08, n_estimators: int = 100, random_state: int = 42):
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.random_state = random_state
        self.model = IsolationForest(
            contamination=self.contamination,
            n_estimators=self.n_estimators,
            random_state=self.random_state,
            n_jobs=-1
        )
        self.is_fitted = False
        self.min_score = 0.0
        self.max_score = 1.0

    def fit(self, X: np.ndarray) -> 'NetworkAnomalyDetector':
        """Fit Isolation Forest on feature matrix."""
        self.model.fit(X)
        self.is_fitted = True
        
        # Determine score range for normalization
        raw_scores = -self.model.score_samples(X)
        self.min_score = float(np.min(raw_scores))
        self.max_score = float(np.max(raw_scores))
        return self

    def predict_anomalies(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Predict whether flows are anomalous.
        
        Returns:
        - anomaly_flags: array of 'Normal' or 'Potentially Anomalous'
        - anomaly_scores: array of float normalized between 0.0 (benign) and 1.0 (highly suspicious)
        """
        if not self.is_fitted:
            raise RuntimeError("Anomaly detector has not been fitted yet.")
            
        preds = self.model.predict(X)  # 1 for inlier/normal, -1 for outlier/anomaly
        raw_scores = -self.model.score_samples(X)
        
        # Normalize scores to [0.0, 1.0]
        denom = (self.max_score - self.min_score) if (self.max_score - self.min_score) > 0 else 1.0
        normalized_scores = np.clip((raw_scores - self.min_score) / denom, 0.0, 1.0)
        
        flags = np.where(preds == -1, "Potentially Anomalous", "Normal")
        return flags, np.round(normalized_scores, 4)

    def fit_predict(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Fit and predict in a single step."""
        self.fit(X)
        return self.predict_anomalies(X)
