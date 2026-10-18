"""
Visualization Module for Cyber Threat Intelligence Dashboard
Creates Plotly figures formatted with dark navy, cyan, and cybersecurity-inspired aesthetics.
"""

from typing import List, Dict, Any, Optional
import numpy as np
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px


# Color Palette
CYBER_BG = "#0B1120"
CYBER_CARD_BG = "#131C31"
CYBER_GRID = "#1E293B"
CYBER_TEXT = "#E2E8F0"
CYBER_MUTED = "#94A3B8"

CYBER_COLORS = [
    "#06B6D4",  # Cyan
    "#3B82F6",  # Blue
    "#10B981",  # Emerald (Safe)
    "#F59E0B",  # Amber (Medium)
    "#EF4444",  # Red (Critical)
    "#8B5CF6",  # Purple
    "#EC4899",  # Pink
    "#14B8A6",  # Teal
]


def apply_cyber_theme(fig: go.Figure, title: str = "") -> go.Figure:
    """Apply consistent cyber dark navy styling to any Plotly figure."""
    fig.update_layout(
        title={
            "text": f"<b>{title}</b>" if title else "",
            "font": {"size": 16, "color": "#F8FAFC", "family": "Segoe UI, sans-serif"},
            "x": 0.02,
            "xanchor": "left"
        },
        paper_bgcolor=CYBER_CARD_BG,
        plot_bgcolor=CYBER_CARD_BG,
        font={"color": CYBER_TEXT, "family": "Segoe UI, sans-serif"},
        margin=dict(l=40, r=40, t=50, b=40),
        legend=dict(
            bgcolor="rgba(19, 28, 49, 0.7)",
            bordercolor=CYBER_GRID,
            borderwidth=1,
            font=dict(color=CYBER_TEXT)
        ),
        xaxis=dict(
            gridcolor=CYBER_GRID,
            zerolinecolor=CYBER_GRID,
            tickfont=dict(color=CYBER_MUTED)
        ),
        yaxis=dict(
            gridcolor=CYBER_GRID,
            zerolinecolor=CYBER_GRID,
            tickfont=dict(color=CYBER_MUTED)
        )
    )
    return fig


def plot_traffic_distribution(df: pd.DataFrame, label_col: str) -> go.Figure:
    """Donut chart showing class breakdown with centered total."""
    counts = df[label_col].value_counts().reset_index()
    counts.columns = ["Class", "Count"]

    fig = go.Figure(data=[
        go.Pie(
            labels=counts["Class"],
            values=counts["Count"],
            hole=0.55,
            marker=dict(colors=CYBER_COLORS, line=dict(color=CYBER_BG, width=2)),
            textinfo="label+percent",
            hoverinfo="label+value+percent"
        )
    ])
    fig.update_layout(
        annotations=[dict(
            text=f"<b>{len(df):,}</b><br><span style='font-size:12px;color:#94a3b8'>Records</span>",
            x=0.5, y=0.5, font_size=18, showarrow=False, font_color="#FFFFFF"
        )]
    )
    return apply_cyber_theme(fig, "Network Traffic Class Distribution")


def plot_confusion_matrix(cm: List[List[int]], classes: List[str]) -> go.Figure:
    """Annotated Confusion Matrix Heatmap."""
    cm_arr = np.array(cm)
    
    # Text annotations with count and percentage
    text_annotations = []
    for i in range(len(classes)):
        row_annot = []
        row_sum = cm_arr[i].sum()
        for j in range(len(classes)):
            val = cm_arr[i, j]
            pct = (val / row_sum * 100) if row_sum > 0 else 0
            row_annot.append(f"<b>{val:,}</b><br>({pct:.1f}%)")
        text_annotations.append(row_annot)

    fig = go.Figure(data=go.Heatmap(
        z=cm_arr,
        x=classes,
        y=classes,
        colorscale=[
            [0.0, "#0F172A"],
            [0.3, "#1E3A8A"],
            [0.7, "#0284C7"],
            [1.0, "#38BDF8"]
        ],
        text=text_annotations,
        texttemplate="%{text}",
        textfont={"size": 11, "color": "#FFFFFF"},
        showscale=True,
        colorbar=dict(title=dict(text="Count", font=dict(color=CYBER_TEXT)), tickfont=dict(color=CYBER_MUTED))
    ))
    fig.update_xaxes(title="<b>Predicted Attack Category</b>", tickangle=-30)
    fig.update_yaxes(title="<b>Ground Truth Label</b>")
    return apply_cyber_theme(fig, "Model Confusion Matrix (Validation Split)")


def plot_feature_importance(feature_importances: List[Dict[str, Any]], top_n: int = 10) -> go.Figure:
    """Horizontal bar chart of top predictive features."""
    top_feats = feature_importances[:top_n][::-1]  # Reverse for ascending display
    names = [f["feature"] for f in top_feats]
    scores = [f["importance"] for f in top_feats]

    fig = go.Figure(data=[
        go.Bar(
            y=names,
            x=scores,
            orientation="h",
            marker=dict(
                color=scores,
                colorscale=[[0.0, "#0284C7"], [1.0, "#06B6D4"]],
                line=dict(color="#38BDF8", width=1)
            ),
            text=[f"{s:.4f}" for s in scores],
            textposition="outside"
        )
    ])
    fig.update_xaxes(title="<b>Gini Importance / Feature Weight</b>")
    fig.update_yaxes(title="")
    return apply_cyber_theme(fig, f"Top {len(names)} Most Influential Flow Features")


def plot_destination_ports(df: pd.DataFrame, port_col: str = "Destination Port", top_n: int = 8) -> go.Figure:
    """Bar chart of top targeted destination ports."""
    from src.threat_analysis import PORT_SERVICES
    
    if port_col not in df.columns:
        return go.Figure()

    top_ports = df[port_col].value_counts().head(top_n).reset_index()
    top_ports.columns = ["Port", "Count"]
    
    labels = []
    for p in top_ports["Port"]:
        try:
            p_int = int(p)
            labels.append(f"{p_int} ({PORT_SERVICES.get(p_int, 'Other')})")
        except:
            labels.append(str(p))

    fig = go.Figure(data=[
        go.Bar(
            x=labels,
            y=top_ports["Count"],
            marker=dict(color="#06B6D4", line=dict(color="#38BDF8", width=1)),
            text=top_ports["Count"],
            textposition="outside"
        )
    ])
    fig.update_xaxes(title="<b>Destination Port (Service)</b>", tickangle=-25)
    fig.update_yaxes(title="<b>Flow Hits</b>")
    return apply_cyber_theme(fig, "Top Targeted Destination Services")


def plot_anomaly_distribution(anomaly_scores: np.ndarray, threshold: float = 0.75) -> go.Figure:
    """Histogram of continuous anomaly scores with threshold marker."""
    fig = go.Figure()
    fig.add_trace(go.Histogram(
        x=anomaly_scores,
        nbinsx=35,
        marker=dict(
            color="#3B82F6",
            line=dict(color=CYBER_BG, width=1)
        ),
        name="Anomaly Score"
    ))
    fig.add_vline(
        x=threshold,
        line_width=2,
        line_dash="dash",
        line_color="#EF4444",
        annotation_text="Suspicious Threshold",
        annotation_position="top right",
        annotation_font_color="#EF4444"
    )
    fig.update_xaxes(title="<b>Normalized Anomaly Score (0.0 = Normal, 1.0 = Highly Anomalous)</b>")
    fig.update_yaxes(title="<b>Flow Frequency</b>")
    return apply_cyber_theme(fig, "Isolation Forest Anomaly Score Distribution")


def plot_attack_pattern_scatter(df: pd.DataFrame, label_col: str = "Label") -> go.Figure:
    """Scatter comparison of Flow Duration vs Flow Packets/s across attack types."""
    available_cols = df.columns
    
    x_col = "Flow Duration" if "Flow Duration" in available_cols else None
    y_col = "Flow Packets/s" if "Flow Packets/s" in available_cols else None
    
    if not x_col or not y_col:
        num_cols = df.select_dtypes(include=[np.number]).columns
        if len(num_cols) >= 2:
            x_col, y_col = num_cols[0], num_cols[1]
        else:
            return go.Figure()

    sample_df = df.sample(min(len(df), 1200), random_state=42)

    fig = px.scatter(
        sample_df,
        x=x_col,
        y=y_col,
        color=label_col if label_col in sample_df.columns else None,
        color_discrete_sequence=CYBER_COLORS,
        hover_data=[c for c in ["Destination Port", "Average Packet Size"] if c in sample_df.columns],
        log_x=True,
        log_y=True
    )
    return apply_cyber_theme(fig, f"Flow Pattern Clustering ({x_col} vs {y_col})")
