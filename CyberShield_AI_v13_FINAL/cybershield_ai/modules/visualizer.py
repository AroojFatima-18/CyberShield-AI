"""
CyberShield AI – Visualization Engine
Plotly charts for confusion matrix, accuracy graphs, probability bars,
threat timeline, and NetworkX graph rendering.
"""
import numpy as np
import plotly.graph_objects as go
import plotly.express as px
import networkx as nx
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

DARK_BG   = "#0a0e1a"
PANEL_BG  = "#0f1629"
ACCENT    = "#00d4ff"
DANGER    = "#ff4444"
WARNING   = "#ffaa00"
SUCCESS   = "#00ff88"
GRID_CLR  = "#1e2d4a"
TEXT_CLR  = "#c8d8f0"

PLOTLY_LAYOUT = dict(
    paper_bgcolor=DARK_BG, plot_bgcolor=PANEL_BG,
    font=dict(color=TEXT_CLR, family="monospace"),
    margin=dict(l=40, r=20, t=50, b=40),
)

def plot_confusion_matrix(cm: np.ndarray, classes: list):
    fig = px.imshow(
        cm, text_auto=True, x=classes, y=classes,
        color_continuous_scale=[[0,"#0a0e1a"],[0.5,"#1a3a6a"],[1,"#00d4ff"]],
        title="Confusion Matrix – Classification Results",
    )
    fig.update_layout(**PLOTLY_LAYOUT)
    fig.update_xaxes(title="Predicted Label", tickangle=30)
    fig.update_yaxes(title="True Label")
    return fig

def plot_class_accuracy(report: dict, classes: list):
    f1_scores = [report[c]["f1-score"] for c in classes if c in report]
    colors = [DANGER if f < 0.7 else WARNING if f < 0.85 else SUCCESS for f in f1_scores]
    fig = go.Figure(go.Bar(
        x=classes, y=f1_scores,
        marker_color=colors,
        text=[f"{v:.2f}" for v in f1_scores],
        textposition="outside",
    ))
    fig.update_layout(
        title="Per-Class F1 Score", yaxis_range=[0, 1.1],
        xaxis_title="Class", yaxis_title="F1 Score",
        **PLOTLY_LAYOUT
    )
    return fig

def plot_probability_radar(proba_dict: dict):
    categories = list(proba_dict.keys())
    values = list(proba_dict.values())
    fig = go.Figure(go.Scatterpolar(
        r=values + [values[0]],
        theta=categories + [categories[0]],
        fill="toself",
        line_color=ACCENT,
        fillcolor="rgba(0,212,255,0.15)",
        name="Class Probability",
    ))
    fig.update_layout(
        polar=dict(
            bgcolor=PANEL_BG,
            radialaxis=dict(visible=True, range=[0,1], color=TEXT_CLR),
            angularaxis=dict(color=TEXT_CLR),
        ),
        title="Classification Probability Distribution",
        **PLOTLY_LAYOUT
    )
    return fig

def plot_threat_gauge(threat_score: int):
    color = DANGER if threat_score >= 75 else WARNING if threat_score >= 40 else SUCCESS
    fig = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=threat_score,
        delta={"reference": 50},
        gauge={
            "axis": {"range": [0,100], "tickcolor": TEXT_CLR},
            "bar": {"color": color},
            "bgcolor": PANEL_BG,
            "bordercolor": GRID_CLR,
            "steps": [
                {"range": [0,30],  "color": "#0a1f0a"},
                {"range": [30,65], "color": "#1f1a0a"},
                {"range": [65,100],"color": "#1f0a0a"},
            ],
            "threshold": {"line": {"color": DANGER,"width": 3}, "value": 75},
        },
        title={"text": "Threat Score", "font": {"color": TEXT_CLR}},
        number={"font": {"color": color, "size": 48}},
    ))
    fig.update_layout(**PLOTLY_LAYOUT)
    return fig

def plot_cv_scores(cv_scores: list):
    folds = [f"Fold {i+1}" for i in range(len(cv_scores))]
    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=folds, y=cv_scores, mode="lines+markers",
        line=dict(color=ACCENT, width=2),
        marker=dict(size=9, color=ACCENT, line=dict(color="#fff",width=1)),
        name="CV Accuracy",
    ))
    fig.add_hline(y=np.mean(cv_scores), line_dash="dot",
                  line_color=SUCCESS, annotation_text=f"Mean: {np.mean(cv_scores):.3f}")
    fig.update_layout(
        title="5-Fold Cross-Validation Accuracy",
        yaxis_range=[0.5, 1.05],
        xaxis_title="Fold", yaxis_title="Accuracy",
        **PLOTLY_LAYOUT
    )
    return fig

def render_investigation_graph(G, result_bfs, result_dfs, result_astar,
                                source_node, target_node):
    """
    Render the investigation graph with all three algorithm paths overlaid.
    Returns a matplotlib Figure.
    """
    fig, axes = plt.subplots(1, 3, figsize=(20, 7), facecolor=DARK_BG)
    pos = nx.spring_layout(G, seed=42, k=1.8)

    algo_configs = [
        (result_bfs, axes[0], "#00d4ff", "BFS – Shortest Hop Path"),
        (result_dfs, axes[1], "#ff8800", "DFS – Deep Chain Traversal"),
        (result_astar, axes[2], "#00ff88", "A* – Optimal Cost Path"),
    ]

    risk_color_map = {
        "low": "#1a4a1a", "medium": "#4a3a0a",
        "high": "#4a1a1a", "critical": "#8a0000",
    }

    for result, ax, path_color, title in algo_configs:
        ax.set_facecolor(PANEL_BG)
        ax.set_title(title, color=path_color, fontsize=10, fontweight="bold", pad=8)

        node_colors = [risk_color_map.get(G.nodes[n].get("risk_level","low"), "#1a2a1a")
                       for n in G.nodes]
        node_sizes  = [300 + G.nodes[n].get("risk_score", 30) * 5 for n in G.nodes]
        border_colors = [path_color if n in (source_node, target_node) else "#333" for n in G.nodes]

        nx.draw_networkx_nodes(G, pos, ax=ax, node_color=node_colors,
                               node_size=node_sizes, edgecolors=border_colors, linewidths=2)
        nx.draw_networkx_labels(G, pos, ax=ax, font_size=5.5,
                                font_color=TEXT_CLR, font_weight="bold")
        nx.draw_networkx_edges(G, pos, ax=ax, edge_color="#2a3a5a",
                               arrows=True, arrowsize=12, width=0.8,
                               connectionstyle="arc3,rad=0.1")

        path = result.get("path", [])
        if len(path) > 1:
            path_edges = [(path[i], path[i+1]) for i in range(len(path)-1)
                          if G.has_edge(path[i], path[i+1])]
            nx.draw_networkx_edges(G, pos, edgelist=path_edges, ax=ax,
                                   edge_color=path_color, width=3.5,
                                   arrows=True, arrowsize=18,
                                   connectionstyle="arc3,rad=0.1")

        # Highlight source/target
        for special, marker, color in [(source_node,"▶","#ffffff"),(target_node,"★",DANGER)]:
            if special in pos:
                x, y = pos[special]
                ax.annotate(marker, (x, y+0.12), fontsize=12, color=color, ha="center")

        stats = f"Explored: {result.get('nodes_explored',0)} nodes"
        if "total_cost" in result:
            stats += f" | Cost: {result['total_cost']}"
        ax.set_xlabel(stats, color="#88aacc", fontsize=8)
        ax.axis("off")

    plt.tight_layout(pad=2.0)
    return fig
