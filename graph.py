"""
graph.py - Matplotlib Data Visualizations
=========================================
Generates server-side statistical charts using Python's Matplotlib library.
NO JavaScript or Chart.js is used. All charts are rendered to high-resolution PNGs.

CHARTS GENERATED:
1. Risk Breakdown Bar Chart (Categories: HTTPS, Domain, URL, Redirects, Content, Headers)
2. Trust Signals Pie Chart (Positive vs Warning vs Risk signals)
3. Scan History Line Chart (Risk scores of past scans over time)
"""

import os
import time
import matplotlib
# Use the non-interactive 'Agg' backend to avoid GUI issues on servers/Windows
matplotlib.use("Agg")
import matplotlib.pyplot as plt


# Dark modern theme palette matching the website CSS
THEME = {
    "bg_color": "#111827",       # Dark slate gray
    "card_bg": "#1f2937",        # Card background
    "text_color": "#f3f4f6",     # Light gray
    "grid_color": "#374151",     # Subdued border/grid
    "green": "#10b981",          # Emerald
    "yellow": "#f59e0b",         # Amber
    "red": "#ef4444",            # Rose Red
    "cyan": "#06b6d4",           # Cyan
    "purple": "#8b5cf6",         # Purple
    "blue": "#3b82f6"            # Blue
}


def ensure_output_dir(output_dir: str):
    """Ensure the static graphs directory exists."""
    os.makedirs(output_dir, exist_ok=True)


def generate_risk_breakdown_chart(breakdown: dict, output_path: str):
    """
    GRAPH 1: Bar Chart showing risk points contributed by each category.
    """
    categories = list(breakdown.keys())
    values = list(breakdown.values())

    # Colors for each category bar
    bar_colors = [
        THEME["cyan"],
        THEME["purple"],
        THEME["blue"],
        THEME["yellow"],
        THEME["green"],
        "#ec4899"  # Pink
    ]

    fig, ax = plt.subplots(figsize=(6.5, 4.2), facecolor=THEME["bg_color"])
    ax.set_facecolor(THEME["card_bg"])

    bars = ax.barh(categories, values, color=bar_colors, height=0.55, edgecolor="#ffffff", linewidth=0.5)

    # Styling axes and text
    ax.set_title("Risk Score Contribution by Category", color=THEME["text_color"], fontsize=12, fontweight="bold", pad=12)
    ax.set_xlabel("Risk Points (Higher = More Risk)", color=THEME["text_color"], fontsize=10, labelpad=8)
    ax.tick_params(colors=THEME["text_color"], labelsize=9)

    # Set x limits to give space for labels
    max_val = max(values) if values else 10
    ax.set_xlim(0, max(30, max_val + 5))

    # Add numeric labels at the end of each bar
    for bar in bars:
        width = bar.get_width()
        ax.text(
            width + 0.6,
            bar.get_y() + bar.get_height() / 2,
            f"{int(width)} pts",
            va="center",
            color=THEME["text_color"],
            fontsize=9,
            fontweight="bold"
        )

    # Subtle grid
    ax.xaxis.grid(True, linestyle="--", alpha=0.3, color=THEME["grid_color"])
    ax.set_axisbelow(True)

    # Remove outer spines
    for spine in ["top", "right", "left", "bottom"]:
        ax.spines[spine].set_color(THEME["grid_color"])

    plt.tight_layout()
    plt.savefig(output_path, dpi=130, facecolor=fig.get_facecolor(), bbox_inches="tight")
    plt.close(fig)


def generate_trust_signals_pie_chart(signal_counts: dict, output_path: str):
    """
    GRAPH 2: Pie/Donut Chart showing proportion of Positive, Warning, and Risk signals.
    """
    labels = ["Positive", "Warnings", "High Risk"]
    counts = [
        signal_counts.get("positive", 0),
        signal_counts.get("warning", 0),
        signal_counts.get("risk", 0)
    ]
    colors = [THEME["green"], THEME["yellow"], THEME["red"]]

    # Filter out categories with 0 count to prevent plotting artifacts
    filtered_labels = []
    filtered_counts = []
    filtered_colors = []
    for label, count, color in zip(labels, counts, colors):
        if count > 0:
            filtered_labels.append(f"{label} ({count})")
            filtered_counts.append(count)
            filtered_colors.append(color)

    # Fallback if no signals
    if not filtered_counts:
        filtered_labels = ["No Signals"]
        filtered_counts = [1]
        filtered_colors = ["#6b7280"]

    fig, ax = plt.subplots(figsize=(5.5, 4.2), facecolor=THEME["bg_color"])
    ax.set_facecolor(THEME["card_bg"])

    wedges, texts, autotexts = ax.pie(
        filtered_counts,
        labels=filtered_labels,
        colors=filtered_colors,
        autopct="%1.0f%%",
        startangle=140,
        pctdistance=0.75,
        wedgeprops=dict(width=0.45, edgecolor=THEME["bg_color"], linewidth=2)
    )

    # Style label texts
    for t in texts:
        t.set_color(THEME["text_color"])
        t.set_fontsize(9)
        t.set_fontweight("bold")
    for at in autotexts:
        at.set_color("#ffffff")
        at.set_fontsize(9)
        at.set_fontweight("bold")

    ax.set_title("Trust Signal Distribution", color=THEME["text_color"], fontsize=12, fontweight="bold", pad=12)

    plt.tight_layout()
    plt.savefig(output_path, dpi=130, facecolor=fig.get_facecolor(), bbox_inches="tight")
    plt.close(fig)


def generate_scan_history_chart(history_records: list, output_path: str):
    """
    GRAPH 3: Line chart showing risk score progression over past scans.
    """
    fig, ax = plt.subplots(figsize=(8.0, 4.0), facecolor=THEME["bg_color"])
    ax.set_facecolor(THEME["card_bg"])

    # If history is empty or has only 1 entry, handle gracefully
    if not history_records:
        ax.text(
            0.5, 0.5, "No scan history available yet.\nAnalyze websites to see history trend.",
            ha="center", va="center", color=THEME["text_color"], fontsize=11, transform=ax.transAxes
        )
    else:
        # Take at most the last 10 scans
        recent = history_records[-10:]
        x_indices = list(range(1, len(recent) + 1))
        scores = [item.get("risk_score", 0) for item in recent]
        labels = [item.get("website", f"Scan {i}") for i, item in enumerate(recent, start=1)]

        # Plot line and points
        ax.plot(x_indices, scores, color=THEME["cyan"], marker="o", linewidth=2.5, markersize=7, label="Risk Score")

        # Color the individual points based on threshold
        for x, score in zip(x_indices, scores):
            pt_color = THEME["green"] if score < 30 else (THEME["yellow"] if score <= 65 else THEME["red"])
            ax.plot(x, score, marker="o", color=pt_color, markersize=8)
            ax.text(x, score + 3, f"{score}", ha="center", color=THEME["text_color"], fontsize=9, fontweight="bold")

        # Draw risk reference threshold zones
        ax.axhspan(0, 29, color=THEME["green"], alpha=0.1, label="Trustworthy (0-29)")
        ax.axhspan(30, 65, color=THEME["yellow"], alpha=0.1, label="Caution (30-65)")
        ax.axhspan(66, 100, color=THEME["red"], alpha=0.1, label="High Risk (66-100)")

        ax.set_xticks(x_indices)
        ax.set_xticklabels(labels, rotation=25, ha="right", color=THEME["text_color"], fontsize=8)

    ax.set_ylim(0, 105)
    ax.set_ylabel("Risk Score (0 - 100)", color=THEME["text_color"], fontsize=10, labelpad=8)
    ax.set_title("Recent Scan Risk Scores", color=THEME["text_color"], fontsize=12, fontweight="bold", pad=12)
    ax.tick_params(colors=THEME["text_color"])

    ax.yaxis.grid(True, linestyle="--", alpha=0.3, color=THEME["grid_color"])
    ax.set_axisbelow(True)

    for spine in ["top", "right", "left", "bottom"]:
        ax.spines[spine].set_color(THEME["grid_color"])

    plt.tight_layout()
    plt.savefig(output_path, dpi=130, facecolor=fig.get_facecolor(), bbox_inches="tight")
    plt.close(fig)


def generate_all_graphs(breakdown: dict, signal_counts: dict, history_records: list, static_dir: str) -> dict:
    """
    Generates all three graphs and saves them to static/graphs/.
    Returns relative filenames for use in Flask templates.
    """
    graphs_dir = os.path.join(static_dir, "graphs")
    ensure_output_dir(graphs_dir)

    # Use timestamp to avoid browser caching issues
    timestamp = int(time.time() * 1000)
    
    file_breakdown = f"graph_breakdown_{timestamp}.png"
    file_signals = f"graph_signals_{timestamp}.png"
    file_history = f"graph_history_{timestamp}.png"

    path_breakdown = os.path.join(graphs_dir, file_breakdown)
    path_signals = os.path.join(graphs_dir, file_signals)
    path_history = os.path.join(graphs_dir, file_history)

    # Generate the 3 charts
    generate_risk_breakdown_chart(breakdown, path_breakdown)
    generate_trust_signals_pie_chart(signal_counts, path_signals)
    generate_scan_history_chart(history_records, path_history)

    return {
        "breakdown_chart": f"graphs/{file_breakdown}",
        "signals_chart": f"graphs/{file_signals}",
        "history_chart": f"graphs/{file_history}"
    }
