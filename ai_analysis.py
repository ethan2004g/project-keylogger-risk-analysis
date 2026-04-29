"""
Project Keylogger — Team Key
AI-powered risk analysis for sanitized session logs.

Parses a sanitized event log, reconstructs typed text per window,
sends it to OpenAI for sensitivity classification, and produces
matplotlib statistical graphs saved to the reports/ directory.

Standalone usage:
    python ai_analysis.py                      # analyze default log
    python ai_analysis.py path/to/log.txt      # analyze specific log file
"""

import json
import os
import re
from collections import defaultdict
from datetime import datetime
from typing import Optional

import config

# ---------------------------------------------------------------------------
# Log parsing — reconstruct events from a sanitized session log
# ---------------------------------------------------------------------------

_LOG_RE = re.compile(
    r"^\[(?P<ts>[^\]]+)\]\s*(?:\[(?P<window>[^\]]+)\]\s*)?(?P<key>.+?)\s*"
    r"\[(?P<level>LOW|MEDIUM|HIGH)\|(?P<vector>[^\]]+)\]$"
)

_SPECIAL_KEYS = {
    "<space>": " ",
    "<enter>": "\n",
    "<return>": "\n",
    "<backspace>": "\b",
    "<tab>": "\t",
}


def _key_to_char(raw: str) -> str:
    low = raw.lower()
    if low in _SPECIAL_KEYS:
        return _SPECIAL_KEYS[low]
    if raw.startswith("<"):
        return ""
    return raw


def parse_log(log_path: str) -> list[dict]:
    """Parse a sanitized session log into a list of structured event dicts."""
    events: list[dict] = []
    try:
        with open(log_path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                m = _LOG_RE.match(line.strip())
                if not m:
                    continue
                events.append(
                    {
                        "ts": m.group("ts"),
                        "window": (m.group("window") or "Unknown").strip(),
                        "key": m.group("key").strip(),
                        "level": m.group("level"),
                        "vector": m.group("vector"),
                    }
                )
    except FileNotFoundError:
        pass
    return events


def reconstruct_text(events: list[dict]) -> dict[str, str]:
    """Rebuild typed text per window title, honouring backspace."""
    buf: dict[str, list[str]] = defaultdict(list)
    for e in events:
        ch = _key_to_char(e["key"])
        w = e["window"]
        if ch == "\b":
            if buf[w]:
                buf[w].pop()
        elif ch:
            buf[w].append(ch)
    return {w: "".join(chars) for w, chars in buf.items()}


def build_stats(events: list[dict]) -> dict:
    """Aggregate counts for risk levels, vectors, windows, and a timeline."""
    level_counts: dict[str, int] = {"LOW": 0, "MEDIUM": 0, "HIGH": 0}
    vector_counts: dict[str, int] = defaultdict(int)
    window_high: dict[str, int] = defaultdict(int)
    timeline_levels: list[str] = []

    for e in events:
        lv = e["level"]
        level_counts[lv] = level_counts.get(lv, 0) + 1
        for v in e["vector"].split("+"):
            vector_counts[v] += 1
        if lv == "HIGH":
            window_high[e["window"]] += 1
        timeline_levels.append(lv)

    return {
        "total": len(events),
        "level_counts": level_counts,
        "vector_counts": dict(vector_counts),
        "window_high_counts": dict(window_high),
        "timeline_levels": timeline_levels,
    }


# ---------------------------------------------------------------------------
# OpenAI sensitivity analysis
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = (
    "You are a cybersecurity risk analyst. You will receive text typed in a specific "
    "application window and must classify its sensitivity. Respond ONLY with valid JSON."
)

_USER_PROMPT_TMPL = """\
Window title: "{window}"

Text typed in this window (reconstructed from keystroke log, may be partial):
\"\"\"
{text}
\"\"\"

Analyze the text for sensitive content. Return a JSON object with exactly these keys:
{{
  "sensitivity_score": <integer 0-100, overall sensitivity>,
  "password_likelihood": <integer 0-100>,
  "pii_likelihood": <integer 0-100, personally identifiable info>,
  "financial_likelihood": <integer 0-100>,
  "api_key_likelihood": <integer 0-100>,
  "detected_categories": [<list of strings, e.g. "password", "email", "credit_card", "api_key", "ssn", "username">],
  "summary": "<1-2 sentence plain-English finding>"
}}
"""


def analyze_with_openai(
    window_texts: dict[str, str],
    api_key: str,
    model: str = "gpt-4o-mini",
) -> dict[str, dict]:
    """Send per-window reconstructed text to OpenAI; return structured risk scores."""
    try:
        from openai import OpenAI
    except ImportError:
        print("[AI Analysis] openai package not installed. Run: pip install openai>=1.0.0")
        return {}

    client = OpenAI(api_key=api_key)
    results: dict[str, dict] = {}

    for window, text in window_texts.items():
        text_chunk = text.strip()
        if not text_chunk:
            continue
        text_chunk = text_chunk[:2000]  # ~500 tokens — keep costs low

        prompt = _USER_PROMPT_TMPL.format(window=window[:120], text=text_chunk)
        try:
            resp = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": _SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                temperature=0,
                response_format={"type": "json_object"},
            )
            raw = resp.choices[0].message.content or "{}"
            results[window] = json.loads(raw)
        except Exception as exc:
            results[window] = {
                "sensitivity_score": 0,
                "password_likelihood": 0,
                "pii_likelihood": 0,
                "financial_likelihood": 0,
                "api_key_likelihood": 0,
                "detected_categories": [],
                "summary": f"Analysis error: {exc}",
            }

    return results


# ---------------------------------------------------------------------------
# Graph generation
# ---------------------------------------------------------------------------

# Dark cyberpunk colour theme matching the project's aesthetic
_BG = "#1e1e2e"
_FG = "#cdd6f4"
_GRID = "#313244"
_PALETTE = {"LOW": "#66BB6A", "MEDIUM": "#FFA726", "HIGH": "#EF5350"}

_METRIC_CFG = [
    ("sensitivity_score",  "Overall",   "#9C27B0"),
    ("password_likelihood","Password",  "#F44336"),
    ("pii_likelihood",     "PII",       "#FF9800"),
    ("financial_likelihood","Financial","#2196F3"),
    ("api_key_likelihood", "API Key",   "#00BCD4"),
]


# ---------------------------------------------------------------------------
# Session risk score — single 0-100 number combining rule-based + AI signals
# ---------------------------------------------------------------------------

def compute_session_risk_score(stats: dict, ai_results: dict) -> int:
    """
    Compute an overall session risk percentage (0–100).

    Weighted from three signals:
      50% — OpenAI average sensitivity score across windows
      30% — proportion of HIGH-risk keystrokes
      20% — presence of critical detected categories (passwords, keys, PII)
    """
    total = stats["total"] or 1

    # Signal 1: AI sensitivity (0-1)
    if ai_results:
        scores = [
            r.get("sensitivity_score", 0)
            for r in ai_results.values()
            if isinstance(r.get("sensitivity_score"), (int, float))
        ]
        ai_signal = (sum(scores) / len(scores) / 100) if scores else 0.0
    else:
        ai_signal = 0.0

    # Signal 2: proportion of HIGH-risk keystrokes (0-1)
    high_signal = stats["level_counts"].get("HIGH", 0) / total

    # Signal 3: critical category hits (password, ssn, credit card, api key…)
    _CRITICAL = {"password", "credit_card", "ssn", "api_key", "private_key", "secret", "token"}
    detected: set[str] = set()
    for r in ai_results.values():
        detected.update(c.lower() for c in r.get("detected_categories", []))
    hits = len(detected & _CRITICAL)
    cat_signal = min(1.0, hits / 2)  # 2+ critical categories = full weight

    raw = ai_signal * 0.50 + high_signal * 0.30 + cat_signal * 0.20
    return min(100, round(raw * 100))


def _risk_label(score: int) -> tuple[str, str]:
    """Return (label, colour) for a 0-100 risk score."""
    if score >= 70:
        return "HIGH RISK", _PALETTE["HIGH"]
    if score >= 35:
        return "MODERATE RISK", _PALETTE["MEDIUM"]
    return "LOW RISK", _PALETTE["LOW"]


def _apply_dark_theme():
    import matplotlib.pyplot as plt

    plt.rcParams.update(
        {
            "figure.facecolor": _BG,
            "axes.facecolor": _BG,
            "axes.edgecolor": _GRID,
            "axes.labelcolor": _FG,
            "xtick.color": _FG,
            "ytick.color": _FG,
            "text.color": _FG,
            "grid.color": _GRID,
            "legend.facecolor": "#313244",
            "legend.edgecolor": _GRID,
            "legend.labelcolor": _FG,
        }
    )


def _save(fig, path: str) -> str:
    fig.savefig(path, dpi=150, bbox_inches="tight", facecolor=_BG)
    fig.clf()
    import matplotlib.pyplot as plt
    plt.close(fig)
    print(f"[AI Analysis] Saved: {path}")
    return path


def _draw_gauge(ax, score: int, label: str, color: str) -> None:
    """Draw a semi-circular speedometer gauge for the risk score."""
    import numpy as np
    import matplotlib.patches as mpatches
    from matplotlib.patches import Arc, FancyArrowPatch, Wedge

    ax.set_xlim(-1.3, 1.3)
    ax.set_ylim(-0.55, 1.2)
    ax.set_aspect("equal")
    ax.axis("off")

    # Colour zones: green → yellow → red (left to right = 0 → 100%)
    zones = [
        (180, 240, "#66BB6A"),   # LOW  (180°–240° on unit circle = 0–33%)
        (120, 180, "#FFA726"),   # MED  (120°–180° = 33–66%)
        (60,  120, "#EF5350"),   # HIGH (60°–120° = 66–100%)
    ]
    for t1, t2, c in zones:
        wedge = Wedge((0, 0), 1.0, t1, t2, width=0.28,
                      facecolor=c, edgecolor=_BG, linewidth=2, alpha=0.85)
        ax.add_patch(wedge)

    # Needle: angle maps score 0→180° (left) to 0° (right) → 180° – score*1.8
    angle_deg = 180.0 - score * 1.8
    angle_rad = np.radians(angle_deg)
    needle_x = 0.72 * np.cos(angle_rad)
    needle_y = 0.72 * np.sin(angle_rad)
    ax.annotate(
        "", xy=(needle_x, needle_y), xytext=(0, 0),
        arrowprops=dict(arrowstyle="-|>", color=_FG, lw=2.5,
                        mutation_scale=18),
    )
    # Centre hub
    hub = mpatches.Circle((0, 0), 0.07, color=_FG, zorder=5)
    ax.add_patch(hub)

    # Score text
    ax.text(0, -0.25, f"{score}%", ha="center", va="center",
            fontsize=38, fontweight="bold", color=color)
    ax.text(0, -0.48, label, ha="center", va="center",
            fontsize=13, color=color, fontweight="bold")
    ax.text(0, 1.12, "Session Leakage Risk", ha="center", va="center",
            fontsize=11, color=_FG)
    # Scale labels
    ax.text(-1.08, -0.08, "0%",   ha="center", fontsize=8, color=_FG)
    ax.text( 0,     1.05,  "50%",  ha="center", fontsize=8, color=_FG)
    ax.text( 1.08, -0.08, "100%", ha="center", fontsize=8, color=_FG)


def _fig1_risk_overview(stats: dict, score: int, ts: str, out_dir: str) -> str:
    """
    Figure 1 — Session risk gauge, risk-level % breakdown, and a
    time-bucketed activity timeline (groups of keystrokes, not individual keys).
    """
    import matplotlib.pyplot as plt
    import matplotlib.gridspec as gridspec
    import numpy as np

    label, color = _risk_label(score)

    fig = plt.figure(figsize=(15, 11))
    fig.suptitle(
        "Project Keylogger — Session Risk Overview",
        fontsize=15, fontweight="bold", color=_FG, y=0.99,
    )
    # Row 0: gauge (left) + risk-% pie (right)
    # Row 1: time-bucketed timeline (full width)
    gs = gridspec.GridSpec(2, 2, figure=fig, hspace=0.40, wspace=0.30,
                           height_ratios=[1.1, 0.9])

    # ---- Gauge ----
    ax_gauge = fig.add_subplot(gs[0, 0])
    _draw_gauge(ax_gauge, score, label, color)

    # ---- Risk level % pie ----
    ax_pie = fig.add_subplot(gs[0, 1])
    total = stats["total"] or 1
    levels = ["LOW", "MEDIUM", "HIGH"]
    counts = [stats["level_counts"].get(l, 0) for l in levels]
    pcts = [c / total * 100 for c in counts]
    non_zero = [(l, p) for l, p in zip(levels, pcts) if p > 0]
    if non_zero:
        pie_labels = [f"{l}\n{p:.1f}%" for l, p in non_zero]
        wedges, _ = ax_pie.pie(
            [p for _, p in non_zero],
            labels=None,
            colors=[_PALETTE[l] for l, _ in non_zero],
            startangle=90,
            wedgeprops={"edgecolor": _BG, "linewidth": 2},
        )
        ax_pie.legend(
            wedges, pie_labels,
            loc="lower center", bbox_to_anchor=(0.5, -0.18),
            ncol=3, fontsize=9, framealpha=0.4,
        )
    ax_pie.set_title("Risk Level Distribution", color=_FG, fontsize=11, pad=12)

    # ---- Time-bucketed stacked bar timeline ----
    ax_tl = fig.add_subplot(gs[1, :])
    tl = stats.get("timeline_levels", [])
    N_BUCKETS = 15  # group into 15 equal chunks regardless of session length

    if len(tl) >= N_BUCKETS:
        chunk_size = max(1, len(tl) // N_BUCKETS)
        buckets = [tl[i : i + chunk_size] for i in range(0, len(tl), chunk_size)]
        # Trim to N_BUCKETS so the last tiny remainder doesn't skew
        buckets = buckets[:N_BUCKETS]
        xs = np.arange(len(buckets))
        h_pcts = [b.count("HIGH")   / len(b) * 100 for b in buckets]
        m_pcts = [b.count("MEDIUM") / len(b) * 100 for b in buckets]
        l_pcts = [b.count("LOW")    / len(b) * 100 for b in buckets]
        bar_w = 0.7

        ax_tl.bar(xs, l_pcts,          bar_w, label="LOW",    color=_PALETTE["LOW"],    alpha=0.88)
        ax_tl.bar(xs, m_pcts, bar_w,   bottom=l_pcts,          label="MEDIUM", color=_PALETTE["MEDIUM"], alpha=0.88)
        # HIGH on top
        bottoms = [l + m for l, m in zip(l_pcts, m_pcts)]
        ax_tl.bar(xs, h_pcts, bar_w,   bottom=bottoms,         label="HIGH",   color=_PALETTE["HIGH"],   alpha=0.88)

        # x-axis: label each bucket as "1"…"15"
        ax_tl.set_xticks(xs)
        ax_tl.set_xticklabels([str(i + 1) for i in range(len(buckets))], fontsize=9)
        ax_tl.set_xlabel(
            f"Session segment  (each bar ≈ {chunk_size} keystrokes)", color=_FG, fontsize=9
        )
        ax_tl.set_ylabel("Risk mix (%)", color=_FG)
        ax_tl.set_ylim(0, 105)
        ax_tl.legend(loc="upper right", fontsize=9)
        ax_tl.grid(axis="y", alpha=0.25)
        ax_tl.set_title("Activity Timeline — Risk Breakdown per Session Segment", color=_FG, fontsize=11)
    else:
        ax_tl.text(0.5, 0.5, "Not enough data for timeline",
                   ha="center", va="center", color=_FG, transform=ax_tl.transAxes)
        ax_tl.set_title("Activity Timeline", color=_FG, fontsize=11)

    plt.tight_layout(rect=[0, 0, 1, 0.97])
    return _save(fig, os.path.join(out_dir, f"risk_overview_{ts}.png"))


def _fig2_ai_sensitivity(ai_results: dict[str, dict], ts: str, out_dir: str) -> Optional[str]:
    """Figure 2 — Grouped bar chart + heatmap of OpenAI scores per window."""
    if not ai_results:
        return None

    import matplotlib.pyplot as plt
    import numpy as np

    windows = list(ai_results.keys())
    short = [(w[:28] + "…") if len(w) > 30 else w for w in windows]
    n = len(windows)
    metrics = [m for m, _, _ in _METRIC_CFG]
    labels = [l for _, l, _ in _METRIC_CFG]
    colors = [c for _, _, c in _METRIC_CFG]

    fig, (ax_bar, ax_heat) = plt.subplots(1, 2, figsize=(16, max(5, n * 0.9 + 3)))
    fig.suptitle(
        "OpenAI Sensitivity Analysis by Window",
        fontsize=14, fontweight="bold", color=_FG,
    )

    # Grouped bar chart
    x = np.arange(n)
    w = 0.14
    for i, (metric, label, color) in enumerate(_METRIC_CFG):
        vals = [ai_results[win].get(metric, 0) for win in windows]
        offset = (i - len(_METRIC_CFG) / 2 + 0.5) * w
        ax_bar.bar(x + offset, vals, w, label=label, color=color, alpha=0.85)
    ax_bar.set_xticks(x)
    ax_bar.set_xticklabels(short, rotation=35, ha="right", fontsize=8)
    ax_bar.set_ylim(0, 115)
    ax_bar.set_ylabel("Score (0–100)", color=_FG)
    ax_bar.set_title("Risk Scores per Window", color=_FG, fontsize=11)
    ax_bar.legend(fontsize=8, loc="upper right")
    ax_bar.grid(axis="y", alpha=0.3)

    # Heatmap
    data = np.array([[ai_results[win].get(m, 0) for m in metrics] for win in windows], dtype=float)
    im = ax_heat.imshow(data, aspect="auto", cmap="RdYlGn_r", vmin=0, vmax=100)
    ax_heat.set_xticks(range(len(metrics)))
    ax_heat.set_xticklabels(labels, rotation=30, ha="right", fontsize=9)
    ax_heat.set_yticks(range(n))
    ax_heat.set_yticklabels(short, fontsize=8)
    ax_heat.set_title("Sensitivity Heatmap", color=_FG, fontsize=11)
    for row in range(n):
        for col in range(len(metrics)):
            val = int(data[row, col])
            txt_color = "white" if val > 55 else "black"
            ax_heat.text(col, row, str(val), ha="center", va="center",
                         fontsize=8, color=txt_color, fontweight="bold")
    cbar = fig.colorbar(im, ax=ax_heat, fraction=0.046, pad=0.04)
    plt.setp(cbar.ax.yaxis.get_ticklabels(), color=_FG)

    plt.tight_layout(rect=[0, 0, 1, 0.94])
    return _save(fig, os.path.join(out_dir, f"ai_sensitivity_{ts}.png"))


def _fig3_summaries(ai_results: dict[str, dict], ts: str, out_dir: str) -> Optional[str]:
    """Figure 3 — Text panel of OpenAI natural-language findings."""
    entries = [
        (w, r) for w, r in ai_results.items() if r.get("summary")
    ]
    if not entries:
        return None

    import matplotlib.pyplot as plt

    fig, ax = plt.subplots(figsize=(14, max(4, len(entries) * 1.5 + 1)))
    ax.axis("off")
    ax.set_title("OpenAI Analysis Summaries", color=_FG, fontsize=13,
                 fontweight="bold", pad=14)

    step = 1.0 / (len(entries) + 0.5)
    y = 1.0 - step * 0.4
    for window, result in entries:
        score = result.get("sensitivity_score", 0)
        cats = result.get("detected_categories", [])
        summary = result.get("summary", "")
        score_color = (
            _PALETTE["HIGH"] if score >= 70
            else _PALETTE["MEDIUM"] if score >= 35
            else _PALETTE["LOW"]
        )
        label = (window[:52] + "…") if len(window) > 54 else window
        cats_str = ", ".join(cats) if cats else "none"
        ax.text(
            0.01, y, f"[{score:3d}]  {label}",
            transform=ax.transAxes, fontsize=9.5,
            color=score_color, fontweight="bold", va="top",
            fontfamily="monospace",
        )
        ax.text(
            0.01, y - step * 0.38,
            f"  Categories: {cats_str}\n  {summary}",
            transform=ax.transAxes, fontsize=8.5,
            color=_FG, va="top", fontfamily="monospace",
        )
        ax.axhline(y=y - step * 0.85, xmin=0.01, xmax=0.99,
                   color=_GRID, linewidth=0.6)
        y -= step

    plt.tight_layout()
    return _save(fig, os.path.join(out_dir, f"ai_summaries_{ts}.png"))


def generate_graphs(
    stats: dict,
    ai_results: dict[str, dict],
    output_dir: str,
) -> tuple[list[str], int]:
    """Produce all graphs, return (list of saved file paths, session risk score)."""
    try:
        import matplotlib
        matplotlib.use("Agg")
    except ImportError:
        print("[AI Analysis] matplotlib not installed. Run: pip install matplotlib")
        return [], 0

    _apply_dark_theme()
    os.makedirs(output_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    saved: list[str] = []

    score = compute_session_risk_score(stats, ai_results)

    saved.append(_fig1_risk_overview(stats, score, ts, output_dir))

    p2 = _fig2_ai_sensitivity(ai_results, ts, output_dir)
    if p2:
        saved.append(p2)

    p3 = _fig3_summaries(ai_results, ts, output_dir)
    if p3:
        saved.append(p3)

    return saved, score


# ---------------------------------------------------------------------------
# Top-level runner for standalone analysis
# ---------------------------------------------------------------------------

def run_analysis(log_path: Optional[str] = None) -> list[str]:
    """
    Full pipeline: parse log -> rebuild text -> OpenAI -> graphs.
    Returns list of saved PNG paths.
    """
    log_path = log_path or config.LOG_PATH
    api_key = os.environ.get("OPENAI_API_KEY") or config.OPENAI_API_KEY
    model = config.OPENAI_MODEL
    output_dir = config.GRAPH_OUTPUT_DIR

    if not api_key:
        print(
            "[AI Analysis] No OpenAI API key configured.\n"
            "  Set the OPENAI_API_KEY environment variable, or set OPENAI_API_KEY in config.py."
        )
        return []

    print(f"[AI Analysis] Parsing log: {log_path}")
    events = parse_log(log_path)
    if not events:
        print("[AI Analysis] No log events found - nothing to analyze.")
        return []

    print(f"[AI Analysis] {len(events)} keystroke events parsed.")
    stats = build_stats(events)
    window_texts = reconstruct_text(events)

    non_empty = {w: t for w, t in window_texts.items() if t.strip()}
    print(
        f"[AI Analysis] Reconstructed text for {len(non_empty)} window(s). "
        f"Sending to OpenAI ({model})..."
    )
    ai_results = analyze_with_openai(non_empty, api_key, model)

    print(f"[AI Analysis] Generating graphs -> {output_dir}")
    saved, score = generate_graphs(stats, ai_results, output_dir)

    label, _ = _risk_label(score)
    print(
        f"\n{'=' * 50}\n"
        f"  SESSION LEAKAGE RISK SCORE: {score}%  -  {label}\n"
        f"{'=' * 50}"
    )
    return saved


if __name__ == "__main__":
    import sys

    log_arg = sys.argv[1] if len(sys.argv) > 1 else None
    paths = run_analysis(log_arg)
    if paths:
        print(f"\n[AI Analysis] Done - {len(paths)} report(s) saved:")
        for p in paths:
            print(f"  {p}")
    else:
        print("[AI Analysis] No graphs generated.")
