#!/usr/bin/env python3
"""
fig_f1_cpu_ringbuf.py — Generates fig_f1_cpu_ringbuf_combined.png

Two-panel figure for IEEE TNSM submission:
  (a) Detection performance metrics vs userspace CPU cost per event
  (b) Per-class recall vs ring buffer utilisation

Usage:
    python3 results/analysis/fig_f1_cpu_ringbuf.py

Output: results/figures/fig_f1_cpu_ringbuf_combined.png
"""

import os
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.lines import Line2D

# ── IEEE TNSM style ───────────────────────────────────────────────────────────
# Two-column journal: full-width figure = 7.16 in, single column = 3.5 in
plt.rcParams.update({
    'font.family':        'serif',
    'font.serif':         ['Times New Roman', 'DejaVu Serif'],
    'font.size':          8,
    'axes.titlesize':     8,
    'axes.titleweight':   'bold',
    'axes.labelsize':     7,
    'xtick.labelsize':    6.5,
    'ytick.labelsize':    6.5,
    'legend.fontsize':    6.5,
    'legend.title_fontsize': 6.5,
    'axes.linewidth':     0.8,
    'grid.linewidth':     0.4,
    'grid.alpha':         0.5,
    'lines.linewidth':    1.0,
    'patch.linewidth':    0.6,
    'xtick.major.width':  0.8,
    'ytick.major.width':  0.8,
    'xtick.minor.width':  0.5,
    'ytick.minor.width':  0.5,
    'xtick.direction':    'in',
    'ytick.direction':    'in',
    'axes.spines.top':    False,
    'axes.spines.right':  False,
    'figure.dpi':         300,
    'savefig.dpi':        600,
    'savefig.bbox':       'tight',
    'savefig.pad_inches': 0.05,
})

OUT_DIR = os.path.join(os.path.dirname(__file__), '..', 'figures')
os.makedirs(OUT_DIR, exist_ok=True)

# ═══════════════════════════════════════════════════════════════════════════════
# DATA  (from measured results — README + evaluate.py output)
# ═══════════════════════════════════════════════════════════════════════════════

# Panel (a): detector metrics vs userspace CPU cost per event
# CPU cost = amortised userspace inference cost (µs/event); kernel overhead is
# fixed at ~4 µs/pkt (XDP+TC) for all detectors.
DETECTORS = {
    'Rule-based':       dict(f1=0.957, prec=0.930, rec=0.987, cpu_us=0.4),
    'Isolation Forest': dict(f1=0.057, prec=0.792, rec=0.030, cpu_us=14.2),
    'OC-SVM':           dict(f1=0.024, prec=0.680, rec=0.012, cpu_us=17.5),
    'Ensemble':         dict(f1=0.054, prec=0.741, rec=0.028, cpu_us=18.3),
}

# BPF hook latencies in µs (from perf measurements)
BPF_HOOKS = [
    ('XDP',  1.970),   # µs
    ('TC',   4.985),   # µs
    ('TP',   3.104),   # µs
]

# Panel (b): per-class recall vs ring buffer utilisation
# RB utilisation = ev_rate × 128 B / (16 MB × 50 Hz) × 100 (%)
# 128 B = sizeof(cla_corr_record); 16 MB ring; 50 Hz = 20 ms sweeper
RB_CAP_BYTES   = 16 * 1024 * 1024   # 16 MB
RB_RECORD_BYTES = 128
SWEEP_HZ        = 50

def rb_util(ev_per_sec):
    return (ev_per_sec * RB_RECORD_BYTES) / (RB_CAP_BYTES * SWEEP_HZ) * 100

# Attack categories: (display name, recall %, estimated event rate ev/s, color)
ATTACK_CATEGORIES = [
    ('Port Scan',             99.6,  1480, '#d62728'),
    ('SYN Flood',             99.5,  1510, '#ff7f0e'),
    ('Cryptomining C2',       93.0,   110, '#9467bd'),
    ('Privilege Escalation',  87.5,   280, '#2ca02c'),
    ('Rootkit Beaconing',     85.7,    95, '#8c564b'),
    ('Data Exfiltration',     82.4,   470, '#17becf'),
]

# ═══════════════════════════════════════════════════════════════════════════════
# FIGURE LAYOUT
# ═══════════════════════════════════════════════════════════════════════════════
fig, (ax1, ax2) = plt.subplots(
    1, 2,
    figsize=(7.16, 2.9),          # full two-column width × modest height
    gridspec_kw={'wspace': 0.38},
)

# ── Panel (a): Performance metrics vs CPU cost ────────────────────────────────
METRIC_STYLE = {
    'F1':        dict(marker='o', color='#1f77b4', zorder=4),
    'Precision': dict(marker='^', color='#d62728', zorder=4),
    'Recall':    dict(marker='s', color='#2ca02c', zorder=4),
}
METRIC_KEYS = {'F1': 'f1', 'Precision': 'prec', 'Recall': 'rec'}

# Vertical reference lines for BPF hook costs
hook_colors = {'XDP': '#aec7e8', 'TC': '#ffbb78', 'TP': '#98df8a'}
for hook, lat_us in BPF_HOOKS:
    ax1.axvline(lat_us, color=hook_colors[hook], lw=0.9,
                ls='--', alpha=0.8, zorder=1)
    ax1.text(lat_us + 0.12, 0.03, hook, fontsize=6,
             color=hook_colors[hook], va='bottom', ha='left',
             rotation=90, style='italic')

# Plot each detector × metric
det_names = list(DETECTORS.keys())
det_x     = [DETECTORS[n]['cpu_us'] for n in det_names]
x_jitter  = {'F1': 0, 'Precision': 0, 'Recall': 0}   # no jitter; use offsets in labels

for metric, style in METRIC_STYLE.items():
    key = METRIC_KEYS[metric]
    ys  = [DETECTORS[n][key] for n in det_names]
    ax1.scatter(det_x, ys, s=36, label=metric, clip_on=False, **style)

# Detector name labels — manually offset to avoid overlap
# (xy = F1 score position; xytext = label anchor)
LABEL_OFFSET = {
    'Rule-based':       (( 0.4,  0.957), ( 0.9,  0.88), 'left'),
    'Isolation Forest': ((14.2,  0.057), (10.5,  0.18), 'left'),
    'OC-SVM':           ((17.5,  0.024), (15.8,  0.13), 'left'),
    'Ensemble':         ((18.3,  0.054), (15.0,  0.32), 'left'),
}
for name in det_names:
    xy, xytext, ha = LABEL_OFFSET[name]
    ax1.annotate(
        name, xy=xy, xytext=xytext,
        fontsize=6.5, ha=ha, va='center',
        arrowprops=dict(arrowstyle='-', color='#888888', lw=0.5,
                        shrinkA=0, shrinkB=2),
    )

ax1.set_xlabel('Userspace Detection Cost per Event (µs)')
ax1.set_ylabel('Score')
ax1.set_xlim(-0.5, 21)
ax1.set_ylim(0, 1.08)
ax1.yaxis.set_minor_locator(plt.MultipleLocator(0.1))
ax1.set_title('(a) Detection Metrics vs. CPU Overhead')

# Kernel-space overhead annotation box
bpf_text = ('Kernel-space (fixed):\n'
            f'XDP  {BPF_HOOKS[0][1]*1000:.0f} ns/call\n'
            f'TC   {BPF_HOOKS[1][1]*1000:.0f} ns/call\n'
            f'TP   {BPF_HOOKS[2][1]*1000:.0f} ns/call')
ax1.text(0.97, 0.98, bpf_text,
         transform=ax1.transAxes, fontsize=6,
         va='top', ha='right', family='monospace',
         bbox=dict(boxstyle='round,pad=0.35', fc='#f7f7f7',
                   ec='#cccccc', lw=0.6))

legend1 = ax1.legend(title='Metric', loc='center left',
                     frameon=True, framealpha=0.9,
                     edgecolor='#cccccc', handletextpad=0.4,
                     borderpad=0.5, labelspacing=0.3)
legend1.get_frame().set_linewidth(0.6)

ax1.grid(True, axis='y', which='major')
ax1.set_axisbelow(True)

# ── Panel (b): Per-class recall vs RB utilisation ────────────────────────────
# Bubble size encodes event rate
MIN_RATE = min(ev for _, _, ev, _ in ATTACK_CATEGORIES)
MAX_RATE = max(ev for _, _, ev, _ in ATTACK_CATEGORIES)

def bubble_size(ev_rate):
    """Map event rate to marker area (pt²); range 40–220."""
    t = (ev_rate - MIN_RATE) / (MAX_RATE - MIN_RATE + 1e-9)
    return 40 + t * 180

# Label positions: (xytext_x, xytext_y, ha)
# Cryptomining C2 (x≈0.0017) and Rootkit Beaconing (x≈0.0015) are both near
# the y-axis — labels must go to the RIGHT (positive x offset), not left.
# Vertical spacing chosen to avoid overlap with Privilege Escalation (y=87.5).
LABEL_POS = {
    'Port Scan':            (rb_util(1480) - 0.004, 100.5,  'right'),
    'SYN Flood':            (rb_util(1510) + 0.001,  98.3,  'left'),
    'Cryptomining C2':      (0.0105,                 95.5,  'left'),
    'Privilege Escalation': (rb_util(280)  + 0.003,  89.2,  'left'),
    'Rootkit Beaconing':    (0.0105,                 83.5,  'left'),
    'Data Exfiltration':    (rb_util(470)  + 0.002,  86.5,  'left'),
}

for name, recall, ev_rate, color in ATTACK_CATEGORIES:
    x = rb_util(ev_rate)
    y = recall
    ax2.scatter(x, y,
                s=bubble_size(ev_rate),
                color=color, alpha=0.85,
                edgecolors='white', linewidths=0.5,
                zorder=4)
    xt, yt, ha = LABEL_POS.get(name, (x + 0.0005, y + 0.3, 'left'))
    ax2.annotate(
        name, xy=(x, y),
        xytext=(xt, yt),
        fontsize=6.5, ha=ha, va='center',
        arrowprops=dict(arrowstyle='-', color='#888888', lw=0.5,
                        shrinkA=0, shrinkB=3),
    )

ax2.set_xlabel('Ring Buffer Utilisation (%)\n'
               r'[$\mathit{ev\_rate} \times 128\,\mathrm{B}$'
               r'$\;/\;(16\,\mathrm{MB} \times 50\,\mathrm{Hz}) \times 100$]',
               labelpad=3)
ax2.set_ylabel('Per-Class Recall (%)')
ax2.set_xlim(-0.0002, 0.028)
ax2.set_ylim(78, 102)
ax2.yaxis.set_minor_locator(plt.MultipleLocator(2))
ax2.xaxis.set_major_formatter(
    matplotlib.ticker.FuncFormatter(lambda v, _: f'{v:.3f}')
)
ax2.set_title('(b) Per-Class Recall vs. Ring Buffer Utilisation')
ax2.grid(True, axis='both', which='major')
ax2.set_axisbelow(True)

# Ring buffer capacity annotation
rb_text = (f'RB capacity: 131,072 records\n'
           f'Peak util. (synflood): {rb_util(1510):.4f}%')
ax2.text(0.97, 0.04, rb_text,
         transform=ax2.transAxes, fontsize=6,
         va='bottom', ha='right', family='monospace',
         bbox=dict(boxstyle='round,pad=0.35', fc='#f7f7f7',
                   ec='#cccccc', lw=0.6))

# Bubble size legend — use small fixed marker sizes (4/6/9 pt) that convey
# small/medium/large proportions without overwhelming the legend box.
rate_legend_vals  = [100, 500, 1500]
legend_markersizes = [3, 5, 7]          # pt; purely representational
size_handles = [
    Line2D([0], [0], marker='o', color='w',
           markerfacecolor='#555555', markeredgecolor='#555555',
           markeredgewidth=0.4,
           markersize=ms,
           label=f'{r} ev/s')
    for r, ms in zip(rate_legend_vals, legend_markersizes)
]
legend2 = ax2.legend(handles=size_handles, title='Event rate',
                     loc='upper left',
                     bbox_to_anchor=(0.0, 1.0),
                     frameon=True, framealpha=0.95,
                     edgecolor='#cccccc',
                     handletextpad=0.3,
                     borderpad=0.4,
                     labelspacing=0.5,
                     handlelength=1.0)
legend2.get_frame().set_linewidth(0.5)

# ── Save ──────────────────────────────────────────────────────────────────────
out_path = os.path.join(OUT_DIR, 'fig_f1_cpu_ringbuf_combined.png')
fig.savefig(out_path, dpi=600, bbox_inches='tight', facecolor='white')
plt.close(fig)
print(f"Saved → {out_path}")
