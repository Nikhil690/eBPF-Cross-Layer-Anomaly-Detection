#!/usr/bin/env python3
"""
fig_architecture.py — System architecture diagram for eBPF-CLA.

Produces: results/figures/fig_architecture.png

Layout (top → bottom):
  1. Network interface / packet ingress+egress
  2. Kernel space  — XDP | TC | Tracepoint eBPF programs + BPF maps
  3. Boundary      — ring_events (RINGBUF) + corr_window_map sweeper
  4. Userspace     — Go processing pipeline → alert / CSV

Usage:
    python3 results/analysis/fig_architecture.py
"""

import os
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch
from matplotlib.lines import Line2D

# ── Style ─────────────────────────────────────────────────────────────────────
plt.rcParams.update({
    'font.family':      'serif',
    'font.serif':       ['Times New Roman', 'DejaVu Serif'],
    'font.size':        9,
    'figure.dpi':       150,
    'savefig.dpi':      300,
    'savefig.bbox':     'tight',
    'savefig.pad_inches': 0.08,
})

# ── Colour palette ────────────────────────────────────────────────────────────
C = {
    'net_bg':    '#ECEFF1',   # network interface band
    'net_box':   '#546E7A',   # packet box
    'ker_bg':    '#E3F2FD',   # kernel space background
    'xdp':       '#1565C0',   # XDP program
    'tc':        '#0277BD',   # TC program
    'tp':        '#00695C',   # Tracepoint program
    'map':       '#4527A0',   # BPF map
    'rb':        '#E65100',   # ring buffer
    'boundary':  '#B0BEC5',   # dashed boundary line
    'usr_bg':    '#E8F5E9',   # userspace background
    'go_box':    '#2E7D32',   # Go processing box
    'alert':     '#B71C1C',   # alert output
    'csv':       '#1B5E20',   # CSV output
    'cookie':    '#F57F17',   # socket_cookie annotation
    'white':     '#FFFFFF',
    'text_dark': '#212121',
    'text_light':'#FFFFFF',
    'arrow':     '#37474F',
    'arrow_map': '#6A1B9A',
}

# ── Helpers ───────────────────────────────────────────────────────────────────
def box(ax, x, y, w, h, fc, ec='#37474F', lw=1.0, radius=0.18, alpha=1.0, zorder=3):
    p = FancyBboxPatch((x, y), w, h,
                       boxstyle=f'round,pad=0,rounding_size={radius}',
                       facecolor=fc, edgecolor=ec, linewidth=lw,
                       alpha=alpha, zorder=zorder)
    ax.add_patch(p)
    return p

def label(ax, x, y, text, color=C['text_dark'], fs=8.5, fw='normal',
          ha='center', va='center', zorder=5, style='normal'):
    ax.text(x, y, text, color=color, fontsize=fs, fontweight=fw,
            ha=ha, va=va, zorder=zorder, style=style,
            multialignment='center')

def arrow(ax, x0, y0, x1, y1, color=C['arrow'], lw=1.3,
          style='->', mutation=10, zorder=4, ls='solid'):
    ax.annotate('', xy=(x1, y1), xytext=(x0, y0),
                arrowprops=dict(arrowstyle=f'->', color=color,
                                lw=lw, mutation_scale=mutation,
                                linestyle=ls),
                zorder=zorder)

def section_label(ax, x, y, text, color, fs=7.5):
    ax.text(x, y, text, color=color, fontsize=fs, fontweight='bold',
            ha='left', va='top', zorder=6,
            bbox=dict(fc=color, ec='none', alpha=0.15, pad=2))

# ═══════════════════════════════════════════════════════════════════════════════
# CANVAS
# ═══════════════════════════════════════════════════════════════════════════════
fig, ax = plt.subplots(figsize=(13, 9))
ax.set_xlim(0, 13)
ax.set_ylim(0, 9)
ax.axis('off')

# ── Title ─────────────────────────────────────────────────────────────────────
ax.text(6.5, 8.82, 'eBPF-CLA: Cross-Layer Anomaly Detection — System Architecture',
        ha='center', va='center', fontsize=11, fontweight='bold', color=C['text_dark'])

# ═══════════════════════════════════════════════════════════════════════════════
# ZONE 1 — Network Interface
# ═══════════════════════════════════════════════════════════════════════════════
box(ax, 0.2, 7.85, 12.6, 0.72, fc=C['net_bg'], ec='#90A4AE', lw=0.8,
    radius=0.25, zorder=1)
ax.text(0.55, 8.58, 'Network Interface (ens3)', fontsize=8, fontweight='bold',
        color='#37474F', va='top')

# Ingress / Egress packet boxes
box(ax, 0.6,  7.97, 2.5, 0.44, fc=C['net_box'], ec='none', radius=0.12)
label(ax, 1.85, 8.19, 'Ingress Packets\n(src→dst)', C['text_light'], fs=7.5, fw='bold')

box(ax, 4.0,  7.97, 2.5, 0.44, fc=C['net_box'], ec='none', radius=0.12)
label(ax, 5.25, 8.19, 'Egress Packets\n(dst→src)', C['text_light'], fs=7.5, fw='bold')

box(ax, 9.7,  7.97, 2.8, 0.44, fc=C['net_box'], ec='none', radius=0.12)
label(ax, 11.1, 8.19, 'connect() Syscalls\n(process layer)', C['text_light'], fs=7.5, fw='bold')

# ═══════════════════════════════════════════════════════════════════════════════
# ZONE 2 — Kernel Space background
# ═══════════════════════════════════════════════════════════════════════════════
box(ax, 0.2, 3.95, 12.6, 3.82, fc=C['ker_bg'], ec='#90CAF9', lw=1.2,
    radius=0.3, zorder=1)
section_label(ax, 0.38, 7.72, '  KERNEL SPACE  ', '#1565C0', fs=7.5)

# ── XDP Program ───────────────────────────────────────────────────────────────
box(ax, 0.45, 6.55, 2.75, 1.05, fc=C['xdp'], ec='none', radius=0.18)
label(ax, 1.825, 7.22, 'XDP Hook', C['text_light'], fs=8.5, fw='bold')
label(ax, 1.825, 6.97, 'xdp_flow_monitor', C['text_light'], fs=7, style='italic')
label(ax, 1.825, 6.73, '@ ingress', C['text_light'], fs=7)

# ── TC Program ────────────────────────────────────────────────────────────────
box(ax, 4.0, 6.55, 2.75, 1.05, fc=C['tc'], ec='none', radius=0.18)
label(ax, 5.375, 7.22, 'TC Hook (cls_bpf)', C['text_light'], fs=8.5, fw='bold')
label(ax, 5.375, 6.97, 'tc_correlate', C['text_light'], fs=7, style='italic')
label(ax, 5.375, 6.73, '@ egress', C['text_light'], fs=7)

# ── Tracepoint Program ────────────────────────────────────────────────────────
box(ax, 9.8, 6.55, 2.75, 1.05, fc=C['tp'], ec='none', radius=0.18)
label(ax, 11.175, 7.22, 'Tracepoint', C['text_light'], fs=8.5, fw='bold')
label(ax, 11.175, 6.97, 'trace_connect', C['text_light'], fs=7, style='italic')
label(ax, 11.175, 6.73, 'sys_enter_connect', C['text_light'], fs=7)

# ── BPF Maps ──────────────────────────────────────────────────────────────────
# flow_stats_map (shared XDP → TC)
box(ax, 0.45, 4.72, 2.75, 1.12, fc=C['map'], ec='none', radius=0.18)
label(ax, 1.825, 5.42, 'flow_stats_map', C['text_light'], fs=8, fw='bold')
label(ax, 1.825, 5.18, 'LRU_HASH  65,536 entries', C['text_light'], fs=6.5)
label(ax, 1.825, 4.97, 'key: 5-tuple (IP+port+proto)', C['text_light'], fs=6.5)
label(ax, 1.825, 4.78, 'Shared: XDP → TC', C['#FFD54F' if False else 'white'],
      fs=6.5, style='italic')

# proc_state_map (TP)
box(ax, 9.8, 4.72, 2.75, 1.12, fc=C['map'], ec='none', radius=0.18)
label(ax, 11.175, 5.42, 'proc_state_map', C['text_light'], fs=8, fw='bold')
label(ax, 11.175, 5.18, 'HASH  4,096 entries', C['text_light'], fs=6.5)
label(ax, 11.175, 4.97, 'key: PID (u32)', C['text_light'], fs=6.5)
label(ax, 11.175, 4.78, 'Owned: Tracepoint', C['text_light'], fs=6.5, style='italic')

# corr_window_map (centre — TC writes, TP updates)
box(ax, 4.45, 4.72, 3.15, 1.12, fc=C['map'], ec='none', radius=0.18)
label(ax, 6.025, 5.42, 'corr_window_map', C['text_light'], fs=8, fw='bold')
label(ax, 6.025, 5.18, 'LRU_HASH  65,536 entries', C['text_light'], fs=6.5)
label(ax, 6.025, 4.97, 'key: socket_cookie (u64)', C['text_light'], fs=6.5)
label(ax, 6.025, 4.78, 'Shared: TC ← TP  |  read by sweeper', C['text_light'],
      fs=6.5, style='italic')

# ring_events (rightmost of centre group, feeds userspace)
box(ax, 7.7, 4.72, 2.2, 1.12, fc=C['rb'], ec='none', radius=0.18)
label(ax, 8.8, 5.42, 'ring_events', C['text_light'], fs=8, fw='bold')
label(ax, 8.8, 5.18, 'RINGBUF  16 MB', C['text_light'], fs=6.5)
label(ax, 8.8, 4.97, '≈131,072 records', C['text_light'], fs=6.5)
label(ax, 8.8, 4.78, 'Written by TC / TP', C['text_light'], fs=6.5, style='italic')

# socket_cookie callout
ax.text(3.42, 6.26, 'socket_cookie\n(join key)',
        ha='center', va='center', fontsize=6.5, color=C['cookie'],
        fontweight='bold', style='italic',
        bbox=dict(fc='#FFF8E1', ec=C['cookie'], lw=0.8, pad=2.5,
                  boxstyle='round,pad=0.25'))

# ═══════════════════════════════════════════════════════════════════════════════
# ZONE 3 — Userspace background
# ═══════════════════════════════════════════════════════════════════════════════
box(ax, 0.2, 0.15, 12.6, 3.72, fc=C['usr_bg'], ec='#A5D6A7', lw=1.2,
    radius=0.3, zorder=1)
section_label(ax, 0.38, 3.82, '  USERSPACE (Go)  ', '#2E7D32', fs=7.5)

# ── Go processing boxes ───────────────────────────────────────────────────────
# Ring buffer reader
box(ax, 0.45, 2.52, 2.2, 0.82, fc=C['go_box'], ec='none', radius=0.15)
label(ax, 1.55, 2.98, 'Ring Buffer\nReader', C['text_light'], fs=7.5, fw='bold')
label(ax, 1.55, 2.62, 'goroutine', C['text_light'], fs=6.5, style='italic')

# Map sweeper
box(ax, 0.45, 1.55, 2.2, 0.82, fc='#558B2F', ec='none', radius=0.15)
label(ax, 1.55, 2.01, 'Map Sweeper\n(20 ms tick)', C['text_light'], fs=7.5, fw='bold')
label(ax, 1.55, 1.65, 'goroutine', C['text_light'], fs=6.5, style='italic')

# Parse
box(ax, 3.05, 2.05, 1.85, 0.82, fc=C['go_box'], ec='none', radius=0.15)
label(ax, 3.975, 2.51, 'ParseCorr\nRecord', C['text_light'], fs=7.5, fw='bold')
label(ax, 3.975, 2.15, 'binary.Read', C['text_light'], fs=6.5, style='italic')

# Feature extraction
box(ax, 5.3, 2.05, 1.95, 0.82, fc=C['go_box'], ec='none', radius=0.15)
label(ax, 6.275, 2.51, 'Extract\nFeatures', C['text_light'], fs=7.5, fw='bold')
label(ax, 6.275, 2.15, '9-dim vector', C['text_light'], fs=6.5, style='italic')

# Welford / OnlineStats
box(ax, 7.65, 2.05, 2.1, 0.82, fc=C['go_box'], ec='none', radius=0.15)
label(ax, 8.7, 2.51, 'OnlineStats\n(Welford)', C['text_light'], fs=7.5, fw='bold')
label(ax, 8.7, 2.15, 'mean + variance', C['text_light'], fs=6.5, style='italic')

# AnomalyScore
box(ax, 10.15, 2.05, 2.1, 0.82, fc=C['go_box'], ec='none', radius=0.15)
label(ax, 11.2, 2.51, 'AnomalyScore', C['text_light'], fs=7.5, fw='bold')
label(ax, 11.2, 2.15, 'Euclidean z-score', C['text_light'], fs=6.5, style='italic')

# Warmup guard annotation
ax.text(11.2, 1.83, 'warmup guard n < 50',
        ha='center', fontsize=6, color='#558B2F', style='italic')

# Threshold annotation
ax.text(11.2, 3.0, 'threshold = 4.0',
        ha='center', fontsize=6.5, color=C['alert'], fontweight='bold',
        bbox=dict(fc='#FFEBEE', ec=C['alert'], lw=0.7, pad=2,
                  boxstyle='round,pad=0.2'))

# Outputs
box(ax, 9.7, 0.65, 1.55, 0.66, fc=C['alert'], ec='none', radius=0.15)
label(ax, 10.475, 0.99, '[ALERT]', C['text_light'], fs=8, fw='bold')
label(ax, 10.475, 0.75, 'log.Printf', C['text_light'], fs=6.5, style='italic')

box(ax, 11.5, 0.65, 1.1, 0.66, fc=C['csv'], ec='none', radius=0.15)
label(ax, 12.05, 0.99, 'CSV', C['text_light'], fs=8, fw='bold')
label(ax, 12.05, 0.75, '--csv flag', C['text_light'], fs=6.5, style='italic')

# Feature list annotation
ax.text(6.3, 1.45,
        'Features: pkt_count · byte_count · syn_count · rst_count · syn_ratio'
        ' · duration · pkt_rate · layer_coverage · connect_rate',
        ha='center', va='center', fontsize=6.5, color='#1B5E20', style='italic',
        bbox=dict(fc='#F1F8E9', ec='#A5D6A7', lw=0.6, pad=3,
                  boxstyle='round,pad=0.3'))

# ═══════════════════════════════════════════════════════════════════════════════
# ARROWS
# ═══════════════════════════════════════════════════════════════════════════════

# Network → eBPF programs (ingress down to XDP)
arrow(ax, 1.85, 7.97, 1.85, 7.60, color=C['net_box'])
# Egress → TC
arrow(ax, 5.25, 7.97, 5.375, 7.60, color=C['net_box'])
# connect() → TP
arrow(ax, 11.1, 7.97, 11.175, 7.60, color=C['net_box'])

# XDP → flow_stats_map
arrow(ax, 1.825, 6.55, 1.825, 5.84, color=C['xdp'])

# flow_stats_map → TC (reverse 5-tuple lookup)
arrow(ax, 3.2, 5.28, 4.45, 5.28, color=C['arrow_map'])
ax.text(3.82, 5.42, 'reverse\n5-tuple lookup', ha='center', va='bottom',
        fontsize=6, color=C['arrow_map'], style='italic')

# socket_cookie callout ↔ TC
ax.annotate('', xy=(4.45, 6.26), xytext=(3.88, 6.26),
            arrowprops=dict(arrowstyle='<->', color=C['cookie'], lw=1.0,
                            mutation_scale=8))

# TC → corr_window_map
arrow(ax, 5.375, 6.55, 5.825, 5.84, color=C['tc'])
ax.text(5.45, 6.18, 'upsert\ncorr record', ha='left', va='center',
        fontsize=6, color=C['tc'], style='italic')

# TC → ring_events (flush when age > 5 ms)
arrow(ax, 6.3, 6.55, 8.35, 5.84, color=C['rb'])
ax.text(7.55, 6.38, 'flush\n(age > 5 ms)', ha='center', va='center',
        fontsize=6, color=C['rb'], style='italic')

# TP → proc_state_map
arrow(ax, 11.175, 6.55, 11.175, 5.84, color=C['tp'])

# proc_state_map → corr_window_map (merge proc stats)
arrow(ax, 9.8, 5.28, 7.6, 5.28, color=C['arrow_map'])
ax.text(8.7, 5.42, 'merge proc\nstats', ha='center', va='bottom',
        fontsize=6, color=C['arrow_map'], style='italic')

# ring_events → Ring Buffer Reader (down across boundary)
arrow(ax, 8.8, 4.72, 8.8, 3.87, color=C['rb'], lw=1.6)
ax.text(9.05, 4.25, 'ring buffer\nread', ha='left', va='center',
        fontsize=6.5, color=C['rb'], style='italic')
# then left to parse
arrow(ax, 8.8, 3.87, 4.9, 3.42, color=C['rb'])
arrow(ax, 4.9, 3.42, 3.975, 2.87, color=C['rb'])

# corr_window_map → Map Sweeper (dashed, 20 ms poll)
ax.annotate('', xy=(1.55, 2.37), xytext=(4.45, 4.85),
            arrowprops=dict(arrowstyle='->', color='#558B2F', lw=1.3,
                            linestyle='dashed', mutation_scale=10))
ax.text(2.5, 3.82, '20 ms\nmap poll', ha='center', va='center',
        fontsize=6.5, color='#558B2F', style='italic')

# Map Sweeper → Parse
arrow(ax, 2.65, 1.96, 3.05, 2.30, color='#558B2F')

# Processing pipeline arrows
arrow(ax, 4.9,  2.46, 5.3,  2.46, color=C['go_box'])
arrow(ax, 7.25, 2.46, 7.65, 2.46, color=C['go_box'])
arrow(ax, 9.75, 2.46, 10.15, 2.46, color=C['go_box'])

# AnomalyScore → ALERT / CSV (score > threshold)
arrow(ax, 11.2, 2.05, 10.475, 1.31, color=C['alert'])
arrow(ax, 11.2, 2.05, 12.05,  1.31, color=C['csv'])

# Ring Buffer Reader → Parse (short hop)
arrow(ax, 2.65, 2.93, 3.05, 2.63, color=C['go_box'])

# ═══════════════════════════════════════════════════════════════════════════════
# LAYER COVERAGE BIT LEGEND
# ═══════════════════════════════════════════════════════════════════════════════
legend_x, legend_y = 0.45, 0.95
ax.text(legend_x, legend_y + 0.38, 'Layer coverage bits:', fontsize=7,
        fontweight='bold', color=C['text_dark'], va='center')
bits = [('0x01 LAYER_XDP',     C['xdp']),
        ('0x02 LAYER_TC',      C['tc']),
        ('0x04 LAYER_SYSCALL', C['tp']),
        ('0x08 LAYER_UPROBE',  '#9E9E9E')]
for i, (txt, c) in enumerate(bits):
    bx = legend_x + i * 2.35
    box(ax, bx, legend_y - 0.08, 0.28, 0.28, fc=c, ec='none', radius=0.06, zorder=5)
    ax.text(bx + 0.36, legend_y + 0.06, txt, fontsize=6.5, va='center',
            color=c if c != '#9E9E9E' else '#757575',
            style='italic' if c == '#9E9E9E' else 'normal')

# "reserved" note for uprobe
ax.text(legend_x + 4 * 2.35 - 1.5, legend_y - 0.12, '(reserved — not yet implemented)',
        fontsize=6, color='#9E9E9E', style='italic')

# ── Kernel / Userspace boundary dashed line ───────────────────────────────────
ax.plot([0.2, 12.8], [3.95, 3.95], color=C['boundary'], lw=1.0,
        ls='--', zorder=2)

# ── Save ──────────────────────────────────────────────────────────────────────
OUT_DIR = os.path.join(os.path.dirname(__file__), '..', 'figures')
os.makedirs(OUT_DIR, exist_ok=True)
out_path = os.path.join(OUT_DIR, 'fig_architecture.png')
fig.savefig(out_path, dpi=300, bbox_inches='tight', facecolor='white')
plt.close(fig)
print(f"Saved → {out_path}")
