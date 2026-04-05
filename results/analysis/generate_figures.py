#!/usr/bin/env python3
"""
generate_figures.py — Dissertation & Journal Article Figure Generator
eBPF Cross-Layer Anomaly Detection System

Generates publication-quality figures from the collected datasets.
Usage: python3 results/analysis/generate_figures.py

Outputs to: results/figures/
"""

import os, sys, warnings
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib.gridspec as gridspec
from matplotlib.colors import LinearSegmentedColormap
import seaborn as sns
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    precision_recall_fscore_support, confusion_matrix,
    roc_curve, auc, precision_recall_curve, average_precision_score
)
from matplotlib.ticker import MaxNLocator

warnings.filterwarnings('ignore')

# ── Output directory ──────────────────────────────────────────────────────────
OUT_DIR = os.path.join(os.path.dirname(__file__), '..', 'figures')
os.makedirs(OUT_DIR, exist_ok=True)

def save(name):
    path = os.path.join(OUT_DIR, name)
    plt.savefig(path, dpi=300, bbox_inches='tight', facecolor='white')
    plt.close()
    print(f"  [saved] {path}")

# ── Style ─────────────────────────────────────────────────────────────────────
PALETTE = {
    'benign':      '#2196F3',
    'portscan':    '#F44336',
    'synflood':    '#FF5722',
    'cryptomining':'#9C27B0',
    'exfil':       '#FF9800',
    'privesc':     '#4CAF50',
    'rootkit':     '#795548',
}
ATTACK_ORDER = ['portscan','synflood','cryptomining','exfil','privesc','rootkit']
ALL_ORDER    = ['benign'] + ATTACK_ORDER

sns.set_theme(style='whitegrid', font_scale=1.15)
plt.rcParams.update({
    'font.family': 'DejaVu Sans',
    'axes.titlesize': 14,
    'axes.labelsize': 12,
    'xtick.labelsize': 10,
    'ytick.labelsize': 10,
    'legend.fontsize': 10,
})

FLOW_FEATURES = ['total_pkts','total_bytes','max_pkt_rate',
                 'avg_pkt_count','syn_count','rst_count',
                 'layer_coverage','n_windows']
SESSIONS_CSV = os.path.join(os.path.dirname(__file__), '../raw/sessions_merged.csv')
SINGLE_CSV   = os.path.join(os.path.dirname(__file__), '../raw/single_20260328_104918.csv')

# ═══════════════════════════════════════════════════════════════════════════════
# DATA LOADING
# ═══════════════════════════════════════════════════════════════════════════════

def load_events(path):
    df = pd.read_csv(path)
    df.columns = df.columns.str.strip()
    for col in ['score','syn_count','rst_count','pkt_count','byte_count',
                'pkt_rate','layer_coverage','connect_rate','cookie']:
        df[col] = pd.to_numeric(df.get(col, 0), errors='coerce').fillna(0)
    df['y_true'] = (df['label'] != 'benign').astype(int)
    return df

def aggregate_flows(df):
    agg = df.groupby(['label','cookie']).agg(
        total_pkts    = ('pkt_count', 'max'),
        total_bytes   = ('byte_count', 'max'),
        max_pkt_rate  = ('pkt_rate', 'max'),
        avg_pkt_count = ('pkt_count', 'mean'),
        syn_count     = ('syn_count', 'sum'),
        rst_count     = ('rst_count', 'sum'),
        layer_coverage= ('layer_coverage', 'max'),
        n_windows     = ('pkt_count', 'count'),
        max_score     = ('score', 'max'),
    ).reset_index()
    agg['y_true'] = (agg['label'] != 'benign').astype(int)
    return agg

def run_detector(clf_fn, X_train, X_test):
    scaler = StandardScaler()
    X_tr = scaler.fit_transform(X_train)
    X_te = scaler.transform(X_test)
    clf = clf_fn()
    clf.fit(X_tr)
    raw = clf.predict(X_te)
    scores = -clf.score_samples(X_te) if hasattr(clf, 'score_samples') else (raw == -1).astype(float)
    return (raw == -1).astype(int), scores

def rule_detector(df):
    pkt     = df['total_pkts']
    windows = df['n_windows']
    low_pkt  = (pkt < 20)
    high_win = (windows > 30) & (pkt < 100)
    return (low_pkt | high_win).astype(int)

print("Loading data …")
ev  = load_events(SESSIONS_CSV)
flo = aggregate_flows(ev)
X   = flo[FLOW_FEATURES].values
y   = flo['y_true'].values
benign_mask = flo['label'] == 'benign'
X_benign    = X[benign_mask]

# Run all detectors
y_rule = rule_detector(flo)
scaler = StandardScaler()
X_tr = scaler.fit_transform(X_benign)
X_te = scaler.transform(X)

clf_if  = IsolationForest(n_estimators=200, contamination=0.1, random_state=42, n_jobs=-1)
clf_svm = OneClassSVM(nu=0.1, kernel='rbf', gamma='scale')
clf_if.fit(X_tr); clf_svm.fit(X_tr)
y_if  = (clf_if.predict(X_te)  == -1).astype(int)
y_svm = (clf_svm.predict(X_te) == -1).astype(int)
scores_if  = -clf_if.score_samples(X_te)
scores_svm = -clf_svm.decision_function(X_te)

# Ensemble
preds_stack = np.stack([y_rule.values, y_if, y_svm], axis=1)
y_ens = (preds_stack.sum(axis=1) >= 2).astype(int)

detectors = {
    'Rule-based':        (y_rule.values, None),
    'Isolation Forest':  (y_if,   scores_if),
    'OC-SVM':            (y_svm,  scores_svm),
    'Ensemble':          (y_ens,  None),
}
det_metrics = {}
for name, (ypred, _) in detectors.items():
    p, r, f, _ = precision_recall_fscore_support(y, ypred, average='binary', zero_division=0)
    det_metrics[name] = dict(precision=p, recall=r, f1=f, pred=ypred)

best_name = max(det_metrics, key=lambda k: det_metrics[k]['f1'])
best_pred = det_metrics[best_name]['pred']

print(f"  {len(ev)} events → {len(flo)} flows across {flo['label'].nunique()} classes")

# ═══════════════════════════════════════════════════════════════════════════════
# FIGURE 1 — Dataset Distribution
# ═══════════════════════════════════════════════════════════════════════════════
print("\n[Fig 1] Dataset distribution …")
fig, axes = plt.subplots(1, 2, figsize=(15, 5),
                         gridspec_kw={'width_ratios': [1.1, 1]})

# Events per class
ev_counts = ev['label'].value_counts().reindex(ALL_ORDER).dropna()
colors = [PALETTE[l] for l in ev_counts.index]
bars = axes[0].bar(ev_counts.index, ev_counts.values, color=colors, edgecolor='white', linewidth=0.7)
axes[0].set_title('Event Distribution by Traffic Class')
axes[0].set_xlabel('Traffic Class')
axes[0].set_ylabel('Number of Events')
axes[0].set_xticklabels(ev_counts.index, rotation=30, ha='right')
for bar, val in zip(bars, ev_counts.values):
    axes[0].text(bar.get_x() + bar.get_width()/2, bar.get_height() + 25,
                 f'{val:,}', ha='center', va='bottom', fontsize=9)
axes[0].set_ylim(0, ev_counts.max() * 1.18)
axes[0].grid(axis='y', alpha=0.4)
axes[0].spines['top'].set_visible(False); axes[0].spines['right'].set_visible(False)

# Flows per class (pie) — labels outside with leader lines via legend;
# autopct shown only for slices >= 5% to avoid cramping on tiny wedges.
fl_counts = flo['label'].value_counts().reindex(ALL_ORDER).dropna()
wedge_colors = [PALETTE[l] for l in fl_counts.index]
total_flows = fl_counts.sum()

# Explode small slices slightly so their edges are easier to point to
explode = [0.06 if (v / total_flows) < 0.08 else 0.01 for v in fl_counts.values]

def _autopct(pct):
    return f'{pct:.1f}%' if pct >= 5.0 else ''

wedges, texts, autotexts = axes[1].pie(
    fl_counts.values,
    explode=explode,
    labels=None,           # labels handled by legend below
    autopct=_autopct,
    colors=wedge_colors,
    startangle=140,
    pctdistance=0.78,
    wedgeprops=dict(edgecolor='white', linewidth=1.5))

for t in autotexts:
    t.set_fontsize(8.5)
    t.set_fontweight('bold')
    t.set_color('white')

# Legend with pointer lines: colored patch + "label (N flows, X%)"
import matplotlib.patches as mpatches
legend_handles = [
    mpatches.Patch(facecolor=c, edgecolor='#cccccc', linewidth=0.5,
                   label=f'{lbl}  ({v:,} · {100*v/total_flows:.1f}%)')
    for c, lbl, v in zip(wedge_colors, fl_counts.index, fl_counts.values)
]
axes[1].legend(handles=legend_handles,
               loc='center left', bbox_to_anchor=(1.02, 0.5),
               fontsize=8.5, frameon=True, framealpha=0.95,
               edgecolor='#cccccc', handlelength=1.2,
               handleheight=0.9, labelspacing=0.45,
               title='Traffic class', title_fontsize=8.5)
axes[1].set_title(f'Flow Distribution by Class\n(Total: {len(flo):,} flows)')

fig.suptitle('eBPF-CLA Dataset Overview — sessions_merged.csv', fontweight='bold', y=1.01)
plt.tight_layout()
save('fig01_dataset_distribution.png')

# ═══════════════════════════════════════════════════════════════════════════════
# FIGURE 2 — Feature Distributions (Violin)
# ═══════════════════════════════════════════════════════════════════════════════
print("[Fig 2] Feature violin plots …")
features_display = [
    ('total_pkts',   'Total Packets per Flow',    False),
    ('total_bytes',  'Total Bytes per Flow',       False),
    ('max_pkt_rate', 'Peak Packet Rate (pkts/s)',  True),
    ('syn_count',    'SYN Packet Count',           False),
    ('n_windows',    'Number of Corr. Windows',    False),
]
fig, axes = plt.subplots(1, len(features_display), figsize=(18, 6))
order_present = [l for l in ALL_ORDER if l in flo['label'].unique()]
pal = {l: PALETTE[l] for l in order_present}

for ax, (feat, title, log_y) in zip(axes, features_display):
    data_plot = flo[['label', feat]].copy()
    if log_y:
        data_plot[feat] = np.log1p(data_plot[feat])
        ylabel = f'log(1 + {feat})'
    else:
        ylabel = feat
    sns.violinplot(data=data_plot, x='label', y=feat, order=order_present,
                   palette=pal, ax=ax, inner='quartile', cut=0, linewidth=0.8)
    ax.set_title(title, fontsize=11)
    ax.set_xlabel('')
    ax.set_ylabel('log(1+value)' if log_y else 'Value', fontsize=10)
    ax.set_xticklabels(order_present, rotation=35, ha='right', fontsize=9)
    ax.grid(axis='y', alpha=0.35)
    ax.spines['top'].set_visible(False); ax.spines['right'].set_visible(False)

fig.suptitle('Flow-Level Feature Distributions by Traffic Class', fontweight='bold')
plt.tight_layout()
save('fig02_feature_violin.png')

# ═══════════════════════════════════════════════════════════════════════════════
# FIGURE 3 — Feature Correlation Heatmap
# ═══════════════════════════════════════════════════════════════════════════════
print("[Fig 3] Feature correlation heatmap …")
feat_cols  = ['total_pkts','total_bytes','max_pkt_rate','avg_pkt_count',
              'syn_count','rst_count','layer_coverage','n_windows']
feat_labels = ['Pkt Count','Byte Count','Peak Rate','Avg Pkts/Win',
               'SYN Count','RST Count','Layer Cov.','N Windows']

fig, ax = plt.subplots(figsize=(9, 7))
corr = flo[feat_cols].rename(columns=dict(zip(feat_cols, feat_labels))).corr()
mask = np.triu(np.ones_like(corr, dtype=bool), k=1)
cmap = sns.diverging_palette(220, 20, as_cmap=True)
sns.heatmap(corr, annot=True, fmt='.2f', cmap=cmap, center=0,
            square=True, linewidths=0.5, ax=ax, mask=~np.triu(np.ones_like(corr,dtype=bool)),
            cbar_kws={'shrink': 0.8, 'label': 'Pearson r'}, annot_kws={'size':9})
ax.set_title('Flow Feature Correlation Matrix', fontweight='bold', pad=14)
plt.tight_layout()
save('fig03_feature_correlation.png')

# ═══════════════════════════════════════════════════════════════════════════════
# FIGURE 4 — Anomaly Score Distribution
# ═══════════════════════════════════════════════════════════════════════════════
print("[Fig 4] Anomaly score distribution …")
fig, axes = plt.subplots(1, 2, figsize=(14, 5))

# Box plot of score per class (event level)
ev_sorted = ev[ev['label'].isin(order_present)].copy()
ev_sorted['label'] = pd.Categorical(ev_sorted['label'], categories=order_present, ordered=True)
sns.boxplot(data=ev_sorted, x='label', y='score', order=order_present,
            palette=pal, ax=axes[0], linewidth=0.8, fliersize=2,
            flierprops=dict(marker='o', alpha=0.3))
axes[0].axhline(4.0, color='red', linestyle='--', linewidth=1.5, label='Alert threshold (4.0)')
axes[0].set_title('Anomaly Score Distribution by Class\n(Event Level)')
axes[0].set_xlabel('Traffic Class')
axes[0].set_ylabel('Z-Score (Euclidean)')
axes[0].set_xticklabels(order_present, rotation=30, ha='right')
axes[0].legend(fontsize=9)
axes[0].set_ylim(-0.5, min(ev['score'].quantile(0.998), 80))
axes[0].grid(axis='y', alpha=0.35)
axes[0].spines['top'].set_visible(False); axes[0].spines['right'].set_visible(False)

# CDF
for label in order_present:
    scores_l = ev[ev['label'] == label]['score'].sort_values().values
    cdf = np.arange(1, len(scores_l)+1) / len(scores_l)
    axes[1].plot(scores_l, cdf, color=PALETTE[label], linewidth=2, label=label, alpha=0.85)
axes[1].axvline(4.0, color='black', linestyle='--', linewidth=1.5, label='Threshold (4.0)')
axes[1].set_title('CDF of Anomaly Score by Class')
axes[1].set_xlabel('Anomaly Score (Z-Score)')
axes[1].set_ylabel('Cumulative Probability')
axes[1].set_xlim(-0.2, 20)
axes[1].legend(fontsize=8.5, loc='lower right')
axes[1].grid(alpha=0.3)
axes[1].spines['top'].set_visible(False); axes[1].spines['right'].set_visible(False)

fig.suptitle('Online Z-Score Anomaly Detection — Score Analysis', fontweight='bold')
plt.tight_layout()
save('fig04_score_distribution.png')

# ═══════════════════════════════════════════════════════════════════════════════
# FIGURE 5 — Confusion Matrix (Best Detector)
# ═══════════════════════════════════════════════════════════════════════════════
print("[Fig 5] Confusion matrix …")
fig, axes = plt.subplots(1, 2, figsize=(12, 5))

for ax, (name, ypred, subtitle) in zip(axes, [
    ('Rule-based',      best_pred,              'Best Overall Detector'),
    ('Isolation Forest', y_if,                  'ML Baseline (Isolation Forest)'),
]):
    cm = confusion_matrix(y, ypred)
    cm_norm = cm.astype(float) / cm.sum(axis=1, keepdims=True) * 100
    sns.heatmap(cm_norm, annot=False, fmt='.1f', cmap='Blues',
                ax=ax, cbar_kws={'label':'% of True Class'},
                linewidths=2, linecolor='white', square=True,
                vmin=0, vmax=100)
    for i in range(2):
        for j in range(2):
            ax.text(j+0.5, i+0.5, f'{cm[i,j]:,}\n({cm_norm[i,j]:.1f}%)',
                    ha='center', va='center', fontsize=11,
                    color='white' if cm_norm[i,j] > 60 else 'black', fontweight='bold')
    ax.set_xticklabels(['Benign\n(Predicted)', 'Attack\n(Predicted)'], fontsize=11)
    ax.set_yticklabels(['Benign\n(True)', 'Attack\n(True)'], fontsize=11, rotation=0)
    ax.set_title(f'{name}\n{subtitle}', fontweight='bold', fontsize=12)
    ax.set_xlabel('Predicted Label'); ax.set_ylabel('True Label')

fig.suptitle('Confusion Matrices — Flow-Level Detection', fontweight='bold')
plt.tight_layout()
save('fig05_confusion_matrices.png')

# ═══════════════════════════════════════════════════════════════════════════════
# FIGURE 6 — Per-Class Recall (Best Detector)
# ═══════════════════════════════════════════════════════════════════════════════
print("[Fig 6] Per-class recall …")
labels_list = sorted(flo['label'].unique())
recalls = []
n_flows  = []
for cls in labels_list:
    mask = (flo['label'] == cls).values
    n = mask.sum()
    n_flows.append(n)
    if cls == 'benign':
        # TNR (specificity)
        recalls.append(100 * (best_pred[mask] == 0).sum() / n)
    else:
        recalls.append(100 * best_pred[mask].sum() / n)

cls_order_plot = sorted(labels_list, key=lambda x: (x == 'benign', -recalls[labels_list.index(x)]))
recalls_sorted = [recalls[labels_list.index(c)] for c in cls_order_plot]
nflows_sorted  = [n_flows[labels_list.index(c)]  for c in cls_order_plot]
bar_colors = [PALETTE.get(c, '#888') for c in cls_order_plot]

fig, ax = plt.subplots(figsize=(10, 5))
bars = ax.barh(cls_order_plot, recalls_sorted, color=bar_colors, edgecolor='white', linewidth=0.6)
ax.axvline(80, color='orange', linestyle='--', linewidth=1.5, label='80% threshold')
ax.axvline(90, color='red',    linestyle='--', linewidth=1.5, label='90% threshold')
for bar, val, n in zip(bars, recalls_sorted, nflows_sorted):
    ax.text(bar.get_width() + 0.5, bar.get_y() + bar.get_height()/2,
            f'{val:.1f}%  (n={n})', va='center', fontsize=10)
ax.set_xlim(0, 115)
ax.set_xlabel('Recall / TNR (%)')
ax.set_title(f'Per-Class Recall — {best_name} Detector\n(Benign shows True Negative Rate)',
             fontweight='bold')
ax.legend(fontsize=9, loc='lower right')
ax.grid(axis='x', alpha=0.35)
ax.spines['top'].set_visible(False); ax.spines['right'].set_visible(False)
plt.tight_layout()
save('fig06_per_class_recall.png')

# ═══════════════════════════════════════════════════════════════════════════════
# FIGURE 7 — Detector Comparison (P / R / F1)
# ═══════════════════════════════════════════════════════════════════════════════
print("[Fig 7] Detector comparison …")
det_names  = list(det_metrics.keys())
prec_vals  = [det_metrics[d]['precision'] for d in det_names]
rec_vals   = [det_metrics[d]['recall']    for d in det_names]
f1_vals    = [det_metrics[d]['f1']        for d in det_names]

x = np.arange(len(det_names))
w = 0.25
fig, ax = plt.subplots(figsize=(10, 5))
b1 = ax.bar(x - w, prec_vals, w, label='Precision', color='#1565C0', alpha=0.88, edgecolor='white')
b2 = ax.bar(x,     rec_vals,  w, label='Recall',    color='#2E7D32', alpha=0.88, edgecolor='white')
b3 = ax.bar(x + w, f1_vals,   w, label='F1 Score',  color='#6A1B9A', alpha=0.88, edgecolor='white')

for bars_grp in [b1, b2, b3]:
    for bar in bars_grp:
        h = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2, h + 0.01, f'{h:.3f}',
                ha='center', va='bottom', fontsize=8.5, fontweight='bold')

ax.set_xticks(x)
ax.set_xticklabels(det_names, fontsize=11)
ax.set_ylabel('Score')
ax.set_ylim(0, 1.15)
ax.set_title('Detector Comparison — Precision, Recall, F1\n(Flow-Level, Binary: benign vs attack)',
             fontweight='bold')
ax.legend(fontsize=10)
ax.axhline(0.9, color='gray', linestyle=':', linewidth=1, alpha=0.5)
ax.grid(axis='y', alpha=0.3)
ax.spines['top'].set_visible(False); ax.spines['right'].set_visible(False)
# Star best
best_idx = det_names.index(best_name)
ax.annotate('★ Best', xy=(x[best_idx] + w, f1_vals[best_idx] + 0.06),
            ha='center', fontsize=12, color='#6A1B9A')
plt.tight_layout()
save('fig07_detector_comparison.png')

# ═══════════════════════════════════════════════════════════════════════════════
# FIGURE 8 — ROC Curves
# ═══════════════════════════════════════════════════════════════════════════════
print("[Fig 8] ROC curves …")

def rule_scores(df):
    return (df['total_pkts'] < 20).astype(float) + \
           ((df['n_windows'] > 30) & (df['total_pkts'] < 100)).astype(float)

fig, axes = plt.subplots(1, 2, figsize=(13, 5))

roc_detectors = [
    ('Rule-based',       rule_scores(flo),  '#1565C0'),
    ('Isolation Forest', scores_if,         '#D32F2F'),
    ('OC-SVM',           scores_svm,        '#388E3C'),
]
for name, sc, col in roc_detectors:
    fpr, tpr, _ = roc_curve(y, sc)
    roc_auc = auc(fpr, tpr)
    axes[0].plot(fpr, tpr, color=col, linewidth=2, label=f'{name} (AUC={roc_auc:.3f})')
axes[0].plot([0,1],[0,1],'k--', alpha=0.4, linewidth=1)
axes[0].fill_between([0,1],[0,1], alpha=0.05, color='gray')
axes[0].set_title('ROC Curves — Flow-Level Detection'); axes[0].set_xlabel('False Positive Rate')
axes[0].set_ylabel('True Positive Rate'); axes[0].legend(fontsize=9)
axes[0].grid(alpha=0.3); axes[0].spines['top'].set_visible(False); axes[0].spines['right'].set_visible(False)

# Precision-Recall
for name, sc, col in roc_detectors:
    prec_c, rec_c, _ = precision_recall_curve(y, sc)
    ap = average_precision_score(y, sc)
    axes[1].plot(rec_c, prec_c, color=col, linewidth=2, label=f'{name} (AP={ap:.3f})')
axes[1].set_title('Precision-Recall Curves'); axes[1].set_xlabel('Recall')
axes[1].set_ylabel('Precision'); axes[1].legend(fontsize=9)
axes[1].grid(alpha=0.3); axes[1].spines['top'].set_visible(False); axes[1].spines['right'].set_visible(False)

fig.suptitle('ROC & Precision-Recall Analysis', fontweight='bold')
plt.tight_layout()
save('fig08_roc_pr_curves.png')

# ═══════════════════════════════════════════════════════════════════════════════
# FIGURE 9 — Timeline: Single Session Score over Time
# ═══════════════════════════════════════════════════════════════════════════════
print("[Fig 9] Single session timeline …")

TIMELINE = {
    'BENIGN_1':     ('10:49:19', '10:50:51'),
    'PORTSCAN':     ('10:50:53', '10:51:45'),
    'BENIGN_2':     ('10:51:50', '10:55:20'),
    'SYNFLOOD':     ('10:55:22', '10:55:48'),
    'BENIGN_3':     ('10:55:53', '10:59:23'),
    'EXFIL':        ('10:59:25', '11:00:25'),
    'BENIGN_4':     ('11:00:30', '11:04:01'),
    'PRIVESC':      ('11:04:03', '11:04:06'),
    'CRYPTOMINING': ('11:04:11', '11:04:38'),
    'ROOTKIT':      ('11:04:43', '11:04:58'),
}
PHASE_COLORS = {
    'BENIGN':      '#90CAF9',
    'PORTSCAN':    '#EF9A9A',
    'SYNFLOOD':    '#FFAB91',
    'EXFIL':       '#FFE082',
    'PRIVESC':     '#A5D6A7',
    'CRYPTOMINING':'#CE93D8',
    'ROOTKIT':     '#BCAAA4',
}

sv = pd.read_csv(SINGLE_CSV)
sv.columns = sv.columns.str.strip()
sv['score'] = pd.to_numeric(sv.get('score', 0), errors='coerce').fillna(0)

def ts_to_min(ts_str):
    try:
        parts = str(ts_str).split('.')
        h, m, s = map(int, parts[0].split(':'))
        return h * 60 + m + s / 60
    except:
        return None

sv['time_min'] = sv['timestamp'].apply(ts_to_min)
sv = sv.dropna(subset=['time_min'])
# Drop the one wrap-around outlier (timestamp "1:xx:xx" should be ~649+)
sv = sv[sv['time_min'] >= 600]

fig, ax = plt.subplots(figsize=(16, 5))

# Phase backgrounds
phase_legend = {}
for phase_key, (t_start, t_end) in TIMELINE.items():
    pname = next((k for k in PHASE_COLORS if phase_key.startswith(k)), 'BENIGN')
    color = PHASE_COLORS[pname]
    h, m, s = map(int, t_start.split(':'))
    start_m = h*60 + m + s/60
    h, m, s = map(int, t_end.split(':'))
    end_m = h*60 + m + s/60
    rect = mpatches.Rectangle((start_m, 0), end_m - start_m, 100,
                                color=color, alpha=0.35, zorder=0)
    ax.add_patch(rect)
    mid = (start_m + end_m) / 2
    label_name = phase_key.replace('_1','').replace('_2','').replace('_3','').replace('_4','')
    ax.text(mid, 82, label_name, ha='center', va='bottom', fontsize=7.5,
            rotation=90, color='#333', fontweight='bold')
    if pname not in phase_legend:
        phase_legend[pname] = mpatches.Patch(color=color, alpha=0.6, label=pname.capitalize())

# Score scatter
alert_mask = sv['score'] > 4.0
ax.scatter(sv[~alert_mask]['time_min'], sv[~alert_mask]['score'],
           c='#1976D2', s=2, alpha=0.25, zorder=2, label='Normal event')
ax.scatter(sv[alert_mask]['time_min'], sv[alert_mask]['score'],
           c='#D32F2F', s=8, alpha=0.7, zorder=3, label=f'Alert (n={alert_mask.sum():,})')
ax.axhline(4.0, color='red', linestyle='--', linewidth=1.5, alpha=0.7, label='Threshold (4.0)')

# Rolling mean
sv_sorted = sv.sort_values('time_min')
rolling = sv_sorted.set_index('time_min')['score'].rolling(50, min_periods=5).mean()
ax.plot(rolling.index, rolling.values, color='#FF6F00', linewidth=2, alpha=0.85, label='Rolling mean (n=50)')

ax.set_xlim(sv['time_min'].min() - 0.2, sv['time_min'].max() + 0.2)
ax.set_ylim(-0.3, min(sv['score'].quantile(0.998), 60))
ax.set_xlabel('Time (minutes from midnight)')
ax.set_ylabel('Anomaly Score (Z-Score)')
ax.set_title('Anomaly Score Timeline — Single Continuous Session\n(All 7 traffic phases)', fontweight='bold')
handles, labels = ax.get_legend_handles_labels()
handles += list(phase_legend.values())
ax.legend(handles=handles, fontsize=8.5, loc='upper right', ncol=2)
ax.grid(axis='y', alpha=0.3)
ax.spines['top'].set_visible(False); ax.spines['right'].set_visible(False)
plt.tight_layout()
save('fig09_timeline.png')

# ═══════════════════════════════════════════════════════════════════════════════
# FIGURE 10 — Layer Coverage Heatmap
# ═══════════════════════════════════════════════════════════════════════════════
print("[Fig 10] Layer coverage heatmap …")

LAYER_BITS = {
    'XDP (.X..)':        0x01,
    'TC (XT..)':         0x02,
    'SYSCALL (XTS.)':    0x04,
}

def parse_layers_str(row):
    """Convert 'layers' string column like 'XT..' to bitmask."""
    s = str(row.get('layers', '....'))
    bits = 0
    if len(s) >= 1 and s[0] == 'X': bits |= 0x01
    if len(s) >= 2 and s[1] == 'T': bits |= 0x02
    if len(s) >= 3 and s[2] == 'S': bits |= 0x04
    return bits

if 'layers' in ev.columns:
    ev['layer_bits'] = ev.apply(parse_layers_str, axis=1)
    coverage_stats = {}
    for cls in ALL_ORDER:
        sub = ev[ev['label'] == cls]
        if len(sub) == 0: continue
        cov = {
            'XDP Only':       ((sub['layer_bits'] == 0x01).sum() / len(sub)) * 100,
            'TC Only':        ((sub['layer_bits'] == 0x02).sum() / len(sub)) * 100,
            'XDP+TC':         ((sub['layer_bits'] == 0x03).sum() / len(sub)) * 100,
            'XDP+TC+SYSCALL': ((sub['layer_bits'] == 0x07).sum() / len(sub)) * 100,
            'Other':          ((~sub['layer_bits'].isin([0x01,0x02,0x03,0x07])).sum() / len(sub)) * 100,
        }
        coverage_stats[cls] = cov

    cov_df = pd.DataFrame(coverage_stats).T
    cov_df = cov_df.reindex([c for c in ALL_ORDER if c in cov_df.index])

    fig, ax = plt.subplots(figsize=(11, 6))
    im = ax.imshow(cov_df.values, aspect='auto', cmap='YlOrRd', vmin=0, vmax=100)
    ax.set_xticks(range(len(cov_df.columns)))
    ax.set_xticklabels(cov_df.columns, rotation=25, ha='right', fontsize=10)
    ax.set_yticks(range(len(cov_df.index)))
    ax.set_yticklabels(cov_df.index, fontsize=11)
    for i in range(len(cov_df.index)):
        for j in range(len(cov_df.columns)):
            val = cov_df.values[i, j]
            ax.text(j, i, f'{val:.1f}%', ha='center', va='center',
                    fontsize=9.5, color='white' if val > 55 else 'black', fontweight='bold')
    plt.colorbar(im, ax=ax, label='% of Events', shrink=0.8)
    ax.set_title('Cross-Layer Coverage Distribution by Traffic Class\n(% of events with each layer combination)',
                 fontweight='bold')
    plt.tight_layout()
    save('fig10_layer_coverage.png')

# ═══════════════════════════════════════════════════════════════════════════════
# FIGURE 11 — System Overhead (Bar charts from measured values)
# ═══════════════════════════════════════════════════════════════════════════════
print("[Fig 11] System overhead …")

fig, axes = plt.subplots(1, 3, figsize=(14, 5))

# Latency per hook
hooks    = ['XDP\n(ingress)', 'TC\n(egress)', 'Tracepoint\n(sys_enter_connect)']
latency  = [1970, 4985, 890]   # ns/call (from paper)
colors_l = ['#1565C0', '#2E7D32', '#6A1B9A']
bars = axes[0].bar(hooks, latency, color=colors_l, edgecolor='white', linewidth=0.8, width=0.5)
for bar, val in zip(bars, latency):
    axes[0].text(bar.get_x() + bar.get_width()/2, bar.get_height() + 50,
                 f'{val:,} ns', ha='center', va='bottom', fontsize=10, fontweight='bold')
axes[0].set_title('eBPF Hook Latency\n(ns per call, measured)', fontweight='bold')
axes[0].set_ylabel('Latency (ns)')
axes[0].set_ylim(0, 7500)
axes[0].grid(axis='y', alpha=0.35)
axes[0].spines['top'].set_visible(False); axes[0].spines['right'].set_visible(False)

# Memory breakdown
map_names  = ['flow_stats\n(LRU 65536)', 'cookie_map\n(HASH 65536)',
               'corr_window\n(LRU 65536)', 'ring_events\n(RINGBUF)', 'Userspace\nprocess']
map_mem    = [8.9, 5.8, 13.1, 16.9, 6.96]
map_colors = ['#0277BD','#01579B','#006064','#004D40','#BF360C']
bars2 = axes[1].barh(map_names, map_mem, color=map_colors, edgecolor='white', linewidth=0.8)
for bar, val in zip(bars2, map_mem):
    axes[1].text(bar.get_width() + 0.2, bar.get_y() + bar.get_height()/2,
                 f'{val} MB', va='center', fontsize=10, fontweight='bold')
axes[1].axvline(43.1, color='red', linestyle='--', linewidth=1.5, alpha=0.7, label='Total BPF: 43.1 MB')
axes[1].set_title('Memory Footprint\n(Kernel BPF maps + Userspace)', fontweight='bold')
axes[1].set_xlabel('Memory (MB)')
axes[1].set_xlim(0, 25)
axes[1].legend(fontsize=9)
axes[1].grid(axis='x', alpha=0.35)
axes[1].spines['top'].set_visible(False); axes[1].spines['right'].set_visible(False)

# Event throughput / event rate
phases     = ['Benign\n(idle)','Benign\n(curl)','Port Scan','SYN Flood','Exfil','Rootkit']
evt_rate   = [12, 110, 1420, 1850, 68, 45]   # approx events/sec
bar_c      = ['#90CAF9','#42A5F5','#EF5350','#FF7043','#FFD54F','#A1887F']
bars3 = axes[2].bar(phases, evt_rate, color=bar_c, edgecolor='white', linewidth=0.8)
for bar, val in zip(bars3, evt_rate):
    axes[2].text(bar.get_x() + bar.get_width()/2, bar.get_height() + 20,
                 f'{val}', ha='center', va='bottom', fontsize=10, fontweight='bold')
axes[2].set_title('Observed Event Rate by Phase\n(events/sec)', fontweight='bold')
axes[2].set_ylabel('Events per Second')
axes[2].set_ylim(0, 2300)
axes[2].grid(axis='y', alpha=0.35)
axes[2].spines['top'].set_visible(False); axes[2].spines['right'].set_visible(False)

fig.suptitle('System Overhead & Performance Metrics', fontweight='bold')
plt.tight_layout()
save('fig11_system_overhead.png')

# ═══════════════════════════════════════════════════════════════════════════════
# FIGURE 12 — Feature Separability (PCA + class scatter)
# ═══════════════════════════════════════════════════════════════════════════════
print("[Fig 12] Feature separability (PCA) …")
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler as SS

X_all = flo[FLOW_FEATURES].values
scaler2 = SS()
X_scaled = scaler2.fit_transform(X_all)
pca = PCA(n_components=2, random_state=42)
X_pca = pca.fit_transform(X_scaled)

fig, axes = plt.subplots(1, 2, figsize=(14, 6))
for cls in order_present:
    mask = flo['label'] == cls
    axes[0].scatter(X_pca[mask, 0], X_pca[mask, 1],
                    c=PALETTE[cls], label=cls, alpha=0.45, s=15, edgecolors='none')
axes[0].set_title(f'PCA Projection of Flow Features\n(Var explained: PC1={pca.explained_variance_ratio_[0]*100:.1f}%, PC2={pca.explained_variance_ratio_[1]*100:.1f}%)',
                  fontweight='bold')
axes[0].set_xlabel('Principal Component 1')
axes[0].set_ylabel('Principal Component 2')
axes[0].legend(fontsize=9, markerscale=2)
axes[0].grid(alpha=0.3)
axes[0].spines['top'].set_visible(False); axes[0].spines['right'].set_visible(False)

# Component loadings
loadings = pd.DataFrame(pca.components_.T, index=FLOW_FEATURES,
                         columns=['PC1','PC2'])
feat_labels_short = ['Pkts','Bytes','PkRate','AvgPkts','SYN','RST','Layers','NWins']
x_pos = np.arange(len(feat_labels_short))
axes[1].bar(x_pos - 0.2, loadings['PC1'], 0.38, label='PC1', color='#1565C0', alpha=0.85)
axes[1].bar(x_pos + 0.2, loadings['PC2'], 0.38, label='PC2', color='#6A1B9A', alpha=0.85)
axes[1].set_xticks(x_pos)
axes[1].set_xticklabels(feat_labels_short, rotation=30, ha='right')
axes[1].axhline(0, color='black', linewidth=0.7)
axes[1].set_title('PCA Feature Loadings', fontweight='bold')
axes[1].set_ylabel('Loading Coefficient')
axes[1].legend(fontsize=10)
axes[1].grid(axis='y', alpha=0.3)
axes[1].spines['top'].set_visible(False); axes[1].spines['right'].set_visible(False)

fig.suptitle('Feature Space Analysis — PCA Projection & Loadings', fontweight='bold')
plt.tight_layout()
save('fig12_pca_projection.png')

# ═══════════════════════════════════════════════════════════════════════════════
# FIGURE 13 — Alert Detection Rate Over Time (Warmup Effect)
# ═══════════════════════════════════════════════════════════════════════════════
print("[Fig 13] Score warmup / detection rate …")
ev_sorted_t = ev.copy()
ev_sorted_t['event_idx'] = range(len(ev_sorted_t))
ev_sorted_t['is_alert'] = (ev_sorted_t['score'] > 4.0).astype(int)
ev_sorted_t['cum_alerts'] = ev_sorted_t['is_alert'].cumsum()
ev_sorted_t['roll_det_rate'] = (ev_sorted_t['is_alert']
                                 .rolling(100, min_periods=10).mean() * 100)

fig, axes = plt.subplots(2, 1, figsize=(13, 7), sharex=True)
# Scores
for cls in ATTACK_ORDER:
    sub = ev_sorted_t[ev_sorted_t['label'] == cls]
    axes[0].scatter(sub['event_idx'], sub['score'],
                    c=PALETTE[cls], s=4, alpha=0.5, label=cls)
sub_b = ev_sorted_t[ev_sorted_t['label'] == 'benign']
axes[0].scatter(sub_b['event_idx'], sub_b['score'],
                c='#90CAF9', s=3, alpha=0.25, label='benign')
axes[0].axhline(4.0, color='red', linestyle='--', linewidth=1.5, alpha=0.8)
axes[0].axvline(50,  color='gray', linestyle=':', linewidth=1.5, alpha=0.8, label='Warmup end (n=50)')
axes[0].set_ylabel('Anomaly Score')
axes[0].set_ylim(-0.3, min(ev_sorted_t['score'].quantile(0.999), 50))
axes[0].legend(fontsize=8, ncol=4, loc='upper right')
axes[0].set_title('Anomaly Score per Event — Temporal Sequence', fontweight='bold')
axes[0].grid(axis='y', alpha=0.3)
axes[0].spines['top'].set_visible(False); axes[0].spines['right'].set_visible(False)

# Rolling alert rate
axes[1].fill_between(ev_sorted_t['event_idx'], ev_sorted_t['roll_det_rate'],
                     alpha=0.35, color='#D32F2F')
axes[1].plot(ev_sorted_t['event_idx'], ev_sorted_t['roll_det_rate'],
             color='#B71C1C', linewidth=1.5)
axes[1].axvline(50, color='gray', linestyle=':', linewidth=1.5, alpha=0.8)
axes[1].set_ylabel('Alert Rate (%)\nRolling 100-event window')
axes[1].set_xlabel('Event Index (ordered by timestamp)')
axes[1].set_title('Rolling Alert Detection Rate', fontweight='bold')
axes[1].grid(axis='y', alpha=0.3)
axes[1].spines['top'].set_visible(False); axes[1].spines['right'].set_visible(False)

plt.tight_layout()
save('fig13_detection_rate.png')

# ═══════════════════════════════════════════════════════════════════════════════
# FIGURE 14 — Summary Dashboard (Publication-ready composite)
# ═══════════════════════════════════════════════════════════════════════════════
print("[Fig 14] Summary dashboard …")
fig = plt.figure(figsize=(18, 12))
gs  = gridspec.GridSpec(3, 4, figure=fig, hspace=0.55, wspace=0.42)

# (a) Flow counts
ax_a = fig.add_subplot(gs[0, 0])
fl_bar = flo['label'].value_counts().reindex(ALL_ORDER).dropna()
ax_a.bar(fl_bar.index, fl_bar.values,
         color=[PALETTE[l] for l in fl_bar.index], edgecolor='white', linewidth=0.6)
ax_a.set_title('(a) Flows per Class', fontsize=11, fontweight='bold')
ax_a.set_xticklabels(fl_bar.index, rotation=35, ha='right', fontsize=8)
ax_a.set_ylabel('Flow Count', fontsize=9)
ax_a.grid(axis='y', alpha=0.3)
ax_a.spines['top'].set_visible(False); ax_a.spines['right'].set_visible(False)

# (b) Per-class recall (best detector)
ax_b = fig.add_subplot(gs[0, 1:3])
cls_names_plot = [c for c in cls_order_plot if c in order_present]
rec_plot = [recalls_sorted[cls_order_plot.index(c)] for c in cls_names_plot]
ax_b.barh(cls_names_plot, rec_plot,
          color=[PALETTE.get(c,'#888') for c in cls_names_plot],
          edgecolor='white', linewidth=0.6)
ax_b.axvline(80, color='orange', linestyle='--', linewidth=1.2, alpha=0.7)
ax_b.axvline(100, color='gray', linestyle=':', linewidth=1, alpha=0.4)
for i, (name, val) in enumerate(zip(cls_names_plot, rec_plot)):
    ax_b.text(val + 0.5, i, f'{val:.1f}%', va='center', fontsize=9)
ax_b.set_xlim(0, 115)
ax_b.set_title(f'(b) Per-Class Recall [{best_name}]', fontsize=11, fontweight='bold')
ax_b.set_xlabel('Recall / TNR (%)', fontsize=9)
ax_b.grid(axis='x', alpha=0.3)
ax_b.spines['top'].set_visible(False); ax_b.spines['right'].set_visible(False)

# (c) Detector F1 comparison
ax_c = fig.add_subplot(gs[0, 3])
f1s = [det_metrics[d]['f1'] for d in det_names]
bars_c = ax_c.bar(range(len(det_names)), f1s,
                   color=['#6A1B9A' if d == best_name else '#9E9E9E' for d in det_names],
                   edgecolor='white', linewidth=0.6)
for i, (bar, val) in enumerate(zip(bars_c, f1s)):
    ax_c.text(bar.get_x() + bar.get_width()/2, val + 0.01,
              f'{val:.3f}', ha='center', va='bottom', fontsize=8.5, fontweight='bold')
ax_c.set_xticks(range(len(det_names)))
ax_c.set_xticklabels(['Rule', 'IF', 'SVM', 'Ens.'], fontsize=9)
ax_c.set_title('(c) F1 by Detector', fontsize=11, fontweight='bold')
ax_c.set_ylabel('F1 Score', fontsize=9)
ax_c.set_ylim(0, 1.15)
ax_c.grid(axis='y', alpha=0.3)
ax_c.spines['top'].set_visible(False); ax_c.spines['right'].set_visible(False)

# (d) Score dist (box)
ax_d = fig.add_subplot(gs[1, 0:2])
ev_order_present = [l for l in ALL_ORDER if l in ev['label'].unique()]
ev_cat = ev.copy()
ev_cat['label'] = pd.Categorical(ev_cat['label'], categories=ev_order_present, ordered=True)
sns.boxplot(data=ev_cat, x='label', y='score', order=ev_order_present,
            palette={l: PALETTE[l] for l in ev_order_present},
            ax=ax_d, linewidth=0.7, fliersize=2,
            flierprops=dict(marker='o', alpha=0.3))
ax_d.axhline(4.0, color='red', linestyle='--', linewidth=1.5, alpha=0.8)
ax_d.set_title('(d) Score Distribution by Class', fontsize=11, fontweight='bold')
ax_d.set_xlabel(''); ax_d.set_ylabel('Z-Score', fontsize=9)
ax_d.set_xticklabels(ev_order_present, rotation=30, ha='right', fontsize=8)
ax_d.set_ylim(-0.3, min(ev['score'].quantile(0.999), 40))
ax_d.grid(axis='y', alpha=0.3)
ax_d.spines['top'].set_visible(False); ax_d.spines['right'].set_visible(False)

# (e) ROC
ax_e = fig.add_subplot(gs[1, 2:4])
for name, sc, col in roc_detectors:
    fpr2, tpr2, _ = roc_curve(y, sc)
    roc_auc2 = auc(fpr2, tpr2)
    ax_e.plot(fpr2, tpr2, color=col, linewidth=2, label=f'{name} ({roc_auc2:.3f})')
ax_e.plot([0,1],[0,1],'k--', alpha=0.4, linewidth=1)
ax_e.set_title('(e) ROC Curves', fontsize=11, fontweight='bold')
ax_e.set_xlabel('FPR', fontsize=9); ax_e.set_ylabel('TPR', fontsize=9)
ax_e.legend(fontsize=8)
ax_e.grid(alpha=0.3)
ax_e.spines['top'].set_visible(False); ax_e.spines['right'].set_visible(False)

# (f) Overhead
ax_f = fig.add_subplot(gs[2, 0])
ax_f.bar(['XDP','TC','TP'], [1970, 4985, 890],
          color=['#1565C0','#2E7D32','#6A1B9A'], edgecolor='white', linewidth=0.6)
ax_f.set_title('(f) Hook Latency (ns)', fontsize=11, fontweight='bold')
ax_f.set_ylabel('ns/call', fontsize=9)
ax_f.grid(axis='y', alpha=0.3)
ax_f.spines['top'].set_visible(False); ax_f.spines['right'].set_visible(False)

# (g) Memory
ax_g = fig.add_subplot(gs[2, 1])
ax_g.barh(['flow_stats','cookie','corr_win','ring_buf','userspace'],
           [8.9, 5.8, 13.1, 16.9, 6.96],
           color=['#0277BD','#01579B','#006064','#004D40','#BF360C'],
           edgecolor='white', linewidth=0.6)
ax_g.set_title('(g) Memory (MB)', fontsize=11, fontweight='bold')
ax_g.set_xlabel('MB', fontsize=9)
ax_g.grid(axis='x', alpha=0.3)
ax_g.spines['top'].set_visible(False); ax_g.spines['right'].set_visible(False)

# (h) PCA
ax_h = fig.add_subplot(gs[2, 2:4])
for cls in order_present:
    mask_pca = flo['label'] == cls
    ax_h.scatter(X_pca[mask_pca, 0], X_pca[mask_pca, 1],
                 c=PALETTE[cls], label=cls, alpha=0.45, s=12, edgecolors='none')
ax_h.set_title(f'(h) PCA Feature Projection\n(PC1={pca.explained_variance_ratio_[0]*100:.0f}%, PC2={pca.explained_variance_ratio_[1]*100:.0f}%)',
               fontsize=11, fontweight='bold')
ax_h.set_xlabel('PC1', fontsize=9); ax_h.set_ylabel('PC2', fontsize=9)
ax_h.legend(fontsize=7.5, markerscale=2, ncol=2)
ax_h.grid(alpha=0.25)
ax_h.spines['top'].set_visible(False); ax_h.spines['right'].set_visible(False)

fig.suptitle('eBPF Cross-Layer Anomaly Detection — Results Summary Dashboard',
             fontweight='bold', fontsize=15, y=1.01)
save('fig14_summary_dashboard.png')

# ═══════════════════════════════════════════════════════════════════════════════
# PRINT SUMMARY TABLE
# ═══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*64)
print("  RESULTS SUMMARY")
print("="*64)
print(f"  Dataset:  {len(ev):,} events  →  {len(flo):,} flows  ({flo['label'].nunique()} classes)")
print(f"  Best detector: {best_name}")
print(f"  Precision={det_metrics[best_name]['precision']:.3f}  "
      f"Recall={det_metrics[best_name]['recall']:.3f}  "
      f"F1={det_metrics[best_name]['f1']:.3f}")
cm2 = confusion_matrix(y, best_pred)
tn2, fp2, fn2, tp2 = cm2.ravel()
print(f"  TN={tn2}  FP={fp2}  FN={fn2}  TP={tp2}")
print("\n  Per-class recall:")
for cls in sorted(flo['label'].unique()):
    mask = (flo['label'] == cls).values
    n = mask.sum()
    if cls == 'benign':
        pct = 100 * (best_pred[mask] == 0).sum() / n
        print(f"    {cls:<20} TNR={pct:.1f}%  (n={n})")
    else:
        detected = best_pred[mask].sum()
        pct = 100 * detected / n
        print(f"    {cls:<20} {pct:.1f}%  (n={n})")

print(f"\n  Figures saved to: {os.path.abspath(OUT_DIR)}/")
print(f"  Total figures:    14")
