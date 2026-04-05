#!/usr/bin/env python3
"""
per_class_f1.py — per-class F1 breakdown for each named attack category.

Addresses reviewer comment:
  "The 6 attack categories should be named explicitly.
   F1=0.957 aggregate — per-class F1 breakdown is needed."

Usage:
    python3 results/analysis/per_class_f1.py results/raw/sessions_merged.csv

For each detector we report:
  • Aggregate binary F1 (benign vs. attack)
  • Per-class F1 for every one of the 6 attack categories, computed as
    one-vs-benign: only benign flows + flows of that class are evaluated,
    giving precision/recall/F1 per attack type.
  • A summary table suitable for copy-paste into a paper.
"""

import sys
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import precision_recall_fscore_support, confusion_matrix

# ── Attack category canonical names (explicit for reviewers) ──────────────────
ATTACK_CATEGORIES = [
    "portscan",       # TCP SYN scan via nmap / /dev/tcp
    "synflood",       # rapid serial TCP SYN connects
    "cryptomining",   # Stratum pool reconnects (ports 3333/4444/14444/45700)
    "privesc",        # execve burst + C2 connection pattern
    "rootkit",        # port-knock sequence + periodic beaconing
    "exfil",          # large-payload HTTP POSTs (data exfiltration)
]

FLOW_FEATURES = ['total_pkts', 'total_bytes', 'max_pkt_rate',
                 'avg_pkt_count', 'syn_count', 'rst_count',
                 'layer_coverage', 'n_windows']


def load_and_prep(path):
    df = pd.read_csv(path)
    df.columns = df.columns.str.strip()
    for col in ['score', 'syn_count', 'rst_count', 'pkt_count', 'byte_count',
                'pkt_rate', 'layer_coverage', 'connect_rate', 'cookie']:
        df[col] = pd.to_numeric(df.get(col, 0), errors='coerce').fillna(0)
    return df


def aggregate_flows(df):
    agg = df.groupby(['label', 'cookie']).agg(
        total_pkts    = ('pkt_count',  'max'),
        total_bytes   = ('byte_count', 'max'),
        max_pkt_rate  = ('pkt_rate',   'max'),
        avg_pkt_count = ('pkt_count',  'mean'),
        syn_count     = ('syn_count',  'sum'),
        rst_count     = ('rst_count',  'sum'),
        layer_coverage= ('layer_coverage', 'max'),
        n_windows     = ('pkt_count',  'count'),
    ).reset_index()
    agg['y_true'] = (agg['label'] != 'benign').astype(int)
    return agg


def rule_predict(flows):
    pkt     = flows['total_pkts']
    windows = flows['n_windows']
    low_pkt  = pkt < 20
    high_win = (windows > 30) & (pkt < 100)
    return (low_pkt | high_win).astype(int).values


def run_detector(clf_fn, X_train, X_test):
    scaler = StandardScaler()
    X_tr = scaler.fit_transform(X_train)
    X_te = scaler.transform(X_test)
    clf = clf_fn()
    clf.fit(X_tr)
    return (clf.predict(X_te) == -1).astype(int)


def per_class_f1(flows, y_pred, categories):
    """
    For each attack category compute F1 using one-vs-benign evaluation:
    subset = benign flows + flows of this category only.
    This isolates the precision/recall trade-off for each attack type.
    """
    benign_mask = flows['label'] == 'benign'
    rows = []
    for cat in categories:
        cat_mask = flows['label'] == cat
        subset   = benign_mask | cat_mask
        if cat_mask.sum() == 0:
            rows.append({'category': cat, 'flows': 0,
                         'precision': float('nan'), 'recall': float('nan'),
                         'f1': float('nan'), 'tp': 0, 'fn': 0, 'fp': 0})
            continue
        y_sub  = (flows['label'][subset] != 'benign').astype(int).values
        yp_sub = y_pred[subset]
        p, r, f, _ = precision_recall_fscore_support(
            y_sub, yp_sub, average='binary', zero_division=0)
        cm = confusion_matrix(y_sub, yp_sub)
        tn, fp, fn, tp = cm.ravel() if cm.shape == (2, 2) else (0, 0, 0, 0)
        rows.append({'category': cat,
                     'flows': int(cat_mask.sum()),
                     'precision': p, 'recall': r, 'f1': f,
                     'tp': int(tp), 'fn': int(fn), 'fp': int(fp)})
    return rows


def print_per_class_table(label, rows):
    CATEGORY_DISPLAY = {
        "portscan":    "Port Scan",
        "synflood":    "SYN Flood",
        "cryptomining":"Cryptomining C2",
        "privesc":     "Privilege Escalation",
        "rootkit":     "Rootkit Beaconing",
        "exfil":       "Data Exfiltration",
    }
    print(f"\n{'='*72}")
    print(f"  Per-class F1 breakdown — {label}")
    print(f"{'='*72}")
    print(f"  {'Attack Category':<24} {'Flows':>5}  {'Prec':>6}  {'Rec':>6}  {'F1':>6}  {'TP':>4}  {'FN':>4}  {'FP':>4}")
    print(f"  {'-'*24} {'-'*5}  {'-'*6}  {'-'*6}  {'-'*6}  {'-'*4}  {'-'*4}  {'-'*4}")
    for r in rows:
        display = CATEGORY_DISPLAY.get(r['category'], r['category'])
        if r['flows'] == 0:
            print(f"  {display:<24} {'N/A':>5}")
            continue
        marker = ("★" if r['f1'] >= 0.90
                  else ("~" if r['f1'] >= 0.70 else "✗"))
        print(f"  {display:<24} {r['flows']:>5}  "
              f"{r['precision']:>6.3f}  {r['recall']:>6.3f}  "
              f"{r['f1']:>6.3f}{marker} "
              f" {r['tp']:>4}  {r['fn']:>4}  {r['fp']:>4}")

    f1_vals = [r['f1'] for r in rows if not np.isnan(r['f1'])]
    if f1_vals:
        print(f"\n  Macro-avg F1 across attack classes: {np.mean(f1_vals):.3f}")
        print(f"  Min F1: {min(f1_vals):.3f}   Max F1: {max(f1_vals):.3f}")


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <sessions.csv>")
        sys.exit(1)

    df    = load_and_prep(sys.argv[1])
    flows = aggregate_flows(df)

    # Validate all expected categories are present
    found   = set(flows['label'].unique()) - {'benign'}
    missing = set(ATTACK_CATEGORIES) - found
    extra   = found - set(ATTACK_CATEGORIES)

    print(f"\nDataset: {sys.argv[1]}")
    print(f"Raw events: {len(df)}  →  Flows: {len(flows)}")
    print(f"\nThe 6 attack categories evaluated:")
    CATEGORY_DISPLAY = {
        "portscan":    "Port Scan          — TCP SYN scan (nmap / /dev/tcp fallback)",
        "synflood":    "SYN Flood          — rapid serial TCP SYN connects to one host",
        "cryptomining":"Cryptomining C2    — Stratum pool reconnects (ports 3333/4444/14444/45700)",
        "privesc":     "Privilege Escalation — execve burst + C2 connection pattern",
        "rootkit":     "Rootkit Beaconing  — port-knock sequence + periodic beaconing",
        "exfil":       "Data Exfiltration  — large-payload HTTP POSTs",
    }
    for i, cat in enumerate(ATTACK_CATEGORIES, 1):
        n = (flows['label'] == cat).sum()
        status = f"{n} flows" if n > 0 else "NOT IN CSV"
        print(f"  {i}. {CATEGORY_DISPLAY[cat]}  [{status}]")
    if missing:
        print(f"\n  WARNING: missing from CSV: {', '.join(sorted(missing))}")
    if extra:
        print(f"  NOTE: extra labels in CSV: {', '.join(sorted(extra))}")

    # ── Build predictions ─────────────────────────────────────────────────────
    X        = flows[FLOW_FEATURES].values
    y        = flows['y_true'].values
    benign_X = X[flows['label'] == 'benign']

    detectors = {}

    # Rule-based
    y_rule = rule_predict(flows)
    p, r, f, _ = precision_recall_fscore_support(y, y_rule, average='binary', zero_division=0)
    detectors['Rule-based (pkt+windows)'] = {'pred': y_rule, 'precision': p, 'recall': r, 'f1': f}

    # Isolation Forest
    if len(benign_X) >= 5:
        y_if = run_detector(
            lambda: IsolationForest(n_estimators=200, contamination=0.1,
                                    random_state=42, n_jobs=-1),
            benign_X, X)
        p, r, f, _ = precision_recall_fscore_support(y, y_if, average='binary', zero_division=0)
        detectors['Isolation Forest'] = {'pred': y_if, 'precision': p, 'recall': r, 'f1': f}

    # OC-SVM
    if len(benign_X) >= 5:
        y_svm = run_detector(
            lambda: OneClassSVM(nu=0.1, kernel='rbf', gamma='scale'),
            benign_X, X)
        p, r, f, _ = precision_recall_fscore_support(y, y_svm, average='binary', zero_division=0)
        detectors['OC-SVM'] = {'pred': y_svm, 'precision': p, 'recall': r, 'f1': f}

    # Ensemble majority vote
    if len(detectors) >= 2:
        preds  = np.stack([v['pred'] for v in detectors.values()], axis=1)
        y_ens  = (preds.sum(axis=1) >= 2).astype(int)
        p, r, f, _ = precision_recall_fscore_support(y, y_ens, average='binary', zero_division=0)
        detectors['Ensemble (majority)'] = {'pred': y_ens, 'precision': p, 'recall': r, 'f1': f}

    # ── Aggregate comparison table ────────────────────────────────────────────
    best_name = max(detectors, key=lambda k: detectors[k]['f1'])

    print(f"\n{'='*72}")
    print("  Detector comparison  (aggregate: benign=0 vs. attack=1)")
    print(f"{'='*72}")
    print(f"  {'Detector':<28} {'Prec':>6}  {'Rec':>6}  {'F1':>6}")
    print(f"  {'-'*28} {'-'*6}  {'-'*6}  {'-'*6}")
    for name, m in detectors.items():
        marker = "  ★ best" if name == best_name else ""
        print(f"  {name:<28} {m['precision']:>6.3f}  {m['recall']:>6.3f}  {m['f1']:>6.3f}{marker}")

    # ── Per-class F1 for every detector ──────────────────────────────────────
    active_cats = [c for c in ATTACK_CATEGORIES if (flows['label'] == c).sum() > 0]

    for name, m in detectors.items():
        rows = per_class_f1(flows, m['pred'], active_cats)
        print_per_class_table(name, rows)

    # ── LaTeX-ready table for the paper ──────────────────────────────────────
    best_pred = detectors[best_name]['pred']
    best_rows = per_class_f1(flows, best_pred, active_cats)

    DISPLAY = {
        "portscan":    "Port Scan",
        "synflood":    "SYN Flood",
        "cryptomining":"Cryptomining C2",
        "privesc":     "Privilege Escalation",
        "rootkit":     "Rootkit Beaconing",
        "exfil":       "Data Exfiltration",
    }

    print(f"\n{'='*72}")
    print(f"  LaTeX table snippet — {best_name}")
    print(f"{'='*72}")
    print(r"  \begin{tabular}{lrrrr}")
    print(r"  \hline")
    print(r"  Attack Category & Flows & Precision & Recall & F1 \\")
    print(r"  \hline")
    for r in best_rows:
        d = DISPLAY.get(r['category'], r['category'])
        print(f"  {d} & {r['flows']} & "
              f"{r['precision']:.3f} & {r['recall']:.3f} & "
              f"\\textbf{{{r['f1']:.3f}}} \\\\")
    f1_vals = [r['f1'] for r in best_rows if not np.isnan(r['f1'])]
    print(r"  \hline")
    print(f"  \\textit{{Macro-avg}} & — & — & — & "
          f"\\textbf{{{np.mean(f1_vals):.3f}}} \\\\")
    print(r"  \hline")
    print(r"  \end{tabular}")


if __name__ == '__main__':
    main()
