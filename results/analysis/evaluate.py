#!/usr/bin/env python3
"""
evaluate.py — per-flow F1 evaluation for eBPF-CLA
Each unique (label, cookie) pair → one aggregated flow record.
Usage: python3 evaluate.py <sessions_csv>
"""
import sys
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (precision_recall_fscore_support,
                             confusion_matrix)

# Features stable at the flow level
FLOW_FEATURES = ['total_pkts', 'total_bytes', 'max_pkt_rate',
                 'avg_pkt_count', 'syn_count', 'rst_count',
                 'layer_coverage', 'n_windows']

def load_and_prep(path):
    df = pd.read_csv(path)
    df.columns = df.columns.str.strip()
    for col in ['score','syn_count','rst_count','pkt_count','byte_count',
                'pkt_rate','layer_coverage','connect_rate','cookie']:
        df[col] = pd.to_numeric(df.get(col, 0), errors='coerce').fillna(0)
    df['y_true'] = (df['label'] != 'benign').astype(int)
    return df

def aggregate_flows(df):
    """Aggregate per-label-cookie → one flow record."""
    agg = df.groupby(['label', 'cookie']).agg(
        total_pkts   = ('pkt_count', 'max'),
        total_bytes  = ('byte_count', 'max'),
        max_pkt_rate = ('pkt_rate', 'max'),
        avg_pkt_count= ('pkt_count', 'mean'),
        syn_count    = ('syn_count', 'sum'),
        rst_count    = ('rst_count', 'sum'),
        layer_coverage=('layer_coverage', 'max'),
        n_windows    = ('pkt_count', 'count'),
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
    return (raw == -1).astype(int)

def rule_detector(df):
    """
    Flag flows where:
      - very few total packets (short-lived probes), OR
      - unusual number of windows for the packet count (scan pattern)
    """
    pkt = df['total_pkts']
    windows = df['n_windows']
    # Scans/floods: many windows but few packets per window
    # Benign: either very few windows (short curl) or many windows with many pkts (SSH)
    low_pkt  = (pkt < 20)                          # short probe (scan/flood individual flow)
    high_win = (windows > 30) & (pkt < 100)        # many sweeps of small flow = scan burst
    return (low_pkt | high_win).astype(int)

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <sessions.csv>")
        sys.exit(1)

    df = load_and_prep(sys.argv[1])
    flows = aggregate_flows(df)

    print(f"\nRaw events: {len(df)} → Flows: {len(flows)}")
    label_counts = flows['label'].value_counts().to_dict()
    print("Flows per label:")
    for k, v in sorted(label_counts.items()):
        print(f"  {k:<20} {v:>5} flows")

    print("\nFlow-level feature means:")
    print(flows.groupby('label')[['total_pkts','total_bytes','max_pkt_rate','n_windows']].mean()
            .round(1).to_string())

    X = flows[FLOW_FEATURES].values
    y = flows['y_true'].values
    benign_mask = flows['label'] == 'benign'
    X_benign = X[benign_mask]

    results = {}

    # ── Rule-based ────────────────────────────────────────────────────────
    y_rule = rule_detector(flows)
    p, r, f, _ = precision_recall_fscore_support(y, y_rule, average='binary', zero_division=0)
    results['Rule (pkt+windows)'] = dict(precision=p, recall=r, f1=f, pred=y_rule)

    # ── Isolation Forest ──────────────────────────────────────────────────
    if len(X_benign) >= 5:
        y_if = run_detector(
            lambda: IsolationForest(n_estimators=200, contamination=0.1,
                                    random_state=42, n_jobs=-1),
            X_benign, X)
        p, r, f, _ = precision_recall_fscore_support(y, y_if, average='binary', zero_division=0)
        results['Isolation Forest'] = dict(precision=p, recall=r, f1=f, pred=y_if)

    # ── OC-SVM ───────────────────────────────────────────────────────────
    if len(X_benign) >= 5:
        y_svm = run_detector(
            lambda: OneClassSVM(nu=0.1, kernel='rbf', gamma='scale'),
            X_benign, X)
        p, r, f, _ = precision_recall_fscore_support(y, y_svm, average='binary', zero_division=0)
        results['OC-SVM'] = dict(precision=p, recall=r, f1=f, pred=y_svm)

    # ── Ensemble ─────────────────────────────────────────────────────────
    if len(results) >= 2:
        preds = np.stack([v['pred'] for v in results.values()], axis=1)
        y_ens = (preds.sum(axis=1) >= 2).astype(int)
        p, r, f, _ = precision_recall_fscore_support(y, y_ens, average='binary', zero_division=0)
        results['Ensemble (majority)'] = dict(precision=p, recall=r, f1=f, pred=y_ens)

    # ── Per-class breakdown ───────────────────────────────────────────────
    best_name = max(results, key=lambda k: results[k]['f1'])
    best_pred = results[best_name]['pred']

    print("\n" + "=" * 64)
    print(f"  Per-class recall ({best_name})")
    print("=" * 64)
    print(f"  {'Label':<22} {'Flows':>5}  {'Recall%':>9}")
    print(f"  {'-'*22} {'-'*5}  {'-'*9}")
    for cls in sorted(flows['label'].unique()):
        mask = (flows['label'] == cls).values
        n = mask.sum()
        if cls == 'benign':
            correct = (best_pred[mask] == 0).sum()
            fp = (best_pred[mask] == 1).sum()
            pct = 100 * correct / n
            marker = "✓" if pct >= 90 else ("~" if pct >= 70 else "✗")
            print(f"  {cls:<22} {n:>5}  {pct:>8.1f}% {marker}  (FP={fp})")
        else:
            detected = best_pred[mask].sum()
            pct = 100 * detected / n
            marker = "✓" if pct >= 80 else ("~" if pct >= 50 else "✗")
            print(f"  {cls:<22} {n:>5}  {pct:>8.1f}% {marker}")

    # ── Summary table ─────────────────────────────────────────────────────
    print("\n" + "=" * 64)
    print("  Detector comparison  (flow-level, benign=0 vs attack=1)")
    print("=" * 64)
    print(f"  {'Detector':<28} {'Prec':>6}  {'Rec':>6}  {'F1':>6}")
    print(f"  {'-'*28} {'-'*6}  {'-'*6}  {'-'*6}")
    for name, m in results.items():
        marker = " ★" if name == best_name else ""
        print(f"  {name:<28} {m['precision']:>6.3f}  {m['recall']:>6.3f}  {m['f1']:>6.3f}{marker}")

    cm = confusion_matrix(y, best_pred)
    tn, fp, fn, tp = cm.ravel()
    print(f"\n  Best → {best_name}")
    print(f"  TN={tn}  FP={fp}  FN={fn}  TP={tp}")
    print(f"  F1={results[best_name]['f1']:.3f}  "
          f"Prec={results[best_name]['precision']:.3f}  "
          f"Rec={results[best_name]['recall']:.3f}")

if __name__ == '__main__':
    main()
