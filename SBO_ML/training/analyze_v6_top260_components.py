#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
from pathlib import Path
import re

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt


ID_COLS = {
    "binary", "binary_norm", "program_name", "json_file", "source_core",
    "build_config", "function", "name_norm", "entry", "schema",
    "merge_stage", "candidate_reasons", "label",
}


def feature_group(c):
    c = str(c)
    cl = c.lower()

    if c.startswith(("pcode_", "mnemonic_")):
        return "opcode_like"

    if c.startswith(("local_buffers_", "v6_aliases_")):
        return "raw_buffer_alias"

    if c.startswith("sinks_v6_"):
        return "v6_sink"

    if c.startswith(("v6_summary_", "v6_loop_summary_", "v6_function_role_")):
        return "v6_summary"

    if c.startswith(("sink_summary_", "buffer_summary_", "v4_summary_")):
        return "sink_buffer_summary"

    if c.startswith(("stack_", "cfg_", "summary_", "callgraph_")):
        return "program_static"

    if "risk" in cl or "safe" in cl or "guard" in cl or "overflow" in cl:
        return "risk_safe"

    if "dst" in cl or "src" in cl or "source" in cl or "size" in cl or "sink" in cl:
        return "dataflow_sink_size"

    return "other"


def numeric_feature_cols(df):
    out = []

    for c in df.columns:
        if c in ID_COLS:
            continue

        s = pd.to_numeric(df[c], errors="coerce")
        if s.notna().sum() == 0:
            continue

        s = s.replace([np.inf, -np.inf], np.nan).fillna(0)
        if s.nunique(dropna=False) <= 1:
            continue

        out.append(c)

    return out


def calc_feature_stats(df, cols):
    y = df["label"].astype(int).values
    rows = []

    for c in cols:
        s = pd.to_numeric(df[c], errors="coerce").replace([np.inf, -np.inf], np.nan).fillna(0)

        s0 = s[y == 0]
        s1 = s[y == 1]

        std = float(s.std())
        sep = 0.0 if std == 0 else abs(float(s1.mean()) - float(s0.mean())) / std

        rows.append({
            "feature": c,
            "group": feature_group(c),
            "nonzero_ratio": float((s != 0).mean()),
            "unique_count": int(s.nunique(dropna=False)),
            "mean_label0": float(s0.mean()),
            "mean_label1": float(s1.mean()),
            "abs_mean_diff": abs(float(s1.mean()) - float(s0.mean())),
            "class_separation": sep,
        })

    return pd.DataFrame(rows)


def main():
    ap = argparse.ArgumentParser()

    ap.add_argument("--data", required=True)
    ap.add_argument("--rank", required=True)
    ap.add_argument("--case", default="score_corr_top260")
    ap.add_argument("--out-dir", default="outputs/reports/top260_feature_audit")

    args = ap.parse_args()

    data_p = Path(args.data)
    rank_p = Path(args.rank)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(data_p, low_memory=False)
    rank = pd.read_csv(rank_p)

    selected = numeric_feature_cols(df)

    rank_cols = [c for c in ["feature", "score", "group", "corr_pruned_order"] if c in rank.columns]
    rank_small = rank[rank_cols].copy()

    stats = calc_feature_stats(df, selected)

    if "feature" in rank_small.columns:
        audit = stats.merge(rank_small, on="feature", how="left", suffixes=("", "_rank"))
    else:
        audit = stats.copy()

    if "score" not in audit.columns:
        audit["score"] = audit["class_separation"]

    audit = audit.sort_values(["score", "class_separation"], ascending=False)

    comp = (
        audit.groupby("group")
        .agg(
            feature_count=("feature", "count"),
            mean_score=("score", "mean"),
            max_score=("score", "max"),
            mean_separation=("class_separation", "mean"),
            mean_nonzero=("nonzero_ratio", "mean"),
        )
        .reset_index()
        .sort_values(["feature_count", "mean_score"], ascending=False)
    )

    audit.to_csv(out_dir / f"{args.case}_feature_audit.csv", index=False)
    comp.to_csv(out_dir / f"{args.case}_group_composition.csv", index=False)

    top = audit.head(80)
    top.to_csv(out_dir / f"{args.case}_top80_features.csv", index=False)

    print("========== GROUP COMPOSITION ==========")
    print(comp.to_string(index=False))

    print("\n========== TOP 40 FEATURES ==========")
    print(top[["feature", "group", "score", "class_separation", "nonzero_ratio"]].head(40).to_string(index=False))

    # Plot 1: group counts
    plt.figure(figsize=(12, 6))
    plt.bar(comp["group"], comp["feature_count"])
    plt.title(f"{args.case}: Feature group composition")
    plt.ylabel("Number of features")
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()
    plt.savefig(out_dir / f"{args.case}_group_counts.png", dpi=220)
    plt.close()

    # Plot 2: mean score by group
    comp2 = comp.sort_values("mean_score", ascending=False)

    plt.figure(figsize=(12, 6))
    plt.bar(comp2["group"], comp2["mean_score"])
    plt.title(f"{args.case}: Mean selector score by group")
    plt.ylabel("Mean score")
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()
    plt.savefig(out_dir / f"{args.case}_group_mean_score.png", dpi=220)
    plt.close()

    # Plot 3: top feature scores
    top30 = audit.head(30).iloc[::-1]

    plt.figure(figsize=(12, 9))
    plt.barh(top30["feature"], top30["score"])
    plt.title(f"{args.case}: Top 30 selected features")
    plt.xlabel("Selector score")
    plt.tight_layout()
    plt.savefig(out_dir / f"{args.case}_top30_features.png", dpi=220)
    plt.close()

    print("\n[OK] wrote:", out_dir)


if __name__ == "__main__":
    main()
