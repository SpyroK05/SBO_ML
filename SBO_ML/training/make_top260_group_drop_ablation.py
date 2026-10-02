#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
from pathlib import Path
import re

import pandas as pd


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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True)
    ap.add_argument("--out-dir", default="outputs/features/top260_group_drop")
    ap.add_argument("--min-group-size", type=int, default=8)
    args = ap.parse_args()

    data_p = Path(args.data)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(data_p, low_memory=False)

    features = [c for c in df.columns if c not in ID_COLS]
    groups = {}

    for c in features:
        g = feature_group(c)
        groups.setdefault(g, []).append(c)

    print("========== GROUPS ==========")
    for g, cols in sorted(groups.items(), key=lambda x: len(x[1]), reverse=True):
        print(g, len(cols))

    # full copy
    df.to_csv(out_dir / "dataset_top260_full.csv", index=False)

    for g, cols in groups.items():
        if len(cols) < args.min_group_size:
            continue

        out = df.drop(columns=cols, errors="ignore")
        path = out_dir / f"dataset_top260_drop_{g}.csv"
        out.to_csv(path, index=False)
        print("[WRITE]", path, out.shape, "dropped", len(cols))

    # Một số tổ hợp thường nhiễu.
    noisy_sets = {
        "drop_opcode_raw_alias": ["opcode_like", "raw_buffer_alias"],
        "drop_other": ["other"],
        "drop_raw_alias_other": ["raw_buffer_alias", "other"],
        "drop_opcode_other": ["opcode_like", "other"],
    }

    for name, gs in noisy_sets.items():
        drop_cols = []
        for g in gs:
            drop_cols.extend(groups.get(g, []))

        if not drop_cols:
            continue

        out = df.drop(columns=drop_cols, errors="ignore")
        path = out_dir / f"dataset_top260_{name}.csv"
        out.to_csv(path, index=False)
        print("[WRITE]", path, out.shape, "dropped", len(drop_cols))


if __name__ == "__main__":
    main()
