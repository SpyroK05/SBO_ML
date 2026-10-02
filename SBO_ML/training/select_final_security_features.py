#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
from pathlib import Path

import numpy as np
import pandas as pd


ID_COLS = [
    "binary", "binary_norm", "program_name", "json_file", "source_core",
    "build_config", "function", "name_norm", "entry", "schema",
    "merge_stage", "candidate_reasons", "label",
]


GROUP_RATIO = {
    "v6_sink": 0.27,
    "risk_safe": 0.20,
    "sink_buffer_summary": 0.12,
    "v6_summary": 0.12,
    "raw_buffer_alias": 0.10,
    "dataflow_sink_size": 0.08,
    "opcode_like": 0.06,
    "stack_memory": 0.04,
    "program_static": 0.01,
    "callgraph_context": 0.00,
    "cfg_control_flow": 0.00,
}


SEMANTIC_BONUS = {
    "v6_sink": 0.08,
    "risk_safe": 0.07,
    "sink_buffer_summary": 0.07,
    "v6_summary": 0.06,
    "raw_buffer_alias": 0.06,
    "stack_memory": 0.06,
    "dataflow_sink_size": 0.02,
    "opcode_like": 0.00,
    "program_static": -0.04,
    "callgraph_context": -0.06,
    "cfg_control_flow": -0.10,
}


def log(*x):
    print(*x, flush=True)


def proxy_penalty(proxy_flags):
    s = str(proxy_flags or "")
    if not s:
        return 0.0

    penalty = 0.0

    if "line_index" in s:
        penalty += 0.10
    if "stack_offset" in s:
        penalty += 0.08
    if "size_proxy" in s:
        penalty += 0.05
    if "generic_count" in s:
        penalty += 0.04

    return penalty


def build_quota(target_k):
    raw = {g: int(round(target_k * r)) for g, r in GROUP_RATIO.items()}

    # Điều chỉnh cho tổng đúng target_k.
    diff = target_k - sum(raw.values())

    priority = [
        "v6_sink", "risk_safe", "sink_buffer_summary", "v6_summary",
        "raw_buffer_alias", "dataflow_sink_size", "opcode_like", "stack_memory"
    ]

    i = 0
    while diff != 0:
        g = priority[i % len(priority)]
        if diff > 0:
            raw[g] += 1
            diff -= 1
        else:
            if raw[g] > 0:
                raw[g] -= 1
                diff += 1
        i += 1

    return raw


def corr_with_selected(X, candidate, selected, corr_cache):
    if not selected:
        return 0.0

    max_corr = 0.0

    x = X[candidate].values

    sx = np.std(x)
    if sx < 1e-12:
        return 1.0

    for s in selected:
        key = tuple(sorted((candidate, s)))

        if key in corr_cache:
            c = corr_cache[key]
        else:
            y = X[s].values
            sy = np.std(y)

            if sy < 1e-12:
                c = 1.0
            else:
                c = abs(np.corrcoef(x, y)[0, 1])
                if not np.isfinite(c):
                    c = 0.0

            corr_cache[key] = c

        max_corr = max(max_corr, c)

        if max_corr >= 0.985:
            break

    return max_corr


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True)
    ap.add_argument("--audit", required=True)
    ap.add_argument("--out-dir", default="outputs/features/final_selected")
    ap.add_argument("--target-k", type=int, default=160)
    ap.add_argument("--corr-threshold", type=float, default=0.965)
    ap.add_argument("--sample-corr", type=int, default=12000)
    args = ap.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(args.data, low_memory=False)
    audit = pd.read_csv(args.audit)
    audit["proxy_flags"] = audit["proxy_flags"].fillna("")

    audit = audit[audit["feature"].isin(df.columns)].copy()

    if audit.empty:
        raise SystemExit("Audit rỗng hoặc feature không khớp dataset.")

    audit["proxy_penalty"] = audit["proxy_flags"].apply(proxy_penalty)
    audit["semantic_bonus"] = audit["group"].map(SEMANTIC_BONUS).fillna(0.0)

    audit["final_select_score"] = (
        audit["audit_score"].astype(float)
        + audit["semantic_bonus"]
        - audit["proxy_penalty"]
    )

    audit = audit.sort_values(
        ["final_select_score", "audit_score", "nonzero_rate"],
        ascending=False,
    ).reset_index(drop=True)

    feature_cols = audit["feature"].tolist()

    # Dùng sample để tính correlation cho nhanh.
    if len(df) > args.sample_corr:
        if "label" in df.columns:
            sample_df = (
                df.groupby("label", group_keys=False)
                .apply(lambda x: x.sample(
                    min(len(x), max(1000, args.sample_corr // 2)),
                    random_state=1337
                ))
            )
        else:
            sample_df = df.sample(args.sample_corr, random_state=1337)
    else:
        sample_df = df

    Xcorr = sample_df[feature_cols].apply(pd.to_numeric, errors="coerce")
    Xcorr = Xcorr.replace([np.inf, -np.inf], np.nan).fillna(0.0)

    quota = build_quota(args.target_k)

    selected = []
    corr_cache = {}

    log("========== QUOTA ==========")
    for g, q in quota.items():
        log(f"{g:24s} {q}")

    log("")
    log("========== SELECTING ==========")

    # Chọn theo quota từng nhóm.
    for group, q in quota.items():
        if q <= 0:
            continue

        sub = audit[audit["group"] == group].copy()

        n_before = len(selected)
        for _, row in sub.iterrows():
            if len(selected) - n_before >= q:
                break

            f = row["feature"]

            if f in selected:
                continue

            # Correlation pruning toàn cục.
            max_corr = corr_with_selected(Xcorr, f, selected, corr_cache)

            if max_corr >= args.corr_threshold:
                continue

            selected.append(f)

        log(f"{group:24s} selected={len(selected) - n_before:3d}/{q:3d}")

    # Nếu chưa đủ target_k thì fill từ feature còn lại, vẫn tránh trùng lặp quá cao.
    for _, row in audit.iterrows():
        if len(selected) >= args.target_k:
            break

        f = row["feature"]

        if f in selected:
            continue

        max_corr = corr_with_selected(Xcorr, f, selected, corr_cache)

        if max_corr >= 0.985:
            continue

        selected.append(f)

    selected = selected[:args.target_k]

    keep_cols = [c for c in ID_COLS if c in df.columns] + selected
    out_df = df[keep_cols].copy()

    out_csv = out_dir / f"dataset_final_security_{len(selected)}.csv"
    out_list = out_dir / f"feature_list_final_security_{len(selected)}.txt"
    out_audit = out_dir / f"selected_feature_audit_{len(selected)}.csv"
    out_summary = out_dir / f"selected_group_summary_{len(selected)}.csv"

    out_df.to_csv(out_csv, index=False)
    Path(out_list).write_text("\n".join(selected), encoding="utf-8")

    selected_audit = audit[audit["feature"].isin(selected)].copy()
    selected_audit = selected_audit.sort_values(
        ["group", "final_select_score"],
        ascending=[True, False]
    )

    selected_audit.to_csv(out_audit, index=False)

    summary = (
        selected_audit.groupby("group", as_index=False)
        .agg(
            feature_count=("feature", "count"),
            mean_audit_score=("audit_score", "mean"),
            max_audit_score=("audit_score", "max"),
            mean_final_select_score=("final_select_score", "mean"),
            proxy_count=("proxy_flags", lambda x: sum(str(v) != "" for v in x)),
        )
        .sort_values(["feature_count", "mean_audit_score"], ascending=False)
    )

    summary.to_csv(out_summary, index=False)

    log("")
    log("========== SELECTED GROUP SUMMARY ==========")
    log(summary.to_string(index=False))

    log("")
    log("[OK] dataset:", out_csv)
    log("[OK] feature list:", out_list)
    log("[OK] selected audit:", out_audit)
    log("[OK] summary:", out_summary)


if __name__ == "__main__":
    main()
