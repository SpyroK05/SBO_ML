#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd


ID_COLS = {
    "binary", "binary_norm", "program_name", "json_file", "source_core",
    "build_config", "function", "name_norm", "entry", "schema",
    "merge_stage", "candidate_reasons", "label",
}


def log(*x):
    print(*x, flush=True)


def auto_find_data():
    patterns = [
        "outputs/features/**/dataset_v6_pruned_score_corr_top260.csv",
        "outputs/features/final_selected/dataset_security_full_top260.csv",
        "outputs/features/dataset_labeled_sbo_rich_v6_context_clean.csv",
        "samples/dataset_v6_pruned_score_corr_top260.csv",
    ]

    cands = []
    for pat in patterns:
        cands.extend(Path(".").glob(pat))

    cands = [p for p in cands if p.exists()]

    if not cands:
        return None

    def priority(p):
        s = str(p)
        if "score_corr_top260" in s:
            return 0
        if "final_selected" in s:
            return 1
        if "v6_context_clean" in s:
            return 2
        return 9

    cands = sorted(cands, key=lambda p: (priority(p), len(str(p))))
    return cands[0]


def auto_find_model_dir():
    patterns = [
        "outputs/models*top260",
        "outputs/**/models*top260",
        "models/*top260*",
        "models/final_model_security_top260",
    ]

    cands = []
    for pat in patterns:
        cands.extend(Path(".").glob(pat))

    cands = [p for p in cands if p.is_dir() and (p / "model_metrics.csv").exists()]

    if not cands:
        return None

    return sorted(cands, key=lambda p: len(str(p)))[0]


def infer_model_features(model_dir):
    if not model_dir:
        return None, None, {}

    model_dir = Path(model_dir)
    if not model_dir.exists():
        return None, None, {}

    feature_cols = None
    source_model = None
    importances = {}

    for name in [
        "RandomForest",
        "DecisionTree",
        "XGBoost",
        "LogisticRegression",
    ]:
        p = model_dir / f"{name}.joblib"
        if not p.exists():
            continue

        try:
            m = joblib.load(p)
        except Exception as e:
            log("[WARN] cannot load", p, e)
            continue

        if feature_cols is None and hasattr(m, "feature_names_in_"):
            feature_cols = list(m.feature_names_in_)
            source_model = name

        if hasattr(m, "feature_importances_") and hasattr(m, "feature_names_in_"):
            for f, v in zip(m.feature_names_in_, m.feature_importances_):
                importances[str(f)] = float(v)

    return feature_cols, source_model, importances


def feature_group(c):
    c = str(c)
    cl = c.lower()

    if c.startswith(("pcode_", "mnemonic_")):
        return "opcode_like"

    if c.startswith("sinks_v6_"):
        return "v6_sink"

    if c.startswith(("sink_summary_", "buffer_summary_", "v4_summary_")):
        return "sink_buffer_summary"

    if c.startswith(("local_buffers_", "v6_aliases_", "v6_alias_summary_")):
        return "raw_buffer_alias"

    if c.startswith(("v6_summary_", "v6_loop_summary_", "v6_function_role_")):
        return "v6_summary"

    if c.startswith("cfg_"):
        return "cfg_control_flow"

    if c.startswith("stack_"):
        return "stack_memory"

    if c.startswith("callgraph_"):
        return "callgraph_context"

    if any(k in cl for k in [
        "risk", "safe", "guard", "bound", "check", "overflow"
    ]):
        return "risk_safe"

    if any(k in cl for k in [
        "dst", "src", "source", "size", "sink", "line_index"
    ]):
        return "dataflow_sink_size"

    if c.startswith("summary_"):
        return "program_static"

    return "other"


def proxy_flags(c):
    cl = str(c).lower()
    flags = []

    patterns = {
        "line_index": ["line_index"],
        "stack_offset": ["stack_offset"],
        "size_proxy": [
            "instruction_count",
            "decompiled_line_count",
            "line_count",
            "caller_names_count",
            "callee_names_count",
        ],
        "generic_count": [
            "summary_instruction_count",
            "callgraph_caller_names_count",
        ],
    }

    for name, pats in patterns.items():
        if any(p in cl for p in pats):
            flags.append(name)

    return ",".join(flags)


def normalize(s):
    s = pd.Series(s).replace([np.inf, -np.inf], np.nan).fillna(0.0)
    mn, mx = float(s.min()), float(s.max())
    if abs(mx - mn) < 1e-12:
        return pd.Series(np.zeros(len(s)), index=s.index)
    return (s - mn) / (mx - mn)


def get_numeric_features(df):
    cols = []

    for c in df.columns:
        if c in ID_COLS:
            continue

        x = pd.to_numeric(df[c], errors="coerce")
        if x.notna().sum() == 0:
            continue

        x = x.replace([np.inf, -np.inf], np.nan).fillna(0)
        if x.nunique(dropna=False) <= 1:
            continue

        cols.append(c)

    return cols


def compute_audit(df, feature_cols, rf_importance):
    rows = []

    present = [c for c in feature_cols if c in df.columns]

    X = df[present].apply(pd.to_numeric, errors="coerce")
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0.0)

    y = None
    has_label = "label" in df.columns and set(pd.unique(df["label"].dropna())).issubset({0, 1})

    if has_label:
        y = df["label"].astype(int).values
        y_mean = y.mean()
        y_std = y.std() + 1e-12

    mi_map = {}

    if has_label:
        try:
            from sklearn.feature_selection import mutual_info_classif
            mi = mutual_info_classif(
                X.values,
                y,
                random_state=1337,
                discrete_features=False,
            )
            mi_map = {c: float(v) for c, v in zip(present, mi)}
        except Exception as e:
            log("[WARN] mutual_info failed:", e)

    for c in present:
        x = X[c].values.astype(float)

        nonzero = float((x != 0).mean())
        nunique = int(pd.Series(x).nunique(dropna=False))

        mean_all = float(np.mean(x))
        std_all = float(np.std(x))

        mean_safe = np.nan
        mean_vuln = np.nan
        diff = np.nan
        separation = np.nan
        corr = np.nan

        if has_label:
            x0 = x[y == 0]
            x1 = x[y == 1]

            mean_safe = float(np.mean(x0)) if len(x0) else 0.0
            mean_vuln = float(np.mean(x1)) if len(x1) else 0.0
            diff = mean_vuln - mean_safe
            separation = abs(diff) / (std_all + 1e-12)

            if std_all > 1e-12:
                corr = float(np.mean((x - x.mean()) * (y - y_mean)) / ((std_all + 1e-12) * y_std))

        rows.append({
            "feature": c,
            "group": feature_group(c),
            "proxy_flags": proxy_flags(c),
            "nonzero_rate": nonzero,
            "nunique": nunique,
            "mean_all": mean_all,
            "mean_safe": mean_safe,
            "mean_vulnerable": mean_vuln,
            "mean_diff_vuln_minus_safe": diff,
            "separation": separation,
            "abs_corr_label": abs(corr) if not pd.isna(corr) else 0.0,
            "corr_label": corr if not pd.isna(corr) else 0.0,
            "mutual_info": mi_map.get(c, 0.0),
            "rf_importance": rf_importance.get(c, 0.0),
        })

    audit = pd.DataFrame(rows)

    if audit.empty:
        return audit

    audit["score_corr_n"] = normalize(audit["abs_corr_label"])
    audit["score_mi_n"] = normalize(audit["mutual_info"])
    audit["score_sep_n"] = normalize(audit["separation"])
    audit["score_rf_n"] = normalize(audit["rf_importance"])

    audit["audit_score"] = (
        0.35 * audit["score_corr_n"]
        + 0.25 * audit["score_mi_n"]
        + 0.20 * audit["score_sep_n"]
        + 0.20 * audit["score_rf_n"]
    )

    semantic_core = {
        "v6_sink",
        "sink_buffer_summary",
        "risk_safe",
        "stack_memory",
        "raw_buffer_alias",
        "v6_summary",
    }

    audit["semantic_core"] = audit["group"].isin(semantic_core).astype(int)
    audit["has_proxy_flag"] = (audit["proxy_flags"].astype(str) != "").astype(int)

    def hint(row):
        if row["semantic_core"] and row["audit_score"] >= 0.25:
            return "strong_keep_candidate"
        if row["semantic_core"] and row["audit_score"] >= 0.12:
            return "keep_review"
        if row["has_proxy_flag"] and row["audit_score"] < 0.25:
            return "proxy_review"
        if row["audit_score"] < 0.08:
            return "low_signal_review"
        return "neutral_review"

    audit["review_hint"] = audit.apply(hint, axis=1)

    audit = audit.sort_values(
        ["audit_score", "semantic_core", "nonzero_rate"],
        ascending=False,
    ).reset_index(drop=True)

    return audit


def write_chat_txt(audit, group_summary, out_txt, data_path, model_dir, source_model):
    lines = []

    lines.append("========== FEATURE INVENTORY FOR REVIEW ==========")
    lines.append(f"DATASET: {data_path}")
    lines.append(f"MODEL_DIR: {model_dir}")
    lines.append(f"FEATURE_SOURCE_MODEL: {source_model}")
    lines.append(f"TOTAL_FEATURES: {len(audit)}")
    lines.append("")

    lines.append("========== GROUP SUMMARY ==========")
    for _, r in group_summary.iterrows():
        lines.append(
            f"{r['group']:24s} count={int(r['feature_count']):4d} "
            f"mean_score={r['mean_audit_score']:.6f} "
            f"max_score={r['max_audit_score']:.6f} "
            f"mean_nonzero={r['mean_nonzero_rate']:.6f}"
        )

    lines.append("")
    lines.append("========== TOP 120 FEATURES BY AUDIT SCORE ==========")

    cols = [
        "feature", "group", "audit_score", "abs_corr_label",
        "mutual_info", "separation", "rf_importance",
        "nonzero_rate", "proxy_flags", "review_hint",
    ]

    for _, r in audit.head(120)[cols].iterrows():
        lines.append(
            f"{r['audit_score']:.6f} | {r['group']:22s} | "
            f"corr={r['abs_corr_label']:.6f} mi={r['mutual_info']:.6f} "
            f"sep={r['separation']:.6f} rf={r['rf_importance']:.6f} "
            f"nz={r['nonzero_rate']:.4f} | "
            f"proxy={r['proxy_flags']} | {r['review_hint']} | {r['feature']}"
        )

    lines.append("")
    lines.append("========== FEATURES BY GROUP ==========")

    for g in group_summary["group"].tolist():
        lines.append("")
        lines.append(f"---- {g} ----")
        sub = audit[audit["group"] == g].sort_values("audit_score", ascending=False)

        for _, r in sub.iterrows():
            lines.append(
                f"{r['audit_score']:.6f} | {r['feature']} "
                f"| proxy={r['proxy_flags']} | hint={r['review_hint']}"
            )

    Path(out_txt).write_text("\n".join(lines), encoding="utf-8")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="")
    ap.add_argument("--model-dir", default="")
    ap.add_argument("--out-dir", default="outputs/reports/feature_inventory_review")
    args = ap.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    data_path = Path(args.data) if args.data else auto_find_data()
    model_dir = Path(args.model_dir) if args.model_dir else auto_find_model_dir()

    if data_path is None or not Path(data_path).exists():
        raise SystemExit(
            "Không tìm thấy dataset. Hãy truyền --data path/to/dataset_v6_pruned_score_corr_top260.csv"
        )

    log("[DATA]", data_path)
    log("[MODEL_DIR]", model_dir)

    feature_cols, source_model, rf_importance = infer_model_features(model_dir)

    df = pd.read_csv(data_path, low_memory=False)

    if feature_cols is None:
        feature_cols = get_numeric_features(df)
        source_model = "dataset_numeric_columns"

    present = [c for c in feature_cols if c in df.columns]
    missing = [c for c in feature_cols if c not in df.columns]

    log("[INFO] dataset shape:", df.shape)
    log("[INFO] feature cols from source:", len(feature_cols))
    log("[INFO] present in dataset:", len(present))
    log("[INFO] missing in dataset:", len(missing))

    audit = compute_audit(df, feature_cols, rf_importance)

    if audit.empty:
        raise SystemExit("Audit rỗng.")

    group_summary = (
        audit.groupby("group", as_index=False)
        .agg(
            feature_count=("feature", "count"),
            mean_audit_score=("audit_score", "mean"),
            max_audit_score=("audit_score", "max"),
            mean_nonzero_rate=("nonzero_rate", "mean"),
            proxy_count=("has_proxy_flag", "sum"),
            core_count=("semantic_core", "sum"),
        )
        .sort_values(["mean_audit_score", "feature_count"], ascending=False)
    )

    audit.to_csv(out_dir / "feature_inventory_all.csv", index=False)
    audit.head(160).to_csv(out_dir / "feature_inventory_top160.csv", index=False)
    group_summary.to_csv(out_dir / "feature_group_summary.csv", index=False)

    write_chat_txt(
        audit=audit,
        group_summary=group_summary,
        out_txt=out_dir / "feature_inventory_for_chat.txt",
        data_path=data_path,
        model_dir=model_dir,
        source_model=source_model,
    )

    meta = {
        "data": str(data_path),
        "model_dir": str(model_dir),
        "source_model": source_model,
        "dataset_shape": list(df.shape),
        "features_total": int(len(feature_cols)),
        "features_present": int(len(present)),
        "features_missing": int(len(missing)),
        "out_dir": str(out_dir),
    }

    (out_dir / "feature_inventory_meta.json").write_text(
        json.dumps(meta, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    log("")
    log("========== GROUP SUMMARY ==========")
    log(group_summary.to_string(index=False))

    log("")
    log("========== TOP 60 FEATURES ==========")
    show_cols = [
        "feature", "group", "audit_score", "abs_corr_label",
        "mutual_info", "separation", "rf_importance",
        "nonzero_rate", "proxy_flags", "review_hint",
    ]
    log(audit.head(60)[show_cols].to_string(index=False))

    log("")
    log("[OK] wrote:", out_dir / "feature_inventory_for_chat.txt")
    log("[OK] wrote:", out_dir / "feature_inventory_all.csv")
    log("[OK] wrote:", out_dir / "feature_group_summary.csv")


if __name__ == "__main__":
    main()
