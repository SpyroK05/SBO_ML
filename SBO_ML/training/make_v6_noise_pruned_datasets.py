#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
from pathlib import Path

import numpy as np
import pandas as pd

from sklearn.model_selection import StratifiedGroupKFold, train_test_split
from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier
from sklearn.feature_selection import mutual_info_classif


ID_COLS = {
    "binary", "binary_norm", "program_name", "json_file", "source_core",
    "build_config", "function", "name_norm", "entry", "schema",
    "merge_stage", "candidate_reasons", "label",
}


def log(*x):
    print(*x, flush=True)


def norm01(x):
    x = np.asarray(x, dtype=float)
    x = np.nan_to_num(x, nan=0.0, posinf=0.0, neginf=0.0)
    lo = float(np.min(x))
    hi = float(np.max(x))
    if hi <= lo:
        return np.zeros_like(x)
    return (x - lo) / (hi - lo)


def feature_group(c):
    if c.startswith(("pcode_", "mnemonic_")):
        return "opcode_like"
    if c.startswith(("local_buffers_", "v6_aliases_")):
        return "raw_buffer_alias"
    if c.startswith(("v6_summary_", "v6_loop_summary_", "v6_function_role_")):
        return "v6_summary"
    if c.startswith("sinks_v6_"):
        return "v6_sink"
    if c.startswith(("sink_summary_", "buffer_summary_", "v4_summary_")):
        return "sink_buffer_summary"
    if c.startswith(("stack_", "cfg_", "summary_", "callgraph_")):
        return "program_static"
    if "risk" in c or "safe" in c or "guard" in c or "overflow" in c:
        return "risk_safe"
    return "other"


def group_weight(c):
    g = feature_group(c)

    if g == "opcode_like":
        return 0.90
    if g == "raw_buffer_alias":
        return 0.88
    if g in {"v6_summary", "v6_sink", "risk_safe"}:
        return 1.08
    if g in {"sink_buffer_summary", "program_static"}:
        return 1.03

    return 1.00


def split_selector(X, y, groups, seed):
    try:
        sgkf = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=seed)
        tr, va = next(sgkf.split(X, y, groups))
        return tr, va, "stratified_group"
    except Exception as e:
        log("[WARN] StratifiedGroupKFold failed:", e)
        idx = np.arange(len(y))
        tr, va = train_test_split(
            idx,
            test_size=0.25,
            random_state=seed,
            stratify=y if len(np.unique(y)) == 2 else None,
        )
        return tr, va, "random_stratified"


def make_numeric_matrix(df):
    feature_cols = []

    for c in df.columns:
        if c in ID_COLS:
            continue

        s = pd.to_numeric(df[c], errors="coerce")
        if s.notna().sum() > 0:
            feature_cols.append(c)

    X = df[feature_cols].apply(pd.to_numeric, errors="coerce")
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0.0)

    nunique = X.nunique(dropna=False)
    feature_cols = [c for c in feature_cols if int(nunique[c]) > 1]
    X = X[feature_cols].copy()

    return X, feature_cols


def compute_scores(X, y, groups, seed, n_jobs, trees, mi_sample):
    tr, va, split_name = split_selector(X, y, groups, seed)
    log("[INFO] selector split:", split_name)
    log("[INFO] selector train:", len(tr), "hold:", len(va))

    Xtr = X.iloc[tr]
    ytr = y[tr]

    log("[1] Train selector RandomForest")
    rf = RandomForestClassifier(
        n_estimators=trees,
        max_features="sqrt",
        min_samples_leaf=1,
        class_weight="balanced_subsample",
        n_jobs=n_jobs,
        random_state=seed,
    )
    rf.fit(Xtr, ytr)

    log("[2] Train selector ExtraTrees")
    et = ExtraTreesClassifier(
        n_estimators=trees,
        max_features="sqrt",
        min_samples_leaf=1,
        class_weight="balanced",
        n_jobs=n_jobs,
        random_state=seed + 17,
    )
    et.fit(Xtr, ytr)

    log("[3] Mutual information")
    rng = np.random.default_rng(seed)

    if len(tr) > mi_sample:
        mi_idx = rng.choice(tr, size=mi_sample, replace=False)
    else:
        mi_idx = tr

    mi = mutual_info_classif(
        X.iloc[mi_idx],
        y[mi_idx],
        random_state=seed,
        discrete_features=False,
    )

    log("[4] Class separation")
    pos = Xtr[ytr == 1]
    neg = Xtr[ytr == 0]

    mean_diff = (pos.mean(axis=0) - neg.mean(axis=0)).abs()
    std_all = Xtr.std(axis=0).replace(0, np.nan)
    sep = (mean_diff / std_all).replace([np.inf, -np.inf], np.nan).fillna(0.0).values

    nonzero_ratio = (X != 0).mean(axis=0).values
    unique_count = X.nunique(dropna=False).values

    rf_n = norm01(rf.feature_importances_)
    et_n = norm01(et.feature_importances_)
    mi_n = norm01(mi)
    sep_n = norm01(sep)

    base_score = 0.42 * rf_n + 0.32 * et_n + 0.16 * mi_n + 0.10 * sep_n

    features = list(X.columns)
    weights = np.array([group_weight(c) for c in features], dtype=float)
    final_score = base_score * weights

    rank = pd.DataFrame({
        "feature": features,
        "group": [feature_group(c) for c in features],
        "score": final_score,
        "base_score": base_score,
        "rf_importance": rf.feature_importances_,
        "et_importance": et.feature_importances_,
        "mutual_info": mi,
        "class_separation": sep,
        "nonzero_ratio": nonzero_ratio,
        "unique_count": unique_count,
        "group_weight": weights,
    })

    rank = rank.sort_values("score", ascending=False).reset_index(drop=True)
    return rank, tr


def corr_prune_order(X_train, ranked_features, score_map, threshold):
    cols = [c for c in ranked_features if c in X_train.columns]

    log("[INFO] correlation matrix cols:", len(cols))
    corr = X_train[cols].corr().abs().fillna(0.0)

    selected = []

    for c in cols:
        keep = True

        for s in selected:
            if float(corr.loc[c, s]) >= threshold:
                keep = False
                break

        if keep:
            selected.append(c)

    return selected


def write_dataset(df, out_dir, name, features):
    meta = [c for c in df.columns if c in ID_COLS]
    cols = []

    for c in meta + list(features):
        if c in df.columns and c not in cols:
            cols.append(c)

    out = out_dir / f"dataset_v6_pruned_{name}.csv"
    df[cols].to_csv(out, index=False)
    log("[WRITE]", out, df[cols].shape)


def main():
    ap = argparse.ArgumentParser()

    ap.add_argument("--data", required=True)
    ap.add_argument("--out-dir", default="outputs/features/v6_pruned")
    ap.add_argument("--group-col", default="source_core")
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--n-jobs", type=int, default=4)
    ap.add_argument("--trees", type=int, default=500)
    ap.add_argument("--mi-sample", type=int, default=20000)
    ap.add_argument("--corr-threshold", type=float, default=0.995)
    ap.add_argument("--topk", default="220,260,300,340")

    args = ap.parse_args()

    data = Path(args.data)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    log("[LOAD]", data)
    df = pd.read_csv(data, low_memory=False)

    df["label"] = pd.to_numeric(df["label"], errors="coerce")
    df = df[df["label"].isin([0, 1])].copy()
    df["label"] = df["label"].astype(int)

    y = df["label"].astype(int).values

    if args.group_col in df.columns:
        groups = df[args.group_col].astype(str).values
    else:
        groups = np.arange(len(df)).astype(str)

    log("[INFO] dataset:", df.shape)
    log("[INFO] labels:")
    log(df["label"].value_counts().to_string())

    X, features = make_numeric_matrix(df)

    log("[INFO] usable nonconstant numeric:", len(features))

    rank, tr = compute_scores(
        X=X,
        y=y,
        groups=groups,
        seed=args.seed,
        n_jobs=args.n_jobs,
        trees=args.trees,
        mi_sample=args.mi_sample,
    )

    rank_path = out_dir / "v6_feature_noise_ranking.csv"
    rank.to_csv(rank_path, index=False)
    log("[OK] ranking:", rank_path)

    score_map = dict(zip(rank["feature"], rank["score"]))

    ranked_features = rank["feature"].tolist()
    Xtr = X.iloc[tr]

    corr_order = corr_prune_order(
        X_train=Xtr,
        ranked_features=ranked_features,
        score_map=score_map,
        threshold=args.corr_threshold,
    )

    corr_rank = pd.DataFrame({
        "feature": corr_order,
        "corr_pruned_order": np.arange(1, len(corr_order) + 1),
        "score": [score_map[c] for c in corr_order],
        "group": [feature_group(c) for c in corr_order],
    })

    corr_rank_path = out_dir / "v6_feature_corr_pruned_order.csv"
    corr_rank.to_csv(corr_rank_path, index=False)
    log("[OK] corr order:", corr_rank_path)
    log("[INFO] corr-pruned features:", len(corr_order))

    topks = [int(x.strip()) for x in args.topk.split(",") if x.strip()]

    drop_group_clean = [
        c for c in df.columns
        if c.startswith(("pcode_", "mnemonic_", "local_buffers_", "v6_aliases_"))
    ]

    group_clean_features = [
        c for c in features
        if c not in set(drop_group_clean)
    ]

    write_dataset(df, out_dir, "group_clean", group_clean_features)

    drop_semantic = [
        c for c in df.columns
        if c.startswith(("pcode_", "mnemonic_", "local_buffers_", "v6_aliases_"))
    ]

    semantic_features = [
        c for c in features
        if c not in set(drop_semantic)
    ]

    write_dataset(df, out_dir, "semantic_clean", semantic_features)

    for k in topks:
        feats = ranked_features[:min(k, len(ranked_features))]
        write_dataset(df, out_dir, f"score_top{k}", feats)

    for k in topks:
        feats = corr_order[:min(k, len(corr_order))]
        write_dataset(df, out_dir, f"score_corr_top{k}", feats)

    security_groups = {
        "v6_summary",
        "v6_sink",
        "risk_safe",
        "sink_buffer_summary",
        "program_static",
    }

    sec_ranked = [
        c for c in corr_order
        if feature_group(c) in security_groups
    ]

    for k in [220, 260, 300]:
        feats = sec_ranked[:min(k, len(sec_ranked))]
        write_dataset(df, out_dir, f"security_corr_top{k}", feats)

    log("[DONE] wrote datasets to:", out_dir)


if __name__ == "__main__":
    main()
