#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import warnings
import os
import sys
import importlib.metadata
from pathlib import Path
from collections import OrderedDict

import joblib
import numpy as np
import pandas as pd

from sklearn.model_selection import train_test_split, StratifiedGroupKFold
from sklearn.metrics import (
    accuracy_score, balanced_accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, average_precision_score, confusion_matrix
)
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier

# Keep compatibility and convergence warnings visible.

try:
    from xgboost import XGBClassifier
    HAS_XGB = True
except Exception:
    HAS_XGB = False


ID_COLS = {
    "binary", "binary_norm", "program_name", "json_file", "source_core",
    "build_config", "function", "name_norm", "entry", "schema",
    "merge_stage", "candidate_reasons", "label",
}

RISK_TOKENS = [
    "vuln_signal", "safe_signal", "risk_score", "safe_score", "risk_minus_safe",
    "rule_", "strict_", "txt_", "interproc", "ip_", "loop", "alias", "alloca",
    "high_quality_guard", "literal_stack", "bounded_stack", "external_source",
    "size_overflow", "unbounded_stack",
]


def log(*xs):
    print(*xs, flush=True)


def parse_float_list(s):
    return [float(x.strip()) for x in str(s).split(",") if x.strip()]


def safe_auc(y, p):
    try:
        return roc_auc_score(y, p)
    except Exception:
        return np.nan


def safe_ap(y, p):
    try:
        return average_precision_score(y, p)
    except Exception:
        return np.nan


def eval_prob(y, p, thr):
    yp = (p >= thr).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, yp, labels=[0, 1]).ravel()

    return {
        "test_accuracy": accuracy_score(y, yp),
        "test_balanced_accuracy": balanced_accuracy_score(y, yp),
        "test_precision_vulnerable": precision_score(y, yp, zero_division=0),
        "test_recall_vulnerable": recall_score(y, yp, zero_division=0),
        "test_f1_vulnerable": f1_score(y, yp, zero_division=0),
        "test_macro_f1": f1_score(y, yp, average="macro", zero_division=0),
        "test_roc_auc": safe_auc(y, p),
        "test_average_precision": safe_ap(y, p),
        "test_tn": int(tn),
        "test_fp": int(fp),
        "test_fn": int(fn),
        "test_tp": int(tp),
    }


def val_metric(y, p, thr):
    yp = (p >= thr).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, yp, labels=[0, 1]).ravel()

    return {
        "threshold": float(thr),
        "f1": f1_score(y, yp, zero_division=0),
        "recall": recall_score(y, yp, zero_division=0),
        "precision": precision_score(y, yp, zero_division=0),
        "accuracy": accuracy_score(y, yp),
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
    }


def better(cand, best, recall_min=None):
    if best is None:
        return True

    if recall_min is not None:
        cand_ok = cand["recall"] >= recall_min
        best_ok = best["recall"] >= recall_min

        if cand_ok and not best_ok:
            return True
        if best_ok and not cand_ok:
            return False

    if cand["f1"] > best["f1"]:
        return True

    if cand["f1"] == best["f1"]:
        if cand["recall"] > best["recall"]:
            return True

        if cand["recall"] == best["recall"]:
            if cand["fp"] < best["fp"]:
                return True

            if cand["fp"] == best["fp"] and cand["precision"] > best["precision"]:
                return True

    return False


def tune_threshold(y, p, recall_min=None):
    best = None

    for thr in np.arange(0.05, 0.951, 0.005):
        cand = val_metric(y, p, thr)

        if better(cand, best, recall_min):
            best = cand

    return best


def group_col(df):
    for c in ["source_core", "binary_norm", "binary", "program_name", "json_file"]:
        if c in df.columns:
            return c

    return None


def split_data(y, groups, random_state):
    idx = np.arange(len(y))

    if groups is None or len(set(groups)) < 5:
        train_val, test = train_test_split(
            idx,
            test_size=0.20,
            stratify=y,
            random_state=random_state,
        )

        train, val = train_test_split(
            train_val,
            test_size=0.25,
            stratify=y[train_val],
            random_state=random_state,
        )

        return train, val, test, "stratified_random"

    sgkf = StratifiedGroupKFold(
        n_splits=5,
        shuffle=True,
        random_state=random_state,
    )

    train_val, test = next(sgkf.split(idx, y, groups))

    sgkf2 = StratifiedGroupKFold(
        n_splits=4,
        shuffle=True,
        random_state=random_state + 1,
    )

    local_train, local_val = next(
        sgkf2.split(
            np.arange(len(train_val)),
            y[train_val],
            groups[train_val],
        )
    )

    return train_val[local_train], train_val[local_val], test, "stratified_group_by_binary_core"


def load_dataset(path):
    log("[1] Load dataset...")

    df = pd.read_csv(path, low_memory=False)

    if "label" not in df.columns:
        raise SystemExit("[ERROR] Không thấy cột label")

    df["label"] = pd.to_numeric(df["label"], errors="coerce")
    df = df.dropna(subset=["label"]).copy()
    df["label"] = df["label"].astype(int)

    gcol = group_col(df)
    groups = df[gcol].astype(str).values if gcol else None

    y = df["label"].values

    log("[INFO] dataset shape:", df.shape)
    log("[INFO] label counts:")
    log(df["label"].value_counts().to_string())

    x_data = {}

    for c in df.columns:
        if c in ID_COLS:
            continue

        s = pd.to_numeric(df[c], errors="coerce")

        if s.notna().sum() == 0:
            continue

        x_data[c] = s.astype(np.float32)

    X = pd.DataFrame(x_data)
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0.0)

    nunique = X.nunique(dropna=False)
    const_cols = nunique[nunique <= 1].index.tolist()

    if const_cols:
        X = X.drop(columns=const_cols)

    log("[2] Prepare X/y...")
    log("[INFO] group col:", gcol)
    log("[INFO] usable numeric features:", X.shape[1])
    log("[INFO] dropped constant features:", len(const_cols))

    return df, X, y, groups, gcol, const_cols


def build_models(scale_pos_weight, n_jobs, random_state, rf_trees=500, xgb_trees=650, xgb_device="cpu"):
    if not HAS_XGB:
        raise SystemExit("[ERROR] Chưa cài xgboost. Trên Kaggle thường có sẵn; nếu thiếu hãy bật Internet rồi chạy: pip install xgboost")

    # Kaggle: GPU chỉ giúp XGBoost, còn RandomForest/DecisionTree vẫn chạy CPU.
    # Để ổn định trên mọi version XGBoost, mặc định dùng CPU hist.
    xgb_params = dict(
        n_estimators=int(xgb_trees),
        max_depth=5,
        learning_rate=0.035,
        subsample=0.90,
        colsample_bytree=0.90,
        reg_lambda=2.0,
        reg_alpha=0.05,
        objective="binary:logistic",
        eval_metric="logloss",
        tree_method="hist",
        random_state=random_state,
        n_jobs=n_jobs,
        scale_pos_weight=scale_pos_weight,
    )

    if str(xgb_device).lower() in {"cuda", "gpu"}:
        # XGBoost >= 2.x: device="cuda"; XGBoost cũ: tree_method="gpu_hist".
        # Nếu Kaggle báo lỗi, chạy lại với --xgb-device cpu.
        xgb_params["device"] = "cuda"

    return OrderedDict({
        "LogisticRegression": Pipeline([
            ("scaler", StandardScaler()),
            ("clf", LogisticRegression(
                max_iter=3000,
                class_weight="balanced",
                solver="lbfgs",
            )),
        ]),

        "DecisionTree": DecisionTreeClassifier(
            random_state=random_state,
            class_weight="balanced",
            min_samples_leaf=2,
        ),

        "RandomForest": RandomForestClassifier(
            n_estimators=int(rf_trees),
            random_state=random_state,
            class_weight="balanced_subsample",
            n_jobs=n_jobs,
            max_features="sqrt",
            min_samples_leaf=1,
        ),

        "XGBoost": XGBClassifier(**xgb_params),
    })


def prob(model, X):
    return model.predict_proba(X)[:, 1]


def signed_log1p(x):
    x = np.asarray(x, dtype=float)
    return np.sign(x) * np.log1p(np.abs(x))


def select_risk_cols(X):
    cols = []

    for c in X.columns:
        if any(t in c for t in RISK_TOKENS):
            cols.append(c)

    return cols[:160]


def meta_matrix(Xdf, probs, risk_cols=None):
    out = pd.DataFrame(index=Xdf.index)

    names = list(probs.keys())

    for n in names:
        p = np.asarray(probs[n], dtype=float)
        out[f"p_{n}"] = p
        out[f"u_{n}"] = 1.0 - 2.0 * np.abs(p - 0.5)

    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            a = names[i]
            b = names[j]
            out[f"diff_{a}_minus_{b}"] = np.asarray(probs[a]) - np.asarray(probs[b])
            out[f"absdiff_{a}_{b}"] = np.abs(np.asarray(probs[a]) - np.asarray(probs[b]))

    if risk_cols:
        for c in risk_cols:
            if c in Xdf.columns:
                out[c] = signed_log1p(Xdf[c].values)

    return out.replace([np.inf, -np.inf], np.nan).fillna(0.0)


def weight_grid(k, step):
    units = int(round(1.0 / step))
    cur = []

    def rec(pos, remain):
        if pos == k - 1:
            yield cur + [remain]
            return

        for v in range(remain + 1):
            cur.append(v)
            yield from rec(pos + 1, remain - v)
            cur.pop()

    for ints in rec(0, units):
        yield np.array(ints, dtype=float) / units


def optimize_weighted(y, probs, names, recall_min, step, max_lr_weight=0.10):
    P = np.vstack([probs[n] for n in names]).T
    best = None

    for w in weight_grid(len(names), step):
        if "LogisticRegression" in names:
            idx = names.index("LogisticRegression")
            if w[idx] > max_lr_weight:
                continue

        p = P.dot(w)
        cand = tune_threshold(y, p, recall_min=recall_min)
        cand["weights"] = {names[i]: float(w[i]) for i in range(len(names))}

        if better(cand, best, recall_min):
            best = cand

    return best


def apply_weighted(probs, info):
    p = None

    for name, w in info["weights"].items():
        if p is None:
            p = w * np.asarray(probs[name])
        else:
            p += w * np.asarray(probs[name])

    return p


def train_stack(X_meta, y_meta, X_select, y_select, X_test, recall_min, C):
    meta = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", LogisticRegression(
            max_iter=3000,
            C=C,
            class_weight="balanced",
        )),
    ])

    meta.fit(X_meta, y_meta)

    p_select = meta.predict_proba(X_select)[:, 1]
    thr = tune_threshold(y_select, p_select, recall_min=recall_min)

    p_test = meta.predict_proba(X_test)[:, 1]

    return meta, thr, p_test


def dynamic_gate_pair(
    X_gate_meta, y_meta, p_a_meta, p_b_meta,
    X_gate_select, y_select, p_a_select, p_b_select,
    X_gate_test, p_a_test, p_b_test,
    w_min_opts, w_max_opts, recall_min
):
    target = (
        np.abs(y_meta - p_b_meta)
        < np.abs(y_meta - p_a_meta)
    ).astype(int)

    if len(np.unique(target)) < 2:
        raw_select = np.full(len(y_select), target.mean())
        raw_test = np.full(len(p_a_test), target.mean())
        gate = None
    else:
        gate = Pipeline([
            ("scaler", StandardScaler()),
            ("clf", LogisticRegression(
                max_iter=3000,
                C=0.35,
                class_weight="balanced",
            )),
        ])

        gate.fit(X_gate_meta, target)

        raw_select = gate.predict_proba(X_gate_select)[:, 1]
        raw_test = gate.predict_proba(X_gate_test)[:, 1]

    best = None

    for w_min in w_min_opts:
        for w_max in w_max_opts:
            if w_max <= w_min:
                continue

            w = w_min + (w_max - w_min) * raw_select
            p = w * p_b_select + (1.0 - w) * p_a_select

            cand = tune_threshold(y_select, p, recall_min=recall_min)
            cand["gate_w_min"] = float(w_min)
            cand["gate_w_max"] = float(w_max)

            if better(cand, best, recall_min):
                best = cand

    w_test = best["gate_w_min"] + (best["gate_w_max"] - best["gate_w_min"]) * raw_test
    p_test = w_test * p_b_test + (1.0 - w_test) * p_a_test

    return gate, best, p_test, w_test


def softmax_gate_3(
    X_meta, y_meta, probs_meta,
    X_select, y_select, probs_select,
    X_test, probs_test,
    names, recall_min
):
    P_meta = np.vstack([probs_meta[n] for n in names]).T
    target = np.argmin(np.abs(P_meta - y_meta.reshape(-1, 1)), axis=1)

    gate = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", LogisticRegression(
            max_iter=3000,
            C=0.35,
            multi_class="multinomial",
            class_weight="balanced",
        )),
    ])

    gate.fit(X_meta, target)

    def aligned_predict(model, X):
        raw = model.predict_proba(X)
        classes = model.named_steps["clf"].classes_

        out = np.zeros((len(X), len(names)))

        for j, cls in enumerate(classes):
            out[:, int(cls)] = raw[:, j]

        s = out.sum(axis=1, keepdims=True)
        s[s == 0] = 1.0

        return out / s

    W_select = aligned_predict(gate, X_select)
    P_select = np.vstack([probs_select[n] for n in names]).T
    p_select = (W_select * P_select).sum(axis=1)

    thr = tune_threshold(y_select, p_select, recall_min=recall_min)

    W_test = aligned_predict(gate, X_test)
    P_test = np.vstack([probs_test[n] for n in names]).T
    p_test = (W_test * P_test).sum(axis=1)

    return gate, thr, p_test, W_test


def add_row(rows, model, role, threshold, ev, extra=None):
    row = {
        "model": model,
        "role": role,
        "best_threshold": threshold,
        "weight_rf": np.nan,
        "weight_xgb": np.nan,
        "weight_tree": np.nan,
        "weight_logistic": np.nan,
        "gate_w_min": np.nan,
        "gate_w_max": np.nan,
    }

    if extra:
        row.update(extra)

    row.update(ev)
    rows.append(row)


def cross_error_analysis(y, pred_dict, out):
    rows = []
    names = list(pred_dict.keys())

    for a in names:
        for b in names:
            if a == b:
                continue

            pa = pred_dict[a]
            pb = pred_dict[b]

            rows.append({
                "base_model": a,
                "helper_model": b,
                "base_FN_helper_TP": int(((y == 1) & (pa == 0) & (pb == 1)).sum()),
                "base_FP_helper_TN": int(((y == 0) & (pa == 1) & (pb == 0)).sum()),
                "base_TP_helper_FN": int(((y == 1) & (pa == 1) & (pb == 0)).sum()),
                "base_TN_helper_FP": int(((y == 0) & (pa == 0) & (pb == 1)).sum()),
                "both_FN": int(((y == 1) & (pa == 0) & (pb == 0)).sum()),
                "both_FP": int(((y == 0) & (pa == 1) & (pb == 1)).sum()),
            })

    pd.DataFrame(rows).to_csv(out, index=False)


def main():
    ap = argparse.ArgumentParser()

    ap.add_argument("--data", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--split-mode", default="group", choices=["group", "random"])
    ap.add_argument("--split-manifest", default="", help="Shared split generated before feature selection.")
    ap.add_argument("--n-jobs", type=int, default=max(1, min(4, os.cpu_count() or 2)))
    ap.add_argument("--rf-trees", type=int, default=300)
    ap.add_argument("--xgb-trees", type=int, default=450)
    ap.add_argument("--xgb-device", default="cpu", choices=["cpu", "cuda", "gpu"])
    ap.add_argument("--random-state", type=int, default=42)
    ap.add_argument("--recall-min", type=float, default=0.95)
    ap.add_argument("--weight-step", type=float, default=0.05)
    ap.add_argument("--gate-w-min-options", default="0.00,0.02,0.05")
    ap.add_argument("--gate-w-max-options", default="0.20,0.35,0.50,0.65")

    args = ap.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    df, X, y, groups, gcol, const_cols = load_dataset(args.data)

    if args.split_manifest:
        try:
            from .protocol import load_partitions
        except ImportError:
            from protocol import load_partitions
        partitions = load_partitions(args.split_manifest, args.data, df)
        train_idx, test_idx = partitions['train'], partitions['test']
        val_idx = np.concatenate([partitions['meta'], partitions['select']])
        split_used = "group_split_before_feature_selection_v1"
    elif args.split_mode == "group":
        train_idx, val_idx, test_idx, split_used = split_data(y, groups, args.random_state)
    else:
        idx = np.arange(len(y))

        train_val_idx, test_idx = train_test_split(
            idx,
            test_size=0.20,
            stratify=y,
            random_state=args.random_state,
        )

        train_idx, val_idx = train_test_split(
            train_val_idx,
            test_size=0.25,
            stratify=y[train_val_idx],
            random_state=args.random_state,
        )

        split_used = "stratified_random"

    if args.split_manifest:
        meta_idx, select_idx = partitions['meta'], partitions['select']
    else:
        log("[WARN] Legacy split mode: feature selection must already exclude test data.")
        meta_local, select_local = train_test_split(
            np.arange(len(val_idx)), test_size=0.50, stratify=y[val_idx],
            random_state=args.random_state + 77,
        )
        meta_idx = val_idx[meta_local]
        select_idx = val_idx[select_local]

    X_train = X.iloc[train_idx]
    X_val = X.iloc[val_idx]
    X_meta = X.iloc[meta_idx]
    X_select = X.iloc[select_idx]
    X_test = X.iloc[test_idx]

    y_train = y[train_idx]
    y_val = y[val_idx]
    y_meta = y[meta_idx]
    y_select = y[select_idx]
    y_test = y[test_idx]

    log("[3] Split train/val/test...")
    log("[INFO] split used:", split_used)
    log("[INFO] group col:", gcol)
    log("[INFO] train:", X_train.shape, dict(pd.Series(y_train).value_counts().sort_index()))
    log("[INFO] val:", X_val.shape, dict(pd.Series(y_val).value_counts().sort_index()))
    log("[INFO] meta-val:", X_meta.shape, dict(pd.Series(y_meta).value_counts().sort_index()))
    log("[INFO] select-val:", X_select.shape, dict(pd.Series(y_select).value_counts().sort_index()))
    log("[INFO] test:", X_test.shape, dict(pd.Series(y_test).value_counts().sort_index()))

    neg = max((y_train == 0).sum(), 1)
    pos = max((y_train == 1).sum(), 1)
    spw = neg / pos

    log("[4] Build models...")
    log("[INFO] scale_pos_weight:", spw)
    log("[INFO] recall_min:", args.recall_min)

    models = build_models(spw, args.n_jobs, args.random_state, args.rf_trees, args.xgb_trees, args.xgb_device)

    probs_val = {}
    probs_meta = {}
    probs_select = {}
    probs_test = {}
    thresholds = {}
    rows = []
    base_pred_test = {}

    log("[5] Train base models...")

    for name, model in models.items():
        log()
        log("[RUN]", name)

        model.fit(X_train, y_train)

        probs_val[name] = prob(model, X_val)
        probs_meta[name] = prob(model, X_meta)
        probs_select[name] = prob(model, X_select)
        probs_test[name] = prob(model, X_test)

        thr = tune_threshold(y_val, probs_val[name])
        thresholds[name] = thr["threshold"]

        ev = eval_prob(y_test, probs_test[name], thr["threshold"])
        add_row(rows, name, "base", thr["threshold"], ev)

        base_pred_test[name] = (probs_test[name] >= thr["threshold"]).astype(int)

        joblib.dump(model, out_dir / f"{name}.joblib")

        log("[OK]", name)
        log(" threshold:", thr["threshold"])
        log(" test_f1_vulnerable:", ev["test_f1_vulnerable"])
        log(" test_recall_vulnerable:", ev["test_recall_vulnerable"])
        log(" confusion:", {
            "tn": ev["test_tn"],
            "fp": ev["test_fp"],
            "fn": ev["test_fn"],
            "tp": ev["test_tp"],
        })

    log()
    log("[6] Weighted Soft Voting ensembles...")

    ensemble_specs = OrderedDict({
        "WEIGHT_RF_XGB": ["RandomForest", "XGBoost"],
        "WEIGHT_RF_DT": ["RandomForest", "DecisionTree"],
        "WEIGHT_XGB_DT": ["XGBoost", "DecisionTree"],
        "WEIGHT_RF_XGB_DT": ["RandomForest", "XGBoost", "DecisionTree"],
        "WEIGHT_ALL4": ["RandomForest", "XGBoost", "DecisionTree", "LogisticRegression"],
    })

    weighted_infos = {}

    for ens_name, names in ensemble_specs.items():
        info = optimize_weighted(
            y_select,
            probs_select,
            names,
            recall_min=args.recall_min,
            step=args.weight_step,
        )

        weighted_infos[ens_name] = info

        p_test = apply_weighted(probs_test, info)
        ev = eval_prob(y_test, p_test, info["threshold"])

        extra = {
            "weight_rf": info["weights"].get("RandomForest", np.nan),
            "weight_xgb": info["weights"].get("XGBoost", np.nan),
            "weight_tree": info["weights"].get("DecisionTree", np.nan),
            "weight_logistic": info["weights"].get("LogisticRegression", np.nan),
        }

        add_row(rows, ens_name, "weighted_soft_voting", info["threshold"], ev, extra)

        log("[OK]", ens_name, info["weights"], "thr=", info["threshold"], "F1=", ev["test_f1_vulnerable"])

    log()
    log("[7] Stacking Logistic meta_model(...)")

    base_names = ["RandomForest", "XGBoost", "DecisionTree", "LogisticRegression"]
    risk_cols = select_risk_cols(X)

    log("[INFO] selected risk/safe cols:", len(risk_cols))

    X_meta_prob = meta_matrix(
        X_meta,
        {n: probs_meta[n] for n in base_names},
        risk_cols=None,
    )

    X_select_prob = meta_matrix(
        X_select,
        {n: probs_select[n] for n in base_names},
        risk_cols=None,
    )

    X_test_prob = meta_matrix(
        X_test,
        {n: probs_test[n] for n in base_names},
        risk_cols=None,
    )

    stack_prob, thr_prob, p_stack_prob = train_stack(
        X_meta_prob,
        y_meta,
        X_select_prob,
        y_select,
        X_test_prob,
        args.recall_min,
        C=0.50,
    )

    ev = eval_prob(y_test, p_stack_prob, thr_prob["threshold"])
    add_row(rows, "STACK_LOGISTIC_PROB_ONLY", "stacking", thr_prob["threshold"], ev)
    joblib.dump(stack_prob, out_dir / "STACK_LOGISTIC_PROB_ONLY.joblib")

    log("[OK] STACK_LOGISTIC_PROB_ONLY", "F1=", ev["test_f1_vulnerable"])

    X_meta_risk = meta_matrix(
        X_meta,
        {n: probs_meta[n] for n in base_names},
        risk_cols=risk_cols,
    )

    X_select_risk = meta_matrix(
        X_select,
        {n: probs_select[n] for n in base_names},
        risk_cols=risk_cols,
    )

    X_test_risk = meta_matrix(
        X_test,
        {n: probs_test[n] for n in base_names},
        risk_cols=risk_cols,
    )

    stack_risk, thr_risk, p_stack_risk = train_stack(
        X_meta_risk,
        y_meta,
        X_select_risk,
        y_select,
        X_test_risk,
        args.recall_min,
        C=0.35,
    )

    ev = eval_prob(y_test, p_stack_risk, thr_risk["threshold"])
    add_row(rows, "STACK_LOGISTIC_PROB_RISK", "stacking", thr_risk["threshold"], ev)
    joblib.dump(stack_risk, out_dir / "STACK_LOGISTIC_PROB_RISK.joblib")

    log("[OK] STACK_LOGISTIC_PROB_RISK", "F1=", ev["test_f1_vulnerable"])

    log()
    log("[8] Dynamic Gate ensembles...")

    w_min_opts = parse_float_list(args.gate_w_min_options)
    w_max_opts = parse_float_list(args.gate_w_max_options)

    gate_pairs = [
        ("RandomForest", "XGBoost"),
        ("RandomForest", "DecisionTree"),
        ("XGBoost", "DecisionTree"),
    ]

    for a, b in gate_pairs:
        Xm = meta_matrix(X_meta, {a: probs_meta[a], b: probs_meta[b]}, risk_cols)
        Xs = meta_matrix(X_select, {a: probs_select[a], b: probs_select[b]}, risk_cols)
        Xt = meta_matrix(X_test, {a: probs_test[a], b: probs_test[b]}, risk_cols)

        gate, info, p_gate, w_gate = dynamic_gate_pair(
            Xm, y_meta, probs_meta[a], probs_meta[b],
            Xs, y_select, probs_select[a], probs_select[b],
            Xt, probs_test[a], probs_test[b],
            w_min_opts,
            w_max_opts,
            args.recall_min,
        )

        ev = eval_prob(y_test, p_gate, info["threshold"])

        name = f"DYNAMIC_GATE_{a}_PLUS_{b}"

        extra = {
            "gate_w_min": info["gate_w_min"],
            "gate_w_max": info["gate_w_max"],
        }

        add_row(rows, name, "dynamic_pair_gate", info["threshold"], ev, extra)

        if gate is not None:
            joblib.dump(gate, out_dir / f"{name}.joblib")

        log("[OK]", name, "F1=", ev["test_f1_vulnerable"])

    names3 = ["RandomForest", "XGBoost", "DecisionTree"]

    Xm3 = meta_matrix(X_meta, {n: probs_meta[n] for n in names3}, risk_cols)
    Xs3 = meta_matrix(X_select, {n: probs_select[n] for n in names3}, risk_cols)
    Xt3 = meta_matrix(X_test, {n: probs_test[n] for n in names3}, risk_cols)

    gate3, info3, p_gate3, W_gate3 = softmax_gate_3(
        Xm3,
        y_meta,
        {n: probs_meta[n] for n in names3},
        Xs3,
        y_select,
        {n: probs_select[n] for n in names3},
        Xt3,
        {n: probs_test[n] for n in names3},
        names3,
        args.recall_min,
    )

    ev = eval_prob(y_test, p_gate3, info3["threshold"])
    add_row(rows, "SOFTMAX_GATE_RF_XGB_DT", "dynamic_three_gate", info3["threshold"], ev)
    joblib.dump(gate3, out_dir / "SOFTMAX_GATE_RF_XGB_DT.joblib")

    log("[OK] SOFTMAX_GATE_RF_XGB_DT", "F1=", ev["test_f1_vulnerable"])

    log()
    log("[9] Save outputs...")

    metrics = pd.DataFrame(rows).sort_values(
        ["test_f1_vulnerable", "test_recall_vulnerable"],
        ascending=False,
    )

    metrics.to_csv(out_dir / "model_metrics.csv", index=False)
    (out_dir / "feature_columns.json").write_text(
        json.dumps(list(X.columns), indent=2), encoding="utf-8"
    )

    pred_cols = [
        c for c in [
            "binary", "binary_norm", "source_core", "build_config",
            "json_file", "function", "name_norm", "entry",
            "label", "merge_stage",
        ]
        if c in df.columns
    ]

    pred = df.iloc[test_idx][pred_cols].copy()
    pred["y_true"] = y_test

    for n in base_names:
        pred[f"p_{n}"] = probs_test[n]

    pred["p_WEIGHT_RF_XGB_DT"] = apply_weighted(probs_test, weighted_infos["WEIGHT_RF_XGB_DT"])
    pred["p_WEIGHT_ALL4"] = apply_weighted(probs_test, weighted_infos["WEIGHT_ALL4"])
    pred["p_STACK_LOGISTIC_PROB_ONLY"] = p_stack_prob
    pred["p_STACK_LOGISTIC_PROB_RISK"] = p_stack_risk
    pred["p_SOFTMAX_GATE_RF_XGB_DT"] = p_gate3

    pred.to_csv(out_dir / "test_predictions.csv", index=False)

    cross_error_analysis(
        y_test,
        base_pred_test,
        out_dir / "model_cross_error_analysis.csv",
    )

    run_info = {
        "random_state": args.random_state,
        "split_manifest": args.split_manifest or None,
        "parameters": vars(args),
        "python_version": sys.version,
        "package_versions": {name: importlib.metadata.version(name) for name in
                             ["scikit-learn", "pandas", "numpy", "xgboost", "joblib"]},
        "data": args.data,
        "split_used": split_used,
        "group_col": gcol,
        "train_shape": list(X_train.shape),
        "val_shape": list(X_val.shape),
        "meta_val_shape": list(X_meta.shape),
        "select_val_shape": list(X_select.shape),
        "test_shape": list(X_test.shape),
        "feature_count": int(X.shape[1]),
        "risk_safe_meta_feature_count": len(risk_cols),
        "recall_min": args.recall_min,
        "weight_step": args.weight_step,
    }

    with open(out_dir / "run_info.json", "w", encoding="utf-8") as f:
        json.dump(run_info, f, indent=2, ensure_ascii=False)

    log()
    log("[DONE] wrote:", out_dir)
    log(metrics.to_string(index=False))


if __name__ == "__main__":
    main()
