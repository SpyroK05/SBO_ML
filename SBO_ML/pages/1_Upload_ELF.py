#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple
import hashlib
import json
import os
import re
import subprocess
import sys
import time

import numpy as np
import pandas as pd
import streamlit as st


# =========================
# Paths / config
# =========================

APP_FILE = Path(__file__).resolve()
PROJECT_ROOT = APP_FILE.parents[1]
SCRIPTS_DIR = PROJECT_ROOT / "scripts"
PIPELINE_SCRIPT = SCRIPTS_DIR / "elf_to_features_generic.py"
DEFAULT_MODEL_DIR = PROJECT_ROOT / "models" / "sbo_detector"
DEFAULT_SCRIPT_DIR = PROJECT_ROOT / "ghidra_scripts"
UPLOAD_DIR = PROJECT_ROOT / "runtime" / "uploads"
ANALYSIS_DIR = PROJECT_ROOT / "runtime" / "analysis"

ID_COLS = [
    "binary", "binary_norm", "program_name", "json_file", "source_core",
    "build_config", "function", "name_norm", "entry", "schema",
]

# =========================
# Runtime/import filtering
# =========================

RUNTIME_FUNCTION_NAMES = {
    "_start", "_init", "_fini",
    "frame_dummy",
    "__libc_start_main",
    "__cxa_finalize",
    "__cxa_atexit",
    "__gmon_start__",
    "__gmon_start",
    "__do_global_dtors_aux",
    "deregister_tm_clones",
    "register_tm_clones",
    "__libc_csu_init",
    "__libc_csu_fini",
    "_dl_relocate_static_pie",
    "__stack_chk_fail",
    "__stack_chk_fail_local",
    "_ITM_registerTMCloneTable",
    "_ITM_deregisterTMCloneTable",
    "__TMC_END__",
    "__dso_handle",
}

IMPORT_API_NAMES = {
    "puts", "putchar",
    "printf", "fprintf", "sprintf", "snprintf", "vprintf", "vsprintf", "vsnprintf",
    "scanf", "sscanf", "fscanf",
    "strcpy", "strncpy", "strcat", "strncat",
    "wcscpy", "wcsncpy", "wcscat", "wcsncat",
    "memcpy", "memmove", "memset", "memcmp",
    "gets", "fgets", "read", "recv", "recvfrom",
    "malloc", "calloc", "realloc", "free",
    "strlen", "strnlen", "strcmp", "strncmp", "strchr", "strstr",
    "exit", "abort", "perror",
}

RUNTIME_PREFIXES = (
    "__x86.get_pc_thunk",
    "__libc_",
    "__cxa_",
    "__gmon_",
    "_Unwind_",
)

RUNTIME_CONTAINS = (
    "tm_clone",
    "registertmclonetable",
    "deregistertmclonetable",
)

DANGEROUS_APIS = {
    "strcpy", "strcat", "gets", "sprintf", "vsprintf",
    "memcpy", "memmove", "strncpy", "strncat",
    "scanf", "sscanf", "fscanf", "read", "recv", "recvfrom",
    "snprintf", "vsnprintf",
    "wcscpy", "wcscat", "wmemcpy", "wmemmove",
}


st.set_page_config(
    page_title="Upload ELF - SBO Detector",
    page_icon="🔬",
    layout="wide",
)


# =========================
# Small helpers
# =========================

def norm_path(value: str | Path, base: Path = PROJECT_ROOT) -> Path:
    p = Path(str(value)).expanduser()
    if not p.is_absolute():
        p = base / p
    return p.resolve()


def safe_filename(name: str, limit: int = 120) -> str:
    name = Path(str(name or "uploaded.elf")).name
    name = re.sub(r"[^A-Za-z0-9_.+-]+", "_", name).strip("._")
    return name[:limit] or "uploaded.elf"


def file_sha256(data: bytes, n: int = 12) -> str:
    return hashlib.sha256(data).hexdigest()[:n]


def is_elf_bytes(data: bytes) -> bool:
    return len(data) >= 4 and data[:4] == b"\x7fELF"


def resolve_ghidra_headless(value: str) -> str:
    value = str(value or "").strip()

    if value:
        p = Path(value).expanduser()
        if p.exists():
            return str(p.resolve())
        return value

    env = os.environ.get("GHIDRA_HEADLESS", "").strip()
    if env:
        return env

    for p in [
        "/usr/share/ghidra/support/analyzeHeadless",
        "/opt/ghidra/support/analyzeHeadless",
    ]:
        if Path(p).exists():
            return p

    return "analyzeHeadless"


def numeric_or_default(value, default: float = 0.0) -> float:
    try:
        x = float(value)
        return x if np.isfinite(x) else default
    except Exception:
        return default


def normalize_function_symbol(name: str) -> str:
    n = str(name or "").strip()
    n = n.replace("@plt", "")
    n = n.replace(".plt", "")
    n = n.replace("_plt", "")
    n = n.split("@")[0]
    return n.strip()


def classify_function_name(name: str):
    raw = str(name or "").strip()
    n = normalize_function_symbol(raw)
    nl = n.lower()

    if not n:
        return "unknown", False

    if n in RUNTIME_FUNCTION_NAMES:
        return "compiler_runtime", True

    if n in IMPORT_API_NAMES:
        return "import_or_plt_api", True

    if raw.endswith("@plt") or raw.endswith(".plt") or raw.endswith("_plt"):
        return "import_or_plt_api", True

    if any(n.startswith(px) for px in RUNTIME_PREFIXES):
        return "compiler_runtime", True

    compact = nl.replace("_", "").replace(".", "")
    if any(x in compact for x in RUNTIME_CONTAINS):
        return "compiler_runtime", True

    if nl.startswith("_itm_") or "itm_" in nl:
        return "compiler_runtime", True

    return "user_candidate", False


def _num(v) -> float:
    try:
        x = float(v)
        if not np.isfinite(x):
            return 0.0
        return x
    except Exception:
        return 0.0


def row_has_nonzero_feature(row, keywords) -> bool:
    for c in row.index:
        cl = str(c).lower()
        if any(k in cl for k in keywords):
            if abs(_num(row.get(c, 0))) > 0:
                return True
    return False


def row_has_sbo_signal(row) -> bool:
    return (
        row_has_nonzero_feature(row, [
            "sink", "dangerous", "strcpy", "strcat", "memcpy",
            "memmove", "sprintf", "gets", "scanf", "read", "recv",
        ])
        or row_has_nonzero_feature(row, [
            "local_buffer", "buffer_summary", "stack_", "dst_stack",
            "overflow_margin", "size_to_dst_ratio",
        ])
    )


def risk_level_one(prob: float, threshold: float = 0.5) -> str:
    p = float(prob)

    if p >= 0.85:
        return "HIGH"
    if p >= 0.65:
        return "MEDIUM"
    if p >= float(threshold):
        return "LOW"
    return "SAFE"


def make_reason(row, source_kind=None, ignored=False) -> str:
    if isinstance(source_kind, bool):
        ignored = source_kind
        source_kind = None

    source_kind = source_kind or "runtime/import/PLT function"

    if ignored:
        return f"{source_kind}, hidden by default"

    reasons = []

    if row_has_nonzero_feature(row, [
        "sink", "dangerous", "strcpy", "strcat", "memcpy",
        "memmove", "sprintf", "gets", "scanf",
    ]):
        reasons.append("dangerous sink/copy-like call")

    if row_has_nonzero_feature(row, [
        "local_buffer", "buffer_summary", "stack_",
    ]):
        reasons.append("stack/local buffer evidence")

    if row_has_nonzero_feature(row, [
        "overflow_margin", "size_to_dst_ratio", "dst_stack_size", "size_value",
    ]):
        reasons.append("size-vs-buffer risk")

    if row_has_nonzero_feature(row, [
        "safe", "guard", "bound", "check",
    ]):
        reasons.append("safe/guard-related signal")

    if not reasons:
        reasons.append("model pattern from binary features")

    return "; ".join(reasons[:3])


# =========================
# Model loading
# =========================

# Shared inference supports base models and explicit weighted voting.
from sbo_core import (
    load_bundle, prepare_X, available_models, pick_default_model,
    predict_from_metrics,
)


@st.cache_resource(show_spinner=False)
def load_model_dir(model_dir_str):
    return load_bundle(norm_path(model_dir_str))


# =========================
# Results
# =========================

def make_result(df: pd.DataFrame, prob: np.ndarray, threshold: float) -> pd.DataFrame:
    keep_cols = [c for c in ID_COLS if c in df.columns]
    out = df[keep_cols].copy() if keep_cols else pd.DataFrame(index=df.index)

    if "function" in out.columns:
        names = out["function"].astype(str).tolist()
    elif "name_norm" in out.columns:
        names = out["name_norm"].astype(str).tolist()
    else:
        names = [""] * len(out)

    prob = np.asarray(prob, dtype=float)

    source_kinds = []
    ignored_flags = []
    reasons = []

    for i, name in enumerate(names):
        kind, ignored = classify_function_name(name)

        if str(name) == "main":
            kind = "user_candidate"
            ignored = False

        # Runtime/import/PLT luôn bị ẩn mặc định, kể cả khi model cho prob > threshold.
        # Lý do: đây không phải hàm người dùng viết, thường chỉ là startup/thunk/stub.
        if kind in {"compiler_runtime", "import_or_plt_api"}:
            ignored = True
        else:
            # Chỉ với hàm user/unknown mới giữ lại nếu model báo vulnerable.
            if prob[i] >= float(threshold):
                ignored = False

        upper_name = str(name).upper()
        if (
            (upper_name.startswith("FUN_") or upper_name.startswith("SUB_"))
            and prob[i] < float(threshold)
            and not row_has_sbo_signal(df.iloc[i])
        ):
            kind = "unknown_low_signal_or_stub"
            ignored = True

        source_kinds.append(kind)
        ignored_flags.append(bool(ignored))
        reasons.append(make_reason(df.iloc[i], kind, bool(ignored)))

    out["source_kind"] = source_kinds
    out["ignored_runtime"] = ignored_flags
    out["prob_vulnerable"] = prob
    out["pred_label"] = (prob >= float(threshold)).astype(int)
    out["prediction"] = np.where(out["pred_label"] == 1, "VULNERABLE", "SAFE")
    out["risk_level"] = [risk_level_one(float(x), threshold) for x in prob]
    out["top_reason"] = reasons

    return out.sort_values("prob_vulnerable", ascending=False).reset_index(drop=True)


# =========================
# Candidate findings
# =========================

def _flatten_dict(obj, prefix=""):
    out = {}

    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}_{k}" if prefix else str(k)

            if isinstance(v, dict):
                out.update(_flatten_dict(v, key))
            elif isinstance(v, list):
                out[key] = v
            else:
                out[key] = v

    return out


def _pick(flat, keys):
    for key in keys:
        if key in flat and flat[key] not in [None, ""]:
            return flat[key]

    for k, v in flat.items():
        kl = str(k).lower()
        if any(str(x).lower() in kl for x in keys):
            if v is not None and str(v) != "":
                return v

    return ""


def _to_float(x, default=0.0):
    try:
        v = float(x)
        if np.isfinite(v):
            return v
    except Exception:
        pass

    return default


def load_raw_functions_from_workdir(work_dir):
    rows = []
    work_dir = Path(work_dir)

    json_files = sorted(work_dir.rglob("raw_json/*.json"))
    if not json_files:
        json_files = sorted(work_dir.rglob("*.json"))

    for jp in json_files:
        if str(jp).endswith(".info.json"):
            continue

        try:
            data = json.loads(jp.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            continue

        funcs = data.get("functions", [])
        if not isinstance(funcs, list):
            continue

        for f in funcs:
            if not isinstance(f, dict):
                continue

            name = (
                f.get("function")
                or f.get("name")
                or f.get("name_norm")
                or f.get("func_name")
                or ""
            )

            entry = (
                f.get("entry")
                or f.get("entry_point")
                or f.get("address")
                or f.get("addr")
                or ""
            )

            rows.append({
                "function": str(name),
                "entry": str(entry),
                "json_file": str(jp),
                "raw": f,
            })

    return rows


def should_ignore_finding_function(function_name):
    try:
        _, ignored = classify_function_name(function_name)
        return bool(ignored)
    except Exception:
        return False


def finding_risk_level(api, prob, overflow_margin, ratio, threshold=0.5):
    api_l = str(api or "").lower()

    if overflow_margin > 0:
        return "HIGH"

    if ratio > 1.0:
        return "HIGH"

    if api_l in {"strcpy", "strcat", "gets", "sprintf", "vsprintf"}:
        if prob >= float(threshold):
            return "HIGH"
        return "MEDIUM"

    if api_l in DANGEROUS_APIS and prob >= 0.65:
        return "MEDIUM"

    return risk_level_one(prob, threshold)


def make_finding_reason(api, dst_size, size_value, overflow_margin, ratio, has_local_buffer, line_text=""):
    reasons = []
    api_l = str(api or "").lower()

    if api_l in {"strcpy", "strcat", "gets", "sprintf", "vsprintf"}:
        reasons.append("unbounded dangerous sink")
    elif api_l in DANGEROUS_APIS:
        reasons.append("dangerous copy/input sink")

    if has_local_buffer:
        reasons.append("stack/local buffer exists")

    if dst_size > 0:
        reasons.append(f"dst buffer size≈{dst_size:g}")

    if size_value > 0:
        reasons.append(f"copy/input size≈{size_value:g}")

    if overflow_margin > 0:
        reasons.append(f"overflow margin≈{overflow_margin:g}")

    if ratio > 1:
        reasons.append(f"size/dst ratio≈{ratio:.2f}")

    if line_text:
        line_short = str(line_text).strip()
        if len(line_short) > 120:
            line_short = line_short[:117] + "..."
        reasons.append(f"line: {line_short}")

    if not reasons:
        reasons.append("function-level ML risk")

    return "; ".join(reasons)


def build_candidate_findings(work_dir, result_df, threshold):
    raw_funcs = load_raw_functions_from_workdir(work_dir)

    if not raw_funcs:
        return pd.DataFrame()

    prob_map = {}

    for _, r in result_df.iterrows():
        fn = str(r.get("function", ""))
        nn = str(r.get("name_norm", ""))
        en = str(r.get("entry", ""))
        prob = _to_float(r.get("prob_vulnerable", 0.0))

        if fn:
            prob_map[("function", fn)] = prob
        if nn:
            prob_map[("function", nn)] = prob
        if en:
            prob_map[("entry", en)] = prob

    findings = []

    for item in raw_funcs:
        f = item["raw"]
        function = item["function"]
        entry = item["entry"]

        if should_ignore_finding_function(function):
            continue

        prob = prob_map.get(("function", function), prob_map.get(("entry", entry), 0.0))

        sinks = f.get("sinks", [])
        local_buffers = f.get("local_buffers", [])

        if not isinstance(sinks, list):
            sinks = []

        has_local_buffer = isinstance(local_buffers, list) and len(local_buffers) > 0

        for sink in sinks:
            if not isinstance(sink, dict):
                continue

            flat = _flatten_dict(sink)

            api = _pick(flat, ["api", "callee", "call_name", "sink_name"])
            api = str(api or "").replace("@plt", "").strip()
            api_l = api.lower()

            dst = _pick(flat, [
                "dst_arg", "dst_var", "dst_buffer", "dst_name",
                "destination", "dst", "buffer", "target_var"
            ])

            src = _pick(flat, ["src_arg", "src_var", "source", "src"])
            line_index = _pick(flat, ["line_index", "call_line", "line_no"])
            line_text = _pick(flat, ["line", "call_text", "code"])
            sink_addr = _pick(flat, ["address", "addr", "call_site", "call_address"])

            dst_size = _to_float(_pick(flat, [
                "dst_stack_size", "dst_buffer_size", "buffer_size",
                "target_size", "v6_dst_stack_size"
            ]))

            size_value = _to_float(_pick(flat, [
                "size_value", "size_arg_value", "copy_size",
                "length", "count", "nbytes", "v6_size_value"
            ]))

            overflow_margin = _to_float(_pick(flat, [
                "overflow_margin", "src_overflow_margin", "margin"
            ]))

            ratio = _to_float(_pick(flat, [
                "size_to_dst_ratio", "ratio", "v6_size_to_dst_ratio"
            ]))

            if api_l not in DANGEROUS_APIS and prob < float(threshold) and overflow_margin <= 0 and ratio <= 1.0:
                continue

            risk = finding_risk_level(
                api=api,
                prob=prob,
                overflow_margin=overflow_margin,
                ratio=ratio,
                threshold=threshold,
            )

            reason = make_finding_reason(
                api=api,
                dst_size=dst_size,
                size_value=size_value,
                overflow_margin=overflow_margin,
                ratio=ratio,
                has_local_buffer=has_local_buffer,
                line_text=line_text,
            )

            findings.append({
                "function": function,
                "entry": entry,
                "function_probability": prob,
                "sink_api": api if api else "unknown_sink",
                "line_index": line_index,
                "sink_address": sink_addr,
                "dst_buffer": dst,
                "src": src,
                "dst_stack_size": dst_size if dst_size else "",
                "size_value": size_value if size_value else "",
                "overflow_margin": overflow_margin if overflow_margin else "",
                "size_to_dst_ratio": ratio if ratio else "",
                "finding_risk": risk,
                "reason": reason,
            })

        if False and (not sinks) and prob >= float(threshold):
            findings.append({
                "function": function,
                "entry": entry,
                "function_probability": prob,
                "sink_api": "not_extracted",
                "line_index": "",
                "sink_address": "",
                "dst_buffer": "",
                "src": "",
                "dst_stack_size": "",
                "size_value": "",
                "overflow_margin": "",
                "size_to_dst_ratio": "",
                "finding_risk": risk_level_one(prob, threshold),
                "reason": "function predicted vulnerable but no explicit sink extracted",
            })

    if not findings:
        return pd.DataFrame()

    out = pd.DataFrame(findings)
    risk_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3, "SAFE": 4}
    out["_risk_order"] = out["finding_risk"].map(risk_order).fillna(9)
    out = out.sort_values(
        ["_risk_order", "function_probability"],
        ascending=[True, False],
    )
    out = out.drop(columns=["_risk_order"]).reset_index(drop=True)

    return out



# =========================
# Hybrid score
# =========================

def _finding_has_safe_evidence(row) -> bool:
    text = " ".join(str(row.get(c, "")) for c in row.index).lower()

    safe_keywords = [
        "safe_proof",
        "strong_guard",
        "size_lt_dst",
        "size_eq_dst",
        "size_le_dst",
        "sizeof",
        "guard",
        "bound",
        "check",
        "snprintf_size_le_dst",
        "memcpy_bound_le_dst",
        "strncpy_bound_le_dst",
        "literal_copy_safe",
    ]

    return any(k in text for k in safe_keywords)


def static_score_from_findings_for_function(finds: pd.DataFrame):
    """
    Tạo điểm static từ candidate findings của một hàm.

    Bản mềm hơn:
    - strcpy/gets/sprintf vẫn là tín hiệu rất mạnh.
    - memcpy/read/snprintf chỉ override mạnh nếu không thấy safe evidence.
    - Nếu model_prob thấp mà chỉ có bounded sink, không ép HIGH quá dễ.
    """
    if finds is None or len(finds) == 0:
        return 0.0, 0, ""

    score = 0.0
    reasons = []

    for _, r in finds.iterrows():
        api = str(r.get("sink_api", "")).lower().replace("@plt", "").strip()
        risk = str(r.get("finding_risk", "")).upper()

        overflow = _to_float(r.get("overflow_margin", 0))
        ratio = _to_float(r.get("size_to_dst_ratio", 0))
        dst_size = _to_float(r.get("dst_stack_size", 0))
        size_value = _to_float(r.get("size_value", 0))
        func_prob = _to_float(r.get("function_probability", 0))

        has_safe_evidence = _finding_has_safe_evidence(r)

        local_score = 0.0

        # Nhóm nguy hiểm không giới hạn: vẫn cho điểm rất cao.
        if api in {"strcpy", "strcat", "gets", "sprintf", "vsprintf"}:
            if has_safe_evidence:
                local_score = 0.68
                reasons.append(f"unbounded sink but safe/guard evidence exists: {api}")
            else:
                local_score = 0.90
                reasons.append(f"unbounded dangerous sink: {api}")

        # Có overflow rõ, nhưng nếu là bounded API và có safe evidence thì không ép quá cao.
        elif overflow > 0 or ratio > 1.0:
            if has_safe_evidence and func_prob < 0.50:
                local_score = 0.55
                reasons.append("possible size overflow, but safe/guard evidence and low model probability")
            elif has_safe_evidence:
                local_score = 0.70
                reasons.append("possible size overflow, but safe/guard evidence exists")
            else:
                local_score = 0.92
                reasons.append("explicit size overflow evidence")

        # Nhóm bounded/copy/input sink: chỉ tăng vừa phải.
        elif api in {"memcpy", "memmove", "strncpy", "strncat", "scanf", "sscanf", "fscanf", "read", "recv", "recvfrom"}:
            if has_safe_evidence and func_prob < 0.50:
                local_score = 0.35
                reasons.append(f"bounded sink with safe evidence: {api}")
            elif has_safe_evidence:
                local_score = 0.55
                reasons.append(f"bounded sink with guard/safe evidence: {api}")
            else:
                local_score = 0.72
                reasons.append(f"dangerous bounded sink: {api}")

        elif risk == "HIGH":
            local_score = 0.75 if has_safe_evidence else 0.88
            reasons.append("high-risk static finding")

        elif risk == "MEDIUM":
            local_score = 0.60 if has_safe_evidence else 0.70
            reasons.append("medium-risk static finding")

        # Có thông tin kích thước thì tăng nhẹ, nhưng không tăng nếu có safe evidence.
        if local_score > 0 and not has_safe_evidence and (dst_size > 0 or size_value > 0):
            local_score = min(0.99, local_score + 0.02)

        score = max(score, local_score)

    n = int(len(finds))

    if n >= 2 and score > 0:
        score = min(0.99, score + 0.02 * (n - 1))

    reason = "; ".join(dict.fromkeys(reasons))
    return float(score), n, reason



def apply_hybrid_scores(result_df: pd.DataFrame, findings_df: pd.DataFrame, threshold: float) -> pd.DataFrame:
    """
    Kết hợp:
    - model_prob: xác suất từ ML model
    - static_finding_score: điểm từ bằng chứng tĩnh cụ thể
    - prob_vulnerable: max(model_prob, static_finding_score)

    Như vậy hàm có strcpy/gets/sprintf nguy hiểm sẽ không bị model bỏ sót,
    nhưng hàm không có finding cụ thể sẽ không bị nâng điểm giả.
    """
    out = result_df.copy()

    out["model_prob"] = pd.to_numeric(out["prob_vulnerable"], errors="coerce").fillna(0.0)
    out["static_finding_score"] = 0.0
    out["explicit_findings"] = 0

    if findings_df is not None and not findings_df.empty and "function" in findings_df.columns:
        for func, group in findings_df.groupby("function"):
            score, n, reason = static_score_from_findings_for_function(group)

            mask = out["function"].astype(str) == str(func)
            if not mask.any():
                continue

            out.loc[mask, "static_finding_score"] = float(score)
            out.loc[mask, "explicit_findings"] = int(n)

            if score > 0:
                old_reason = out.loc[mask, "top_reason"].astype(str)
                new_reason = "static finding: " + reason if reason else "static finding evidence"
                out.loc[mask, "top_reason"] = np.where(
                    score >= out.loc[mask, "model_prob"],
                    new_reason,
                    old_reason,
                )

    out["prob_vulnerable"] = out[["model_prob", "static_finding_score"]].max(axis=1)
    out["pred_label"] = (out["prob_vulnerable"] >= float(threshold)).astype(int)
    out["prediction"] = np.where(out["pred_label"] == 1, "VULNERABLE", "SAFE")
    out["risk_level"] = [risk_level_one(float(x), threshold) for x in out["prob_vulnerable"]]

    # Sau khi hybrid score xong, nếu runtime/import bị nâng điểm thì vẫn ẩn mặc định.
    if "source_kind" in out.columns and "ignored_runtime" in out.columns:
        runtime_mask = out["source_kind"].isin(["compiler_runtime", "import_or_plt_api"])
        out.loc[runtime_mask, "ignored_runtime"] = True

    # Ưu tiên hàm có finding cụ thể, sau đó tới xác suất.
    out["_has_finding"] = (out["explicit_findings"] > 0).astype(int)
    out = out.sort_values(
        ["_has_finding", "prob_vulnerable"],
        ascending=[False, False],
    ).drop(columns=["_has_finding"]).reset_index(drop=True)

    return out


# =========================
# Pipeline
# =========================

def save_upload(uploaded_file) -> Path:
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

    data = uploaded_file.getvalue()
    digest = file_sha256(data)
    name = safe_filename(uploaded_file.name)
    path = UPLOAD_DIR / f"{time.time_ns()}_{digest}_{name}"

    path.write_bytes(data)
    return path


def build_pipeline_cmd(
    upload_path: Path,
    out_csv: Path,
    model_dir: Path,
    work_dir: Path,
    script_dir: Path,
    ghidra_headless: str,
    timeout: int,
) -> List[str]:
    return [
        sys.executable,
        str(PIPELINE_SCRIPT),
        "--elf", str(upload_path),
        "--out-csv", str(out_csv),
        "--model-dir", str(model_dir),
        "--work-dir", str(work_dir),
        "--script-dir", str(script_dir),
        "--ghidra-headless", str(ghidra_headless),
        "--timeout", str(int(timeout)),
    ]


def run_pipeline(cmd: List[str], timeout: int) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        cwd=str(PROJECT_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=int(timeout) + 180,
    )


# =========================
# UI render helpers
# =========================

def render_metrics_header(feature_cols, models, metrics):
    c1, c2, c3 = st.columns(3)
    c1.metric("Feature schema", f"{len(feature_cols):,}")
    c2.metric("Loaded models", len(models))
    c3.metric("Metrics rows", len(metrics))


def render_result_summary(result: pd.DataFrame, missing: Sequence[str]):
    total = int(len(result))
    vuln = int((result["pred_label"] == 1).sum()) if total else 0
    high = int((result["risk_level"] == "HIGH").sum()) if total else 0
    max_prob = float(result["prob_vulnerable"].max()) if total else 0.0

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Functions shown", f"{total:,}")
    m2.metric("Predicted vulnerable", f"{vuln:,}")
    m3.metric("High risk", f"{high:,}")
    m4.metric("Max probability", f"{max_prob:.4f}")

    if missing:
        st.warning(
            f"Có {len(missing):,} feature trong schema model không sinh ra từ ELF này. "
            "Các feature thiếu đã được gán 0. Nếu số này quá lớn, hãy kiểm tra lại "
            "ExtractSBOFeatureRaw.java và vectorizer."
        )


# =========================
# Main
# =========================

def main():
    st.title("🔬 Upload ELF → Ghidra → Predict")
    st.caption(
        "Phân tích tĩnh ELF bằng Ghidra, vectorize feature theo schema model, "
        "sau đó dự đoán nguy cơ Stack-Based Buffer Overflow."
    )

    with st.sidebar:
        st.header("Cấu hình")

        model_dir_input = st.text_input(
            "Model dir",
            value=str(DEFAULT_MODEL_DIR.relative_to(PROJECT_ROOT))
            if DEFAULT_MODEL_DIR.is_relative_to(PROJECT_ROOT)
            else str(DEFAULT_MODEL_DIR),
        )

        ghidra_headless_input = st.text_input(
            "Ghidra analyzeHeadless",
            value=os.environ.get(
                "GHIDRA_HEADLESS",
                "/usr/share/ghidra/support/analyzeHeadless",
            ),
        )

        script_dir_input = st.text_input(
            "Ghidra script dir",
            value=str(DEFAULT_SCRIPT_DIR.relative_to(PROJECT_ROOT))
            if DEFAULT_SCRIPT_DIR.is_relative_to(PROJECT_ROOT)
            else str(DEFAULT_SCRIPT_DIR),
        )

        timeout = st.number_input(
            "Timeout mỗi file, giây",
            min_value=60,
            max_value=3600,
            value=360,
            step=60,
        )

        if st.button("Reload model/cache"):
            st.cache_resource.clear()
            st.rerun()

    model_dir_path = norm_path(model_dir_input)
    script_dir_path = norm_path(script_dir_input)
    ghidra_headless = resolve_ghidra_headless(ghidra_headless_input)

    if not PIPELINE_SCRIPT.exists():
        st.error(f"Không thấy pipeline script: {PIPELINE_SCRIPT}")
        st.stop()

    try:
        model_dir, models, metrics, feature_cols, load_errors = load_model_dir(str(model_dir_path))
    except Exception as e:
        st.error(str(e))
        st.stop()

    if load_errors:
        with st.expander("Model load warnings", expanded=False):
            for name, err in load_errors.items():
                st.warning(f"{name}: {err}")

    if not (script_dir_path / "ExtractSBOFeatureRaw.java").exists():
        st.warning(
            f"Không thấy {script_dir_path / 'ExtractSBOFeatureRaw.java'}. "
            "Pipeline sẽ lỗi nếu Ghidra script chưa được copy đúng chỗ."
        )

    render_metrics_header(feature_cols, models, metrics)

    default_model = pick_default_model(metrics, models)
    model_names = available_models(metrics, models)

    if not model_names:
        st.error("Không có model tương thích để dự đoán.")
        st.stop()

    selected_model = st.selectbox(
        "Chọn model để predict",
        options=model_names,
        index=model_names.index(default_model) if default_model in model_names else 0,
    )

    metric_row = metrics[metrics["model"].astype(str) == selected_model].iloc[0]
    default_thr = numeric_or_default(metric_row.get("best_threshold", 0.5), 0.5)
    default_thr = min(max(default_thr, 0.05), 0.95)

    threshold = st.slider(
        "Ngưỡng vulnerable",
        min_value=0.05,
        max_value=0.95,
        value=float(default_thr),
        step=0.005,
    )

    use_hybrid = st.checkbox(
        "Kết hợp điểm luật tĩnh (thử nghiệm)", value=False,
        help="Điểm kết hợp không phải xác suất đã hiệu chuẩn và chưa có benchmark riêng.",
    )

    show_runtime = st.checkbox(
        "Hiện cả hàm runtime/import/PLT",
        value=False,
        help="Mặc định ẩn _start, frame_dummy, _ITM..., printf@plt, strcpy@plt... để tập trung vào hàm người dùng.",
    )

    uploaded = st.file_uploader("Upload file ELF", type=None)

    if uploaded is None:
        st.info("Hãy upload một file ELF Linux 64-bit/32-bit để phân tích.")
        st.stop()

    uploaded_bytes = uploaded.getvalue()
    if not is_elf_bytes(uploaded_bytes):
        st.error("File upload không phải ELF hợp lệ. Magic bytes phải là 7F 45 4C 46.")
        st.stop()

    file_info = {
        "Tên file": uploaded.name,
        "Kích thước": f"{len(uploaded_bytes):,} bytes",
        "SHA256": hashlib.sha256(uploaded_bytes).hexdigest(),
    }

    with st.expander("Thông tin file upload", expanded=False):
        st.json(file_info)

    if st.button("Chạy Ghidra và dự đoán", type="primary"):
        try:
            upload_path = save_upload(uploaded)
            run_id = upload_path.stem
            work_dir = ANALYSIS_DIR / run_id
            out_csv = work_dir / "features_aligned.csv"
            work_dir.mkdir(parents=True, exist_ok=True)

            cmd = build_pipeline_cmd(
                upload_path=upload_path,
                out_csv=out_csv,
                model_dir=model_dir,
                work_dir=work_dir,
                script_dir=script_dir_path,
                ghidra_headless=ghidra_headless,
                timeout=int(timeout),
            )

            st.subheader("Pipeline command")
            st.code(" ".join(cmd), language="bash")

            with st.spinner("Đang chạy Ghidra headless và vectorize feature..."):
                proc = run_pipeline(cmd, int(timeout))

            with st.expander("Log Ghidra / Vectorize", expanded=proc.returncode != 0):
                st.code(proc.stdout or "")

            if proc.returncode != 0:
                st.error(f"Pipeline lỗi, return code = {proc.returncode}")
                st.stop()

            if not out_csv.exists():
                st.error(f"Không thấy output feature CSV: {out_csv}")
                st.stop()

            df = pd.read_csv(out_csv, low_memory=False)
            if df.empty:
                st.error("Feature CSV rỗng, không có function nào để predict.")
                st.stop()

            X, missing = prepare_X(df, feature_cols)
            info_file = Path(str(out_csv) + ".info.json")
            if info_file.exists():
                info = json.loads(info_file.read_text(encoding="utf-8"))
                missing = info.get("missing_feature_columns", missing)
            if missing:
                st.warning(f"Extractor chưa sinh {len(missing)} đặc trưng; đã điền 0. Kết quả có thể lệch so với benchmark.")

            prob, used_model, used_components, note = predict_from_metrics(
                models=models,
                metrics=metrics,
                X=X,
                selected_model=selected_model,
                raw_df=df,
            )

            if note:
                st.warning(note)

            result = make_result(df, prob, threshold)

            # Build candidate findings một lần, rồi dùng để tăng điểm hybrid.
            findings = build_candidate_findings(work_dir, result, threshold)
            if use_hybrid:
                result = apply_hybrid_scores(result, findings, threshold)
                st.info("Đang hiển thị điểm kết hợp ML + luật tĩnh; không phải xác suất đã hiệu chuẩn.")

            if findings is not None and not findings.empty and "function" in findings.columns:
                prob_lookup = result.set_index("function")["prob_vulnerable"].to_dict()
                findings["function_probability"] = (
                    findings["function"].map(prob_lookup).fillna(findings["function_probability"])
                )

            view_result = result.copy() if show_runtime else result[~result["ignored_runtime"]].copy()

            render_result_summary(view_result, missing)

            st.write("Model dùng:", used_model)
            st.write("Thành phần:", used_components)

            top_cols = [
                c for c in [
                    "function", "name_norm", "entry",
                    "prob_vulnerable", "prediction", "risk_level",
                    "source_kind", "top_reason",
                ]
                if c in view_result.columns
            ]

            # =========================
            # Compact results UI
            # =========================

            display_cols = [
                c for c in [
                    "function",
                    "entry",
                    "model_prob",
                    "static_finding_score",
                    "prob_vulnerable",
                    "explicit_findings",
                    "prediction",
                    "risk_level",
                    "source_kind",
                    "top_reason",
                ]
                if c in view_result.columns
            ]

            st.subheader("Kết quả chính")

            st.caption(
                "Bảng này chỉ hiển thị các hàm quan trọng sau khi ẩn runtime/import/PLT. "
                "Sắp xếp theo xác suất vulnerable giảm dần."
            )

            st.dataframe(
                view_result[display_cols].head(50),
                width="stretch",
                height=360,
            )

            with st.expander("Xem bảng function-level đầy đủ", expanded=False):
                st.dataframe(view_result, width="stretch", height=420)

            with st.expander("Candidate Findings / Vị trí nghi ngờ trong hàm", expanded=not findings.empty):
                if findings.empty:
                    st.info("Chưa trích được candidate finding cụ thể từ raw JSON. Vẫn dùng function-level result.")
                else:
                    finding_cols = [
                        c for c in [
                            "function",
                            "function_probability",
                            "sink_api",
                            "line_index",
                            "dst_buffer",
                            "src",
                            "dst_stack_size",
                            "size_value",
                            "overflow_margin",
                            "size_to_dst_ratio",
                            "finding_risk",
                            "reason",
                        ]
                        if c in findings.columns
                    ]

                    st.caption(
                        "Một hàm có nhiều sink nguy hiểm sẽ xuất hiện nhiều dòng. "
                        "Đây là candidate finding, không phải kết luận exploit chắc chắn."
                    )

                    st.dataframe(
                        findings[finding_cols],
                        width="stretch",
                        height=360,
                    )

            st.subheader("Tải kết quả")

            d1, d2, d3 = st.columns(3)

            with d1:
                st.download_button(
                    "Function-level CSV",
                    data=view_result.to_csv(index=False).encode("utf-8"),
                    file_name="sbo_elf_predictions.csv",
                    mime="text/csv",
                )

            with d2:
                if findings.empty:
                    st.download_button(
                        "Candidate findings CSV",
                        data="".encode("utf-8"),
                        file_name="sbo_candidate_findings.csv",
                        mime="text/csv",
                        disabled=True,
                    )
                else:
                    st.download_button(
                        "Candidate findings CSV",
                        data=findings.to_csv(index=False).encode("utf-8"),
                        file_name="sbo_candidate_findings.csv",
                        mime="text/csv",
                    )

            with d3:
                st.download_button(
                    "Feature CSV",
                    data=df.to_csv(index=False).encode("utf-8"),
                    file_name="sbo_elf_features.csv",
                    mime="text/csv",
                )

            info_path = Path(str(out_csv) + ".info.json")
            if info_path.exists():
                st.download_button(
                    "Tải info JSON",
                    data=info_path.read_bytes(),
                    file_name="sbo_elf_features.info.json",
                    mime="application/json",
                )

        except subprocess.TimeoutExpired as e:
            st.error(f"Pipeline timeout sau khoảng {int(timeout) + 180} giây.")
            with st.expander("Log trước khi timeout", expanded=True):
                st.code(str(e))
        except Exception as e:
            st.error(str(e))


if __name__ == "__main__":
    main()
