#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Convert an uploaded ELF into a function-level feature CSV for SBO prediction.

Pipeline:
  1) Validate ELF
  2) Run Ghidra headless with ExtractSBOFeatureRaw.java/.py
  3) Read raw JSON
  4) Flatten numeric features
  5) Align columns to the trained model schema

This version is adjusted for the Java script ExtractSBOFeatureRaw.java and the
raw JSON schema produced by that script:
  {
    "schema": "...",
    "program": {"program_name": "...", ...},
    "function_count": N,
    "functions": [...]
  }
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple

import joblib
import numpy as np
import pandas as pd


ID_COLS = [
    "binary", "binary_norm", "program_name", "json_file", "source_core",
    "build_config", "function", "name_norm", "entry", "schema",
]

# Dicts that should become sparse count columns instead of nested prefixes.
SPECIAL_COUNT_DICTS = {
    "pcode": "pcode",
    "pcode_counts": "pcode",
    "pcode_count": "pcode",
    "mnemonic": "mnemonic",
    "mnemonics": "mnemonic",
    "mnemonic_counts": "mnemonic",
    "opcode": "mnemonic",
    "opcode_counts": "mnemonic",
}

FEATURE_DICT_KEYS = {"features", "feature_vector", "numeric_features"}

DEFAULT_MODEL_CANDIDATES = [
    "RandomForest.joblib",
    "XGBoost.joblib",
    "DecisionTree.joblib",
    "LogisticRegression.joblib",
]

DEFAULT_SCRIPT_CANDIDATES = [
    "ExtractSBOFeatureRaw.java",
    "ExtractSBOFeatureRaw.py",
]

SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9_.+-]+")
KEY_BAD_RE = re.compile(r"[^A-Za-z0-9_]+")
KEY_UNDERSCORE_RE = re.compile(r"_+")


def log(*x: Any) -> None:
    print(*x, flush=True)


def die(msg: str, code: int = 1) -> None:
    raise RuntimeError(msg)




def clean_runtime_log(*paths):
    """
    Dọn file runtime cũ.
    Chỉ nhận path thật. Nếu lỡ truyền stdout/log text vào thì bỏ qua.
    """
    for path in paths:
        try:
            if path is None:
                continue

            raw = str(path)

            # Nếu là log stdout/stderr thì thường có newline rất dài.
            # Không được coi nó là đường dẫn file.
            if "\n" in raw or "\r" in raw:
                continue

            if len(raw) > 240:
                continue

            p = Path(raw)

            if not p.exists():
                continue

            if p.is_file():
                if p.suffix.lower() in {".json", ".csv", ".log", ".tmp"}:
                    p.unlink()
                continue

            if p.is_dir():
                for pattern in ("*.json", "*.csv", "*.log", "*.tmp"):
                    for child in p.rglob(pattern):
                        if child.is_file():
                            child.unlink()

        except Exception as e:
            try:
                log("[WARN] clean_runtime_log failed:", path, e)
            except Exception:
                print("[WARN] clean_runtime_log failed:", path, e, flush=True)

def is_number(x: Any) -> bool:
    if isinstance(x, (bool, np.bool_)):
        return True
    if isinstance(x, (int, float, np.integer, np.floating)):
        try:
            return math.isfinite(float(x))
        except Exception:
            return False
    return False


def as_float(x: Any) -> float:
    return 1.0 if isinstance(x, (bool, np.bool_)) and x else float(x)


def safe_name(s: Any, max_len: int = 120) -> str:
    text = str(s or "").strip()
    text = SAFE_NAME_RE.sub("_", text).strip("_")
    return text[:max_len] if text else "unknown"


def norm_key(k: Any) -> str:
    text = str(k or "")
    text = text.replace(".", "_").replace("-", "_").replace(" ", "_")
    text = KEY_BAD_RE.sub("_", text)
    text = KEY_UNDERSCORE_RE.sub("_", text)
    return text.strip("_")


def flatten_obj(obj: Any, prefix: str = "") -> Dict[str, float]:
    """Flatten only numeric content from nested JSON objects."""
    out: Dict[str, float] = {}

    if not isinstance(obj, Mapping):
        return out

    for raw_k, v in obj.items():
        k0 = norm_key(raw_k)
        if not k0:
            continue

        # Some vectorizers put all numeric values under a single feature dict.
        # Do not add an extra features_ prefix for those groups.
        if k0 in FEATURE_DICT_KEYS and isinstance(v, Mapping):
            out.update(flatten_obj(v, prefix))
            continue

        key = norm_key(f"{prefix}_{k0}" if prefix else k0)
        if not key:
            continue

        if is_number(v):
            out[key] = as_float(v)
            continue

        if isinstance(v, Mapping):
            lk = k0.lower()
            if lk in SPECIAL_COUNT_DICTS:
                pfx = SPECIAL_COUNT_DICTS[lk]
                for kk, vv in v.items():
                    if is_number(vv):
                        out[f"{pfx}_{norm_key(kk)}"] = as_float(vv)
                continue

            out.update(flatten_obj(v, key))
            continue

        if isinstance(v, list):
            agg = aggregate_list(v)
            for ak, av in agg.items():
                out[f"{key}_{ak}"] = av
            continue

    return out


def aggregate_list(values: Sequence[Any]) -> Dict[str, float]:
    if not values:
        return {"count": 0.0}

    nums = [as_float(x) for x in values if is_number(x)]
    if nums:
        arr = np.asarray(nums, dtype=np.float64)
        return {
            "count": float(arr.size),
            "sum": float(arr.sum()),
            "mean": float(arr.mean()),
            "max": float(arr.max()),
            "min": float(arr.min()),
        }

    buckets: Dict[str, List[float]] = {}
    dict_count = 0

    for item in values:
        if not isinstance(item, Mapping):
            continue
        dict_count += 1
        flat = flatten_obj(item, "")
        for k, v in flat.items():
            buckets.setdefault(k, []).append(float(v))

    if not buckets:
        return {"count": float(len(values))}

    out: Dict[str, float] = {"count": float(len(values)), "dict_count": float(dict_count)}
    for k, arr0 in buckets.items():
        if not arr0:
            continue
        arr = np.asarray(arr0, dtype=np.float64)
        out[f"{k}_count"] = float(arr.size)
        out[f"{k}_sum"] = float(arr.sum())
        out[f"{k}_mean"] = float(arr.mean())
        out[f"{k}_max"] = float(arr.max())
        out[f"{k}_min"] = float(arr.min())

    return out


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8", errors="ignore"))


def extract_functions(raw_obj: Any) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    if isinstance(raw_obj, list):
        return [x for x in raw_obj if isinstance(x, dict)], {}

    if not isinstance(raw_obj, Mapping):
        return [], {}

    program = raw_obj.get("program") if isinstance(raw_obj.get("program"), Mapping) else {}

    # Compatible with ExtractSBOFeatureRaw.java and older/generic JSON formats.
    binary = (
        raw_obj.get("binary")
        or raw_obj.get("binary_name")
        or raw_obj.get("program_name")
        or program.get("program_name")
        or program.get("executable_path")
    )

    program_name = (
        raw_obj.get("program_name")
        or program.get("program_name")
        or raw_obj.get("binary")
        or binary
    )

    meta = {
        "binary": binary,
        "program_name": program_name,
        "schema": raw_obj.get("schema") or "ghidra_runtime_generic",
        "source_core": raw_obj.get("source_core"),
        "build_config": raw_obj.get("build_config"),
    }

    for key in ("functions", "function_features", "funcs"):
        funcs = raw_obj.get(key)
        if isinstance(funcs, list):
            return [x for x in funcs if isinstance(x, dict)], meta

    # If the whole JSON represents one function.
    return [dict(raw_obj)], meta


def function_id_fields(func: Mapping[str, Any], meta: Mapping[str, Any], json_file: Path) -> Dict[str, str]:
    name = (
        func.get("function")
        or func.get("name")
        or func.get("name_norm")
        or func.get("func_name")
        or "unknown"
    )

    entry = (
        func.get("entry")
        or func.get("entry_point")
        or func.get("address")
        or func.get("addr")
        or ""
    )

    binary = meta.get("binary") or meta.get("program_name") or json_file.stem or "uploaded_elf"
    binary = str(binary)

    source_core = meta.get("source_core") or Path(binary).stem or safe_name(binary)

    return {
        "binary": binary,
        "binary_norm": safe_name(binary),
        "program_name": str(meta.get("program_name") or Path(binary).name or binary),
        "json_file": json_file.name,
        "source_core": safe_name(source_core),
        "build_config": str(meta.get("build_config") or "uploaded"),
        "function": str(name),
        "name_norm": safe_name(name),
        "entry": str(entry),
        "schema": str(meta.get("schema") or "ghidra_runtime_generic"),
    }


def raw_json_to_dataframe(json_files: Sequence[Path]) -> pd.DataFrame:
    rows: List[Dict[str, Any]] = []

    for jp in json_files:
        try:
            raw = load_json(Path(jp))
        except Exception as e:
            log("[WARN] JSON load failed:", jp, e)
            continue

        funcs, meta = extract_functions(raw)
        if not funcs:
            log("[WARN] Không có function trong JSON:", jp)
            continue

        for func in funcs:
            row = function_id_fields(func, meta, Path(jp))
            feats = flatten_obj(func, "")

            # Avoid duplicating ID-like columns as numeric features.
            for c in ID_COLS:
                feats.pop(c, None)

            row.update(feats)
            rows.append(row)

    if not rows:
        raise RuntimeError("Không trích được function feature nào từ raw JSON.")

    return pd.DataFrame.from_records(rows)


def load_feature_cols_from_file(path: Path) -> Optional[List[str]]:
    if not path.exists():
        return None

    suffix = path.suffix.lower()

    if suffix == ".json":
        obj = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
        if isinstance(obj, list):
            return [str(x) for x in obj]
        if isinstance(obj, Mapping):
            for key in ("feature_cols", "feature_columns", "features", "columns"):
                val = obj.get(key)
                if isinstance(val, list):
                    return [str(x) for x in val]
        return None

    if suffix in {".txt", ".list"}:
        cols = [x.strip() for x in path.read_text(encoding="utf-8", errors="ignore").splitlines()]
        return [x for x in cols if x and not x.startswith("#")]

    if suffix == ".csv":
        df = pd.read_csv(path, nrows=1)
        if len(df.columns) == 1:
            vals = pd.read_csv(path).iloc[:, 0].dropna().astype(str).tolist()
            return vals
        return [str(c) for c in df.columns if str(c) not in ID_COLS]

    return None


def feature_names_from_model(model: Any) -> Optional[List[str]]:
    if hasattr(model, "feature_names_in_"):
        return [str(x) for x in list(model.feature_names_in_)]

    if isinstance(model, Mapping):
        for key in ("feature_cols", "feature_columns", "features", "columns"):
            val = model.get(key)
            if isinstance(val, list):
                return [str(x) for x in val]
        for key in ("model", "estimator", "clf", "classifier"):
            if key in model:
                cols = feature_names_from_model(model[key])
                if cols:
                    return cols

    # sklearn Pipeline.
    if hasattr(model, "named_steps"):
        try:
            for step in reversed(list(model.named_steps.values())):
                cols = feature_names_from_model(step)
                if cols:
                    return cols
        except Exception:
            pass

    return None


def infer_feature_cols(model_dir: Path, feature_cols_file: str = "") -> List[str]:
    model_dir = Path(model_dir)

    if feature_cols_file:
        cols = load_feature_cols_from_file(Path(feature_cols_file).expanduser())
        if cols:
            return [c for c in cols if c not in ID_COLS]
        raise RuntimeError(f"Không đọc được feature columns từ file: {feature_cols_file}")

    for fn in ("feature_columns.json", "feature_cols.json", "feature_columns.txt", "feature_cols.txt"):
        cols = load_feature_cols_from_file(model_dir / fn)
        if cols:
            return [c for c in cols if c not in ID_COLS]

    joblib_files: List[Path] = []
    for fn in DEFAULT_MODEL_CANDIDATES:
        p = model_dir / fn
        if p.exists():
            joblib_files.append(p)

    # Fallback: any joblib/pkl model in model_dir.
    seen = {p.resolve() for p in joblib_files}
    for pattern in ("*.joblib", "*.pkl"):
        for p in sorted(model_dir.glob(pattern)):
            if p.resolve() not in seen:
                joblib_files.append(p)
                seen.add(p.resolve())

    for p in joblib_files:
        try:
            model = joblib.load(p)
            cols = feature_names_from_model(model)
            if cols:
                log(f"[INFO] feature schema lấy từ model: {p.name}")
                return [c for c in cols if c not in ID_COLS]
        except Exception as e:
            log("[WARN] Không đọc được model schema:", p, e)

    raise RuntimeError(
        "Không lấy được feature_names_in_ từ model. "
        "Hãy train model bằng pandas DataFrame hoặc lưu feature_columns.json/txt."
    )


def align_to_model_schema(df: pd.DataFrame, feature_cols: Sequence[str]) -> pd.DataFrame:
    feature_cols = [str(c) for c in feature_cols if str(c) not in ID_COLS]
    out = df.copy()

    missing = [c for c in feature_cols if c not in out.columns]
    if missing:
        out = pd.concat([out, pd.DataFrame(0.0, index=out.index, columns=missing)], axis=1)

    # Keep only ID + model columns and force numeric for model features.
    id_present = [c for c in ID_COLS if c in out.columns]
    aligned = out[id_present + list(feature_cols)].copy()

    aligned.loc[:, feature_cols] = aligned.loc[:, feature_cols].apply(pd.to_numeric, errors="coerce")
    aligned.loc[:, feature_cols] = aligned.loc[:, feature_cols].replace([np.inf, -np.inf], np.nan).fillna(0.0)

    return aligned


def check_elf(path: Path) -> None:
    if not path.exists():
        raise RuntimeError(f"File không tồn tại: {path}")
    if not path.is_file():
        raise RuntimeError(f"Đường dẫn không phải file: {path}")

    with path.open("rb") as f:
        magic = f.read(4)

    if magic != b"\x7fELF":
        raise RuntimeError("File upload không phải ELF hợp lệ.")


def find_ghidra_headless(user_value: str = "") -> str:
    if user_value:
        p = Path(user_value).expanduser()
        if p.exists():
            return str(p)

    env = os.environ.get("GHIDRA_HEADLESS", "").strip()
    if env and Path(env).exists():
        return env

    for p in (
        "/usr/share/ghidra/support/analyzeHeadless",
        "/opt/ghidra/support/analyzeHeadless",
        "/opt/ghidra_12.0.4_PUBLIC/support/analyzeHeadless",
    ):
        if Path(p).exists():
            return p

    found = shutil.which("analyzeHeadless")
    if found:
        return found

    raise RuntimeError("Không tìm thấy analyzeHeadless. Hãy set GHIDRA_HEADLESS hoặc cài Ghidra.")


def resolve_ghidra_script(script_dir: Path, script_name: str = "") -> str:
    script_dir = Path(script_dir)

    candidates = [script_name] if script_name else DEFAULT_SCRIPT_CANDIDATES
    for name in candidates:
        if not name:
            continue
        p = script_dir / name
        if p.exists():
            return p.name

    tried = ", ".join(str(script_dir / x) for x in candidates if x)
    raise RuntimeError(f"Không thấy Ghidra script. Đã thử: {tried}")


def run_ghidra(
    elf_path: Path,
    raw_dir: Path,
    work_dir: Path,
    script_dir: Path,
    ghidra_headless: str,
    timeout: int,
    script_name: str = "",
) -> List[Path]:
    script_file = resolve_ghidra_script(script_dir, script_name)

    project_dir = work_dir / "ghidra_project"
    project_dir.mkdir(parents=True, exist_ok=True)

    # Avoid stale JSON from previous ELF runs.
    if raw_dir.exists():
        shutil.rmtree(raw_dir)
    raw_dir.mkdir(parents=True, exist_ok=True)

    project_name = "sbo_runtime_" + str(int(time.time()))

    cmd = [
        ghidra_headless,
        str(project_dir),
        project_name,
        "-import", str(elf_path),
        "-scriptPath", str(script_dir),
        "-postScript", script_file, str(raw_dir),
        "-analysisTimeoutPerFile", str(timeout),
        "-deleteProject",
    ]

    log("[GHIDRA CMD]")
    log(" ".join(cmd))

    proc = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=timeout + 120,
    )


    if proc.returncode != 0:
        raise RuntimeError(f"Ghidra failed với return code {proc.returncode}")

    json_files = sorted(raw_dir.rglob("*.json"))

    # Defensive fallback if a custom script writes elsewhere under work_dir.
    if not json_files:
        json_files = sorted(work_dir.rglob("*.json"))

    if not json_files:
        raise RuntimeError("Ghidra chạy xong nhưng không tìm thấy raw JSON.")

    return json_files


def existing_json_files(raw_json_dir: str) -> List[Path]:
    p = Path(raw_json_dir).expanduser().resolve()
    if not p.exists():
        raise RuntimeError(f"raw-json-dir không tồn tại: {p}")
    files = sorted(p.rglob("*.json")) if p.is_dir() else [p]
    if not files:
        raise RuntimeError(f"Không tìm thấy JSON trong: {p}")
    return files


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="Run Ghidra ExtractSBOFeatureRaw and convert raw JSON to model-ready CSV."
    )

    ap.add_argument("--elf", help="Đường dẫn ELF upload. Bắt buộc nếu không dùng --raw-json-dir.")
    ap.add_argument("--raw-json-dir", default="", help="Bỏ qua Ghidra và vectorize JSON có sẵn.")
    ap.add_argument("--out-csv", required=True)
    ap.add_argument("--model-dir", required=True)
    ap.add_argument("--feature-cols", default="", help="File feature columns json/txt/csv nếu model không có feature_names_in_.")
    ap.add_argument("--work-dir", default="runtime/analysis/current")
    ap.add_argument("--script-dir", default="ghidra_scripts")
    ap.add_argument("--ghidra-script", default="ExtractSBOFeatureRaw.java", help="Mặc định dùng file Java mới.")
    ap.add_argument("--ghidra-headless", default="")
    ap.add_argument("--timeout", type=int, default=360)

    args = ap.parse_args(argv)

    if not args.raw_json_dir and not args.elf:
        ap.error("Cần --elf hoặc --raw-json-dir")

    return args


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)

    out_csv = Path(args.out_csv).expanduser().resolve()
    model_dir = Path(args.model_dir).expanduser().resolve()
    work_dir = Path(args.work_dir).expanduser().resolve()
    raw_dir = work_dir / "raw_json"

    work_dir.mkdir(parents=True, exist_ok=True)
    out_csv.parent.mkdir(parents=True, exist_ok=True)

    if args.raw_json_dir:
        log("[1] Use existing raw JSON")
        json_files = existing_json_files(args.raw_json_dir)
        elf = Path(args.elf).expanduser().resolve() if args.elf else Path("uploaded_elf")
    else:
        elf = Path(args.elf).expanduser().resolve()
        check_elf(elf)
        ghidra = find_ghidra_headless(args.ghidra_headless)

        log("[1] Run Ghidra")
        json_files = run_ghidra(
            elf_path=elf,
            raw_dir=raw_dir,
            work_dir=work_dir,
            script_dir=Path(args.script_dir).expanduser().resolve(),
            ghidra_headless=ghidra,
            timeout=args.timeout,
            script_name=args.ghidra_script,
        )

    log("[2] JSON files:")
    for jp in json_files:
        log(" -", jp)

    log("[3] Vectorize raw JSON")
    df = raw_json_to_dataframe(json_files)
    log("[INFO] raw feature df shape:", df.shape)

    log("[4] Align to model schema")
    feature_cols = infer_feature_cols(model_dir, args.feature_cols)
    missing_features = [c for c in feature_cols if c not in df.columns]
    aligned = align_to_model_schema(df, feature_cols)

    aligned.to_csv(out_csv, index=False)

    X = aligned[list(feature_cols)] if feature_cols else pd.DataFrame(index=aligned.index)
    avg_nonzero = float((X != 0).sum(axis=1).mean()) if len(X) else 0.0
    total_nonzero = int((X != 0).sum().sum()) if len(X) else 0

    info = {
        "elf": str(elf),
        "out_csv": str(out_csv),
        "rows": int(len(aligned)),
        "feature_cols": int(len(feature_cols)),
        "missing_feature_columns": missing_features,
        "missing_feature_count": len(missing_features),
        "raw_columns_before_align": int(df.shape[1]),
        "avg_nonzero_features_per_function": avg_nonzero,
        "total_nonzero_feature_values": total_nonzero,
        "json_files": [str(x) for x in json_files],
        "ghidra_script": args.ghidra_script if not args.raw_json_dir else "skipped",
    }

    Path(str(out_csv) + ".info.json").write_text(
        json.dumps(info, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    log("[OK] wrote:", out_csv)
    log(json.dumps(info, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        log("\n[STOP] interrupted")
        raise SystemExit(130)
    except Exception as e:
        log("[ERROR]", e)
        raise SystemExit(1)
