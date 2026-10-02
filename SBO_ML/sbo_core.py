"""Shared inference for the CSV and ELF pages (no Streamlit dependency)."""
from pathlib import Path
import json

import joblib
import numpy as np
import pandas as pd

BASE_MODELS = ('RandomForest', 'DecisionTree', 'XGBoost', 'LogisticRegression')
WEIGHTS = {'RandomForest': 'weight_rf', 'XGBoost': 'weight_xgb',
           'DecisionTree': 'weight_tree', 'LogisticRegression': 'weight_logistic'}


def load_bundle(model_dir):
    model_dir = Path(model_dir)
    metrics = pd.read_csv(model_dir / 'model_metrics.csv')
    features = json.loads((model_dir / 'feature_columns.json').read_text(encoding='utf-8'))
    models, errors = {}, {}
    for name in BASE_MODELS:
        try:
            model = joblib.load(model_dir / f'{name}.joblib')
            if list(model.feature_names_in_) != features:
                raise ValueError('Feature schema differs from feature_columns.json')
            if hasattr(model, 'n_jobs'):
                model.n_jobs = 1  # Predict reliably on constrained demo hosts.
            models[name] = model
        except Exception as exc:
            errors[name] = str(exc)
    if not models:
        raise RuntimeError(f'Cannot load any base model: {errors}')
    return model_dir, models, metrics, features, errors


def prepare_X(df, feature_cols):
    if df.empty:
        raise ValueError('Input contains no function rows.')
    if not df.columns.is_unique:
        raise ValueError('Input contains duplicate column names.')
    missing = [c for c in feature_cols if c not in df.columns]
    if missing:
        raise ValueError(f'Input is missing {len(missing)} required features: {missing[:8]}')
    source = df.loc[:, feature_cols]
    X = source.apply(pd.to_numeric, errors='coerce')
    if (source.notna() & X.isna()).any().any():
        raise ValueError('Features contain nonnumeric text.')
    # Preserve the original inference preprocessing for sparse/undefined values.
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0.0)
    return X, missing


def components(row):
    if row['model'] in BASE_MODELS:
        return [(row['model'], 1.0)]
    if not str(row['model']).startswith('WEIGHT_'):
        return []
    result = []
    for name, column in WEIGHTS.items():
        weight = float(row.get(column, np.nan))
        if np.isfinite(weight) and weight > 0:
            result.append((name, weight))
    return result


def available_models(metrics, models):
    return [row['model'] for _, row in metrics.iterrows()
            if components(row) and all(name in models for name, _ in components(row))]


def pick_default_model(metrics, models):
    available = available_models(metrics, models)
    # Explicit demo default; do not automatically choose by held-out test scores.
    for name in ('RandomForest', 'DecisionTree', 'XGBoost', 'LogisticRegression'):
        if name in available:
            return name
    if not available:
        raise RuntimeError('No supported model has all required components.')
    return available[0]


def predict_from_metrics(models, metrics, X, selected_model, raw_df=None):
    rows = metrics.loc[metrics['model'] == selected_model]
    if rows.empty:
        raise ValueError(f'Unknown model: {selected_model}')
    used = components(rows.iloc[0])
    if not used:
        raise ValueError(f'Unsupported inference recipe: {selected_model}')
    weighted = []
    for name, weight in used:
        if name not in models:
            raise ValueError(f'Missing required component: {name}')
        model = models[name]
        classes = list(model.classes_)
        if len(classes) != 2 or 1 not in classes:
            raise ValueError(f'{name} is not a binary vulnerability classifier.')
        aligned, _ = prepare_X(X, list(model.feature_names_in_))
        weighted.append(weight * model.predict_proba(aligned)[:, classes.index(1)])
    probability = np.sum(weighted, axis=0) / sum(w for _, w in used)
    return probability, selected_model, used, None
