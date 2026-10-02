"""Explicit group partitions shared by feature selection and training."""
import hashlib
import json
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedGroupKFold

PARTITIONS = ('train', 'meta', 'select', 'test')


def sha256(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def validate_partitions(df, manifest):
    group_col = manifest['group_col']
    if group_col not in df or df[group_col].isna().any():
        raise ValueError('Missing group identifiers.')
    if 'label' not in df or not df['label'].isin([0, 1]).all():
        raise ValueError('Every row must have a binary 0/1 label.')
    ids, groups = set(), set()
    for name in PARTITIONS:
        rows = manifest['partitions'][name]
        if not rows or any(type(i) is not int or not 0 <= i < len(df) for i in rows):
            raise ValueError(f'Invalid row indexes in {name}.')
        if len(set(rows)) != len(rows) or ids.intersection(rows):
            raise ValueError('Partitions overlap by row.')
        group_set = set(df.iloc[rows][group_col].astype(str))
        if groups.intersection(group_set):
            raise ValueError('Partitions overlap by group.')
        if set(df.iloc[rows]['label']) != {0, 1}:
            raise ValueError(f'{name} does not contain both classes; use more groups.')
        ids.update(rows)
        groups.update(group_set)
    if ids != set(range(len(df))):
        raise ValueError('Partitions must cover every input row exactly once.')


def make_partitions(df, seed=42, group_col='source_core'):
    if group_col not in df or df[group_col].isna().any():
        raise ValueError(f'Input requires nonempty {group_col}.')
    if not df['label'].isin([0, 1]).all():
        raise ValueError('Labels must be 0/1, with no missing values.')
    y = df['label'].to_numpy()
    groups = df[group_col].astype(str).to_numpy()
    idx = np.arange(len(df))
    def split(rows, folds, random_state):
        if len(set(groups[rows])) < folds:
            raise ValueError('Too few groups for the requested split; no random-row fallback.')
        splitter = StratifiedGroupKFold(folds, shuffle=True, random_state=random_state)
        a, b = next(splitter.split(rows, y[rows], groups[rows]))
        return rows[a], rows[b]
    train_val, test = split(idx, 5, seed)
    train, val = split(train_val, 4, seed + 1)
    meta, select = split(val, 2, seed + 77)
    result = {'protocol': 'group_split_before_feature_selection_v1',
              'random_state': seed, 'group_col': group_col, 'row_count': len(df),
              'partitions': {k: v.tolist() for k, v in
                             zip(PARTITIONS, (train, meta, select, test))}}
    validate_partitions(df, result)
    return result


def load_partitions(path, data_path, df):
    manifest = json.loads(Path(path).read_text(encoding='utf-8'))
    if manifest['dataset_sha256'] != sha256(data_path):
        raise ValueError('Dataset hash does not match the saved split manifest.')
    validate_partitions(df, manifest)
    return {name: np.asarray(manifest['partitions'][name], dtype=int) for name in PARTITIONS}
