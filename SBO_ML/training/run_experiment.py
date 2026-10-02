"""Split first, select features only on train, then fit the supplied ensemble suite."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import pandas as pd

try:
    from .protocol import make_partitions, sha256
except ImportError:
    from protocol import make_partitions, sha256

HERE = Path(__file__).resolve().parent
ID_COLUMNS = {'binary', 'binary_norm', 'program_name', 'json_file', 'source_core',
              'build_config', 'function', 'name_norm', 'entry', 'schema',
              'merge_stage', 'candidate_reasons', 'label'}


def run(script, *args):
    subprocess.run([sys.executable, str(HERE / script), *map(str, args)], check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data', required=True, help='Original full feature CSV; not the 200-row demo.')
    parser.add_argument('--out-dir', required=True, help='New directory for one experiment.')
    parser.add_argument('--features', type=int, choices=[160, 260], default=260)
    parser.add_argument('--seed', type=int, default=42)
    parser.add_argument('--n-jobs', type=int, default=4)
    parser.add_argument('--selector-trees', type=int, default=500)
    parser.add_argument('--rf-trees', type=int, default=300)
    parser.add_argument('--xgb-trees', type=int, default=450)
    parser.add_argument('--xgb-device', choices=['cpu', 'cuda'], default='cpu')
    parser.add_argument('--weight-step', type=float, default=.05)
    parser.add_argument('--prepare-only', action='store_true', help='Validate and save outer partitions only.')
    args = parser.parse_args()
    data = Path(args.data).resolve()
    out = Path(args.out_dir).resolve()
    if out.exists() and any(out.iterdir()):
        raise ValueError('Output directory must be new or empty; choose a new run name.')
    out.mkdir(parents=True, exist_ok=True)
    df = pd.read_csv(data, low_memory=False)
    manifest = make_partitions(df, args.seed)
    manifest['source_dataset_sha256'] = sha256(data)
    manifest['dataset_sha256'] = manifest['source_dataset_sha256']
    (out / 'source_split_manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    if args.prepare_only:
        print('Group partitions verified; no feature selection or training performed.')
        return

    # Only this partition is visible to all feature-ranking/audit scripts.
    train_csv = out / 'train_for_selection.csv'
    train_df = df.iloc[manifest['partitions']['train']]
    train_df.to_csv(train_csv, index=False)
    selected_dir = out / 'feature_selection'
    run('make_v6_noise_pruned_datasets.py', '--data', train_csv, '--out-dir', selected_dir,
        '--group-col', 'source_core', '--seed', args.seed, '--n-jobs', args.n_jobs,
        '--trees', args.selector_trees, '--corr-threshold', .995, '--topk', 260)
    selected_csv = selected_dir / 'dataset_v6_pruned_score_corr_top260.csv'
    if args.features == 160:
        audit_dir = out / 'train_feature_audit'
        run('export_feature_inventory_for_review.py', '--data', selected_csv,
            '--model-dir', out / 'no_pretrained_models', '--out-dir', audit_dir)
        final_dir = out / 'feature_selection_160'
        run('select_final_security_features.py', '--data', selected_csv,
            '--audit', audit_dir / 'feature_inventory_all.csv', '--out-dir', final_dir,
            '--target-k', 160, '--corr-threshold', .965)
        candidates = list(final_dir.glob('dataset_final_security_*.csv'))
        if len(candidates) != 1:
            raise ValueError('Cannot identify the selected 160-feature dataset.')
        selected_csv = candidates[0]
    columns = pd.read_csv(selected_csv, nrows=0).columns.tolist()
    feature_cols = [c for c in columns if c not in ID_COLUMNS]
    if len(feature_cols) != args.features:
        raise ValueError(f'Only {len(feature_cols)} features available; requested {args.features}.')
    full_csv = out / 'dataset_selected.csv'
    df.loc[:, columns].to_csv(full_csv, index=False)
    manifest['dataset_sha256'] = sha256(full_csv)
    manifest['selected_features'] = feature_cols
    split_path = out / 'split_manifest.json'
    split_path.write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    run('train_sbo_v5_ensemble_suite_kaggle.py', '--data', full_csv, '--out-dir', out / 'models',
        '--split-manifest', split_path, '--n-jobs', args.n_jobs, '--random-state', args.seed,
        '--rf-trees', args.rf_trees, '--xgb-trees', args.xgb_trees,
        '--xgb-device', args.xgb_device, '--weight-step', args.weight_step, '--recall-min', .95)


if __name__ == '__main__':
    main()
