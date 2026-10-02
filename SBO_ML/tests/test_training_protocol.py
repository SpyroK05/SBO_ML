import copy
import json
from pathlib import Path
from uuid import uuid4
import unittest
import pandas as pd
from training.protocol import make_partitions, validate_partitions, load_partitions, sha256


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.df = pd.DataFrame({'source_core': [f'group_{i // 4}' for i in range(400)],
                                'label': [i % 2 for i in range(400)],
                                'value': list(range(400))})
        self.manifest = make_partitions(self.df)

    def test_partition_is_reproducible_and_covers_all_rows(self):
        self.assertEqual(self.manifest, make_partitions(self.df))
        validate_partitions(self.df, self.manifest)
        rows = [i for part in self.manifest['partitions'].values() for i in part]
        self.assertEqual(sorted(rows), list(range(len(self.df))))

    def test_group_leakage_is_rejected(self):
        df = self.df.copy()
        parts = self.manifest['partitions']
        df.loc[parts['test'][0], 'source_core'] = df.loc[parts['train'][0], 'source_core']
        with self.assertRaisesRegex(ValueError, 'overlap by group'):
            validate_partitions(df, self.manifest)

    def test_row_leakage_is_rejected(self):
        manifest = copy.deepcopy(self.manifest)
        manifest['partitions']['test'].append(manifest['partitions']['train'][0])
        with self.assertRaisesRegex(ValueError, 'overlap by row'):
            validate_partitions(self.df, manifest)

    def test_missing_group_does_not_fall_back_to_random_rows(self):
        with self.assertRaisesRegex(ValueError, 'source_core'):
            make_partitions(self.df.drop(columns='source_core'))

    def test_dataset_change_invalidates_manifest(self):
        stem = Path.cwd() / ('sbo_test_' + uuid4().hex)
        data, split = stem.with_suffix('.csv'), stem.with_suffix('.json')
        try:
            self.df.to_csv(data, index=False)
            self.manifest['dataset_sha256'] = sha256(data)
            split.write_text(json.dumps(self.manifest), encoding='utf-8')
            partitions = load_partitions(split, data, self.df)
            self.assertEqual(len(partitions['train']), len(self.manifest['partitions']['train']))
            data.write_text(data.read_text() + '\n', encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'hash'):
                load_partitions(split, data, self.df)
        finally:
            data.unlink(missing_ok=True)
            split.unlink(missing_ok=True)


if __name__ == '__main__':
    unittest.main()
