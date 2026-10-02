"""Regression tests for input validation and ensemble behavior."""
import unittest
from pathlib import Path
import json
import hashlib
import zlib
import numpy as np
import pandas as pd
from sbo_core import prepare_X, predict_from_metrics, available_models

ROOT = Path(__file__).resolve().parents[1]


class FakeModel:
    feature_names_in_ = np.array(['feature'])
    classes_ = np.array([1, 0])  # Check positive-class lookup, not column position.

    def __init__(self, probability):
        self.probability = probability

    def predict_proba(self, X):
        p = np.full(len(X), self.probability)
        return np.column_stack([p, 1 - p])


class InferenceTests(unittest.TestCase):
    def setUp(self):
        self.X = pd.DataFrame({'feature': [2.0, 3.0]})
        self.metrics = pd.DataFrame([
            {'model': 'RandomForest'},
            {'model': 'WEIGHT_RF_DT', 'weight_rf': .75, 'weight_tree': .25},
            {'model': 'STACK_LOGISTIC_PROB_RISK'},
        ])
        self.models = {'RandomForest': FakeModel(.8), 'DecisionTree': FakeModel(.2)}

    def test_class_order_and_weighted_vote(self):
        p, name, _, _ = predict_from_metrics(self.models, self.metrics, self.X, 'WEIGHT_RF_DT')
        np.testing.assert_allclose(p, [.65, .65])
        self.assertEqual(name, 'WEIGHT_RF_DT')

    def test_missing_component_does_not_change_model(self):
        models = {'RandomForest': self.models['RandomForest']}
        self.assertEqual(available_models(self.metrics, models), ['RandomForest'])
        with self.assertRaisesRegex(ValueError, 'Missing required'):
            predict_from_metrics(models, self.metrics, self.X, 'WEIGHT_RF_DT')

    def test_unsupported_meta_model_is_not_selectable(self):
        self.assertNotIn('STACK_LOGISTIC_PROB_RISK', available_models(self.metrics, self.models))
        with self.assertRaisesRegex(ValueError, 'Unsupported'):
            predict_from_metrics(self.models, self.metrics, self.X, 'STACK_LOGISTIC_PROB_RISK')

    def test_missing_feature_rejected(self):
        with self.assertRaisesRegex(ValueError, 'missing'):
            prepare_X(self.X, ['absent'])

    def test_invalid_text_rejected_and_sparse_values_preserved(self):
        with self.assertRaisesRegex(ValueError, 'nonnumeric'):
            prepare_X(pd.DataFrame({'feature': ['invalid']}), ['feature'])
        X, _ = prepare_X(pd.DataFrame({'feature': [None, np.inf, 2]}), ['feature'])
        np.testing.assert_allclose(X['feature'], [0, 0, 2])

    def test_model_compression_is_lossless(self):
        folder = ROOT / 'models/sbo_detector'
        manifest = json.loads((folder / 'artifact_manifest.json').read_text())
        for name, item in manifest.items():
            packed = (folder / name).read_bytes()
            self.assertEqual(hashlib.sha256(packed).hexdigest(), item['compressed_sha256'])
            self.assertEqual(hashlib.sha256(zlib.decompress(packed)).hexdigest(), item['original_sha256'])


if __name__ == '__main__':
    unittest.main()
