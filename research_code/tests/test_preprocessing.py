"""Train-only fitting tests; no classifier is imported or fitted."""

import unittest
import numpy as np
import pandas as pd
from src.features import MODEL_INPUTS
from src.preprocessing import make_preprocessor


class PreprocessingTests(unittest.TestCase):
    def frame(self, values):
        frame = pd.DataFrame({name: values for name in MODEL_INPUTS})
        frame["scp_process_count"] = 0.0
        frame["ScenarioID"] = "not-a-predictor"
        frame["GroundTruthLabel"] = 1
        frame["protected_resource_event_count"] = 999
        return frame

    def test_imputation_and_constant_selection_fit_training_only(self):
        pipeline = make_preprocessor("random_forest")
        train = self.frame([1.0, np.nan, 3.0])
        pipeline.fit(train)
        statistics = pipeline["impute"].statistics_.copy()
        retained = list(pipeline.get_feature_names_out())
        validation = self.frame([1000.0, np.nan])
        validation["scp_process_count"] = 1000.0
        result = pipeline.transform(validation)
        np.testing.assert_array_equal(pipeline["impute"].statistics_, statistics)
        self.assertEqual(result["windows_event_count"].iloc[1], 2.0)
        self.assertNotIn("scp_process_count", retained)
        self.assertNotIn("protected_resource_event_count", retained)
        self.assertNotIn("GroundTruthLabel", retained)
        self.assertNotIn("ScenarioID", retained)
        self.assertEqual(list(result.columns), retained)

    def test_scaler_does_not_learn_validation_or_test_values(self):
        pipeline = make_preprocessor("tabpfn").fit(self.frame([1.0, 2.0, 3.0]))
        mean = pipeline["scale"].mean_.copy()
        pipeline.transform(self.frame([1000000.0]))
        np.testing.assert_array_equal(pipeline["scale"].mean_, mean)
        np.testing.assert_allclose(mean, 2.0)


if __name__ == "__main__":
    unittest.main()
