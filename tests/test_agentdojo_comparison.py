import copy
import unittest
from adapters.agentdojo_pi.compare import compare_summaries, MATCH_FIELDS


class ComparisonTests(unittest.TestCase):
    def fixture(self):
        summary = {key: None for key in MATCH_FIELDS}
        summary.update(status="completed", mode="baseline", attack=None,
            user_tasks=["user_task_0", "user_task_1"], injection_tasks=[],
            official_results={"utility_results": [
                {"user_task": "user_task_0", "injection_task": "", "value": True}],
                "security_results": []},
            task_outcomes=[{"phase": "clean", "user_task": "user_task_1", "status": "error"}])
        guarded = copy.deepcopy(summary)
        guarded["mode"] = "guarded"
        return summary, guarded

    def test_missing_scores_are_not_counted_as_failure_or_defense(self):
        b, g = self.fixture()
        g["official_results"]["utility_results"][0]["value"] = False
        result = compare_summaries(b, g)
        self.assertEqual(result["paired_scored"], 1)
        self.assertEqual(result["counts"]["baseline_only_succeeded"], 1)
        self.assertEqual(result["counts"]["unscored_on_either_side"], 1)
        self.assertIsNone(result["rows"][0]["baseline_attack_success"])

    def test_different_configs_or_task_sets_rejected(self):
        for key in ("model", "source_sha256", "manifest_sha256", "user_tasks"):
            b, g = self.fixture()
            g[key] = ["other"] if key == "user_tasks" else "other"
            with self.subTest(key=key), self.assertRaises(ValueError):
                compare_summaries(b, g)

    def test_missing_metadata_or_duplicate_scores_rejected(self):
        b, g = self.fixture()
        del b["model"]
        with self.assertRaises(ValueError):
            compare_summaries(b, g)
        b, g = self.fixture()
        b["official_results"]["utility_results"] *= 2
        with self.assertRaises(ValueError):
            compare_summaries(b, g)
