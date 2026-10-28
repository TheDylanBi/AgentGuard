import copy
import unittest
from adapters.agentdojo_pi.compare import MATCH_FIELDS
from adapters.agentdojo_pi.review_report import summarize, compare_formats


class ReviewReportTests(unittest.TestCase):
    def test_clean_only_never_schedules_attack_trials(self):
        from adapters.agentdojo_pi.validate_review import protocol
        self.assertEqual(len(protocol(clean_only=True)), 4)
        self.assertTrue(all(t['phase'] == 'clean' for t in protocol(clean_only=True)))
        with self.assertRaises(ValueError):
            protocol(True, True)

    def test_experiment_protocol_is_fixed_before_scores(self):
        from adapters.agentdojo_pi.validate_review import protocol
        trials = protocol(True)
        self.assertEqual([row["intent_format"] for row in trials[:4]], ["rules", "review", "review", "rules"])
        self.assertEqual([row["users"] for row in trials if row["phase"] == "pilot"],
                         [["user_task_0", "user_task_1", "user_task_2", "user_task_3"]] * 2)
        self.assertEqual(len(trials), 7)
        self.assertEqual(trials[-1]["id"], "full_review")

    def fixture(self):
        data = {key: None for key in MATCH_FIELDS}
        data.update(status="completed_with_errors", mode="guarded", intent_format="rules",
            intent_model="fixture", intent_output_format="text", intent_compact_json=False,
            read_preflight=False, intent_config_sha256="fixture-config", attack=None,
            user_tasks=["user_task_0", "user_task_1"], injection_tasks=None,
            task_accounting={"planned_by_phase": {"clean": 2, "prescreen": 0, "attack": 0}},
            task_outcomes=[{"phase": "clean", "user_task": "user_task_0", "injection_task": None,
                            "status": "scored", "utility": True, "security": True, "elapsed_seconds": 2},
                           {"phase": "clean", "user_task": "user_task_1", "injection_task": None,
                            "status": "error", "utility": None, "security": None, "elapsed_seconds": 10}],
            official_results={"utility_results": [{"user_task": "user_task_0", "injection_task": "", "value": True}],
                              "security_results": []}, runs=[])
        return data

    def test_errors_reduce_coverage_and_observed_success_not_official_scored_rate(self):
        row = summarize(self.fixture())["phases"]["clean"]
        self.assertEqual(row["observed_success_over_planned"], .5)
        self.assertEqual(row["utility_on_scored"], 1)
        self.assertEqual(row["score_coverage"], .5)
        self.assertEqual(row["errors"], 1)
        self.assertIsNone(row["attack_success_on_scored"])
        self.assertEqual(row["latency"]["p50_seconds"], 6)

    def test_guarded_pair_requires_identical_source_and_intent_service(self):
        a = self.fixture(); b = copy.deepcopy(a); b["intent_format"] = "review"
        result = compare_formats(a, b)
        self.assertEqual(result["paired_scored"], 1)
        self.assertEqual(result["counts"]["unscored_on_either_side"], 1)
        self.assertEqual(a["mode"], "guarded")
        for key in ("source_sha256", "intent_model", "intent_config_sha256"):
            changed = copy.deepcopy(b); changed[key] = "other"
            with self.subTest(key=key), self.assertRaises(ValueError):
                compare_formats(a, changed)
        changed=copy.deepcopy(b);changed['authorization_contracts_sha256']='extra-approval'
        with self.assertRaises(ValueError):compare_formats(a,changed)

    def test_attack_and_prescreen_denominators_remain_separate(self):
        data = self.fixture()
        data["task_accounting"]["planned_by_phase"] = {"prescreen": 1, "attack": 2}
        data["task_outcomes"][0]["phase"] = "prescreen"
        data["task_outcomes"][1]["phase"] = "attack"
        phases = summarize(data)["phases"]
        self.assertEqual(phases["prescreen"]["successful"], 1)
        self.assertEqual(phases["attack"]["successful"], 0)
        self.assertIsNone(phases["attack"]["attack_success_on_scored"])
        self.assertEqual(phases["attack"]["unprocessed"], 1)
