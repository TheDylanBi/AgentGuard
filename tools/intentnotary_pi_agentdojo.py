"""Use the IntentNotary Pi pipeline with the official AgentDojo benchmark."""

import json
import os
from contextlib import nullcontext
from datetime import date
from functools import lru_cache
from pathlib import Path

from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline
from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.logging import Logger, TraceLogger
from agentdojo.task_suite.load_suites import get_suite
from google.genai.errors import ServerError

from adapters.agentdojo_pi.errors import ActionModelError
from adapters.agentdojo_pi.host import SIMULATION_ABLATIONS
from adapters.agentdojo_pi.pipeline import PiPipeline
from policy.call_review import ReviewStageError
from policy.review_snapshot import capture_review_inputs


@lru_cache
def _simulation_day(version, suite):
    env = get_suite(version, suite).load_and_inject_default_environment({})
    calendar = getattr(env, "calendar", None)
    return calendar.current_day.isoformat() if calendar is not None else None


class OfficialPiReview(BasePipelineElement):
    def __init__(self, model):
        self.model = model
        self.pi_package = os.environ["INTENTNOTARY_PI_PACKAGE"]
        self.pi_agent_dir = os.environ["INTENTNOTARY_PI_AGENT_DIR"]
        self.profile = os.environ.get("INTENTNOTARY_PI_PROFILE", "operation")
        if self.profile not in {"baseline", "standard", "operation"}:
            raise ValueError("Unknown IntentNotary AgentDojo profile")
        self.ablation = os.environ.get("INTENTNOTARY_PI_ABLATION", "full")
        if self.ablation not in SIMULATION_ABLATIONS:
            raise ValueError(f"Unknown IntentNotary AgentDojo ablation: {self.ablation}")
        if self.profile == "baseline" and self.ablation != "full":
            raise ValueError("IntentNotary AgentDojo ablations require a guarded profile")
        self.run_day = os.environ.get("INTENTNOTARY_PAYMENT_EXECUTION_DAY") or date.today().isoformat()

    def query(self, query, runtime, env, messages=(), extra_args=None):
        logger = Logger.get()
        if not isinstance(logger, TraceLogger):
            raise RuntimeError("IntentNotary Pi requires an AgentDojo task trace")
        suite = logger.context["suite_name"]
        version = logger.context["benchmark_version"]
        manifest = Path(__file__).resolve().parents[1] / "adapters" / "agentdojo_pi" / f"{suite}_manifest.json"
        baseline = self.profile == "baseline"
        audit = Path(logger.dirpath) / "intentnotary-pi-audit" / suite
        trusted_day = _simulation_day(version, suite)
        pipeline = PiPipeline(
            manifest=manifest,
            pi_package=self.pi_package,
            pi_agent_dir=self.pi_agent_dir,
            provider="remote-action",
            model=self.model,
            mode="baseline" if baseline else "guarded",
            intent_format="rules" if baseline else "review",
            review_profile="standard" if baseline else self.profile,
            review_coordination="scoped",
            ablation=self.ablation,
            output=audit,
            node=os.environ.get("INTENTNOTARY_PI_NODE", "node"),
            max_turns=16,
            timeout=300,
            trusted_current_day=trusted_day,
            calendar_reminder_window="09:00-10:00",
            payment_date_policy="run-day",
            payment_execution_day=trusted_day or self.run_day,
            equal_share_policy="two-party",
            action_output_budget="model",
        )
        def save_snapshot(snapshot):
            folder = audit / "review-inputs"
            folder.mkdir(parents=True, exist_ok=True, mode=0o700)
            with (folder / (snapshot["snapshot_hash"].split(":")[-1] + ".json")).open(
                    "w", encoding="utf-8") as file:
                json.dump(snapshot, file, ensure_ascii=False)

        capture = (os.environ.get("INTENTNOTARY_PI_CAPTURE_REVIEW") == "1"
                   and not baseline and self.ablation != "no-semantic-review")
        with capture_review_inputs(save_snapshot) if capture else nullcontext():
            try:
                return pipeline.query(query, runtime, env, messages, extra_args)
            except (ActionModelError, ReviewStageError) as error:
                status = error.diagnostic.get("status")
                if not error.task_local or status == "review_state_changed":
                    raise
                # Route a failed task through AgentDojo's own error handling.
                # Its fallback score and error marker remain visible in traces.
                message = f"IntentNotary task error ({type(error).__name__}: {status})"
                raise ServerError(500, {"error": {"code": 500, "message": message}}) from error


def _with_intentnotary_pi(cls, config):
    if config.llm != "openai-compatible" or not config.model_id or config.defense is not None:
        raise ValueError("Use --model OPENAI_COMPATIBLE --model-id MODEL and omit --defense")
    element = OfficialPiReview(config.model_id)
    pipeline = cls([element])
    variant = element.profile if element.ablation == "full" else f"{element.profile}-{element.ablation}"
    pipeline.name = f"openai-compatible-intentnotary-pi-{variant}-{config.model_id}"
    return pipeline


AgentPipeline.from_config = classmethod(_with_intentnotary_pi)
