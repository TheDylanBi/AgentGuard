"""Load AttriGuard into the official AgentDojo benchmark via --module-to-load."""

import json
import os
from functools import partial

from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline
from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop, tool_result_to_str
from AttriGuard import AttriGuardExecutionLoop
from my_agent_pipeline import _get_attriguard_aux_llms


_original_from_config = AgentPipeline.from_config.__func__


def _with_attriguard(cls, config):
    if config.defense is not None:
        raise ValueError("Omit --defense when loading the AttriGuard module.")

    pipeline = _original_from_config(cls, config)
    elements = list(pipeline.elements)
    if len(elements) != 4 or not isinstance(elements[-1], ToolsExecutionLoop):
        raise RuntimeError("Unexpected AgentDojo pipeline layout for AttriGuard.")

    attenuation_llm, judge_llm = _get_attriguard_aux_llms(config.tool_delimiter)
    formatter = tool_result_to_str
    if config.tool_output_format == "json":
        formatter = partial(tool_result_to_str, dump_fn=json.dumps)

    elements[-1] = AttriGuardExecutionLoop(
        elements[-2],
        tool_output_formatter=formatter,
        attenuation_llm=attenuation_llm,
        judge_llm=judge_llm,
        attenuation_level=int(os.getenv("ATTRIGUARD_LEVEL", "2")),
        survival_mode=os.getenv("ATTRIGUARD_SURVIVAL", "fuzzy"),
        skip_empty_tool_results_audit=bool(int(os.getenv("ATTRIGUARD_SKIP_EMPTY_AUDIT", "1"))),
        debug=bool(int(os.getenv("ATTRIGUARD_DEBUG", "0"))),
    )
    pipeline.elements = elements
    pipeline.name = f"{pipeline.name}-attriguard"
    return pipeline


AgentPipeline.from_config = classmethod(_with_attriguard)
