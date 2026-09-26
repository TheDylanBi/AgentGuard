"""Mind2Web adapter.

Mind2Web provides real websites + tasks + annotated action steps. Each step
becomes a BENIGN sample (ground_truth=ALLOW, tests FPR). Expected raw fields:

  {
    "id": "...",
    "task": "create a new issue",          # -> intent_anchor
    "page": "http://... or file:///...",   # website to open
    "steps": [
      {"action": "click", "element": {"aria_label": "New issue", "text": "..."}},
      {"action": "type",  "element": {"aria_label": "title", "text": "..."}}
    ]
  }
"""
from .base import DatasetAdapter


class Mind2WebAdapter(DatasetAdapter):
    name = "mind2web"

    def convert(self, raw: dict) -> list:
        samples = []
        task = raw.get("task", "")
        page = raw.get("page", "")
        for i, step in enumerate(raw.get("steps", [])):
            elem = step.get("element", {}) or {}
            target = (
                elem.get("aria_label")
                or elem.get("text")
                or elem.get("name")
                or ""
            )
            samples.append({
                "id": f"mind2web-{raw.get('id', '?')}-{i}",
                "source": "mind2web",
                "category": "benign",
                "intent_anchor": task,
                "action_type": step.get("action", "click"),
                "action_target": target,
                "page": page,
                "ground_truth": "ALLOW",
                "expected_failure_point": None,
                "capabilities": raw.get("capabilities"),
            })
        return samples
