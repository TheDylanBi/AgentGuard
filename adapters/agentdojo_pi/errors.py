"""Expected model failures that may be isolated without inventing scores."""
import json


class ActionModelError(RuntimeError):
    def __init__(self, diagnostic):
        self.diagnostic = diagnostic
        super().__init__("Action model failed: " + json.dumps(diagnostic))

    @property
    def task_local(self):
        return self.diagnostic.get("status") in {
            "truncated_output", "missing_final_answer", "tool_rejection_budget_exhausted",
            "context_limit", "tool_parse_error", "content_filter",
        }
