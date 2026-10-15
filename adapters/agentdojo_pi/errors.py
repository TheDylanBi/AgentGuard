"""Expected model failures that may be isolated without inventing scores."""
import json


class ActionModelError(RuntimeError):
    def __init__(self, diagnostic):
        self.diagnostic = diagnostic
        super().__init__("Action model failed: " + json.dumps(diagnostic))
