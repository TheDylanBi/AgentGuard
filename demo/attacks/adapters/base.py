"""Dataset adapter interface.

A DatasetAdapter converts ONE raw dataset sample into a list of NORMALIZED
auth samples. Adding a new dataset = writing one adapter (a field-mapping
function). Everything else (conversion, eval, metrics) is reused.

Normalized sample fields:
  id                      unique id
  source                  dataset name
  category                "attack" | "benign"
  intent_anchor           user task / intent text
  action_type             click | type | read_file | write_file | shell | ...
  action_target           element name / path / command
  page                    url or file:// path to open in the browser
  ground_truth            BLOCK | ALLOW | CONFIRM
  expected_failure_point  I | E | C | P | T | None
  capabilities            optional tool capability dict (else default used)
"""


class DatasetAdapter:
    name = "base"

    def convert(self, raw: dict) -> list:
        """raw sample -> list of normalized samples."""
        raise NotImplementedError
