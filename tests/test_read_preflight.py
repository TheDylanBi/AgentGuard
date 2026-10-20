import copy
import unittest
from pydantic import BaseModel
from policy.tool_contract import ToolContract
from policy.read_preflight import compile_read_calls, read_call_schema


class Search(BaseModel):
    query: str
    date: str | None = None


class ListArgs(BaseModel):
    pass


class ReadPreflightTests(unittest.TestCase):
    def setUp(self):
        self.contracts = {"search": ToolContract("search", Search), "list": ToolContract("list", ListArgs)}

    def test_typed_arguments_compile_to_one_conjunction_without_target_guesses(self):
        data = {"calls": [{"tool": "search", "arguments": {"query": "topic", "date": None}},
                          {"tool": "list", "arguments": {}}]}
        original = copy.deepcopy(data)
        rules = compile_read_calls(data, self.contracts)
        self.assertEqual(rules[0]["predicate"], {"op": "and", "args": [
            {"op": "eq", "field": "payload.query", "value": "topic"},
            {"op": "in", "field": "payload.date", "value": [None]}]})
        self.assertEqual(rules[1]["predicate"], {"op": "true"})
        self.assertEqual(original, data)

    def test_unknown_tools_missing_defaults_extra_fields_and_coercions_rejected(self):
        for call in ({"tool": "write", "arguments": {}},
                     {"tool": "search", "arguments": {"query": "topic"}},
                     {"tool": "search", "arguments": {"query": 1, "date": None}},
                     {"tool": "list", "arguments": {"target": "shared"}},
                     {"tool": "list", "arguments": {}, "deny": []}):
            with self.subTest(call=call), self.assertRaises(ValueError):
                compile_read_calls({"calls": [call]}, self.contracts)

    def test_decoding_schema_requires_full_args_and_no_fabricated_target(self):
        schema = read_call_schema([{"name": "search", "parameters": Search.model_json_schema()},
                                   {"name": "list", "parameters": ListArgs.model_json_schema()}])
        choices = schema["properties"]["calls"]["items"]["anyOf"]
        self.assertEqual(choices[0]["properties"]["arguments"]["required"], ["query", "date"])
        self.assertFalse(choices[1]["properties"]["arguments"]["additionalProperties"])


if __name__ == "__main__":
    unittest.main()
