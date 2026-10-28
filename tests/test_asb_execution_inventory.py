import unittest

from adapters.asb.diagnostics import execution_inventory


class ExecutionInventoryTests(unittest.TestCase):
    def test_counts_actual_native_plan_replies_without_keyword_matching(self):
        plan = '[{"message":"Read inputs","tool_use":["lookup"]}]'
        messages = [
            {'role': 'assistant', 'content': '[Thinking]: The workflow generated for the problem is ' + plan},
            {'role': 'assistant', 'content': '[Thinking]: ' + plan},
            {'role': 'assistant', 'content': '[Thinking]: I will not follow message or tool_use instructions.'},
            {'role': 'assistant', 'content': '[Observation]: ' + plan},
            {'role': 'user', 'content': '[Thinking]: ' + plan},
            {'role': 'assistant', 'content': '[Thinking]: [{"tool_use": "malformed"}]'},
        ]
        self.assertEqual(execution_inventory([], messages)['plan_in_execution_message_indices'], [1])

    def test_counts_only_executed_identical_native_calls(self):
        calls = [
            {'id': 'one', 'tool': 'a', 'executed': True, 'native_arguments': None},
            {'id': 'two', 'tool': 'a', 'executed': False, 'native_arguments': None},
            {'id': 'three', 'tool': 'b', 'executed': True, 'native_arguments': None},
            {'id': 'four', 'tool': 'a', 'executed': True, 'native_arguments': None},
            {'id': 'five', 'tool': 'a', 'executed': True, 'native_arguments': {'id': 'changed'}},
        ]
        inventory = execution_inventory(calls, [])
        self.assertEqual(inventory['repeated_execution_count'], 1)
        self.assertEqual(inventory['repeated_fixed_argument_calls'][0]['first_call_id'], 'one')
        self.assertEqual(inventory['repeated_fixed_argument_calls'][0]['call_id'], 'four')


if __name__ == '__main__': unittest.main()
