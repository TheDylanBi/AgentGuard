import json
import unittest
from unittest.mock import patch

from demo.attacks.rjudge_review import review_record
from demo.attacks.rjudge_guard_proxy import GuardProxy, ProxyConfig, reconstruct_public_example
from demo.attacks.rjudge_judgment import build_messages, PROMPT_REASON, PROMPT_PRED
from policy.call_review import CallReviewer


class DirectReviewTests(unittest.TestCase):
    def public(self):
        return {'profile': 'Test agent', 'contents': [
            [{'role': 'user', 'content': 'Read product 1'}],
            [{'role': 'agent', 'action': 'amazon_get_product_details / Action Input: {"product_id":"1"}'}],
            [{'role': 'environment', 'content': 'UNTRUSTED_FUTURE_RESULT'}]]}

    def run_review(self, decision):
        packets = []
        def caller(packet, **kwargs):
            packets.append(packet)
            return {'decision': decision, 'code': 'authorized' if decision == 'allow' else
                    'wrong_target' if decision == 'deny' else 'insufficient_evidence',
                    'fields': [], 'evidence_ids': ['user']}
        with patch('demo.attacks.rjudge_review.check_hard_boundaries', return_value={'verdict':'PASS'}):
            result = review_record(self.public(), engine=object(),
                reviewer_factory=lambda user, context: CallReviewer(user, context, caller=caller))
        return result, packets

    def test_allow_and_causal_context(self):
        result, packets = self.run_review('allow')
        self.assertEqual(result['prediction'], 'safe')
        self.assertEqual(result['review_requests'], 1)
        self.assertNotIn('UNTRUSTED_FUTURE_RESULT', json.dumps(packets[0]))

    def test_denial_and_abstention_are_distinct(self):
        self.assertEqual(self.run_review('deny')[0]['prediction'], 'unsafe')
        self.assertEqual(self.run_review('needs_evidence')[0]['prediction'], 'abstain')

    def test_no_actions_is_uncovered(self):
        self.assertEqual(review_record({'profile':'agent', 'contents':[]}, engine=object())['prediction'], 'abstain')

    def test_official_none_action_is_not_a_tool_call(self):
        public = {'profile':'agent','contents':[[{'role':'agent','thought':'Final answer','action':None}]]}
        messages = build_messages(public) + [{'role':'user','content':PROMPT_REASON}]
        restored = reconstruct_public_example(messages)
        self.assertIsNone(restored['contents'][0][0]['action'])

    def test_proxy_uses_cached_direct_result_without_upstream(self):
        public = self.public()
        messages = build_messages(public) + [{'role':'user','content':PROMPT_REASON}]
        result = {'protocol':'review-direct-v1','prediction':'abstain','reason':'unsupported_action',
                  'scope':'test','elapsed_seconds':1,'review_seconds':0,'review_requests':0}
        proxy = GuardProxy(ProxyConfig('', '', protocol='review'), engine=object())
        with patch('demo.attacks.rjudge_review.review_record', return_value=result) as review, \
             patch('urllib.request.urlopen', side_effect=AssertionError('No upstream judgment')):
            self.assertEqual(proxy.forward({'messages':messages})[0],200)
            label = messages + [{'role':'assistant','content':'analysis'}, {'role':'user','content':PROMPT_PRED}]
            response = proxy.forward({'messages':label})
        self.assertEqual(review.call_count,1)
        self.assertEqual(json.loads(response[1])['choices'][0]['message']['content'],'undetermined')
        self.assertTrue(response[3]['cache_hit'])
