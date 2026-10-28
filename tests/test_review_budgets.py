"""Finite transport recovery never changes the call or replays execution."""
import copy
import os
import unittest
from unittest.mock import Mock,patch

from policy.call_review import CallReviewer,ReviewStageError,bind_decision,decision_schema
from tests.test_call_review import semantic,verdict


class ReviewBudgetTests(unittest.TestCase):
    def test_initial_and_recovery_share_one_call_budget(self):
        tick=[0.0];calls=[]
        def caller(packet,**options):
            calls.append((copy.deepcopy(packet),options))
            if len(calls)==1:
                tick[0]=30
                raise ReviewStageError({'status':'invalid_output','http_status':200,'output_error':'truncated_output'})
            tick[0]=35
            return verdict(packet)
        with patch.dict(os.environ,{},clear=True),patch('policy.call_review.time.monotonic',side_effect=lambda:tick[0]):
            reviewer=CallReviewer('Read A.',caller=caller);reviewer.deadline=100
            self.assertEqual(reviewer.check('c','read',{},semantic(),'s')['decision'],'allow')
        self.assertEqual(calls[0][1]['timeout_seconds'],30)
        self.assertEqual(calls[1][1]['timeout_seconds'],15)
        self.assertEqual(calls[0][0],calls[1][0])

    def test_reserve_stops_review_before_task_is_exhausted_without_sending(self):
        caller=Mock()
        with patch.dict(os.environ,{},clear=True),patch('policy.call_review.time.monotonic',return_value=0):
            reviewer=CallReviewer('task',caller=caller);reviewer.deadline=16
            with self.assertRaises(ReviewStageError) as caught:reviewer.check('c','read',{},semantic(),'s')
        self.assertEqual(caught.exception.diagnostic['status'],'review_budget_exhausted')
        self.assertTrue(caught.exception.task_local);caller.assert_not_called()

    def test_transient_connection_failure_retries_same_review_once(self):
        packets=[]
        def caller(packet,**options):
            packets.append(copy.deepcopy(packet))
            if len(packets)==1:raise ReviewStageError({'status':'timeout','network_error_type':'ConnectionError'})
            return verdict(packet)
        reviewer=CallReviewer('Read A.',caller=caller)
        self.assertEqual(reviewer.check('c','read',{},semantic(),'s')['decision'],'allow')
        self.assertEqual(packets[0],packets[1]);self.assertEqual(len(packets),2)

    def test_repeated_transient_failures_never_become_authorization(self):
        caller=Mock(side_effect=ReviewStageError({'status':'timeout'}));reviewer=CallReviewer('task',caller=caller)
        with self.assertRaises(ReviewStageError):reviewer.check('c','read',{},semantic(),'s')
        self.assertEqual(caller.call_count,2);self.assertEqual(reviewer.records[-1]['status'],'error')

    def test_bad_request_is_not_a_transient_error(self):
        caller=Mock(side_effect=ReviewStageError({'status':'http_error','http_status':400}))
        reviewer=CallReviewer('task',caller=caller)
        with self.assertRaises(ReviewStageError):reviewer.check('c','read',{},semantic(),'s')
        self.assertEqual(caller.call_count,1)

    def test_late_response_cannot_overrun_call_budget_or_action_reserve(self):
        for deadline,elapsed,status in [(100,46,'review_call_deadline'),(35,21,'review_budget_exhausted')]:
            tick=[0.0]
            def caller(p,**kw):tick[0]=elapsed;return verdict(p)
            with patch.dict(os.environ,{},clear=True),patch('policy.call_review.time.monotonic',side_effect=lambda:tick[0]):
                r=CallReviewer('task',caller=caller);r.deadline=deadline
                with self.assertRaises(ReviewStageError) as caught:r.check('c','read',{},semantic(),'s')
            self.assertEqual(caught.exception.diagnostic['status'],status)

    def test_invalid_negative_code_is_precise_error_never_retried_to_allow(self):
        caller=Mock(side_effect=lambda p,**kw:{**verdict(p,'deny','wrong_target'),'code':'authorized'})
        reviewer=CallReviewer('task',caller=caller)
        with self.assertRaises(ReviewStageError) as caught:reviewer.check('c','read',{},semantic(),'s')
        self.assertEqual(caught.exception.diagnostic['failure'],'invalid_decision_code')
        self.assertEqual(caller.call_count,1)

    def test_decision_schema_enforces_decision_code_pairs(self):
        schema=decision_schema({'action':{'parameters':{}}})
        self.assertEqual(len(schema['oneOf']),3)
        for decision,code,valid in [('allow','authorized',True),('deny','wrong_target',True),
                                     ('deny','authorized',False),('confirm','ambiguous_target',False)]:
            payload={'decision':decision,'code':code,'fields':[],'evidence_ids':['user']}
            packet={'request_id':'current','action':{'parameters':{}},'observations':[]}
            if valid:self.assertEqual(bind_decision(payload,packet)['decision'],decision)
            else:
                with self.assertRaises(ValueError):bind_decision(payload,packet)

    def test_nonfinite_and_inconsistent_budgets_fail_configuration(self):
        for env in [{'ICB_REVIEW_CALL_TIMEOUT_SECONDS':'NaN'}, {'ICB_REVIEW_ACTION_RESERVE_SECONDS':'-1'},
                    {'ICB_REVIEW_CALL_TIMEOUT_SECONDS':'1','ICB_REVIEW_MIN_ATTEMPT_SECONDS':'2'}]:
            with patch.dict(os.environ,env,clear=True),self.assertRaises(ValueError):CallReviewer('task')


if __name__=='__main__':unittest.main()
