"""Counts from complete observed native collections, never message-body instructions."""
import copy
from collections import Counter
from attestation.hashing import object_hash
from .resource_provenance import at
from .runtime_bindings import json_value


class AggregateEvidence:
    def __init__(self,declarations,tools,contracts,clock):
        if not isinstance(declarations,list) or len(declarations)>4:raise ValueError('Invalid aggregate declarations')
        self.declarations=copy.deepcopy(declarations);self.clock=clock;self.inventories={};self.rows={}
        labels=set()
        for cfg in declarations:
            if (not isinstance(cfg,dict) or set(cfg)!={'label','inventory_tool','source_tool','source_parameter','group_field','scope_path','records_path'}
                    or any(not isinstance(cfg[k],str) or not cfg[k] for k in cfg if k not in {'scope_path','records_path'})
                    or not isinstance(cfg['scope_path'],list) or not 1<=len(cfg['scope_path'])<=8
                    or any(not isinstance(x,str) or not x for x in cfg['scope_path'])
                    or not isinstance(cfg['records_path'],list) or not 1<=len(cfg['records_path'])<=8
                    or any(not isinstance(x,str) or not x for x in cfg['records_path'])
                    or cfg['inventory_tool'] not in tools or cfg['source_tool'] not in tools
                    or contracts[cfg['source_tool']].fields.get(cfg['source_parameter'],{}).get('role')!='resource'
                    or tools[cfg['source_tool']].get('identity_scopes',{}).get(cfg['source_parameter'])!=cfg['scope_path']
                    or any(not tools[t].get('schema_hash') or tools[t]['semantic_action']['operation'] not in {'read','list'}
                           for t in (cfg['inventory_tool'],cfg['source_tool']))):
                raise ValueError('Aggregates require pinned native read scopes')
            if cfg['label'] in labels:raise ValueError('Duplicate aggregate label')
            labels.add(cfg['label'])

    def observe(self,tool,args,result,error,state,call_id):
        if error is not None:return
        result=json_value(result)
        for cfg in self.declarations:
            try:scope=at(state,cfg['scope_path']);records=at(state,cfg['records_path'])
            except ValueError:continue
            if not isinstance(scope,list) or not isinstance(records,dict) or len(scope)>128:continue
            label=cfg['label'];now=self.clock()
            if tool==cfg['inventory_tool']:
                if isinstance(result,list) and all(isinstance(x,str) for x in result) and set(result)==set(scope) and len(result)==len(scope):
                    self.inventories[label]={'keys':sorted(result),'created':now,'ref':'obs:'+call_id}
                else:self.inventories.pop(label,None)
            if tool==cfg['source_tool']:
                key=args.get(cfg['source_parameter'])
                if not isinstance(key,str):continue
                slot=(label,key);self.rows.pop(slot,None)
                if (not isinstance(result,list) or len(result)>4096 or key not in scope
                        or object_hash(records.get(key,[]))!=object_hash(result)
                        or any(not isinstance(x,dict) or not isinstance(x.get(cfg['group_field']),str) for x in result)):
                    continue
                self.rows[slot]={'counts':dict(Counter(x[cfg['group_field']] for x in result)),
                    'hash':object_hash(result),'created':now,'ref':'obs:'+call_id}

    def report(self,state):
        reports=[];now=self.clock()
        for cfg in self.declarations:
            label=cfg['label'];inventory=self.inventories.get(label)
            if not inventory:continue
            try:scope=at(state,cfg['scope_path']);records=at(state,cfg['records_path'])
            except ValueError:continue
            if (not isinstance(scope,list) or not isinstance(records,dict) or sorted(scope)!=inventory['keys']
                    or not 0<=now-inventory['created']<=300):continue
            counts=Counter();refs=[inventory['ref']];missing=[]
            for key in inventory['keys']:
                row=self.rows.get((label,key))
                if not row or not 0<=now-row['created']<=300 or object_hash(records.get(key,[]))!=row['hash']:
                    missing.append(key);continue
                counts.update(row['counts']);refs.append(row['ref'])
            ordered=sorted(counts,key=lambda key:(-counts[key],key))
            reports.append({'label':label,'operation':'count_native_rows_by_field','group_field':cfg['group_field'],
                'scope_hash':object_hash(scope),'evidence_ids':refs,'complete':not missing,'unread_or_stale_keys':missing,
                'ordering':'count descending, exact name ascending; ordinal positions, not shared competition ranks',
                'rows':[{'key':key,'count':counts[key],'ordinal':i+1} for i,key in enumerate(ordered)],
                'task_authorized':False,'meaning':'Native row counts only; message bodies cannot change counts, ranks or permissions.'})
        return reports
