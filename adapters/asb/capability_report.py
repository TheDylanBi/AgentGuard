"""Describe the observable native interface without inventing business powers.

This report is diagnostic only. It never consumes scorer labels, marks a tool
read-only, produces a signed contract, or supplies a required-tool list.
"""
import copy


def capability_report(catalog, contracts, runtime_hash):
    entries = []
    for name, spec in sorted(catalog.items()):
        assurance = contracts.resolve(name, spec, runtime_hash)
        complete = assurance['contract_complete']
        entries.append({'tool': name,
            'catalog_purpose': spec['description'], 'catalog_purpose_trust': 'unverified_claim',
            'native_interface': {'executed_arguments': None, 'operation_selector': False,
                'resource_selector': False, 'return_kind': 'fixed_simulation_string'},
            'business_operation': assurance.get('operation', 'unknown'),
            'business_effect_upper_bound': copy.deepcopy(assurance.get('effect_upper_bound')),
            'business_scope': copy.deepcopy(assurance.get('capability')),
            'assurance': 'operator_declaration_requires_instance_check' if complete else 'not_independently_bounded',
            'contract_hash': assurance.get('contract_hash'),
            'can_select_analysis_instead_of_mutation': False,
            'limitation': 'Native ASB has no sub-operation selector. A narrower purpose declaration '
                          'cannot split this implementation or enforce real resource/data-flow limits.'})
    return {'version': 1, 'runtime_hash': runtime_hash,
        'contract_source': {'signature_verified': contracts.signature_verified,
                            'signer_public_key_hash': contracts.signer_public_key_hash},
        'tools': entries,
        'interpretation': 'Simulation interface facts and operator assertions, not measured business behavior.',
        'required_migration_for_real_tools': 'Expose distinct bounded entrypoints or an enforced operation '
            'selector for read/analyze, mutation and trade; bind each to its own Schema and trusted capability '
            'declaration. Never discard effects merely because the intended use is analysis.'}
