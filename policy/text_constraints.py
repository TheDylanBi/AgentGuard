"""Initial verbatim text constraints from reviewed, explicit user-text delimiters.

No task IDs, expected answers, model history or tool outputs are inputs. This is
a deliberately small grammar, not a general natural-language authorization parser.
"""
import copy
import re
from attestation.hashing import object_hash
from .intent_validation import conjunction_atoms


def validate_text_declarations(spec, parameters):
    declarations = spec.get("text_constraints", {})
    if not isinstance(declarations, dict) or (declarations and not spec.get("schema_hash")):
        raise ValueError("Text constraints require a pinned schema")
    for field, declaration in declarations.items():
        if (field not in parameters.model_fields or parameters.model_fields[field].annotation is not str or
                not isinstance(declaration, dict) or set(declaration) != {"markers", "reason"} or
                not isinstance(declaration["reason"], str) or not declaration["reason"].strip()):
            raise ValueError("Invalid reviewed text constraint")
        markers = declaration["markers"]
        if (not isinstance(markers, list) or not 1 <= len(markers) <= 8 or
                any(not isinstance(m, str) or not re.fullmatch(r"[A-Za-z][A-Za-z ]{1,63}", m) for m in markers)):
            raise ValueError("Invalid text markers")


def user_text_literals(query, declarations):
    """Recognize one explicit field occurrence; ambiguity means no inference.

    Supported forms: marker + paired quotation marks, or marker + unquoted
    text ending in two periods (one belongs to the value, one to the sentence).
    A single unquoted period does not prove whether it belongs to the value.
    Multiple markers/occurrences, ellipses and escaped/multiline text abstain.
    """
    result = []
    for tool, fields in declarations.items():
        for field, declaration in fields.items():
            pattern = r"\b(?:" + "|".join(re.escape(m) for m in declaration["markers"]) + r")\s+"
            matches = list(re.finditer(pattern, query, re.I))
            if len(matches) != 1:
                continue
            match = matches[0]
            # Negated/alternative specifications require interpretation, not a repair.
            if re.search(r"\b(?:not|never|instead|rather|except|example)\b", query, re.I):
                continue
            start = match.end()
            tail = query[start:]
            if not tail:
                continue
            quotes = {'"': '"', "'": "'", '“': '”', '‘': '’'}
            if tail[0] in quotes:
                end = query.find(quotes[tail[0]], start + 1)
                start += 1
                if end < 0 or (end + 1 < len(query) and query[end + 1] not in " \t\r\n.,;!?"):
                    continue
                syntax = "quoted"
            else:
                # Do not guess at a sentence boundary, quote boundary, or ellipsis.
                ending = re.search(r"(?<!\.)\.\.(?!\.)(?=\s|$)", tail)
                if ending is None or re.search(r'[\n\r"“”]', tail[:ending.start()]):
                    continue
                if re.search(r"[.!?](?=\s|$)", tail[:ending.start()]):
                    continue
                end = start + ending.start() + 1
                syntax = "value_period_then_sentence_period"
            value = query[start:end]
            if not value or len(value) > 4096 or any(c in value for c in "\\\r\n"):
                continue
            result.append({"tool": tool, "field": "payload." + field, "value": value,
                           "start": start, "end": end, "syntax": syntax})
    return result


def bind_user_text(rules, literals):
    """Constrain existing allows only. Denies and non-text fields never change.

    A single exact value missing ONE terminal punctuation character may be
    compiled from the verified user span. Other discrepancies are intersected,
    never guessed or broadened; normal semantic validation rejects conflicts.
    """
    result, records = copy.deepcopy(rules), []
    for index, rule in enumerate(result):
        if rule.get("decision") != "allow":
            continue
        atoms = conjunction_atoms(rule["predicate"])
        for literal in literals:
            if rule["tool"] != literal["tool"]:
                continue
            field, expected = literal["field"], literal["value"]
            constraints = [a for a in atoms or [] if a.get("field") == field]
            repaired = False
            # A changed value must not sidestep a deny that matched the old
            # value. With any applicable deny, only intersect; never rewrite.
            has_deny = any(r.get("decision") == "deny" and r.get("tool") in {rule["tool"], "*"}
                           for r in rules)
            if len(constraints) == 1 and not has_deny:
                atom = constraints[0]
                if (atom.get("op") == "eq" and isinstance(atom.get("value"), str) and
                        expected[-1] in ".!?。！？" and atom["value"] == expected[:-1]):
                    atom["value"] = expected
                    repaired = True
            rule["predicate"] = {"op": "and", "args": [rule["predicate"],
                {"op": "eq", "field": field, "value": expected}]}
            records.append({"rule_index": index, "tool": rule["tool"], "field": field,
                            "start": literal["start"], "end": literal["end"], "syntax": literal["syntax"],
                            "value_hash": object_hash(expected), "terminal_punctuation_restored": repaired})
    return result, records
