"""Unit tests for the Progent-style symbolic least-privilege layer.

Run directly (no pytest dependency):

    python tests/test_symbolic.py
"""
import sys
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from policy import symbolic
from policy.engine import PolicyEngine

_PASS = 0
_FAIL = 0


def _check(name, cond, extra=""):
    global _PASS, _FAIL
    if cond:
        _PASS += 1
        print(f"  PASS  {name}")
    else:
        _FAIL += 1
        print(f"  FAIL  {name}  {extra}")


def _fields(t, target, payload=None):
    return symbolic.action_fields(t, target, payload or {})


# ---------------------------------------------------------------------------
# predicate_holds
# ---------------------------------------------------------------------------

def test_predicate_holds():
    print("\n[predicate_holds]")
    f = _fields("email", "x", {"to": "alice@x.com", "amount": 50})
    _check("eq match", symbolic.predicate_holds({"op": "eq", "field": "payload.to", "value": "alice@x.com"}, f))
    _check("eq no-match", not symbolic.predicate_holds({"op": "eq", "field": "payload.to", "value": "bob@x.com"}, f))
    _check("ne", symbolic.predicate_holds({"op": "ne", "field": "payload.to", "value": "bob@x.com"}, f))
    _check("le", symbolic.predicate_holds({"op": "le", "field": "payload.amount", "value": 100}, f))
    _check("le false", not symbolic.predicate_holds({"op": "le", "field": "payload.amount", "value": 10}, f))
    _check("ge", symbolic.predicate_holds({"op": "ge", "field": "payload.amount", "value": 50}, f))
    _check("in", symbolic.predicate_holds({"op": "in", "field": "type", "value": ["email", "shell"]}, f))
    _check("not_in", symbolic.predicate_holds({"op": "not_in", "field": "type", "value": ["shell"]}, f))
    _check("glob", symbolic.predicate_holds({"op": "glob", "field": "target", "value": "/workspace/*"},
                                            _fields("read_file", "/workspace/a.txt")))
    _check("glob false", not symbolic.predicate_holds({"op": "glob", "field": "target", "value": "/workspace/*"},
                                                      _fields("read_file", "/etc/passwd")))
    _check("contains", symbolic.predicate_holds({"op": "contains", "field": "target", "value": "rm -rf"},
                                                _fields("shell", "sudo rm -rf /")))
    _check("and", symbolic.predicate_holds(
        {"op": "and", "args": [
            {"op": "eq", "field": "payload.to", "value": "alice@x.com"},
            {"op": "le", "field": "payload.amount", "value": 100}]}, f))
    _check("or", symbolic.predicate_holds(
        {"op": "or", "args": [
            {"op": "eq", "field": "payload.to", "value": "bob@x.com"},
            {"op": "eq", "field": "payload.to", "value": "alice@x.com"}]}, f))
    _check("not", symbolic.predicate_holds(
        {"op": "not", "args": [{"op": "eq", "field": "payload.to", "value": "bob@x.com"}]}, f))
    _check("true", symbolic.predicate_holds({"op": "true"}, f))
    _check("unknown op false", not symbolic.predicate_holds({"op": "nope"}, f))


# ---------------------------------------------------------------------------
# check_rules
# ---------------------------------------------------------------------------

def test_check_rules():
    print("\n[check_rules]")
    rules = [
        {"tool": "email", "decision": "allow",
         "predicate": {"op": "eq", "field": "payload.to", "value": "alice@x.com"}},
        {"tool": "email", "decision": "deny",
         "predicate": {"op": "ne", "field": "payload.to", "value": "alice@x.com"}},
    ]
    _check("allow matched", symbolic.check_rules("email", _fields("email", "x", {"to": "alice@x.com"}), rules)[0] == "allow")
    _check("deny matched", symbolic.check_rules("email", _fields("email", "x", {"to": "bob@x.com"}), rules)[0] == "deny")
    _check("outside", symbolic.check_rules("email", _fields("email", "x", {"to": "carol@x.com"}), [rules[0]])[0] == "outside")
    _check("wildcard tool", symbolic.check_rules("shell", _fields("shell", "rm -rf /"),
                                                 [{"tool": "*", "decision": "deny", "predicate": {"op": "true"}}])[0] == "deny")
    _check("deny beats allow", symbolic.check_rules("email", _fields("email", "x", {"to": "a@x.com"}),
                                                    [{"tool": "email", "decision": "allow", "predicate": {"op": "true"}},
                                                     {"tool": "email", "decision": "deny", "predicate": {"op": "true"}}])[0] == "deny")
    _check("empty rules outside", symbolic.check_rules("email", _fields("email", "x"), [])[0] == "outside")

    # rule precedence: specific exception overrides wildcard default-deny
    prio = [
        {"tool": "email", "decision": "allow", "predicate": {"op": "eq", "field": "payload.to", "value": "alice@x.com"}},
        {"tool": "*", "decision": "deny", "predicate": {"op": "true"}},
    ]
    _check("specific allow overrides wildcard deny",
           symbolic.check_rules("email", _fields("email", "send", {"to": "alice@x.com"}), prio)[0] == "allow")
    _check("out-of-scope still denied by wildcard deny",
           symbolic.check_rules("email", _fields("email", "send", {"to": "bob@x.com"}), prio)[0] == "deny")
    same_tool = [
        {"tool": "email", "decision": "allow", "predicate": {"op": "true"}},
        {"tool": "email", "decision": "deny", "predicate": {"op": "true"}},
    ]
    _check("specific deny overrides specific allow",
           symbolic.check_rules("email", _fields("email", "x"), same_tool)[0] == "deny")


# ---------------------------------------------------------------------------
# classify_update (monotonic, SMT)
# ---------------------------------------------------------------------------

def test_classify_update():
    print("\n[classify_update]")
    old_allow = {"tool": "t", "decision": "allow", "predicate": {"op": "le", "field": "payload.amount", "value": 100}}
    _check("allow narrowing", symbolic.classify_update(
        {"tool": "t", "decision": "allow", "predicate": {"op": "le", "field": "payload.amount", "value": 50}},
        [old_allow]) == "narrowing")
    _check("allow expansion", symbolic.classify_update(
        {"tool": "t", "decision": "allow", "predicate": {"op": "le", "field": "payload.amount", "value": 200}},
        [old_allow]) == "expansion")
    _check("new allow = expansion", symbolic.classify_update(
        {"tool": "t2", "decision": "allow", "predicate": {"op": "true"}}, [old_allow]) == "expansion")

    old_deny = {"tool": "t", "decision": "deny",
                "predicate": {"op": "in", "field": "payload.to", "value": ["a", "b"]}}
    _check("new deny = narrowing", symbolic.classify_update(
        {"tool": "t", "decision": "deny", "predicate": {"op": "true"}}, [old_allow]) == "narrowing")
    _check("deny growth = narrowing", symbolic.classify_update(
        {"tool": "t", "decision": "deny",
         "predicate": {"op": "in", "field": "payload.to", "value": ["a", "b", "c"]}}, [old_deny]) == "narrowing")
    _check("deny shrink = expansion", symbolic.classify_update(
        {"tool": "t", "decision": "deny",
         "predicate": {"op": "in", "field": "payload.to", "value": ["a"]}}, [old_deny]) == "expansion")

    # glob narrowing via SMT prefix implication
    oldg = {"tool": "read_file", "decision": "allow",
            "predicate": {"op": "glob", "field": "target", "value": "/workspace/*"}}
    _check("glob narrowing", symbolic.classify_update(
        {"tool": "read_file", "decision": "allow",
         "predicate": {"op": "glob", "field": "target", "value": "/workspace/meetings/*"}},
        [oldg]) == "narrowing")
    _check("glob incomparable = expansion", symbolic.classify_update(
        {"tool": "read_file", "decision": "allow",
         "predicate": {"op": "glob", "field": "target", "value": "/other/*"}},
        [oldg]) == "expansion")

    # eq-to-in narrowing
    _check("eq subset of in = narrowing", symbolic.classify_update(
        {"tool": "t", "decision": "allow", "predicate": {"op": "eq", "field": "payload.to", "value": "a"}},
        [old_deny if False else {"tool": "t", "decision": "allow",
                                 "predicate": {"op": "in", "field": "payload.to", "value": ["a", "b"]}}]) == "narrowing")


# ---------------------------------------------------------------------------
# make_minimal_allow_rule / apply_update
# ---------------------------------------------------------------------------

def test_minimal_and_apply():
    print("\n[make_minimal_allow_rule / apply_update]")
    fields = _fields("email", "send", {"to": "alice@x.com"})
    mr = symbolic.make_minimal_allow_rule("email", fields)
    _check("minimal covers exact", symbolic.predicate_holds(mr["predicate"], fields))
    _check("minimal excludes other", not symbolic.predicate_holds(
        mr["predicate"], _fields("email", "send", {"to": "bob@x.com"})))

    r1 = {"tool": "t", "decision": "allow", "predicate": {"op": "true"}}
    r2 = {"tool": "t", "decision": "deny", "predicate": {"op": "true"}}
    out = symbolic.apply_update([r1], r2)
    _check("apply appends", len(out) == 2 and r2 in out)
    out2 = symbolic.apply_update([r1, r2], r2)
    _check("apply dedupes identical", len(out2) == 2)


# ---------------------------------------------------------------------------
# engine integration
# ---------------------------------------------------------------------------

def test_engine():
    print("\n[engine integration]")
    eng = PolicyEngine(str(ROOT / "policy" / "policies"))

    def A(t, target, payload=None):
        return SimpleNamespace(type=t, target=target, payload=payload or {})

    # sink tool (network/credential egress), sensitive param declared
    email_caps = {"actions": ["email"], "network": "allowed", "credential": "allowed",
                  "process": "denied", "persistence": "denied",
                  "filesystem_read": [], "filesystem_write": [],
                  "sensitive_params": ["payload.to"]}
    # non-sink tool, sensitive param declared
    notes_caps = {"actions": ["notes"], "network": "denied", "credential": "denied",
                  "process": "denied", "persistence": "denied",
                  "filesystem_read": [], "filesystem_write": [],
                  "sensitive_params": ["payload.note_id"]}

    rules = [{"tool": "email", "decision": "allow",
              "predicate": {"op": "eq", "field": "payload.to", "value": "alice@x.com"}},
             {"tool": "email", "decision": "deny",
              "predicate": {"op": "ne", "field": "payload.to", "value": "alice@x.com"}}]
    r = eng.evaluate(A("email", "send", {"to": "alice@x.com"}), "unknown", 0, capability=email_caps, rules=rules)
    _check("sink specific-allow + covered param -> ALLOW", r["verdict"] == "ALLOW", str(r))
    r = eng.evaluate(A("email", "send", {"to": "bob@evil.com"}), "unknown", 0, capability=email_caps, rules=rules)
    _check("deny rule -> BLOCK", r["verdict"] == "BLOCK", str(r))

    # P2: sink tool outside -> CONFIRM (semantic gap, not hard BLOCK — per core
    # principle: only deterministic violations BLOCK)
    r = eng.evaluate(A("email", "send", {"to": "carol@x.com"}), "unknown", 0, capability=email_caps, rules=[rules[0]])
    _check("P2 sink outside -> CONFIRM", r["verdict"] == "CONFIRM", str(r))

    # P3: sink type-level allow (no param constraint) -> CONFIRM
    r = eng.evaluate(A("email", "send", {"to": "alice@x.com"}), "unknown", 0, capability=email_caps,
                     rules=[{"tool": "email", "decision": "allow", "predicate": {"op": "true"}}])
    _check("P3 sink type-level allow -> CONFIRM", r["verdict"] == "CONFIRM", str(r))

    # P0/P3: non-sink outside -> CONFIRM (expansion, approvable)
    r = eng.evaluate(A("notes", "read", {"note_id": "n2"}), "unknown", 0, capability=notes_caps,
                     rules=[{"tool": "notes", "decision": "allow",
                             "predicate": {"op": "eq", "field": "payload.note_id", "value": "n1"}}])
    _check("non-sink outside -> CONFIRM", r["verdict"] == "CONFIRM" and "policy_update" in r, str(r))

    # P3: non-sink type-level allow -> CONFIRM (under-constrained)
    r = eng.evaluate(A("notes", "read", {"note_id": "n1"}), "unknown", 0, capability=notes_caps,
                     rules=[{"tool": "notes", "decision": "allow", "predicate": {"op": "true"}}])
    _check("P3 non-sink type-level allow -> CONFIRM", r["verdict"] == "CONFIRM", str(r))

    # no rules + no yaml -> fail-closed BLOCK
    r = eng.evaluate(A("email", "send", {"to": "x"}), "unknown", 0, capability=email_caps, rules=[])
    _check("no rules + no yaml fail-closed", r["verdict"] == "BLOCK", str(r))

    # P1: no rules + tool WITH yaml -> fail-closed (shell high-risk BLOCK,
    # read_file medium CONFIRM) instead of silent ALLOW.
    shell_caps = {"actions": ["shell"], "process": "allowed", "network": "denied",
                  "credential": "denied", "persistence": "denied",
                  "filesystem_read": [], "filesystem_write": []}
    r = eng.evaluate(A("shell", "sudo rm -rf /"), "unknown", 0, capability=shell_caps, rules=[])
    _check("P1 shell + no rules -> BLOCK", r["verdict"] == "BLOCK", str(r))
    read_caps = {"actions": ["read_file"], "filesystem_read": ["/workspace/*"],
                 "network": "denied", "credential": "denied", "process": "denied",
                 "persistence": "denied"}
    r = eng.evaluate(A("read_file", "/workspace/a.txt"), "unknown", 0, capability=read_caps, rules=[])
    _check("P1 read_file + no rules -> CONFIRM", r["verdict"] == "CONFIRM", str(r))

    # monotonic confinement via non-sink expansion
    base = [{"tool": "notes", "decision": "allow",
             "predicate": {"op": "eq", "field": "payload.note_id", "value": "n1"}}]
    r = eng.evaluate(A("notes", "read", {"note_id": "n2"}), "unknown", 0, capability=notes_caps, rules=base)
    update = r["policy_update"]["rule"]
    r2 = eng.evaluate(A("notes", "read", {"note_id": "n2"}), "unknown", 0, capability=notes_caps,
                      rules=symbolic.apply_update(base, update))
    _check("non-sink expansion applied -> ALLOW", r2["verdict"] == "ALLOW", str(r2))

    # P1: path envelope violation -> BLOCK (hard capability boundary)
    r = eng.evaluate(A("read_file", "/etc/passwd"), "unknown", 0,
                     capability={"actions": ["read_file"], "filesystem_read": ["/workspace/*"],
                                 "network": "denied", "credential": "denied", "process": "denied",
                                 "persistence": "denied"},
                     rules=[{"tool": "read_file", "decision": "allow",
                             "predicate": {"op": "glob", "field": "target", "value": "/etc/*"}}])
    _check("P1 path envelope violation -> BLOCK", r["verdict"] == "BLOCK", str(r))


def test_canonicalization():
    """Attack 1 defense: case / percent-encoding / Unicode aliases."""
    import unicodedata
    from policy import taint

    print("\n[canonicalization]")
    f = _fields("email", "send", {"to": "ALICE@Company.com"})
    _check("eq case-insensitive",
           symbolic.predicate_holds({"op": "eq", "field": "payload.to", "value": "alice@company.com"}, f))

    f = _fields("email", "send", {"to": "alice%40company.com"})
    _check("eq percent-decode",
           symbolic.predicate_holds({"op": "eq", "field": "payload.to", "value": "alice@company.com"}, f))

    nfd = unicodedata.normalize("NFD", "café")
    f = _fields("email", "send", {"to": nfd})
    _check("eq Unicode NFC/NFD",
           symbolic.predicate_holds({"op": "eq", "field": "payload.to", "value": "café"}, f))

    f = _fields("read_file", "%2fetc%2fpasswd")
    _check("deny eq catches encoded path",
           symbolic.predicate_holds({"op": "eq", "field": "target", "value": "/etc/passwd"}, f))

    f = _fields("shell", "RM -RF /")
    _check("contains case-insensitive",
           symbolic.predicate_holds({"op": "contains", "field": "target", "value": "rm -rf"}, f))

    # canonicalization applies to object-ID matching: percent-encoded path
    # EXACTLY matches the canonical object id (not substring/derived).
    a = SimpleNamespace(type="send", target="send", payload={"attachment": "~%2f.ssh%2fid_rsa"})
    _check("taint references canonicalized",
           taint.references_tainted(a, ["~/.ssh/id_rsa"]) == "~/.ssh/id_rsa")


def main():
    test_predicate_holds()
    test_check_rules()
    test_classify_update()
    test_minimal_and_apply()
    test_engine()
    test_canonicalization()
    print(f"\n{'=' * 60}\nRESULT: {_PASS} passed, {_FAIL} failed\n{'=' * 60}")
    sys.exit(1 if _FAIL else 0)


if __name__ == "__main__":
    main()
