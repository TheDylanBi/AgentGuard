"""P5/P2-1 tests: structured two-level taint (object-ID + field-level).

Unit-level (no gateway):

    python tests/test_taint.py
"""
import sys
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from policy import taint
from policy.engine import PolicyEngine

_PASS = 0
_FAIL = 0


def check(name, cond, extra=""):
    global _PASS, _FAIL
    if cond:
        _PASS += 1
        print(f"  PASS  {name}")
    else:
        _FAIL += 1
        print(f"  FAIL  {name}  {extra}")


def test_classify():
    print("\n[taint.classify: object-ID matching]")
    sink_caps = {"network_egress": "allowed"}
    non_sink = {"network": "denied", "credential": "denied", "persistence": "denied"}

    check("non-sink -> None",
          taint.classify(SimpleNamespace(target="send", payload={}), non_sink, None) is None)

    # Level 1: exact object-ID reference
    direct = SimpleNamespace(target="send", payload={"attachment": "~/.ssh/id_rsa"})
    r = taint.classify(direct, sink_caps, {"tainted_objects": ["~/.ssh/id_rsa"], "dirty": True})
    check("sink + exact ref -> BLOCK", r is not None and r[0] == "BLOCK", str(r))

    # Level 2: derived (content EMBEDS the id, but is not a direct ref)
    derived = SimpleNamespace(target="send", payload={"content": "copy of ~/.ssh/id_rsa"})
    r = taint.classify(derived, sink_caps, {"tainted_objects": ["~/.ssh/id_rsa"], "dirty": True})
    check("sink + embedded (derived) -> CONFIRM", r is not None and r[0] == "CONFIRM", str(r))

    r = taint.classify(direct, sink_caps, {"tainted_objects": [], "dirty": False})
    check("sink + clean -> None", r is None, str(r))

    src_caps = {"credential_access": "allowed", "network_egress": "denied",
                "external_share": "denied", "network": "denied", "persistence": "denied"}
    check("credential_access alone is not a sink", taint.is_sink(src_caps) is False)

    # structured record
    st = taint.record_source_read({}, "~/.ssh/id_rsa", source="credential")
    check("record structured object",
          st["dirty"] is True and st["tainted_objects"][0]["object_id"] == "~/.ssh/id_rsa"
          and st["tainted_objects"][0]["source"] == "credential", str(st))

    # P2-1: path-boundary matching (NOT substring)
    check("path-boundary matches /tmp/a/x", taint._object_matches("/tmp/a/x", "/tmp/a") is True)
    check("path-boundary rejects /tmp/abc", taint._object_matches("/tmp/abc", "/tmp/a") is False)
    check("exact matches", taint._object_matches("/tmp/a", "/tmp/a") is True)

    # field-level tracking
    hits = taint.references_tainted_field_level(
        SimpleNamespace(target="send", payload={"attachment": "/tmp/a/x", "note": "hi"}),
        [{"object_id": "/tmp/a", "source": "private_file"}])
    check("field-level returns (field, object_id)",
          bool(hits) and hits[0][0] == "payload.attachment" and hits[0][1] == "/tmp/a", str(hits))


def test_engine():
    print("\n[engine taint step]")
    eng = PolicyEngine(str(ROOT / "policy" / "policies"))
    caps = {"actions": ["send"], "network_egress": "allowed",
            "sensitive_params": ["payload.content"], "sources": []}
    rules = [{"tool": "send", "decision": "allow",
              "predicate": {"op": "glob", "field": "payload.content", "value": "*"}}]

    def A(content):
        return SimpleNamespace(type="send", target="send", payload={"content": content})

    r = eng.evaluate(A("hello world"), "unknown", 0, capability=caps, rules=rules)
    check("clean sink -> ALLOW", r["verdict"] == "ALLOW", str(r))

    r = eng.evaluate(A("~/.ssh/id_rsa"), "unknown", 0, capability=caps, rules=rules,
                     taint_state={"tainted_objects": ["~/.ssh/id_rsa"], "dirty": True})
    check("direct exact ref -> BLOCK (Level 1)", r["verdict"] == "BLOCK", str(r))

    r = eng.evaluate(A("summary of the report"), "unknown", 0, capability=caps, rules=rules,
                     taint_state={"tainted_objects": ["id_rsa"], "dirty": True})
    check("derived -> CONFIRM (Level 2)", r["verdict"] == "CONFIRM", str(r))


def main():
    test_classify()
    test_engine()
    print(f"\n{'=' * 60}\nRESULT: {_PASS} passed, {_FAIL} failed\n{'=' * 60}")
    sys.exit(1 if _FAIL else 0)


if __name__ == "__main__":
    main()
