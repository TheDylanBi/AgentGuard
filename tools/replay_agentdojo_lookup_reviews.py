"""Compare review prompts on captured inputs without executing AgentDojo tools."""
import argparse
import json
from pathlib import Path

from policy.call_review import ReviewStageError, bind_decision, operation_review, review_call
from policy.intent_anchor import intent_request_diagnostic
from policy.review_snapshot import validate_snapshot


def decision(caller, packet):
    try:
        result = bind_decision(caller(packet, timeout_seconds=80), packet)
    except ReviewStageError as error:
        return {"error": error.diagnostic.get("status")}
    except ValueError as error:
        return {"error": str(error)}
    diagnostic = intent_request_diagnostic()
    return {"decision": result["decision"], "code": result["code"],
            "reasoning_chars": diagnostic.get("reasoning_chars"),
            "prompt_tokens": diagnostic.get("prompt_tokens")}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input_dir", type=Path)
    parser.add_argument("--limit", type=int, default=12)
    args = parser.parse_args()
    emitted = set()
    for file in sorted(args.input_dir.glob("*.json")):
        snapshot = json.loads(file.read_text(encoding="utf-8"))
        validate_snapshot(snapshot)
        packet = snapshot["packet"]
        action = packet["action"]
        if action.get("operation") not in {"read", "list", "search"}:
            continue
        identity = (packet["original_user_request"], action["operation"], action["resource_type"])
        if identity in emitted:
            continue
        emitted.add(identity)
        print(json.dumps({
            "snapshot": file.stem,
            "operation": action["operation"],
            "resource_type": action["resource_type"],
            "standard": decision(review_call, packet),
            "operation_profile": decision(operation_review, packet),
        }), flush=True)
        if len(emitted) >= args.limit:
            break
    if not emitted:
        parser.error("No lookup snapshots found")


if __name__ == "__main__":
    main()
