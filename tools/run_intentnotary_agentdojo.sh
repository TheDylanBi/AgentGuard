#!/usr/bin/env bash
# Run AgentDojo's benchmark with an IntentNotary Pi profile.
set -euo pipefail
umask 077

project=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
: "${INTENTNOTARY_PI_PACKAGE:?Set the path to the installed Pi package}"
: "${INTENTNOTARY_PI_AGENT_DIR:?Set the path to the Pi configuration directory}"

python_bin=${INTENTNOTARY_AGENTDOJO_PYTHON:-python}
model=${INTENTNOTARY_AGENTDOJO_MODEL:-qwen3-32b-awq}
export PYTHONPATH="$project/tools:$project${PYTHONPATH:+:$PYTHONPATH}"

exec "$python_bin" -X utf8 -u -m agentdojo.scripts.benchmark \
    --model OPENAI_COMPATIBLE --model-id "$model" --benchmark-version v1.2.2 \
    --max-workers 1 --module-to-load intentnotary_pi_agentdojo "$@"
