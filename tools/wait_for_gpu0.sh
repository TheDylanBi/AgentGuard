#!/usr/bin/env bash

if [[ ${1:-} == -- ]]; then
    shift
fi
if (( $# == 0 )); then
    printf 'Usage: bash wait_for_gpu0.sh -- COMMAND [ARG ...]\n' >&2
    exit 2
fi
if ! command -v nvidia-smi >/dev/null; then
    printf 'nvidia-smi was not found in PATH.\n' >&2
    exit 127
fi

threshold_mib=50
poll_seconds=10

while true; do
    if used=$(nvidia-smi --id=0 --query-gpu=memory.used --format=csv,noheader,nounits) &&
        [[ $used =~ ^[[:space:]]*([0-9]+)[[:space:]]*$ ]]; then
        used_mib=${BASH_REMATCH[1]}
        if (( 10#$used_mib < threshold_mib )); then
            printf '[%s] GPU 0 uses %s MiB. Starting command.\n' "$(date -Is)" "$used_mib" >&2
            exec -- "$@"
        fi
        printf '[%s] GPU 0 uses %s MiB. Waiting for less than %s MiB.\n' \
            "$(date -Is)" "$used_mib" "$threshold_mib" >&2
    else
        printf '[%s] Could not read GPU 0 memory usage. Retrying.\n' "$(date -Is)" >&2
    fi
    sleep "$poll_seconds"
done
