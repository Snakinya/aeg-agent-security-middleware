#!/usr/bin/env bash
set -euo pipefail

command -v llama-server >/dev/null 2>&1 || {
  printf '[singguard] llama-server is missing. Install it with: brew install llama.cpp\n' >&2
  exit 2
}

user_home="${HOME:?HOME is required}"
state_root="${LOCAL_POC_DATA_ROOT:-$user_home/.volc-agent-launchpad}"
model_path="${SINGGUARD_MODEL_PATH:-$state_root/models/singguard-nsfa/Sing-Guard-0.8B-Q4_K_M.gguf}"
host="${SINGGUARD_HOST:-127.0.0.1}"
port="${SINGGUARD_PORT:-18080}"
alias="${SINGGUARD_MODEL:-singguard-nsfa-0.8b}"

if [[ ! -f "$model_path" ]]; then
  printf '[singguard] model is missing: %s\n' "$model_path" >&2
  printf '[singguard] download inclusionAI/SingGuard-NSFA-0.8B-GGUF Q4_K_M first.\n' >&2
  exit 2
fi

printf '[singguard] model: %s\n' "$model_path" >&2
printf '[singguard] endpoint: http://%s:%s/v1\n' "$host" "$port" >&2

exec llama-server \
  --model "$model_path" \
  --host "$host" \
  --port "$port" \
  --ctx-size 4096 \
  --n-gpu-layers 99 \
  --alias "$alias" \
  --no-webui \
  --reasoning-format none
