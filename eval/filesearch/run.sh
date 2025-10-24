#!/bin/bash
# File search run script (Figure 9)
set -eu -o pipefail

if ! uname -r | grep -q "cache-ext"; then
	echo "This script is intended to be run on a cache_ext kernel."
	echo "Please switch to the cache_ext kernel and try again."
	exit 1
fi

SCRIPT_PATH=$(realpath $0)
BASE_DIR=$(realpath "$(dirname $SCRIPT_PATH)/../../")
BENCH_PATH="$BASE_DIR/bench"
POLICY_PATH="$BASE_DIR/policies"
FILES_PATH=$(realpath "$BASE_DIR/../linux")
RESULTS_PATH="$BASE_DIR/results"
if [ $# -lt 1 ]; then
	echo "Usage: $0 <results_file_name>"
	exit 1
fi
RESULTS_FILE="$RESULTS_PATH/$1"

ITERATIONS=1

mkdir -p "$RESULTS_PATH"

# Disable MGLRU
if ! "$BASE_DIR/utils/disable-mglru.sh"; then
	echo "Failed to disable MGLRU. Please check the script."
	exit 1
fi

# Baseline and cache_ext
python3 "$BENCH_PATH/bench_filesearch.py" \
	--cpu 8 \
	--policy-loader "$POLICY_PATH/cache_ext_agent.out" \
	--results-file "$RESULTS_FILE" \
	--data-dir "$FILES_PATH" \
	--iterations "$ITERATIONS" \
	--no-reuse-results

# Enable MGLRU
if ! "$BASE_DIR/utils/enable-mglru.sh"; then
	echo "Failed to enable MGLRU. Please check the script."
	exit 1
fi

# # MGLRU
# # TODO: Remove --policy-loader requirement when using --default-only
# python3 "$BENCH_PATH/bench_filesearch.py" \
# 	--cpu 8 \
# 	--policy-loader "$POLICY_PATH/cache_ext_mru.out" \
# 	--results-file "$RESULTS_PATH/filesearch_results_mglru.json" \
# 	--data-dir "$FILES_PATH" \
# 	--iterations "$ITERATIONS" \
# 	--default-only

# Disable MGLRU
if ! "$BASE_DIR/utils/disable-mglru.sh"; then
	echo "Failed to disable MGLRU. Please check the script."
	exit 1
fi

echo "File search benchmark completed. Results saved to $RESULTS_PATH."
