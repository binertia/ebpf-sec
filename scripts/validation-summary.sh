#!/usr/bin/env bash
set -euo pipefail

usage() {
	cat <<'EOF'
Usage: scripts/validation-summary.sh LOGFILE [...]

Summarizes saved Runtime Guard smoke/stress helper output. The script accepts
logs produced by the current helpers and older logs that only contain raw
journal output. It exits nonzero if any log has a failed helper result, missing
runtime stats, or nonzero required drop counters.
EOF
}

if [[ $# -eq 0 ]]; then
	usage >&2
	exit 2
fi

extract_last_prefixed() {
	local file=$1
	local prefix=$2
	awk -v prefix="$prefix" '
		index($0, prefix) {
			value = substr($0, index($0, prefix) + length(prefix))
			found = 1
		}
		END {
			if (!found) {
				exit 1
			}
			print value
		}
	' "$file"
}

extract_first_line() {
	local file=$1
	local prefix=$2
	awk -v prefix="$prefix" '
		index($0, prefix) == 1 {
			print substr($0, length(prefix) + 1)
			found = 1
			exit
		}
		END {
			if (!found) {
				exit 1
			}
		}
	' "$file"
}

final_runtime_stats() {
	local file=$1
	local summary_stats
	summary_stats="$(grep -F 'final_runtime_stats:' "$file" | tail -n 1 | sed 's/^final_runtime_stats:[[:space:]]*//' || true)"
	if [[ -n "$summary_stats" && "$summary_stats" != "not found" ]]; then
		printf '%s' "$summary_stats"
		return
	fi
	grep 'runtime stats:' "$file" | tail -n 1 || true
}

counter_value() {
	local stats=$1
	local counter=$2
	local regex="(^|[[:space:]])${counter}=([0-9]+)"
	if [[ "$stats" =~ $regex ]]; then
		printf '%s' "${BASH_REMATCH[2]}"
		return
	fi
	printf 'missing'
}

stats_token() {
	local stats=$1
	local token=$2
	local regex="(^|[[:space:]])${token}=([^[:space:]]+)"
	if [[ "$stats" =~ $regex ]]; then
		printf '%s' "${BASH_REMATCH[2]}"
	fi
}

summarize_log() {
	local file=$1
	local failed=0
	local stats
	local value
	local collector_ring
	local collector_correlation
	stats="$(final_runtime_stats "$file")"

	echo "===== $file ====="
	echo "os: $(extract_first_line "$file" 'os: ' || true)"
	echo "kernel: $(extract_first_line "$file" 'kernel: ' || true)"
	echo "arch: $(extract_first_line "$file" 'arch: ' || true)"
	echo "systemd: $(extract_first_line "$file" 'systemd: ' || true)"
	echo "go: $(extract_first_line "$file" 'go: ' || true)"
	echo "cgroup_fs: $(extract_first_line "$file" 'cgroup_fs: ' || true)"
	echo "virtualization: $(extract_first_line "$file" 'virtualization: ' || true)"
	echo "container: $(extract_first_line "$file" 'container: ' || true)"
	echo "helper_exit: $(extract_first_line "$file" 'helper_exit: ' || printf 'unknown')"
	echo "result: $(extract_last_prefixed "$file" 'Finished with result: ' || printf 'unknown')"
	echo "service_runtime: $(extract_last_prefixed "$file" 'Service runtime: ' || printf 'unknown')"
	echo "cpu_time: $(extract_last_prefixed "$file" 'CPU time consumed: ' || printf 'unknown')"
	echo "memory_peak: $(extract_last_prefixed "$file" 'Memory peak: ' || printf 'unknown')"

	if [[ -z "$stats" ]]; then
		echo "final_runtime_stats: missing"
		failed=1
	else
		echo "final_runtime_stats: $stats"
		for counter in ring_dropped correlation_dropped persist_dropped incident_persist_dropped; do
			value="$(counter_value "$stats" "$counter")"
			case "$value" in
			0)
				echo "$counter: ok"
				;;
			missing)
				echo "$counter: missing"
				failed=1
				;;
			*)
				echo "$counter: nonzero ($value)"
				failed=1
				;;
			esac
		done
		collector_ring="$(stats_token "$stats" collector_ring_dropped)"
		if [[ -n "$collector_ring" ]]; then
			echo "collector_ring_dropped: $collector_ring"
		fi
		collector_correlation="$(stats_token "$stats" collector_correlation_dropped)"
		if [[ -n "$collector_correlation" ]]; then
			echo "collector_correlation_dropped: $collector_correlation"
		fi
	fi

	local helper_exit
	helper_exit="$(extract_first_line "$file" 'helper_exit: ' || true)"
	if [[ -n "$helper_exit" && "$helper_exit" != "0" ]]; then
		failed=1
	fi
	local result
	result="$(extract_last_prefixed "$file" 'Finished with result: ' || true)"
	if [[ -n "$result" && "$result" != "success" ]]; then
		failed=1
	fi
	echo
	return "$failed"
}

overall_failed=0
for file in "$@"; do
	if [[ ! -r "$file" ]]; then
		echo "cannot read log file: $file" >&2
		overall_failed=1
		continue
	fi
	if ! summarize_log "$file"; then
		overall_failed=1
	fi
done

exit "$overall_failed"
