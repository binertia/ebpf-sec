#!/usr/bin/env bash

tracejutsu_os_name() {
	if [[ -r /etc/os-release ]]; then
		(
			. /etc/os-release
			printf '%s' "${PRETTY_NAME:-unknown}"
		)
		return
	fi
	printf 'unknown'
}

tracejutsu_command_line() {
	local command_name=$1
	shift
	if ! command -v "$command_name" >/dev/null 2>&1; then
		printf 'unavailable'
		return
	fi
	"$command_name" "$@" 2>/dev/null | sed -n '1p'
}

tracejutsu_virtualization() {
	if ! command -v systemd-detect-virt >/dev/null 2>&1; then
		printf 'unknown'
		return
	fi
	local detected
	detected="$(systemd-detect-virt 2>/dev/null || true)"
	if [[ -z "$detected" ]]; then
		printf 'none'
		return
	fi
	printf '%s' "$detected"
}

tracejutsu_container() {
	if ! command -v systemd-detect-virt >/dev/null 2>&1; then
		printf 'unknown'
		return
	fi
	local detected
	detected="$(systemd-detect-virt --container 2>/dev/null || true)"
	if [[ -z "$detected" ]]; then
		printf 'none'
		return
	fi
	printf '%s' "$detected"
}

tracejutsu_cgroup_fs() {
	stat -fc '%T' /sys/fs/cgroup 2>/dev/null || printf 'unknown'
}

tracejutsu_print_host_fingerprint() {
	echo
	echo "===== host fingerprint ====="
	echo "hostname: $(hostname 2>/dev/null || printf 'unknown')"
	echo "os: $(tracejutsu_os_name)"
	echo "kernel: $(uname -srmo 2>/dev/null || printf 'unknown')"
	echo "arch: $(uname -m 2>/dev/null || printf 'unknown')"
	echo "systemd: $(tracejutsu_command_line systemctl --version)"
	echo "go: $(tracejutsu_command_line go version)"
	echo "cgroup_fs: $(tracejutsu_cgroup_fs)"
	echo "virtualization: $(tracejutsu_virtualization)"
	echo "container: $(tracejutsu_container)"
}

tracejutsu_require_sudo_access() {
	if sudo -n true 2>/dev/null; then
		return
	fi
	if [[ -t 0 ]]; then
		sudo -v
		return
	fi
	echo "sudo credentials are required before building temporary test artifacts" >&2
	echo "run this helper from an interactive terminal or configure non-interactive sudo" >&2
	exit 1
}

tracejutsu_final_runtime_stats() {
	local journal_output=$1
	printf '%s\n' "$journal_output" | grep 'runtime stats:' | tail -n 1 || true
}

tracejutsu_stats_counter_value() {
	local stats=$1
	local counter=$2
	local regex="(^|[[:space:]])${counter}=([0-9]+)"
	if [[ "$stats" =~ $regex ]]; then
		printf '%s' "${BASH_REMATCH[2]}"
		return
	fi
	printf 'missing'
}

tracejutsu_stats_token() {
	local stats=$1
	local token=$2
	local regex="(^|[[:space:]])${token}=([^[:space:]]+)"
	if [[ "$stats" =~ $regex ]]; then
		printf '%s' "${BASH_REMATCH[2]}"
	fi
}

tracejutsu_validation_exit_status() {
	local run_status=$1
	local final_stats=$2
	local counter
	local value
	if [[ "$run_status" -ne 0 ]]; then
		return "$run_status"
	fi
	if [[ -z "$final_stats" ]]; then
		return 1
	fi
	for counter in ring_dropped correlation_dropped persist_dropped incident_persist_dropped; do
		value="$(tracejutsu_stats_counter_value "$final_stats" "$counter")"
		if [[ "$value" != "0" ]]; then
			return 1
		fi
	done
	return 0
}

tracejutsu_print_validation_summary() {
	local run_status=$1
	local run_output=$2
	local journal_output=$3
	local final_stats
	local validation_status
	local counter
	local value
	local collector_ring
	local collector_correlation
	final_stats="$(tracejutsu_final_runtime_stats "$journal_output")"

	echo
	echo "===== validation summary ====="
	echo "helper_exit: $run_status"
	printf '%s\n' "$run_output" |
		grep -E '^(Finished with result|Main processes terminated|Service runtime|CPU time consumed|Memory peak):' || true
	if [[ -n "$final_stats" ]]; then
		echo "final_runtime_stats: $final_stats"
		for counter in ring_dropped correlation_dropped persist_dropped incident_persist_dropped; do
			value="$(tracejutsu_stats_counter_value "$final_stats" "$counter")"
			if [[ "$value" == "0" ]]; then
				echo "$counter: ok"
			elif [[ "$value" == "missing" ]]; then
				echo "$counter: missing"
			else
				echo "$counter: nonzero ($value)"
			fi
		done
		collector_ring="$(tracejutsu_stats_token "$final_stats" collector_ring_dropped)"
		if [[ -n "$collector_ring" ]]; then
			echo "collector_ring_dropped: $collector_ring"
		fi
		collector_correlation="$(tracejutsu_stats_token "$final_stats" collector_correlation_dropped)"
		if [[ -n "$collector_correlation" ]]; then
			echo "collector_correlation_dropped: $collector_correlation"
		fi
	else
		echo "final_runtime_stats: not found"
	fi
	if tracejutsu_validation_exit_status "$run_status" "$final_stats"; then
		validation_status=pass
	else
		validation_status=fail
	fi
	echo "validation_result: $validation_status"
}
