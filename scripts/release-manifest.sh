#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

usage() {
	cat <<'EOF'
Usage: scripts/release-manifest.sh [--dir DIR] [--sign] [--verify] [--local-user KEY]

Writes and verifies a sorted SHA256SUMS manifest for release artifacts in DIR.
The manifest includes:
  - tracejutsu-*.tar.gz
  - tracejutsu_*.deb

By default the script regenerates DIR/SHA256SUMS and verifies it. With --sign,
it also writes DIR/SHA256SUMS.asc as an armored detached GPG signature and
verifies that signature. With --verify, it verifies an existing manifest and
any existing detached signature without rewriting files.

Options:
  --dir DIR          Release artifact directory. Default: dist.
  --sign             Generate and verify SHA256SUMS.asc.
  --verify           Verify existing SHA256SUMS instead of regenerating it.
  --local-user KEY   Pass --local-user KEY to gpg when signing.
  --help             Show this help.
EOF
}

out_dir=dist
sign_manifest=0
verify_only=0
local_user=""

while [[ $# -gt 0 ]]; do
	case "$1" in
	--dir)
		if [[ $# -lt 2 ]]; then
			echo "--dir requires a value" >&2
			exit 2
		fi
		out_dir=$2
		shift 2
		;;
	--sign)
		sign_manifest=1
		shift
		;;
	--verify)
		verify_only=1
		shift
		;;
	--local-user)
		if [[ $# -lt 2 ]]; then
			echo "--local-user requires a value" >&2
			exit 2
		fi
		local_user=$2
		shift 2
		;;
	--help|-h)
		usage
		exit 0
		;;
	*)
		echo "unknown argument: $1" >&2
		usage >&2
		exit 2
		;;
	esac
done

if [[ "$sign_manifest" -eq 1 && "$verify_only" -eq 1 ]]; then
	echo "--sign and --verify are mutually exclusive" >&2
	exit 2
fi

require_command() {
	if ! command -v "$1" >/dev/null 2>&1; then
		echo "missing required command: $1" >&2
		exit 1
	fi
}

artifact_paths() {
	find "$out_dir" -maxdepth 1 -type f \
		\( -name 'tracejutsu-*.tar.gz' -o -name 'tracejutsu_*.deb' \) \
		-print | LC_ALL=C sort
}

write_manifest() {
	local tmp
	local artifact
	mapfile -t artifacts < <(artifact_paths)
	if [[ "${#artifacts[@]}" -eq 0 ]]; then
		echo "no release artifacts found in $out_dir" >&2
		exit 1
	fi
	tmp="$(mktemp "$out_dir/.SHA256SUMS.XXXXXX")"
	(
		cd "$out_dir"
		for artifact in "${artifacts[@]}"; do
			sha256sum "${artifact##*/}"
		done
	) >"$tmp"
	chmod 0644 "$tmp"
	mv "$tmp" "$manifest"
}

verify_manifest() {
	if [[ ! -f "$manifest" ]]; then
		echo "missing manifest: $manifest" >&2
		exit 1
	fi
	(
		cd "$out_dir"
		sha256sum -c SHA256SUMS
	)
}

sign_manifest_file() {
	local gpg_args
	require_command gpg
	if [[ -z "${GPG_TTY:-}" && -t 0 ]]; then
		export GPG_TTY
		GPG_TTY="$(tty)"
	fi
	gpg_args=(--yes --armor --detach-sign --output "$signature")
	if [[ -n "$local_user" ]]; then
		gpg_args+=(--local-user "$local_user")
	fi
	gpg "${gpg_args[@]}" "$manifest"
	chmod 0644 "$signature"
}

verify_signature() {
	if [[ ! -f "$signature" ]]; then
		echo "signature not found: $signature"
		return
	fi
	require_command gpg
	gpg --verify "$signature" "$manifest"
}

require_command find
require_command chmod
require_command mktemp
require_command mv
require_command sha256sum
require_command sort

if [[ ! -d "$out_dir" ]]; then
	echo "release artifact directory does not exist: $out_dir" >&2
	exit 1
fi
out_dir="$(cd "$out_dir" && pwd)"
manifest="$out_dir/SHA256SUMS"
signature="$manifest.asc"
artifacts=()

if [[ "$verify_only" -eq 0 ]]; then
	write_manifest
fi
verify_manifest
if [[ "$sign_manifest" -eq 1 ]]; then
	sign_manifest_file
	verify_signature
elif [[ "$verify_only" -eq 1 && -f "$signature" ]]; then
	verify_signature
fi

echo
echo "release manifest:"
echo "$manifest"
if [[ -f "$signature" ]]; then
	echo "$signature"
fi
