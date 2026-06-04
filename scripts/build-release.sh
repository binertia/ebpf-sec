#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

usage() {
	cat <<'EOF'
Usage: scripts/build-release.sh [--version VERSION] [--out DIR] [--target linux/amd64] [--target linux/arm64]

Builds version-stamped Runtime Guard tarballs and SHA256 checksums. By default
the script builds the current Linux amd64 or arm64 host architecture only.

Cross-building arm64 from amd64 requires CC=aarch64-linux-gnu-gcc or an
available aarch64-linux-gnu-gcc in PATH. Cross-building amd64 from another
architecture similarly requires CC or x86_64-linux-gnu-gcc.

If SOURCE_DATE_EPOCH is set, build metadata and archive timestamps use that
Unix timestamp.
EOF
}

version=""
out_dir="dist"
targets=()

while [[ $# -gt 0 ]]; do
	case "$1" in
	--version)
		if [[ $# -lt 2 ]]; then
			echo "--version requires a value" >&2
			exit 2
		fi
		version=$2
		shift 2
		;;
	--out)
		if [[ $# -lt 2 ]]; then
			echo "--out requires a value" >&2
			exit 2
		fi
		out_dir=$2
		shift 2
		;;
	--target)
		if [[ $# -lt 2 ]]; then
			echo "--target requires a value" >&2
			exit 2
		fi
		targets+=("$2")
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

require_command() {
	if ! command -v "$1" >/dev/null 2>&1; then
		echo "missing required command: $1" >&2
		exit 1
	fi
}

validate_label() {
	local name=$1
	local value=$2
	if [[ ! "$value" =~ ^[A-Za-z0-9._:+-]+$ ]]; then
		echo "$name contains unsupported characters: $value" >&2
		exit 2
	fi
}

validate_target() {
	case "$1" in
	linux/amd64|linux/arm64)
		;;
	*)
		echo "unsupported target: $1" >&2
		echo "supported targets: linux/amd64 linux/arm64" >&2
		exit 2
		;;
	esac
}

target_cc() {
	local target=$1
	local host_target
	host_target="$(go env GOOS)/$(go env GOARCH)"
	if [[ -n "${CC:-}" ]]; then
		printf '%s' "$CC"
		return
	fi
	if [[ "$target" == "$host_target" ]]; then
		return
	fi
	case "$target" in
	linux/arm64)
		if command -v aarch64-linux-gnu-gcc >/dev/null 2>&1; then
			printf 'aarch64-linux-gnu-gcc'
			return
		fi
		;;
	linux/amd64)
		if command -v x86_64-linux-gnu-gcc >/dev/null 2>&1; then
			printf 'x86_64-linux-gnu-gcc'
			return
		fi
		;;
	esac
	echo "cross-building $target requires CC or a matching cross compiler in PATH" >&2
	exit 1
}

build_date_utc() {
	if [[ -n "${SOURCE_DATE_EPOCH:-}" ]]; then
		if [[ ! "$SOURCE_DATE_EPOCH" =~ ^[0-9]+$ ]]; then
			echo "SOURCE_DATE_EPOCH must be a Unix timestamp: $SOURCE_DATE_EPOCH" >&2
			exit 2
		fi
		date -u -d "@$SOURCE_DATE_EPOCH" +%Y-%m-%dT%H:%M:%SZ
		return
	fi
	date -u +%Y-%m-%dT%H:%M:%SZ
}

normalize_tree_metadata() {
	local root=$1
	find "$root" -type d -exec chmod 0755 {} +
	find "$root" -type f -exec chmod 0644 {} +
	chmod 0755 "$root/runtime-guard"
	if [[ -n "${SOURCE_DATE_EPOCH:-}" ]]; then
		find "$root" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
	fi
}

write_tarball() {
	local source_dir=$1
	local artifact_name=$2
	local tarball=$3
	if [[ -n "${SOURCE_DATE_EPOCH:-}" ]]; then
		tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$SOURCE_DATE_EPOCH" \
			-C "$source_dir" -cf - "$artifact_name" | gzip -n >"$tarball"
		return
	fi
	tar --sort=name --owner=0 --group=0 --numeric-owner -C "$source_dir" -czf "$tarball" "$artifact_name"
}

require_command date
require_command find
require_command git
require_command go
require_command gzip
require_command sha256sum
require_command tar

export GOCACHE="${GOCACHE:-/tmp/runtime-guard-gocache}"
export GOMODCACHE="${GOMODCACHE:-/tmp/runtime-guard-gomodcache}"

if [[ -z "$version" ]]; then
	version="$(git describe --tags --always --dirty)"
fi
commit="$(git rev-parse --short=12 HEAD)"
build_date="$(build_date_utc)"

validate_label version "$version"
validate_label commit "$commit"
validate_label build_date "$build_date"

if [[ "${#targets[@]}" -eq 0 ]]; then
	host_target="$(go env GOOS)/$(go env GOARCH)"
	validate_target "$host_target"
	targets=("$host_target")
fi
for target in "${targets[@]}"; do
	validate_target "$target"
done

mkdir -p "$out_dir"
out_dir="$(cd "$out_dir" && pwd)"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
sha_file="$out_dir/SHA256SUMS"
: >"$sha_file"

for target in "${targets[@]}"; do
	target_os="${target%/*}"
	target_arch="${target#*/}"
	artifact_name="runtime-guard-${version}-${target_os}-${target_arch}"
	artifact_root="$tmp_dir/$artifact_name"
	binary_path="$artifact_root/runtime-guard"
	cc="$(target_cc "$target")"

	mkdir -p "$artifact_root/docs" "$artifact_root/packaging/systemd"
	build_env=(
		"CGO_ENABLED=1"
		"GOOS=$target_os"
		"GOARCH=$target_arch"
	)
	if [[ -n "$cc" ]]; then
		build_env+=("CC=$cc")
	fi
	ldflags="-s -w -X main.buildVersion=$version -X main.buildCommit=$commit -X main.buildDate=$build_date"

	echo "building $target -> $artifact_name.tar.gz"
	env "${build_env[@]}" go build -trimpath -ldflags "$ldflags" -o "$binary_path" ./cmd/runtime-guard
	cp README.md "$artifact_root/"
	cp docs/INSTALL.md "$artifact_root/docs/"
	cp packaging/systemd/runtime-guard.service "$artifact_root/packaging/systemd/"
	normalize_tree_metadata "$artifact_root"

	tarball="$out_dir/$artifact_name.tar.gz"
	write_tarball "$tmp_dir" "$artifact_name" "$tarball"
	(
		cd "$out_dir"
		sha256sum "$artifact_name.tar.gz" >"$artifact_name.tar.gz.sha256"
		cat "$artifact_name.tar.gz.sha256" >>"$sha_file"
	)
done

echo
echo "release artifacts:"
find "$out_dir" -maxdepth 1 -type f \( -name 'runtime-guard-*.tar.gz' -o -name 'runtime-guard-*.tar.gz.sha256' -o -name SHA256SUMS \) -print | sort
