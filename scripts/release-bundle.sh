#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

usage() {
	cat <<'EOF'
Usage: scripts/release-bundle.sh --version VERSION [--out DIR] [--target linux/amd64] [--target linux/arm64] [--maintainer "NAME <EMAIL>"] [--include-rpm] [--rpm-release RELEASE] [--packager "NAME <EMAIL>"] [--license LICENSE] [--sign] [--local-user KEY] [--allow-dirty] [--allow-existing-out] [--allow-placeholder-metadata] [--skip-deb] [--skip-dependency-review]

Builds a release bundle in an empty output directory:
  - versioned tarball(s)
  - Debian package(s), unless --skip-deb is supplied
  - optional RPM package(s), when --include-rpm is supplied
  - dependency-review.md, unless --skip-dependency-review is supplied
  - SHA256SUMS, and optionally SHA256SUMS.asc

If SOURCE_DATE_EPOCH is unset, it is set to the current HEAD commit time so
build metadata and staged timestamps are repeatable for the commit.

Run scripts/release-check.sh before publishing a bundle. This helper builds and
verifies artifacts; it does not run tests, live eBPF validation, or package
install smoke tests.
EOF
}

version=""
out_dir=""
targets=()
maintainer="${TRACEJUTSU_PACKAGE_MAINTAINER:-Tracejutsu Maintainers <maintainers@example.invalid>}"
include_rpm=0
rpm_release=1
packager="${TRACEJUTSU_PACKAGE_MAINTAINER:-Tracejutsu Maintainers <maintainers@example.invalid>}"
package_license="${TRACEJUTSU_PACKAGE_LICENSE:-LicenseRef-Private}"
sign_manifest=0
local_user=""
allow_dirty=0
allow_existing_out=0
allow_placeholder_metadata=0
skip_deb=0
skip_dependency_review=0

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
	--maintainer)
		if [[ $# -lt 2 ]]; then
			echo "--maintainer requires a value" >&2
			exit 2
		fi
		maintainer=$2
		shift 2
		;;
	--include-rpm)
		include_rpm=1
		shift
		;;
	--rpm-release)
		if [[ $# -lt 2 ]]; then
			echo "--rpm-release requires a value" >&2
			exit 2
		fi
		rpm_release=$2
		shift 2
		;;
	--packager)
		if [[ $# -lt 2 ]]; then
			echo "--packager requires a value" >&2
			exit 2
		fi
		packager=$2
		shift 2
		;;
	--license)
		if [[ $# -lt 2 ]]; then
			echo "--license requires a value" >&2
			exit 2
		fi
		package_license=$2
		shift 2
		;;
	--sign)
		sign_manifest=1
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
	--allow-dirty)
		allow_dirty=1
		shift
		;;
	--allow-existing-out)
		allow_existing_out=1
		shift
		;;
	--allow-placeholder-metadata)
		allow_placeholder_metadata=1
		shift
		;;
	--skip-deb)
		skip_deb=1
		shift
		;;
	--skip-dependency-review)
		skip_dependency_review=1
		shift
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

require_non_placeholder_metadata() {
	local field=$1
	local value=$2
	if [[ "$allow_placeholder_metadata" -eq 1 ]]; then
		return
	fi
	case "$value" in
	"Tracejutsu Maintainers <maintainers@example.invalid>"|LicenseRef-Private)
		echo "$field uses placeholder metadata: $value" >&2
		echo "pass a real value or use --allow-placeholder-metadata for local test bundles" >&2
		exit 2
		;;
	esac
}

require_clean_tracked_worktree() {
	if [[ "$allow_dirty" -eq 1 ]]; then
		return
	fi
	if ! git diff --quiet || ! git diff --cached --quiet; then
		echo "tracked worktree changes are present; commit them or use --allow-dirty" >&2
		exit 1
	fi
}

require_empty_or_allowed_out_dir() {
	local dir=$1
	if [[ ! -d "$dir" ]]; then
		return
	fi
	if [[ "$allow_existing_out" -eq 1 ]]; then
		return
	fi
	if find "$dir" -mindepth 1 -maxdepth 1 -print -quit | grep -q .; then
		echo "output directory is not empty: $dir" >&2
		echo "choose a new --out directory or use --allow-existing-out" >&2
		exit 1
	fi
}

run() {
	printf '\n===== %s =====\n' "$*"
	"$@"
}

require_command date
require_command find
require_command git
require_command go
require_command grep

if [[ -z "$version" ]]; then
	echo "--version is required for release bundles" >&2
	exit 2
fi

if [[ "${#targets[@]}" -eq 0 ]]; then
	host_target="$(go env GOOS)/$(go env GOARCH)"
	validate_target "$host_target"
	targets=("$host_target")
fi
for target in "${targets[@]}"; do
	validate_target "$target"
done

if [[ -z "$out_dir" ]]; then
	out_dir="dist/$version"
fi
require_empty_or_allowed_out_dir "$out_dir"
mkdir -p "$out_dir"
out_dir="$(cd "$out_dir" && pwd)"

require_clean_tracked_worktree
if [[ "$skip_deb" -ne 1 ]]; then
	require_non_placeholder_metadata maintainer "$maintainer"
fi
if [[ "$include_rpm" -eq 1 ]]; then
	require_non_placeholder_metadata packager "$packager"
	require_non_placeholder_metadata license "$package_license"
fi

if [[ -z "${SOURCE_DATE_EPOCH:-}" ]]; then
	export SOURCE_DATE_EPOCH
	SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)"
fi
if [[ ! "$SOURCE_DATE_EPOCH" =~ ^[0-9]+$ ]]; then
	echo "SOURCE_DATE_EPOCH must be a Unix timestamp: $SOURCE_DATE_EPOCH" >&2
	exit 2
fi

echo "Tracejutsu release bundle"
echo "version: $version"
echo "commit: $(git rev-parse --short=12 HEAD)"
echo "source_date_epoch: $SOURCE_DATE_EPOCH"
echo "out: $out_dir"
echo "targets: ${targets[*]}"
echo "debian_package: $([[ "$skip_deb" -eq 1 ]] && printf 'no' || printf 'yes')"
echo "rpm_package: $([[ "$include_rpm" -eq 1 ]] && printf 'yes' || printf 'no')"
echo "dependency_review: $([[ "$skip_dependency_review" -eq 1 ]] && printf 'no' || printf 'yes')"
echo "sign_manifest: $([[ "$sign_manifest" -eq 1 ]] && printf 'yes' || printf 'no')"

release_args=(--version "$version" --out "$out_dir")
for target in "${targets[@]}"; do
	release_args+=(--target "$target")
done
run scripts/build-release.sh "${release_args[@]}"

if [[ "$skip_deb" -ne 1 ]]; then
	for target in "${targets[@]}"; do
		run scripts/build-deb.sh --version "$version" --out "$out_dir" --target "$target" --maintainer "$maintainer"
	done
fi

if [[ "$include_rpm" -eq 1 ]]; then
	for target in "${targets[@]}"; do
		run scripts/build-rpm.sh --version "$version" --release "$rpm_release" --out "$out_dir" --target "$target" --packager "$packager" --license "$package_license"
	done
fi

if [[ "$skip_dependency_review" -ne 1 ]]; then
	run scripts/dependency-review.sh --out "$out_dir/dependency-review.md"
fi

manifest_args=(--dir "$out_dir")
if [[ "$sign_manifest" -eq 1 ]]; then
	manifest_args+=(--sign)
	if [[ -n "$local_user" ]]; then
		manifest_args+=(--local-user "$local_user")
	fi
fi
run scripts/release-manifest.sh "${manifest_args[@]}"
run scripts/release-manifest.sh --dir "$out_dir" --verify

echo
echo "release bundle complete:"
find "$out_dir" -maxdepth 1 -type f -print | sort
