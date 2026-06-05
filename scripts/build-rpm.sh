#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

usage() {
	cat <<'EOF'
Usage: scripts/build-rpm.sh [--version VERSION] [--release RELEASE] [--out DIR] [--target linux/amd64|linux/arm64] [--packager "NAME <EMAIL>"] [--license LICENSE]

Builds an RPM package for Tracejutsu and writes a SHA256 checksum. The package
installs:
  - /usr/bin/tracejutsu
  - /lib/systemd/system/tracejutsu.service
  - documentation under /usr/share/doc/tracejutsu

The package does not enable or start the service automatically.

If SOURCE_DATE_EPOCH is set, build metadata and staged package timestamps use
that Unix timestamp. RPM build-time reproducibility also depends on the host
rpm toolchain.

Set --packager or TRACEJUTSU_PACKAGE_MAINTAINER before publishing a package for
other users. The default packager is a placeholder. Set --license to match the
project license before public distribution.
EOF
}

version=""
rpm_release="1"
out_dir="dist"
target=""
packager="${TRACEJUTSU_PACKAGE_MAINTAINER:-Tracejutsu Maintainers <maintainers@example.invalid>}"
license="${TRACEJUTSU_PACKAGE_LICENSE:-LicenseRef-Private}"

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
	--release)
		if [[ $# -lt 2 ]]; then
			echo "--release requires a value" >&2
			exit 2
		fi
		rpm_release=$2
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
		target=$2
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
		license=$2
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

validate_release_label() {
	local name=$1
	local value=$2
	if [[ ! "$value" =~ ^[A-Za-z0-9._:+~-]+$ ]]; then
		echo "$name contains unsupported characters: $value" >&2
		exit 2
	fi
}

validate_rpm_version() {
	local name=$1
	local value=$2
	if [[ ! "$value" =~ ^[0-9][A-Za-z0-9._+~]*$ ]]; then
		echo "$name must start with a digit and contain only RPM-safe characters: $value" >&2
		exit 2
	fi
}

validate_rpm_release() {
	if [[ ! "$1" =~ ^[A-Za-z0-9._+~]+$ ]]; then
		echo "RPM release contains unsupported characters: $1" >&2
		exit 2
	fi
}

validate_single_line_field() {
	local name=$1
	local value=$2
	if [[ -z "$value" ]]; then
		echo "$name must not be empty" >&2
		exit 2
	fi
	if [[ "$value" == *$'\n'* || "$value" == *$'\r'* || "$value" =~ [[:cntrl:]] ]]; then
		echo "$name must be a single-line package field" >&2
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

rpm_arch() {
	case "$1" in
	linux/amd64)
		printf 'x86_64'
		;;
	linux/arm64)
		printf 'aarch64'
		;;
	esac
}

target_cc() {
	local requested_target=$1
	local host_target
	host_target="$(go env GOOS)/$(go env GOARCH)"
	if [[ -n "${CC:-}" ]]; then
		printf '%s' "$CC"
		return
	fi
	if [[ "$requested_target" == "$host_target" ]]; then
		return
	fi
	case "$requested_target" in
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
	echo "cross-building $requested_target requires CC or a matching cross compiler in PATH" >&2
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

changelog_date() {
	if [[ -n "${SOURCE_DATE_EPOCH:-}" ]]; then
		date -u -d "@$SOURCE_DATE_EPOCH" '+%a %b %d %Y'
		return
	fi
	date -u '+%a %b %d %Y'
}

normalize_tree_metadata() {
	local root=$1
	find "$root" -type d -exec chmod 0755 {} +
	find "$root" -type f -exec chmod 0644 {} +
	chmod 0755 "$root/usr/bin/tracejutsu"
	if [[ -n "${SOURCE_DATE_EPOCH:-}" ]]; then
		find "$root" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
	fi
}

require_command date
require_command find
require_command git
require_command go
require_command install
require_command rpmbuild
require_command sed
require_command sha256sum

export GOCACHE="${GOCACHE:-/tmp/tracejutsu-gocache}"
export GOMODCACHE="${GOMODCACHE:-/tmp/tracejutsu-gomodcache}"

if [[ -z "$target" ]]; then
	target="$(go env GOOS)/$(go env GOARCH)"
fi
validate_target "$target"

commit="$(git rev-parse --short=12 HEAD)"
if [[ -z "$version" ]]; then
	version="0.0.0+$commit"
fi
rpm_version="${version#v}"
build_date="$(build_date_utc)"
rpm_changelog_date="$(changelog_date)"

validate_release_label version "$version"
validate_release_label commit "$commit"
validate_release_label build_date "$build_date"
validate_rpm_version "RPM version" "$rpm_version"
validate_rpm_release "$rpm_release"
validate_single_line_field packager "$packager"
validate_single_line_field license "$license"

target_os="${target%/*}"
target_arch="${target#*/}"
package_arch="$(rpm_arch "$target")"
package_name="tracejutsu-${rpm_version}-${rpm_release}.${package_arch}"

mkdir -p "$out_dir"
out_dir="$(cd "$out_dir" && pwd)"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
staging_root="$tmp_dir/staging"
rpm_top="$tmp_dir/rpmbuild"
spec_file="$tmp_dir/tracejutsu.spec"

install -d \
	"$staging_root/usr/bin" \
	"$staging_root/lib/systemd/system" \
	"$staging_root/usr/share/doc/tracejutsu" \
	"$rpm_top/BUILD" \
	"$rpm_top/BUILDROOT" \
	"$rpm_top/RPMS" \
	"$rpm_top/SOURCES" \
	"$rpm_top/SPECS" \
	"$rpm_top/SRPMS"

cc="$(target_cc "$target")"
build_env=(
	"CGO_ENABLED=1"
	"GOOS=$target_os"
	"GOARCH=$target_arch"
)
if [[ -n "$cc" ]]; then
	build_env+=("CC=$cc")
fi
ldflags="-s -w -X main.buildVersion=$version -X main.buildCommit=$commit -X main.buildDate=$build_date"

env "${build_env[@]}" go build -trimpath -ldflags "$ldflags" -o "$staging_root/usr/bin/tracejutsu" ./cmd/tracejutsu
chmod 0755 "$staging_root/usr/bin/tracejutsu"
install -m 0644 packaging/systemd/tracejutsu.service "$staging_root/lib/systemd/system/tracejutsu.service"
sed -i 's#/usr/local/bin/tracejutsu#/usr/bin/tracejutsu#g' "$staging_root/lib/systemd/system/tracejutsu.service"
install -m 0644 README.md "$staging_root/usr/share/doc/tracejutsu/README.md"
install -m 0644 docs/INSTALL.md "$staging_root/usr/share/doc/tracejutsu/INSTALL.md"
install -m 0644 docs/OPERATIONS.md "$staging_root/usr/share/doc/tracejutsu/OPERATIONS.md"
normalize_tree_metadata "$staging_root"

cat >"$spec_file" <<EOF
Name: tracejutsu
Version: $rpm_version
Release: $rpm_release
Summary: Local-first eBPF runtime security analyst
License: $license
Packager: $packager
Requires: glibc
Requires: systemd

%description
Tracejutsu observes selected runtime events with eBPF, groups related activity
into deterministic incidents, and stores local SQLite evidence for terminal
inspection and optional local LLM analysis.

%prep

%build

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}
cp -a %{_tracejutsu_staging}/. %{buildroot}/

%post
if command -v systemctl >/dev/null 2>&1; then
	systemctl daemon-reload || true
fi
exit 0

%postun
if command -v systemctl >/dev/null 2>&1; then
	systemctl daemon-reload || true
fi
exit 0

%files
%attr(0755,root,root) /usr/bin/tracejutsu
%attr(0644,root,root) /lib/systemd/system/tracejutsu.service
%doc /usr/share/doc/tracejutsu/README.md
%doc /usr/share/doc/tracejutsu/INSTALL.md
%doc /usr/share/doc/tracejutsu/OPERATIONS.md

%changelog
* $rpm_changelog_date $packager - $rpm_version-$rpm_release
- Built Tracejutsu $version.
EOF

rpmbuild_args=(
	-bb
	--target "$package_arch"
	--define "_topdir $rpm_top"
	--define "_tracejutsu_staging $staging_root"
)
if [[ -n "${SOURCE_DATE_EPOCH:-}" ]]; then
	rpmbuild_args+=(
		--define "use_source_date_epoch_as_buildtime 1"
		--define "clamp_mtime_to_source_date_epoch 1"
		--define "source_date_epoch_from_changelog 1"
	)
fi
rpmbuild "${rpmbuild_args[@]}" "$spec_file"

built_rpm="$(find "$rpm_top/RPMS" -type f -name 'tracejutsu-*.rpm' -print -quit)"
if [[ -z "$built_rpm" ]]; then
	echo "built RPM not found in $rpm_top/RPMS" >&2
	exit 1
fi

rpm_path="$out_dir/$package_name.rpm"
mv "$built_rpm" "$rpm_path"
(
	cd "$out_dir"
	sha256sum "$package_name.rpm" >"$package_name.rpm.sha256"
)

echo
echo "RPM package:"
echo "$rpm_path"
echo "$rpm_path.sha256"
