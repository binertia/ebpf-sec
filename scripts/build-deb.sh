#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

usage() {
	cat <<'EOF'
Usage: scripts/build-deb.sh [--version VERSION] [--out DIR] [--target linux/amd64|linux/arm64] [--maintainer "NAME <EMAIL>"]

Builds a Debian package for Tracejutsu and writes a SHA256 checksum. The
package installs:
  - /usr/bin/tracejutsu
  - /lib/systemd/system/tracejutsu.service
  - documentation under /usr/share/doc/tracejutsu

The package does not enable or start the service automatically.

If SOURCE_DATE_EPOCH is set, build metadata and package timestamps use that
Unix timestamp.

Set --maintainer or TRACEJUTSU_PACKAGE_MAINTAINER before publishing a package
for other users. The default maintainer is a placeholder.
EOF
}

version=""
out_dir="dist"
target=""
maintainer="${TRACEJUTSU_PACKAGE_MAINTAINER:-Tracejutsu Maintainers <maintainers@example.invalid>}"

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
		target=$2
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

validate_debian_version() {
	if [[ ! "$1" =~ ^[0-9][A-Za-z0-9.+:~-]*$ ]]; then
		echo "Debian version must start with a digit and contain only Debian-safe characters: $1" >&2
		exit 2
	fi
}

validate_control_field() {
	local name=$1
	local value=$2
	if [[ -z "$value" ]]; then
		echo "$name must not be empty" >&2
		exit 2
	fi
	if [[ "$value" == *$'\n'* || "$value" == *$'\r'* || "$value" =~ [[:cntrl:]] ]]; then
		echo "$name must be a single-line Debian control field" >&2
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

debian_arch() {
	case "$1" in
	linux/amd64)
		printf 'amd64'
		;;
	linux/arm64)
		printf 'arm64'
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

normalize_tree_metadata() {
	local root=$1
	find "$root" -type d -exec chmod 0755 {} +
	find "$root" -type f -exec chmod 0644 {} +
	chmod 0755 "$root/usr/bin/tracejutsu"
	chmod 0755 "$root/DEBIAN/postinst" "$root/DEBIAN/postrm"
	if [[ -n "${SOURCE_DATE_EPOCH:-}" ]]; then
		find "$root" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
	fi
}

require_command date
require_command dpkg-deb
require_command find
require_command git
require_command go
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
debian_version="${version#v}"
build_date="$(build_date_utc)"

validate_release_label version "$version"
validate_release_label commit "$commit"
validate_release_label build_date "$build_date"
validate_debian_version "$debian_version"
validate_control_field maintainer "$maintainer"

target_os="${target%/*}"
target_arch="${target#*/}"
package_arch="$(debian_arch "$target")"
package_name="tracejutsu_${debian_version}_${package_arch}"

mkdir -p "$out_dir"
out_dir="$(cd "$out_dir" && pwd)"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
pkg_root="$tmp_dir/$package_name"

install -d \
	"$pkg_root/DEBIAN" \
	"$pkg_root/usr/bin" \
	"$pkg_root/lib/systemd/system" \
	"$pkg_root/usr/share/doc/tracejutsu"

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

env "${build_env[@]}" go build -trimpath -ldflags "$ldflags" -o "$pkg_root/usr/bin/tracejutsu" ./cmd/tracejutsu
chmod 0755 "$pkg_root/usr/bin/tracejutsu"
install -m 0644 packaging/systemd/tracejutsu.service "$pkg_root/lib/systemd/system/tracejutsu.service"
sed -i 's#/usr/local/bin/tracejutsu#/usr/bin/tracejutsu#g' "$pkg_root/lib/systemd/system/tracejutsu.service"
install -m 0644 README.md "$pkg_root/usr/share/doc/tracejutsu/README.md"
install -m 0644 docs/INSTALL.md "$pkg_root/usr/share/doc/tracejutsu/INSTALL.md"
install -m 0644 docs/OPERATIONS.md "$pkg_root/usr/share/doc/tracejutsu/OPERATIONS.md"

cat >"$pkg_root/DEBIAN/control" <<EOF
Package: tracejutsu
Version: $debian_version
Section: admin
Priority: optional
Architecture: $package_arch
Maintainer: $maintainer
Depends: libc6, systemd
Description: Local-first eBPF runtime security analyst
 Tracejutsu observes selected runtime events with eBPF, groups related
 activity into deterministic incidents, and stores local SQLite evidence for
 terminal inspection and optional local LLM analysis.
EOF

cat >"$pkg_root/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if command -v systemctl >/dev/null 2>&1; then
	systemctl daemon-reload || true
fi
exit 0
EOF
chmod 0755 "$pkg_root/DEBIAN/postinst"

cat >"$pkg_root/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
if command -v systemctl >/dev/null 2>&1; then
	systemctl daemon-reload || true
fi
exit 0
EOF
chmod 0755 "$pkg_root/DEBIAN/postrm"
normalize_tree_metadata "$pkg_root"

deb_path="$out_dir/$package_name.deb"
dpkg-deb --build --root-owner-group "$pkg_root" "$deb_path"
(
	cd "$out_dir"
	sha256sum "$package_name.deb" >"$package_name.deb.sha256"
)

echo
echo "Debian package:"
echo "$deb_path"
echo "$deb_path.sha256"
