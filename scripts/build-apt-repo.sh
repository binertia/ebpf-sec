#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

usage() {
	cat <<'EOF'
Usage: scripts/build-apt-repo.sh --deb PATH [--deb PATH ...] [--out DIR] [--suite stable] [--component main] [--origin NAME] [--label NAME] [--codename NAME] [--description TEXT] [--sign] [--local-user KEY] [--allow-existing-out]

Builds a static Debian APT repository from one or more Tracejutsu .deb files.
The repository layout is suitable for publishing from static object storage or
a normal web server:

  pool/main/t/tracejutsu/*.deb
  dists/SUITE/COMPONENT/binary-ARCH/Packages
  dists/SUITE/COMPONENT/binary-ARCH/Packages.gz
  dists/SUITE/Release
  dists/SUITE/InRelease and Release.gpg, when --sign is supplied

The helper refuses a non-empty output directory unless --allow-existing-out is
supplied. It only generates repository metadata; validate installation from the
published repository on a fresh host before treating it as a release channel.
EOF
}

deb_inputs=()
out_dir="dist/apt-repo"
suite="stable"
component="main"
origin="Tracejutsu"
label="Tracejutsu"
codename=""
description="Tracejutsu release repository"
sign_repo=0
local_user=""
allow_existing_out=0

while [[ $# -gt 0 ]]; do
	case "$1" in
	--deb)
		if [[ $# -lt 2 ]]; then
			echo "--deb requires a value" >&2
			exit 2
		fi
		deb_inputs+=("$2")
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
	--suite)
		if [[ $# -lt 2 ]]; then
			echo "--suite requires a value" >&2
			exit 2
		fi
		suite=$2
		shift 2
		;;
	--component)
		if [[ $# -lt 2 ]]; then
			echo "--component requires a value" >&2
			exit 2
		fi
		component=$2
		shift 2
		;;
	--origin)
		if [[ $# -lt 2 ]]; then
			echo "--origin requires a value" >&2
			exit 2
		fi
		origin=$2
		shift 2
		;;
	--label)
		if [[ $# -lt 2 ]]; then
			echo "--label requires a value" >&2
			exit 2
		fi
		label=$2
		shift 2
		;;
	--codename)
		if [[ $# -lt 2 ]]; then
			echo "--codename requires a value" >&2
			exit 2
		fi
		codename=$2
		shift 2
		;;
	--description)
		if [[ $# -lt 2 ]]; then
			echo "--description requires a value" >&2
			exit 2
		fi
		description=$2
		shift 2
		;;
	--sign)
		sign_repo=1
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
	--allow-existing-out)
		allow_existing_out=1
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

validate_path_label() {
	local name=$1
	local value=$2
	if [[ ! "$value" =~ ^[A-Za-z0-9._+-]+$ ]]; then
		echo "$name contains unsupported characters: $value" >&2
		exit 2
	fi
}

validate_single_line() {
	local name=$1
	local value=$2
	if [[ "$value" == *$'\n'* || "$value" == *$'\r'* ]]; then
		echo "$name must be a single line" >&2
		exit 2
	fi
}

absolute_existing_file() {
	local input=$1
	if [[ ! -f "$input" ]]; then
		echo "file does not exist: $input" >&2
		exit 1
	fi
	(
		cd "$(dirname "$input")"
		printf '%s/%s\n' "$(pwd)" "$(basename "$input")"
	)
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

deb_field() {
	local deb=$1
	local field=$2
	local value
	value="$(dpkg-deb -f "$deb" "$field")" || {
		echo "failed to read Debian package field $field from $deb" >&2
		exit 1
	}
	if [[ -z "$value" ]]; then
		echo "Debian package field $field is empty in $deb" >&2
		exit 1
	fi
	printf '%s\n' "$value"
}

append_package_stanza() {
	local deb=$1
	local packages_file=$2
	local filename=$3
	local control
	control="$(dpkg-deb -f "$deb")"
	{
		printf '%s\n' "$control"
		printf 'Filename: %s\n' "$filename"
		printf 'Size: %s\n' "$(stat -c%s "$deb")"
		printf 'MD5sum: %s\n' "$(md5sum "$deb" | awk '{print $1}')"
		printf 'SHA1: %s\n' "$(sha1sum "$deb" | awk '{print $1}')"
		printf 'SHA256: %s\n' "$(sha256sum "$deb" | awk '{print $1}')"
		printf '\n'
	} >>"$packages_file"
}

write_release_sums() {
	local release_file=$1
	local algorithm=$2
	local command=$3
	local metadata
	mapfile -t metadata < <(
		cd "$dists_dir"
		find "$component" -type f \( -name Packages -o -name Packages.gz \) -print | LC_ALL=C sort
	)
	printf '%s:\n' "$algorithm" >>"$release_file"
	for path in "${metadata[@]}"; do
		printf ' %s %16s %s\n' "$($command "$dists_dir/$path" | awk '{print $1}')" "$(stat -c%s "$dists_dir/$path")" "$path" >>"$release_file"
	done
}

sign_release() {
	local release_file=$1
	local inrelease_file=$2
	local release_gpg_file=$3
	local gpg_args
	require_command gpg
	if [[ -z "${GPG_TTY:-}" && -t 0 ]]; then
		export GPG_TTY
		GPG_TTY="$(tty)"
	fi
	gpg_args=(--yes)
	if [[ -n "$local_user" ]]; then
		gpg_args+=(--local-user "$local_user")
	fi
	gpg "${gpg_args[@]}" --clearsign --output "$inrelease_file" "$release_file"
	gpg "${gpg_args[@]}" --armor --detach-sign --output "$release_gpg_file" "$release_file"
	chmod 0644 "$inrelease_file" "$release_gpg_file"
}

require_command awk
require_command cp
require_command date
require_command dpkg-deb
require_command find
require_command gzip
require_command grep
require_command md5sum
require_command mkdir
require_command mktemp
require_command paste
require_command sha1sum
require_command sha256sum
require_command sort
require_command stat

if [[ "${#deb_inputs[@]}" -eq 0 ]]; then
	echo "at least one --deb is required" >&2
	exit 2
fi
if [[ -z "$codename" ]]; then
	codename=$suite
fi

validate_path_label suite "$suite"
validate_path_label component "$component"
validate_path_label codename "$codename"
validate_single_line origin "$origin"
validate_single_line label "$label"
validate_single_line description "$description"

require_empty_or_allowed_out_dir "$out_dir"
mkdir -p "$out_dir"
out_dir="$(cd "$out_dir" && pwd)"

arch_tmp="$(mktemp)"
trap 'rm -f "$arch_tmp"' EXIT
declare -A initialized_packages=()

for input in "${deb_inputs[@]}"; do
	deb="$(absolute_existing_file "$input")"
	package_name="$(deb_field "$deb" Package)"
	arch="$(deb_field "$deb" Architecture)"
	if [[ "$package_name" != tracejutsu ]]; then
		echo "Debian package name is $package_name, expected tracejutsu" >&2
		exit 1
	fi
	if [[ ! "$arch" =~ ^[A-Za-z0-9._-]+$ ]]; then
		echo "Debian package architecture contains unsupported characters: $arch" >&2
		exit 1
	fi
	pool_dir="$out_dir/pool/main/t/tracejutsu"
	pool_file="$pool_dir/$(basename "$deb")"
	package_dir="$out_dir/dists/$suite/$component/binary-$arch"
	packages_file="$package_dir/Packages"
	mkdir -p "$pool_dir" "$package_dir"
	cp -f "$deb" "$pool_file"
	if [[ -z "${initialized_packages[$packages_file]+set}" ]]; then
		: >"$packages_file"
		initialized_packages[$packages_file]=1
	fi
	append_package_stanza "$pool_file" "$packages_file" "${pool_file#"$out_dir/"}"
	printf '%s\n' "$arch" >>"$arch_tmp"
done

while IFS= read -r packages_file; do
	gzip -n -c "$packages_file" >"$packages_file.gz"
	chmod 0644 "$packages_file" "$packages_file.gz"
done < <(find "$out_dir/dists/$suite/$component" -type f -name Packages -print | LC_ALL=C sort)

architectures="$(LC_ALL=C sort -u "$arch_tmp" | paste -sd' ' -)"
dists_dir="$out_dir/dists/$suite"
release_file="$dists_dir/Release"
{
	printf 'Origin: %s\n' "$origin"
	printf 'Label: %s\n' "$label"
	printf 'Suite: %s\n' "$suite"
	printf 'Codename: %s\n' "$codename"
	printf 'Date: %s\n' "$(date -Ru)"
	printf 'Architectures: %s\n' "$architectures"
	printf 'Components: %s\n' "$component"
	printf 'Description: %s\n' "$description"
} >"$release_file"
write_release_sums "$release_file" MD5Sum md5sum
write_release_sums "$release_file" SHA1 sha1sum
write_release_sums "$release_file" SHA256 sha256sum
chmod 0644 "$release_file"

if [[ "$sign_repo" -eq 1 ]]; then
	sign_release "$release_file" "$dists_dir/InRelease" "$dists_dir/Release.gpg"
fi

echo "APT repository:"
echo "$out_dir"
echo
find "$out_dir" -type f -print | LC_ALL=C sort
