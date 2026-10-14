#!/bin/sh
# Regenerates the sha256-pinned apk dependency closure for one architecture.
# Run from this directory for both runtime and build packages:
#
#   ./gen-lock.sh arm64
#   ./gen-lock.sh amd64
#   ./gen-lock.sh arm64 build
#   ./gen-lock.sh amd64 build
#
# The closure is resolved by apk inside the same base image the Dockerfile pins,
# and the repository release is read from that image, so the lock always matches
# what the build installs. apk reports each package's own repository URL, and
# the digest is computed from the signed .apk apk itself downloaded, so a line
# is "<sha256> <url>" with both halves coming from the resolver rather than a
# guess.
set -eu

case "${1:-}" in
arm64 | amd64) arch=$1 ;;
*)
	echo "usage: $0 arm64|amd64" >&2
	exit 2
	;;
esac

case "${2:-runtime}" in
runtime) manifest=packages.list; out="packages-$arch.lock" ;;
build) manifest=build-packages.list; out="build-packages-$arch.lock" ;;
*) echo "usage: $0 arm64|amd64 [runtime|build]" >&2; exit 2 ;;
esac

cd "$(dirname "$0")"
base=$(sed -n '1s/^FROM \([^ ]*\).*/\1/p' Dockerfile)
if [ -z "$base" ]; then
	echo "cannot read the base image from Dockerfile" >&2
	exit 1
fi

docker run --rm --platform "linux/$arch" \
	-v "$PWD:/mnt:ro" -e "MANIFEST=$manifest" --entrypoint /bin/sh "$base" -eu -c '
cdn="https://dl-cdn.alpinelinux.org/alpine/v$(cut -d. -f1,2 /etc/alpine-release)"
printf "%s\n%s\n" "$cdn/main" "$cdn/community" > /etc/apk/repositories
apk update --quiet
set -- $(sed -e "s/#.*//" "/mnt/$MANIFEST")
mkdir /fetch
apk fetch --recursive --quiet --output /fetch "$@"
apk fetch --recursive --simulate --url "$@" | while read -r url; do
	file="/fetch/${url##*/}"
	if [ ! -f "$file" ]; then
		echo "apk reported $url but did not download it" >&2
		exit 1
	fi
	printf "%s %s\n" "$(sha256sum "$file" | cut -d" " -f1)" "$url"
done
' >"$out.tmp"

if [ ! -s "$out.tmp" ]; then
	rm -f "$out.tmp"
	echo "generation produced no packages" >&2
	exit 1
fi
total=$(wc -l <"$out.tmp" | tr -d ' ')
distinct=$(awk '{n = split($2, part, "/"); print part[n]}' "$out.tmp" | sort -u | wc -l | tr -d ' ')
if [ "$total" != "$distinct" ]; then
	rm -f "$out.tmp"
	echo "generation produced duplicate packages" >&2
	exit 1
fi
sort -t/ -k8 "$out.tmp" >"$out"
rm -f "$out.tmp"
echo "$out: $(wc -l <"$out" | tr -d ' ') packages pinned"
