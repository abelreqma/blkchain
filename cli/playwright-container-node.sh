#!/bin/sh
set -eu

: "${BLKCHAIN_PLAYWRIGHT_CONTAINER:?set BLKCHAIN_PLAYWRIGHT_CONTAINER}"

if [ "$#" -lt 1 ]; then
	exit 64
fi

shift
exec "${BLKCHAIN_DOCKER_BIN:-docker}" exec --user 1000:1000 -i \
	"$BLKCHAIN_PLAYWRIGHT_CONTAINER" node \
	/opt/blkchain-playwright/package/cli.js "$@"
