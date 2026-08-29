#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"

exec cargo run --locked --offline --quiet --example release-gates -- "$@"
