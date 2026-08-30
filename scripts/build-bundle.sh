#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"

if [ "$#" -ne 2 ]; then
    echo "usage: $0 FROZEN_BINARY RELEASE_EVIDENCE" >&2
    exit 2
fi

binary=$1
evidence=$2
case "$binary:$evidence" in
    /*:/*) ;;
    *)
        echo "bundle inputs must use absolute paths" >&2
        exit 2
        ;;
esac

cargo run --locked --offline --quiet --example release-gates -- \
    validate-release --binary "$binary" --evidence "$evidence"

version=$(sed -n 's/^version = "\([^"]*\)"$/\1/p' Cargo.toml | head -1)
case "$version" in
    "")
        echo "could not read package version" >&2
        exit 1
        ;;
esac

bundle_name="juno-$version-macos-arm64"
stage="dist/.stage-$bundle_name-$$"
destination="dist/$bundle_name"

if [ -e "$destination" ]; then
    echo "bundle already exists: $destination" >&2
    exit 1
fi

mkdir -p "$stage/config" "$stage/schemas" "$stage/scripts" "$stage/templates"
cleanup() {
    if [ -d "$stage" ]; then
        rm -r "$stage"
    fi
}
trap cleanup EXIT HUP INT TERM

cp "$binary" "$stage/juno"
cp "$evidence" "$stage/release-evidence.json"
cp LICENSE README.md "$stage/"
cp config/model-catalog.toml config/routing-defaults.toml config/compatibility.toml "$stage/config/"
cp schemas/*.json "$stage/schemas/"
cp scripts/desktop-certification.applescript "$stage/scripts/"
cp -R templates/agents templates/instructions "$stage/templates/"
chmod 755 "$stage/juno"
chmod 644 "$stage/release-evidence.json"

find "$stage" -type f ! -name SHA256SUMS -print0 \
    | sort -z \
    | xargs -0 shasum -a 256 \
    | sed "s#  $stage/#  #" > "$stage/SHA256SUMS"

mkdir -p dist
mv "$stage" "$destination"
trap - EXIT HUP INT TERM
echo "$destination"
