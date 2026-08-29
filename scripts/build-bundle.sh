#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"

cargo build --locked --offline --release

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

mkdir -p "$stage/config" "$stage/schemas" "$stage/templates"
cleanup() {
    if [ -d "$stage" ]; then
        rm -r "$stage"
    fi
}
trap cleanup EXIT HUP INT TERM

cp target/release/juno "$stage/juno"
cp LICENSE README.md "$stage/"
cp config/model-catalog.toml config/routing-defaults.toml config/compatibility.toml "$stage/config/"
cp schemas/evidence-packet.schema.json schemas/verifier-result.schema.json "$stage/schemas/"
cp -R templates/agents templates/instructions "$stage/templates/"

find "$stage" -type f ! -name SHA256SUMS -print0 \
    | sort -z \
    | xargs -0 shasum -a 256 \
    | sed "s#  $stage/#  #" > "$stage/SHA256SUMS"

mkdir -p dist
mv "$stage" "$destination"
trap - EXIT HUP INT TERM
echo "$destination"
