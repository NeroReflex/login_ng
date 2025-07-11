#!/bin/sh

set -e

new_version=${1}
version=$(grep -oP 'version\s*=\s*"\K[0-9]+\.[0-9]+\.[0-9]+' Cargo.toml | head -n 1)
echo "Replacing version $version with $new_version"
sed -i "s/\"$version\"/\"$new_version\"/g" Cargo.lock
cargo bitbake
git add .
git commit -m "Bump version to $new_version"
git tag $new_version