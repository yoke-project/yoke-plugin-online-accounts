#!/usr/bin/env bash
# Runs the application as an installed instance in a world of its own under try/.world — an install root, an
# instance's state, the two secrets — grants the Plugin what its Manifest declares, and follows the unit from
# the channel `panel`: every question's answer, the stream and every event, one line each. The world is kept
# between runs, so an account signed in stays signed in. An interrupt stops the instance.
#
# Usage: run.sh --clients <file> [--seconds N]
#   --clients <file>   the deployment's clients, JSON by provider; given once, then kept in the world
#   --fresh            forgets the world first: its instance, its accounts and its clients
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
plugin=com.yoke.online-accounts unit=online-accounts app=com.yoke.online-accounts-try instance=oa
manifest="$here/../plugin/$plugin.yaml"
clients="" follow_args=()
while (( $# )); do
  case "$1" in
    --clients) clients="$2"; shift ;;
    --fresh) rm -rf "$here/.world" ;;
    --seconds) follow_args+=(--seconds "$2"); shift ;;
    *) echo "run.sh: unknown argument $1" >&2; exit 2 ;;
  esac
  shift
done

# A world of its own, kept here; its sockets go under a short directory, since the longest socket path of the
# instance is computed under it and bounded.
world="$here/.world" runtime="/tmp/oa-$(id -u)"
mkdir -p "$runtime" "$world/state" "$world/config/yoke" "$world/out" "$world/apps"
chmod 2775 "$world/apps"
chmod 700 "$runtime"
export XDG_RUNTIME_DIR="$runtime" XDG_STATE_HOME="$world/state" XDG_CONFIG_HOME="$world/config"
printf 'install_root: %s\n' "$world/apps" > "$world/config/yoke/manager.conf"

# The Plugin as the application carries it, built from ../plugin whenever it changed, and the package made.
cargo build --release --quiet --manifest-path "$here/../plugin/Cargo.toml"
if ! cmp -s "$here/../plugin/target/release/$unit" "$here/components/plugins/$unit"; then
  cp "$here/../plugin/target/release/$unit" "$here/components/plugins/$unit"
  cp "$manifest" "$here/manifests/"
fi
# The package is made from a copy in the world, so the digest and the version written into it leave
# try/yoke.yaml as it is written.
project="$world/project"
rm -rf "$project" && mkdir -p "$project"
cp -r "$here/yoke.yaml" "$here/plugins.yaml" "$here/components" "$here/manifests" "$project/"
yoke-compose set "units.$unit.digest" "sha256:$(sha256sum "$project/components/plugins/$unit" | cut -d' ' -f1)" --dir "$project" > /dev/null
# An installed version is never replaced: a package that changed is installed under a version of its own,
# named by what it carries, and the instance is moved to it. Without this a changed yoke.yaml or a rebuilt
# Plugin would never reach an instance that already exists.
written="$(sed -n 's/^version: //p' "$project/yoke.yaml")"
version="$written-try-$(cat "$project/yoke.yaml" "$project/plugins.yaml" "$project/manifests/"* | sha256sum | cut -c1-12)"
yoke-compose set version "$version" --dir "$project" > /dev/null
cargo build --release --quiet --manifest-path "$here/follow/Cargo.toml"
rm -f "$world/out/"*.yoke
yoke-compose build --dir "$project" --out "$world/out" > /dev/null
yoke instance stop "$instance" > /dev/null 2>&1 || true
yoke app install "$world/out/"*.yoke > /dev/null
if shown="$(yoke instance show "$instance" 2>/dev/null)"; then
  was="$(sed -n 's/^version: //p' <<<"$shown")"
  if [[ "$was" != "$version" ]]; then
    yoke instance set-version "$instance" "$version" > /dev/null
    # A pre-release is never pruned: the version the instance leaves is removed by name.
    yoke app remove "$app" --version "$was" > /dev/null
  fi
else
  yoke instance create "$app" --name "$instance" --version "$version" > /dev/null
  # No account yet: the secret the unit rewrites starts as an empty record.
  echo '{}' | yoke instance set-secret "$instance" tokens > /dev/null
fi
if [[ -n "$clients" ]]; then
  yoke instance set-secret "$instance" clients < "$clients" > /dev/null
fi
shown="$(yoke instance show "$instance")"
grep -q 'clients present' <<<"$shown" || { echo "run.sh: give the clients once, with --clients <file>" >&2; exit 2; }

yoke instance start "$instance" > /dev/null
trap 'yoke instance stop "$instance" > /dev/null 2>&1' EXIT
until yoke core status --instance "$instance" > /dev/null 2>&1; do sleep 0.3; done
# An instance starts with nothing granted; a grant reaches the unit at its next admission.
for capability in $(sed -n 's/^  - name: //p' "$manifest"); do
  yoke plugin grant "$plugin" "$capability" --instance "$instance" > /dev/null
done
yoke unit restart "$unit" --instance "$instance" > /dev/null
sleep 1
section() { awk -v s="$1:" '$0 == s {on=1; next} /^[a-z]/ {on=0} on && /^  - id: / {print $3}' "$manifest"; }
follow_args+=(--ask oauth.accounts)
for s in $(section streams); do follow_args+=(--stream "$s"); done
echo "run.sh: $instance runs; sign in with: XDG_RUNTIME_DIR=$XDG_RUNTIME_DIR XDG_STATE_HOME=$XDG_STATE_HOME XDG_CONFIG_HOME=$XDG_CONFIG_HOME yoke unit command $unit oauth.login --input - --instance $instance <<< '{\"provider\":\"microsoft\"}'" >&2
"$here/follow/target/release/follow" --instance "$instance" --channel panel --unit "$unit" "${follow_args[@]}"
