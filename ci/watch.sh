#!/usr/bin/env bash
# The watch: this Plugin against what Yoke last published. The newest programs are installed from the module
# proxy, the Plugin is built and taken into try/ by them as anyone's would be, packaged, installed as an
# instance with both of its secrets — no provider's client, and no account — run under a real Core, and asked
# its accounts. The answer is an empty list: the Plugin admitted, holding the secret it rewrites, and
# answering under the release.
# Usage: watch.sh [results directory]
#   YOKE_PROGRAMS=<dir> runs it with the programs there instead of the newest release's, for a build of Yoke
#   not published yet.
set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
results="${1:-$root/.results}"
mkdir -p "$results"
date -u +%Y-%m-%dT%H:%M:%SZ > "$results/started"
CASE=yoke-plugin-online-accounts:the-watch.01

finish() { # <verdict line>
  echo "$1" | tee "$results/checks.txt"
  date -u +%Y-%m-%dT%H:%M:%SZ > "$results/finished"
  [[ "$1" == pass* ]]
  exit $?
}

# Short, since the longest socket path of the instance is computed under it and bounded.
work="$(mktemp -d /tmp/w.XXX)"
trap 'yoke instance stop watch > /dev/null 2>&1; rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/r" "$work/state" "$work/config/yoke" "$work/out" "$work/apps"
chmod 2775 "$work/apps"
chmod 700 "$work/r"
export GOBIN="$work/bin" PATH="$work/bin:$PATH" XDG_RUNTIME_DIR="$work/r" XDG_STATE_HOME="$work/state" XDG_CONFIG_HOME="$work/config"
printf 'install_root: %s\n' "$work/apps" > "$work/config/yoke/manager.conf"

if [[ -n "${YOKE_PROGRAMS:-}" ]]; then
  release="the programs in $YOKE_PROGRAMS"
  export PATH="$YOKE_PROGRAMS:$PATH"
else
  release="$(go list -m -f '{{.Version}}' github.com/yoke-project/yoke@latest)" || finish "FAIL  $CASE — the newest release of yoke cannot be read"
  for program in yoke yoke-compose yoke-core yoke-guardian yoke-auth; do
    go install "github.com/yoke-project/yoke/cmd/$program@$release" || finish "FAIL  $CASE — $program $release does not install"
  done
fi
echo "watch: yoke $release"
echo "$release" > "$results/release"

cd "$root/try" || finish "FAIL  $CASE — no try/"
rm -f components/plugins/online-accounts manifests/com.yoke.online-accounts.yaml
said="$(yoke-compose update plugin com.yoke.online-accounts --yes 2>&1)" || finish "FAIL  $CASE — the Plugin is not taken under $release: $(tail -n 2 <<<"$said" | tr '\n' ' ')"
said="$(yoke-compose build --out "$work/out" 2>&1)" || finish "FAIL  $CASE — the application is not packaged under $release: $(tail -n 2 <<<"$said" | tr '\n' ' ')"
said="$(yoke app install "$work/out/"*.yoke 2>&1)" || finish "FAIL  $CASE — the package is not installed under $release: $(tail -n 2 <<<"$said" | tr '\n' ' ')"
yoke instance create com.yoke.online-accounts-try --name watch > /dev/null || finish "FAIL  $CASE — no instance is created under $release"
echo '{}' | yoke instance set-secret watch clients > /dev/null || finish "FAIL  $CASE — the secret clients is not set"
echo '{}' | yoke instance set-secret watch tokens > /dev/null || finish "FAIL  $CASE — the secret tokens is not set"
said="$(yoke instance start watch 2>&1)" || finish "FAIL  $CASE — the instance did not start under $release: $(tail -n 3 <<<"$said" | tr '\n' ' ')"
for _ in $(seq 1 30); do
  yoke core status --instance watch > /dev/null 2>&1 && break
  sleep 1
done

# std: yoke-plugin-online-accounts:the-watch.01
probe() { # says why on a failure
  yoke plugin grant com.yoke.online-accounts query.oauth.accounts.answer --instance watch > /dev/null || { echo "the grant was refused"; return 1; }
  yoke unit restart online-accounts --instance watch > /dev/null || { echo "the unit did not restart"; return 1; }
  sleep 3
  local said
  said="$(yoke unit ask online-accounts oauth.accounts --instance watch 2>&1)" || { echo "the question was refused: $said"; return 1; }
  grep -q '"accounts":\[\]' <<<"$said" || { echo "the answer is not an empty list of accounts: $said"; return 1; }
}

if probe > "$work/why"; then verdict="pass  $CASE"; else verdict="FAIL  $CASE — under $release: $(cat "$work/why")"; fi
finish "$verdict"
