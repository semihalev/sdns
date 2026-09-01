#!/usr/bin/env bash
# Fails when the site disagrees with the repository it documents.
#
# Every finding this catches was found by a human reading both, which is not a
# process that survives the review being forgotten. The project already applies
# this instinct elsewhere — `sdns -t` judges a config against the runtime, and
# contrib/linux/sdns.conf is regenerated from the code rather than edited — so
# this is the same idea pointed at the documentation.
#
# Run from the repository root: docs/check-drift.sh
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

fail=0
note() { printf '  %s\n' "$1"; fail=1; }

# ---------------------------------------------------------------- metrics
# The reference claims a count and lists rows; the code registers a set. All
# three have disagreed at once before: the prose said 60, the tables held 63,
# the code exported 64.
echo "metrics"
metrics_page=docs/_docs/reference/metrics.md
registered=$(grep -rhoE 'Name:[[:space:]]*"(dns|dns64|rpz|reflex|failure|nxdomain|aggressive|dnssec)_[a-z0-9_]+"' \
    --include='*.go' . | grep -v '_test.go' | sed 's/.*"\(.*\)"/\1/' | sort -u)
documented=$(grep -oE '^\| `[a-z][a-z0-9_]+` \|' "$metrics_page" | tr -d '|` ' | sort -u)

missing=$(comm -23 <(echo "$registered") <(echo "$documented"))
[ -n "$missing" ] && note "registered but not documented: $(echo "$missing" | tr '\n' ' ')"

invented=$(comm -13 <(echo "$registered") <(echo "$documented"))
[ -n "$invented" ] && note "documented but not registered: $(echo "$invented" | tr '\n' ' ')"

n_reg=$(echo "$registered" | grep -c .)
n_doc=$(echo "$documented" | grep -c .)
n_says=$(grep -oE 'exports [0-9]+ metrics' "$metrics_page" | grep -oE '[0-9]+')
[ "$n_reg" != "$n_doc" ] && note "table holds $n_doc rows, code registers $n_reg"
[ "$n_says" != "$n_reg" ] && note "prose says $n_says, code registers $n_reg"
for f in docs/_docs/deployment/monitoring.md docs/index.html; do
    other=$(grep -oE '(All )?[0-9]+ metrics' "$f" | grep -oE '^[0-9]+|[0-9]+' | head -1)
    [ -n "$other" ] && [ "$other" != "$n_reg" ] && note "$f says $other metrics, code registers $n_reg"
done
[ "$fail" -eq 0 ] && echo "  $n_reg registered, $n_doc documented, counts agree"

# ---------------------------------------------------------------- config keys
# The index calls itself complete. A key the parser accepts and the site never
# mentions is the difference between a reference and a rough guide.
echo "config keys"
before=$fail
# Both halves of the schema: fields with an explicit toml tag, and fields
# without one — the decoder matches those case-insensitively on the field
# name, so `api`, `directory` and `cookiesecret` are accepted keys that a
# tag-only scan reports as absent, which is a false green.
tagged=$(grep -oE '`toml:"[a-z_0-9]+"' config/config.go | sed 's/.*"\(.*\)"/\1/')
untagged=$(awk '/^type (Config|.*Config) struct/,/^}/' config/config.go \
    | grep -vE 'toml:|^\}|^type|^[[:space:]]*//|^[[:space:]]*$' \
    | awk '{print $1}' | grep -E '^[A-Z][A-Za-z0-9]*$' | tr 'A-Z' 'a-z')
keys=$(printf '%s\n%s\n' "$tagged" "$untagged" | sort -u | grep -v '^$')
undocumented=""
for k in $keys; do
    grep -rqF "$k" docs/_docs docs/index.html 2>/dev/null || undocumented="$undocumented $k"
done
[ -n "$undocumented" ] && note "accepted by the parser, absent from the site:$undocumented"
[ "$fail" -eq "$before" ] && echo "  $(echo "$keys" | grep -c .) keys, all present"

# ---------------------------------------------------------------- toolchain
# Two pages agreed with each other and disagreed with go.mod, sending readers
# to a build failure.
echo "go version"
before=$fail
want=$(grep -oE '^go [0-9]+\.[0-9]+' go.mod | awk '{print $2}')
while read -r line; do
    said=$(echo "$line" | grep -oE 'Go [0-9]+\.[0-9]+' | awk '{print $2}')
    [ "$said" = "$want" ] || note "$(echo "$line" | cut -d: -f1) says Go $said, go.mod requires $want"
done < <(grep -rn 'Go [0-9]\+\.[0-9]\+ or newer' docs/_docs || true)
[ "$fail" -eq "$before" ] && echo "  go.mod requires $want, pages agree"

# ---------------------------------------------------------------- install
# The README and the installation page ship side by side; a reader who follows
# one and then the other should not be given two different commands.
echo "install commands"
before=$fail
for cmd in 'yay -S' 'snap install' 'brew install'; do
    a=$(grep -hoE "$cmd [^ ]+" README.md | head -1)
    b=$(grep -hoE "$cmd [^ ]+" docs/_docs/getting-started/installation.md | head -1)
    [ -n "$a" ] && [ -n "$b" ] && [ "$a" != "$b" ] && note "README: '$a' vs installation page: '$b'"
done
[ "$fail" -eq "$before" ] && echo "  README and installation page agree"

# ---------------------------------------------------------------- versions
# The install commands name a release; the workflow resolves it at build time,
# so the checked-in fallback only has to be a plausible one. A hard-coded
# version anywhere else is a value nobody will remember to bump.
echo "pinned versions"
before=$fail
# README.md is excluded on purpose: it is plain markdown on GitHub with no
# templating, so it uses :latest and points at the site for the current tag.
hard=$(grep -rnE 'ghcr\.io/semihalev/sdns:[0-9]' docs/_docs docs/index.html 2>/dev/null || true)
[ -n "$hard" ] && note "hard-coded image tag (use site.sdns_version): $(echo "$hard" | cut -d: -f1-2 | tr '\n' ' ')"
[ "$fail" -eq "$before" ] && echo "  no hard-coded image tags"

echo
if [ "$fail" -ne 0 ]; then
    echo "site has drifted from the repository"
    exit 1
fi
echo "no drift"
