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
# --exclude, not a `grep -v '_test.go'` downstream: -h has already stripped the
# filenames by then, so the filter could never match and test fixtures counted
# as registered metrics. Excluding at the source is the only place it works.
registered=$(grep -rhoE 'Name:[[:space:]]*"(dns|dns64|rpz|reflex|failure|nxdomain|aggressive|dnssec)_[a-z0-9_]+"' \
    --include='*.go' --exclude='*_test.go' . | sed 's/.*"\(.*\)"/\1/' | sort -u)
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
# The schema comes from the parser's own view of the root Config type rather
# than from a guess about which type names matter, and it carries the table
# path — rpz.enabled and ecs.enabled are different keys, and collapsing them
# meant deleting either row stayed green.
schema=$(go run ./docs/schemakeys 2>/dev/null | sort -u)

# The documented side is read the same way: a row's key is qualified by the
# section heading above it, so the comparison is path against path.
documented_keys=$(awk '
    /^## `?\[\[?[a-z0-9_.]+\]?\]`?/ {
        s = $0
        sub(/^## `?\[+/, "", s); sub(/\]+`?.*$/, "", s)
        prefix = s "."; next
    }
    /^### `?\[\[?[a-z0-9_.]+\]?\]`?/ {
        s = $0
        sub(/^### `?\[+/, "", s); sub(/\]+`?.*$/, "", s)
        prefix = s "."; next
    }
    /^## / { prefix = ""; next }
    /^\| `[a-z]/ {
        k = $0
        sub(/^\| `/, "", k); sub(/`.*$/, "", k)
        print prefix k
    }
' docs/_docs/reference/config-keys.md | sed 's/\.ttl\./.ttl./' | sort -u)

echo "config keys"
before=$fail
if [ -z "$schema" ]; then
    note "could not extract the config schema"
else
    # Both directions. A key the parser accepts and the index omits is a hole;
    # a key the index carries and the parser no longer knows is a leftover that
    # sends readers to a setting that does nothing.
    missing_keys=$(comm -23 <(echo "$schema") <(echo "$documented_keys"))
    stale_keys=$(comm -13 <(echo "$schema") <(echo "$documented_keys"))
    [ -n "$missing_keys" ] && note "accepted by the parser, absent from the key index: $(echo "$missing_keys" | tr '\n' ' ')"
    [ -n "$stale_keys" ] && note "in the key index, not accepted by the parser: $(echo "$stale_keys" | tr '\n' ' ')"
    [ "$fail" -eq "$before" ] && echo "  $(echo "$schema" | grep -c .) keys, index agrees in both directions"
fi

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
    # A missing side used to skip the comparison silently, so deleting a
    # command from either document passed.
    if [ -z "$a" ]; then note "'$cmd' missing from README.md"
    elif [ -z "$b" ]; then note "'$cmd' missing from the installation page"
    elif [ "$a" != "$b" ]; then note "README: '$a' vs installation page: '$b'"
    fi
done
[ "$fail" -eq "$before" ] && echo "  README and installation page agree"

# ---------------------------------------------------------------- platforms
# The installation page prints a matrix and calls it the list of pre-built
# binaries. That claim is only true while it tracks the release config: the
# page missed OpenBSD, NetBSD and the whole mips family for as long as nobody
# reread .goreleaser.yml next to it.
echo "release platforms"
before=$fail
release_os=$(awk '
    /^ *(targets|goos):/ { collect = 1; next }
    /^ *[a-z_]+:/         { collect = 0 }
    collect && /^ *- /    { t = $2; sub(/_.*$/, "", t); print t }
' .goreleaser.yml | sort -u)
release_arch=$(awk '
    /^ *(targets|goarch):/ { collect = 1; next }
    /^ *[a-z_]+:/          { collect = 0 }
    collect && /^ *- /     { t = $2; sub(/^[a-z]+_/, "", t); print t }
' .goreleaser.yml | sort -u)

install_page=docs/_docs/getting-started/installation.md
for os in $release_os; do
    # The page writes these the way a reader says them, not the way Go spells
    # them. Only darwin actually differs; the rest match case-insensitively.
    case "$os" in darwin) shown="macOS" ;; *) shown="$os" ;; esac
    grep -qi "| *$shown\b\|, *$shown\b\|$shown," "$install_page" \
        || note "goreleaser builds $os, the installation page does not list it"
done
for arch in $release_arch; do
    # goarm turns `arm` into armv5/6/7 in the artifact names, and that is how
    # the page writes it.
    case "$arch" in arm) shown="armv" ;; *) shown="$arch" ;; esac
    grep -q "$shown" "$install_page" \
        || note "goreleaser builds $arch, the installation page does not list it"
done
[ "$fail" -eq "$before" ] && echo "  installation page covers every released platform"

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
