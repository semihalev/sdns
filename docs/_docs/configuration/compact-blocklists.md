---
layout: doc
title: Compact blocklists
category: Configuration
order: 6
description: Use a persistent, disk-backed index for large blocklists on Linux and Darwin.
---

Compact mode keeps feed and local-file rules in memory-mapped files rather than
a Go map. It is intended for large lists on routers and single-board computers
with limited RAM and flash write endurance. Keep the default map for small
lists or if you do not want to manage a persistent index. Configured entries
and the whitelist stay in memory. API edits are journaled and folded into the
disk-backed store; edits not yet folded are also kept in memory.

```toml
blocklist_compact = true
# blocklist_compact_dir = "/var/lib/sdns/blocklist-compact"
# blocklist_refresh_interval = "24h"
# blocklist_checkpoint_window = "24h"
```

## Settings and storage

| Key | Default | Meaning |
|---|---|---|
| `blocklist_compact` | `false` | Enables compact storage. Supported on Linux and Darwin; enabling it on other platforms stops startup. |
| `blocklist_compact_dir` | `""` | Empty or omitted uses `<directory>/blocklist-compact`. |
| `blocklist_refresh_interval` | `"0s"` | `"0s"` limits refresh to startup. A positive value waits this long between passes. There is no periodic pass without remote URLs. |
| `blocklist_checkpoint_window` | `"24h"` when enabled | Time before capturing uncheckpointed policy. Explicit `"0s"` makes it eligible for capture immediately; disk I/O still runs in the background. |

Both durations must be nonnegative, and positive values require compact mode.
Restart to change any of these four settings or the feed URLs.

Use a writable directory on persistent storage such as flash, not tmpfs.
Keep it separate from `blocklistdir`: neither directory may contain the other.
`sdns -t` checks directory overlap by filesystem identity, including aliases of
existing directories. Startup checks again after creating the state directory,
before creating the lock or policy files.
Only one sdns process may use the directory; it holds an exclusive lock.
Allow disk space for the active policy, the last durable checkpoint, a
replacement and temporary sort or diff files. Incompatible or invalid
checkpoints stop startup rather than being overwritten. Use a fresh directory
if the format or the set of feed URLs changes; keep the previous directory if
you need to go back.

## Feed and local updates

Up to 61 distinct remote feeds can own rules. Regular files under
`blocklistdir` count as one local owner. Compact mode follows symlinks
to regular files and a symlink used as `blocklistdir` itself. It does not
descend into symlinked subdirectories and skips FIFOs and other non-regular
files, including symlinks to those files. A dangling link anywhere in the tree
or a root that is not a directory fails the scan rather than removing the
current local rules. A rule in more than one source stays in the index until
its last owner drops it.
Old copies saved by the map backend count as local rules too. Check for them
before switching, or they can keep blocking entries that the remote feed has
removed.

The first install needs every configured feed. On later starts sdns opens the
checkpoint without downloading feeds first, checks for local changes, and
refreshes cached feeds in the background. A feed fetched during first install
is skipped on that first background pass. Later passes also check local files.
A `304 Not Modified` response reuses existing rules; a downloaded feed with the
same parsed rules leaves the policy files alone, though HTTP validators may
still be checkpointed. An ordinary change writes a segment and folds part of
the index rather than rewriting the entire base. Larger pending changes can
cause more of the base to be folded. A failed pass does not publish a partial
replacement.

The [blocking rules]({{ '/docs/configuration/access-control/' | relative_url }}#blocking-names)
still apply. Configured rules and manual API edits are separate from the feed
and local index. `SIGHUP` adds newly configured `blocklist` entries and replaces
the whitelist. Removing an entry from the configuration does not unblock it;
remove it through the API. An API removal suppresses the exact stored rule,
not a surviving parent rule or independently stored child rules.

## Resource checks

On Linux, memory checks use `MemAvailable` or the tightest remaining memory
under applicable cgroup v2 limits, including ancestors visible through the
cgroup mount, whichever is smaller.
If the cgroup mount is absent or is not v2, only `MemAvailable` applies.
The checks estimate memory to prepare the update and reopen it later. They do
not cap the process or account for future changes in available RAM. Mapped
pages still use RAM when resident. If a delta is too large or does not fit in
memory, sdns can try a streaming rebuild, which can fetch changed feeds again.
If the replacement cannot be admitted, the existing policy stays active. If the
checkpoint itself cannot be opened at startup, sdns does not fall back to an
empty list.
On macOS, no system RAM probe or admission gate runs; the workspace budget is
capped at 1 GiB. Filesystem space checks still apply.

Before staging a candidate, sdns budgets its writes against usable free space
on the compact filesystem, leaving the greater of 32 MiB or 10% of filesystem
capacity free, plus room for a checkpoint. The checkpoint rechecks available
space before writing. On Linux the data barrier uses `syncfs`, which can flush
unrelated dirty data on the same filesystem. Darwin syncs the new files
individually.

## Checkpoints and recovery

First install waits for a durable checkpoint before serving. Later changes
can serve before they are checkpointed. The first uncheckpointed manifest
change, including a metadata-only change, starts the window. Later changes
do not extend its deadline. The window is not a guarantee that the checkpoint
will finish by then. A recoverable write
failure leaves the previous checkpoint in place and is retried. An uncertain
manifest replacement stops policy writes until restart.

Offline restart verifies the checkpoint's files and rolling key count before
serving. An interruption during publication may leave the previous or the new
complete policy; changes that only went live can be lost. An interrupted
first install with no checkpoint still needs its inputs. Acknowledged API edits
are synced to a journal. Refresh or checkpoint completion, or a growing
pending batch, requests a background fold. Startup replays only unfolded edits,
truncates an unterminated final record, and rejects malformed complete records.
Shutdown does not flush pending feed revisions.

## Switching backends

To enable compact mode, provision the directory, review the local lists, set
`blocklist_compact = true`, and restart. Look for `Compact blocklist policy ready`
and check known blocked, allowed and whitelisted names. Watch for refresh
failures and rebuilds. Checkpoint completion and failure logs include
`active_policy_age` and
`last_durable_policy_age`; an increasing gap can mean changes are serving but
not yet durable.

To switch back, reconcile manual API additions and removals with the map
backend's inputs first; it does not import them from compact storage. Set
`blocklist_compact = false`, remove any positive compact durations, and restart.
The compact directory stays on disk.
