#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
#
# The GitHub organization move (G0 M13 F8; docs/runbooks/org-move.md): one
# mechanical change that rewrites the Go module path and the repository's
# GitHub location across the tracked files.
#
#   tools/scripts/move-module-path.sh [--apply] [--keep-images] [--no-gen] OLD NEW
#   tools/scripts/move-module-path.sh github.com/katocxl/pantherclaw github.com/pantherclaw/pantherclaw
#
# Without --apply it is a dry run: it prints every file it would change and
# how many references each holds, and writes nothing. With --apply it
# rewrites, in every tracked text file:
#   1. the module path OLD (go.mod module and require/replace lines of every
#      Go module, imports, -X ldflags, buf go_package_prefix, sqlc go_type
#      imports, https://OLD links in docs, charts and pages);
#   2. raw.githubusercontent.com/<owner>/<repo> (install.sh links);
#   3. the bare repository slug <owner>/<repo> (gh --repo, install.sh REPO=);
#   4. `owner: <owner>` in .goreleaser.yaml (the release target);
#   5. ghcr.io/<owner>/ image names, unless --keep-images (a repository in an
#      organization cannot push to the old personal namespace; released
#      pclaw binaries keep the digests they embed);
# and then regenerates the protobuf code with buf (unless --no-gen), because
# the generated descriptors hold go_package as length-prefixed bytes that a
# text rewrite would corrupt (*.pb.go are therefore never rewritten as text).
#
# Never rewritten: go.sum and lock files (the main modules are not in them),
# untracked and ignored files, the person @<owner> (CODEOWNERS, profile
# links), and the historical records docs/g0/, docs/adr/ and docs/UPGRADES.md.
set -euo pipefail

apply=0 keep_images=0 gen=1
args=()
for a in "$@"; do
  case "$a" in
    --apply) apply=1 ;;
    --keep-images) keep_images=1 ;;
    --no-gen) gen=0 ;;
    -h|--help) sed -n '4,30p' "$0"; exit 0 ;;
    -*) echo "unknown flag: $a" >&2; exit 2 ;;
    *) args+=("$a") ;;
  esac
done
if [ "${#args[@]}" -ne 2 ]; then
  echo "usage: $0 [--apply] [--keep-images] [--no-gen] OLD NEW" >&2
  exit 2
fi
old=${args[0]} new=${args[1]}
pathre='^github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$'
for p in "$old" "$new"; do
  if ! printf '%s' "$p" | grep -Eq "$pathre"; then
    echo "not a github.com/<owner>/<repo> path: $p" >&2
    exit 2
  fi
done
[ "$old" != "$new" ] || { echo "OLD and NEW are the same" >&2; exit 2; }

old_slug=${old#github.com/} new_slug=${new#github.com/}
old_owner=${old_slug%%/*} new_owner=${new_slug%%/*}

root=$(git rev-parse --show-toplevel)
cd "$root"
if ! grep -Eq "^module ${old//./\\.}\$" go.mod; then
  echo "go.mod does not declare module $old" >&2
  exit 1
fi

# Escape for a sed -E pattern and replacement.
re() { printf '%s' "$1" | sed -e 's/[][\.*^$+?(){}|#/]/\\&/g'; }
rep() { printf '%s' "$1" | sed -e 's/[\&#]/\\&/g'; }
B='([^A-Za-z0-9_-]|$)' # right boundary: OLD/x and OLD" match, OLD-edge does not

sed_args=(
  -e "s#$(re "$old")$B#$(rep "$new")\\1#g"
  -e "s#raw\\.githubusercontent\\.com/$(re "$old_slug")$B#raw.githubusercontent.com/$(rep "$new_slug")\\1#g"
  -e "s#(^|[^A-Za-z0-9_./-])$(re "$old_slug")$B#\\1$(rep "$new_slug")\\2#g"
)
if [ "$keep_images" -eq 0 ] && [ "$old_owner" != "$new_owner" ]; then
  sed_args+=(-e "s#ghcr\\.io/$(re "$old_owner")/#ghcr.io/$(rep "$new_owner")/#g")
fi

# Candidate files: tracked text files that mention the old slug (or the old
# image namespace), minus the files this script never rewrites. Pathspecs keep
# the file list out of argv (Windows limits a native command line to 32 KiB).
img_pat=""
if [ "$keep_images" -eq 0 ] && [ "$old_owner" != "$new_owner" ]; then
  img_pat="ghcr.io/$old_owner/"
fi
spec=(-- . ':(exclude,glob)**/*.pb.go' ':(exclude,glob)**/go.sum'
  ':(exclude,glob)**/*.lock' ':(exclude,glob)**/pnpm-lock.yaml'
  ':(exclude,glob)**/package-lock.json' ':(exclude)docs/g0'
  ':(exclude)docs/adr' ':(exclude)docs/UPGRADES.md'
  ':(exclude)docs/runbooks/org-move.md' ':(exclude)tools/scripts/move-module-path.sh')

# The lines that reference the old location, per file (one git grep).
files=()
total=0 changed=0
while IFS= read -r line; do
  f=${line%:*} n=${line##*:}
  [ -f "$f" ] || continue
  files+=("$f")
  changed=$((changed + 1)) total=$((total + n))
  printf '%5d  %s\n' "$n" "$f"
done < <(git grep -cI -F -e "$old_slug" ${img_pat:+-e "$img_pat"} "${spec[@]}" || true)

if [ "$apply" -eq 1 ] && [ "${#files[@]}" -gt 0 ]; then
  # sed -i in batches; it keeps LF endings and the file mode.
  printf '%s\0' "${files[@]}" | xargs -0 -n 200 sed -i -E "${sed_args[@]}"
fi

# The GoReleaser release target (`release.github.owner`).
gr_re="^([[:space:]]*owner:[[:space:]]*)$(re "$old_owner")[[:space:]]*\$"
if [ "$old_owner" != "$new_owner" ] && grep -Eq "$gr_re" .goreleaser.yaml; then
  printf '%5d  %s (release owner)\n' "$(grep -Ec "$gr_re" .goreleaser.yaml)" .goreleaser.yaml
  if [ "$apply" -eq 1 ]; then
    sed -i -E "s#$gr_re#\1$(rep "$new_owner")#" .goreleaser.yaml
  fi
fi

echo "module path: $old -> $new (slug $old_slug -> $new_slug)"
if [ "${old_slug#*/}" != "${new_slug#*/}" ]; then
  echo "note: the repository name changes too; check release.github.name in .goreleaser.yaml"
fi
if [ "$keep_images" -eq 0 ] && [ "$old_owner" != "$new_owner" ]; then
  echo "images:      ghcr.io/$old_owner/ -> ghcr.io/$new_owner/"
else
  echo "images:      unchanged"
fi
echo "files: $changed, lines referencing the old location: $total"

if [ "$apply" -eq 0 ]; then
  echo "dry run: nothing written; rerun with --apply"
  exit 0
fi

if [ "$gen" -eq 1 ]; then
  echo "regenerating protobuf code (buf generate)"
  pins="$root/tools/pins"
  CGO_ENABLED=0 go tool -modfile="$pins/buf/go.mod" buf generate
  (cd proto/third_party/otlp && CGO_ENABLED=0 go tool -modfile="$pins/buf/go.mod" buf generate)
fi

left=$(git grep -lI -F "$old" -- '*.go' '*/go.mod' 'go.mod' ':!docs/g0' ':!docs/adr' || true)
if [ -n "$left" ]; then
  echo "the old module path is still referenced in:" >&2
  echo "$left" >&2
  exit 1
fi
echo "done: run task gen:check, task check and go build ./... next"
