#!/usr/bin/env bash
# =============================================================================
# publish-dashboard.sh — regenerate the gh-pages branch from dashboard/ on the
# CURRENT branch and force-push it, so publishing the dashboard is one command:
#
#   ./scripts/publish-dashboard.sh
#
# gh-pages is an ORPHAN branch containing only the dashboard files at its root
# (index.html, app.js, style.css, README.md, data/merged.json) — no harness
# code, no results/. Each publish is a fresh single commit (no history bloat);
# the commit message records which source commit it was generated from. GitHub
# Pages serves it at https://megonen.github.io/pqc-bench/ — the app's data
# fetch is RELATIVE ("data/merged.json"), which is what makes the subfolder
# Pages URL work; keep it that way.
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if ! git diff --quiet -- dashboard/; then
  echo "WARNING: dashboard/ has uncommitted changes — publishing the WORKING TREE state." >&2
fi
SRC_COMMIT="$(git rev-parse --short HEAD)"
SRC_BRANCH="$(git rev-parse --abbrev-ref HEAD)"

STAGE="$(mktemp -d)"
WT="$(mktemp -d)"
cleanup() {
  git worktree remove --force "$WT" 2>/dev/null || true
  rm -rf "$STAGE" "$WT"
}
trap cleanup EXIT

# stage exactly the dashboard files (never .DS_Store etc.)
cp -R dashboard/. "$STAGE"/
find "$STAGE" -name '.DS_Store' -delete
touch "$STAGE/.nojekyll"   # serve files verbatim; no Jekyll processing

# build the orphan branch in a temporary worktree (main tree untouched)
git branch -D gh-pages 2>/dev/null || true
git worktree add --no-checkout --detach "$WT" >/dev/null
git -C "$WT" checkout --orphan gh-pages
git -C "$WT" rm -rf --cached -q . 2>/dev/null || true
cp -R "$STAGE"/. "$WT"/
git -C "$WT" add -A
git -C "$WT" -c user.name=megonen -c user.email=megonen@users.noreply.github.com \
  commit -q -m "publish dashboard from $SRC_BRANCH @ $SRC_COMMIT"
git -C "$WT" push -f origin gh-pages
echo "published gh-pages from $SRC_BRANCH @ $SRC_COMMIT"
echo "URL: https://megonen.github.io/pqc-bench/ (allow ~1 min for Pages deploy)"
