# Issue tracker: GitHub

Issues and specs for this repo live as GitHub issues. Use the `gh` CLI for all operations.

## Conventions

> Shell: every command below targets a bash/POSIX shell. Windows PowerShell strips embedded double quotes when passing arguments to native commands, which breaks the `--jq` expressions carrying string literals (e.g. `.state=="OPEN"`); run those through `bash -lc '...'` (or WSL) instead.

- **Canonical repo**: `XinFinOrg/XDPoSChain`. Every `gh issue`/`gh pr` command below pins it with `-R XinFinOrg/XDPoSChain`, so a clone whose `gh` resolves to a fork cannot act on the wrong tracker. `gh api` has no `-R`: pin it either by spelling the endpoint out (`repos/XinFinOrg/XDPoSChain/...`) or by setting `GH_REPO=XinFinOrg/XDPoSChain`, because its `{owner}`/`{repo}` placeholders are otherwise resolved from the current directory's repository.
- **Create an issue**: `gh issue create -R XinFinOrg/XDPoSChain --title "..." --body "..."`. Use a heredoc for multi-line bodies.
- **Read an issue**: `gh issue view -R XinFinOrg/XDPoSChain <number>` for the human-readable view. The same command with `--comments` prints the comment thread alone, not the issue — on a ticket with no comments it prints nothing — so run it as a second step when the discussion matters. For structured data use `--json`, adding the `comments` field when you need them: `gh issue view -R XinFinOrg/XDPoSChain <number> --json title,body,labels,comments --jq '{title, body, labels: [.labels[].name], comments: [.comments[].body]}'`.
- **Make an issue a sub-issue of a parent**: `gh issue create -R XinFinOrg/XDPoSChain --parent <parent> ...`, or `gh issue edit -R XinFinOrg/XDPoSChain <parent> --add-sub-issue <child>` afterwards (newer `gh`). Older `gh`: `gh api --method POST repos/XinFinOrg/XDPoSChain/issues/<parent>/sub_issues -F sub_issue_id=<child-db-id>` (database id, as in **Blocking** below). Without sub-issues, put `Part of #<parent>` at the top of the child body.
- **List issues**: `gh issue list -R XinFinOrg/XDPoSChain --state open --limit 200 --json number,title,body,labels,comments --jq '[.[] | {number, title, body, labels: [.labels[].name], comments: [.comments[].body]}]'` with appropriate `--label` and `--state` filters. Pass `--limit` explicitly: `gh` fetches 30 per call by default and truncates silently, and `--limit 0` is rejected; keep the number above the open-issue count as the tracker grows, and if the returned count equals the limit, raise the limit and re-run — truncation is silent.
- **Comment on an issue**: `gh issue comment -R XinFinOrg/XDPoSChain <number> --body "..."`
- **Apply / remove labels**: `gh issue edit -R XinFinOrg/XDPoSChain <number> --add-label "..."` / `--remove-label "..."`
- **Close**: `gh issue close -R XinFinOrg/XDPoSChain <number> --comment "..."`

## Pull requests as a triage surface

**PRs as a request surface: no.** _(Set to `yes` if this repo treats external PRs as feature requests; `/triage` reads this flag.)_

When set to `yes`, PRs run through the same labels and states as issues, using the `gh pr` equivalents:

- **Read a PR**: `gh pr view -R XinFinOrg/XDPoSChain <number>` (add `--comments` for the conversation comments alone — it prints neither the PR nor the inline code-review comments, and on a PR with no comments it prints nothing) and `gh pr diff -R XinFinOrg/XDPoSChain <number>` for the diff. Inline review comments (the "Files changed" threads) are a separate API surface: `gh api --paginate 'repos/XinFinOrg/XDPoSChain/pulls/<number>/comments' --jq '.[] | {path, line, user: .user.login, in_reply_to, body}'` — run it when the complete discussion matters, since neither command above returns it.
- **List external PRs for triage**: `gh api --paginate 'repos/XinFinOrg/XDPoSChain/pulls?state=open' --jq '.[] | select(.author_association | IN("OWNER","MEMBER","COLLABORATOR") | not) | {number, title, author: .user.login, author_association, labels: [.labels[].name]}'`.
- **Comment / label / close**: `gh pr comment -R XinFinOrg/XDPoSChain`, `gh pr edit -R XinFinOrg/XDPoSChain --add-label`/`--remove-label`, `gh pr close -R XinFinOrg/XDPoSChain`.

GitHub shares one number space across issues and PRs, so a bare `#42` may be either: resolve with `gh pr view -R XinFinOrg/XDPoSChain 42` and fall back to `gh issue view -R XinFinOrg/XDPoSChain 42`.

## When a skill says "publish to the issue tracker"

Create a GitHub issue.

## When a skill says "fetch the relevant ticket"

Run `gh issue view -R XinFinOrg/XDPoSChain <number>` (append `--comments` when the comment thread is also needed).

## Wayfinding operations

Used by `/wayfinder`. The **map** is a single issue with **child** issues as tickets.

- **Map**: a single issue labelled `wayfinder:map`, holding the Notes / Decisions-so-far / Fog body. `gh issue create -R XinFinOrg/XDPoSChain --label wayfinder:map`.
- **Child ticket**: an issue linked to the map as a GitHub sub-issue (see **Make an issue a sub-issue of a parent**). Where sub-issues aren't enabled, add the child to a task list in the map body and put `Part of #<map>` at the top of the child body. Labels: `wayfinder:<type>` (`research`/`prototype`/`grilling`/`task`). Once claimed, the ticket is assigned to the driving dev.
- **Blocking**: GitHub's **native issue dependencies**, the canonical, UI-visible representation. Add an edge with `gh api --method POST repos/XinFinOrg/XDPoSChain/issues/<child>/dependencies/blocked_by -F issue_id=<blocker-db-id>`, where `<blocker-db-id>` is the blocker's numeric **database id** (`gh api repos/XinFinOrg/XDPoSChain/issues/<n> --jq .id`, _not_ the `#number` or `node_id`). GitHub reports `issue_dependencies_summary.blocked_by` (open blockers only, the live gate). Where dependencies aren't available, fall back to a `Blocked by: #<n>, #<n>` line at the top of the child body. A ticket is unblocked when every blocker is closed.
- **Frontier query**: list the map's open children from the map itself: `gh api graphql -f query='query($owner:String!,$name:String!,$map:Int!,$cursor:String){repository(owner:$owner,name:$name){issue(number:$map){subIssues(first:100,after:$cursor){pageInfo{hasNextPage endCursor} nodes{number state title assignees(first:1){nodes{login}} issueDependenciesSummary{blockedBy}}}}}}' -f owner=XinFinOrg -f name=XDPoSChain -F map=<map> --jq '{frontier: [.data.repository.issue.subIssues.nodes[] | select(.state=="OPEN" and (.assignees.nodes|length)==0 and .issueDependenciesSummary.blockedBy==0) | .number], hasNextPage: .data.repository.issue.subIssues.pageInfo.hasNextPage, endCursor: .data.repository.issue.subIssues.pageInfo.endCursor}'`. The output carries the page's `frontier` (the open, unassigned, unblocked child numbers) together with `hasNextPage` and `endCursor` — keep `pageInfo` inside the `--jq`: with a numbers-only `--jq`, an empty page is indistinguishable from an empty frontier and the cursor for the next page is unavailable. `$cursor` defaults to null on the first page; while `hasNextPage` is true, re-run the same command with an extra `-f cursor=<endCursor>` and stop once it prints false. Where sub-issues aren't enabled, walk the map body's ticket list in order and take the first entry that is open, unassigned and unblocked: `gh issue view -R XinFinOrg/XDPoSChain <map> --json body --jq '.body' | grep -oE '^[[:space:]]*-[[:space:]]*\[[ xX]\][[:space:]]+(#|\[[^]]+\]\([^)]*XinFinOrg/XDPoSChain/issues/)[0-9]+' | grep -oE '[0-9]+$' | awk '!seen[$0]++'` lists the task-list tickets in map order (the pattern accepts both `- [ ] #<n>` and a task-list link to this repo's `/issues/<n>`; the pipeline needs a POSIX shell for `grep`/`awk`); run `gh issue view -R XinFinOrg/XDPoSChain <n> --json number,state,assignees,body,blockedBy --jq 'select(.state=="OPEN" and (.assignees|length)==0 and ([.blockedBy.nodes[] | select(.state=="OPEN")] | length)==0) | .number'` on each `<n>` in that order and take the first that prints a number. Drop any with an open blocker or an assignee; first in map order wins. (The GraphQL query above already applies both filters; where dependencies aren't available, read the same `body` and treat an open issue named in the `Blocked by` line as a blocker, resolving the numbers it lists with `gh issue view -R XinFinOrg/XDPoSChain <n> --json state`.)
- **Claim**: `gh issue edit -R XinFinOrg/XDPoSChain <n> --add-assignee @me`, the session's first write.
- **Resolve**: `gh issue comment -R XinFinOrg/XDPoSChain <n> --body "<answer>"`, then `gh issue close -R XinFinOrg/XDPoSChain <n>`, then append a context pointer (gist + link) to the map's Decisions-so-far.
