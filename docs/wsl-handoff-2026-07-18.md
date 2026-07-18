# WSL continuation handoff — 2026-07-18

## Scope

The user stopped new feature development and requested a final commit/push plus
a non-destructive handoff to `~/dirextalk`. This document records the finished
work, verified evidence, preserved state, and the only approved next-work
sequence. It does not authorize deployment, cloud changes, or resuming an
incomplete implementation.

## Finished work

| Repository | Branch / commit | Handoff state |
| --- | --- | --- |
| `dirextalk-agent` | implementation baseline `71c3cab` plus this handoff document | Clean locally; no Git remote is configured. |
| `dirextalk-message-server` | `adam/0714` at `4ae3a37` | Pushed. Current `main` merge retains the Agent façade. |
| `dirextalk-flutter` | `adam/0714` at `944c17b` | Pushed. Adds the signed cloud-Plan review entry point. |
| `dirextalk-deployer` | `deployer/agent-image` at `956ddf4` | Pushed. Repairs Lightsail agent probe/catalog delivery. |
| `dirextalk-connect` | `codex/remote-mcp-contract-20260710` at `f7ecb2d` | Pushed. |
| `dirextalk-connect` | `release/approval-expiry-20260718` at `39834a7` | Pushed candidate with owner-bound, expiring approval cards. |

The Agent repository has no configured remote, so its handoff is by local Git
clone/copy. Do not add an assumed remote or create a tag without the canonical
repository, visibility, and immutable-release policy being confirmed.

## Verification accepted at this boundary

- Agent: focused Go tests and `go vet` recorded in the preceding P2 checkpoint
  passed; no Agent source changed between that checkpoint and this handoff.
- Message Server: focused Agent façade tests, release contract test,
  `go build ./cmd/dirextalk-message-server`, and `git diff --check` passed.
- Flutter: focused Agent/approval/cloud tests, targeted analysis, and
  `git diff --check` passed; the Plan-review change at `944c17b` passed its
  focused widget and approval tests.
- Connect candidate: focused approval/expiry/delivery/stop tests, race
  coverage, `go test ./platform/matrix -count=1`, and diff checks passed.
- Deployer: targeted Git Bash S5 tests and syntax checks passed. Broad npm and
  WSL checks are intentionally not marked green because a WSL child process
  hung; it was stopped without changing WSL state.

## Safety and preserved local state

- The temporary eu-west-2 `z3.dirextalk.ai` deployment was destroyed. Temporary
  ECR/Lightsail/Route53 resources and Docker Hub test tags were removed. Do not
  redeploy or recreate cloud resources in a continuation session without a new
  explicit deployment stage.
- Never store, copy, commit, or reuse the model credential supplied in chat.
  Rotate it before any later testing. A future runtime setup must use an
  operator-provisioned mounted secret and immutable Agent catalog entry.
- `dirextalk-agent/.worktrees/p2-zero-residue-release` is intentionally
  untouched on `codex/p2-zero-residue-release` at `71c3cab`; its only change is
  the untracked incomplete `internal/releaselifecycle/` directory. It is not
  reviewed, committed, merged, or deleted.
- Existing user artifacts and worktrees are preserved: Message Server
  `.release-attestations/` and executable, Flutter/Connect worktrees, and dirty
  WSL repositories must not be overwritten.

## Next work, in order (not started here)

1. **P3-R0: reproducible remote Agent build.** Confirm the canonical Agent Git
   remote, visibility, and immutable prerelease/tag policy; publish/tag the
   exact Agent module; pin Message Server to it; remove `replace
   ../dirextalk-agent`; prove an isolated Message Server build.
2. **P3-R1: Agent-owned runtime profiles.** Add a Message Server owner-only
   façade over Agent runtime config and server-side mounted secrets. Flutter
   continues to talk only to Message Server and never sends model API keys on
   the remote path.
3. **P2 release evidence.** Under a separately authorized release stage,
   perform the real digest-pinned Agent/Worker/reaper artifact publication plus
   Worker AMI build, verification, and destruction.

## WSL operating rule

Use `~/dirextalk` as the workspace. Bring clean repositories to the commits
listed above. If an existing WSL repository has local edits, keep it untouched
and use a separate handoff checkout for the corresponding pushed branch. Keep
this document copied to `~/dirextalk/WSL-CONTINUATION.md` for the next Codex
session.

## Completed WSL migration

The migration was completed without overwriting any pre-existing WSL work:

- `~/dirextalk/dirextalk-agent` is a clean local clone on
  `agent/docker-image` at this handoff commit; it intentionally has no assumed
  remote.
- `~/dirextalk/dirextalk-message-server` is clean on `adam/0714` at
  `4ae3a37`, and `~/dirextalk/dirextalk-flutter` is clean on `adam/0714` at
  `944c17b`.
- The original WSL deployer and Connect worktrees remain untouched on `main`
  with their pre-existing local edits. Their target, clean handoff clones are
  respectively at
  `~/dirextalk/.handoff/final-20260718/dirextalk-deployer` on
  `deployer/agent-image` (`956ddf4`) and
  `~/dirextalk/.handoff/final-20260718/dirextalk-connect` on
  `release/approval-expiry-20260718` (`39834a7`).
- Windows workspace instructions that differed from the pre-existing WSL files
  were copied without replacement to
  `~/dirextalk/.handoff/final-20260718/workspace-docs/`. The local checkpoint
  and incomplete P2 `releaselifecycle` snapshot are alongside them in the same
  handoff directory.
