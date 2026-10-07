# Releases

Only `packages/sdk` is published, as the public, unscoped npm package
`agenthooksprotocol`. The root, testing, and conformance packages stay private.
This SDK releases independently of the other language SDKs.

## One-time setup

1. Keep this GitHub repository public for npm provenance. Create the GitHub
   environment **release**; add required reviewers and restrict deployments to
   `main` as appropriate.
2. Use the existing **Agent Hooks Protocol Bot** GitHub App. Install it on this
   repository with **Contents: read/write** and **Pull requests: read/write**.
   Set Actions variable **`RELEASE_APP_ID`** to its App ID and Actions secret
   **`RELEASE_APP_PRIVATE_KEY`** to a PEM private key generated in its settings.
   Organization-level values may be shared with just the four SDK repositories.
   The workflow mints a short-lived installation token scoped to this repository
   and those two permissions; it is revoked when the job ends. Release PRs,
   tags, and GitHub releases use the bot identity and trigger normal PR CI.
   No personal access token is needed. Keep branch protection enabled.
3. Ensure you own the unscoped npm name `agenthooksprotocol`. Name availability
   is not checked by this workflow. If it is unavailable, resolve ownership or
   explicitly change the package name and all imports before releasing; there
   is no automatic scoped fallback.
4. npm trusted publisher setup starts from an existing package's settings.
   If the package does not exist, an authorized maintainer must bootstrap it
   manually using their local npm login (no npm token in GitHub). From a clean
   checkout, use Node 24, install pnpm 10.18.3, run `pnpm install --frozen-lockfile`
   and `pnpm --filter agenthooksprotocol build`. In `packages/sdk`, temporarily
   set the version to `0.0.0-bootstrap.0` with
   `npm version 0.0.0-bootstrap.0 --no-git-tag-version`, then run
   `npm publish --access public --tag bootstrap`. Restore `package.json`
   afterward; do not commit this bootstrap version. This reserves the package
   without consuming the intended first stable version, `0.1.0`.
5. In npm **agenthooksprotocol → Settings → Trusted Publisher**, select GitHub
   Actions and enter these exact, case-sensitive values:
   - Organization/user: `agenthooksprotocol`
   - Repository: `typescript-sdk`
   - Workflow filename: `release.yml` (not its full path)
   - Environment: `release`
   - Allowed actions: enable direct publishing with `npm publish`.
   Complete the first trusted publish within **2 days** of creating the
   configuration; otherwise delete the expired configuration and recreate it.
   After setup, prefer npm's **Require two-factor authentication and disallow
   tokens** publishing access setting. No npm authentication secret is needed.

## Lifecycle

Use conventional commits (`fix:`, `feat:`, and breaking-change markers). Every
push to `main` invokes the existing CI through `workflow_call`. After it passes,
release-please v4 maintains a version/changelog PR for `packages/sdk`. Review
and merge that PR to create its component-prefixed GitHub release/tag. The same
workflow publishes only when `packages/sdk--release_created` is true, checking
out the exact `packages/sdk--sha` release output. The `release` environment gate
applies before publishing. There is no separate release/tag-event workflow.

The SDK package starts at `0.1.0`. The manifest starts at `0.0.0`, a sentinel
indicating no previous release. `initial-version: 0.1.0` sets only the first
release; subsequent versions follow conventional commits. No configuration
cleanup is required after the first release.

Publishing uses GitHub-hosted runners, Node 24, npm 11, and job-scoped OIDC.
It builds the SDK and publishes its compiled `dist/src`, source files (for source
maps), README, and Apache-2.0 license. It does not publish workspace test tools.
Existing CI remains the test gate; no publishing/install tests, registry probes,
or postpublish verification jobs are added. If publishing fails, fix the cause
and rerun only the failed publish job in the original run to retain its release
outputs; do not overwrite an already published npm version.

## References

- [npm trusted publishing](https://docs.npmjs.com/trusted-publishers/): requires
  npm **11.5.1+**, Node **22.14.0+**, and supported hosted runners. Provenance is
  automatic for public packages from public GitHub repositories; the workflow
  also requests it explicitly.
- [release-please manifest configuration](https://github.com/googleapis/release-please/blob/main/docs/manifest-releaser.md)
- [release-please action path outputs](https://github.com/googleapis/release-please-action#path-outputs)

## Contract pin notification

After the complete **Release** workflow succeeds for a `main` push, the separate
`release-notify.yml` workflow sends a `sdk-released` repository dispatch to
`agenthooksprotocol/agent-hooks-protocol`. It requires the `publish` job from that exact run attempt to have succeeded. It also checks that a
non-draft, non-prerelease GitHub release has a stable version tag pointing at that
exact workflow run head, including annotated tag dereferencing. Ordinary Release
Please PR updates do not send a notification.

The contract receiver uses the repository, revision, and run ID in the notification
to propose released SDK pins in one bot PR. This is event-driven: there is no
schedule, registry probe, package installation, or additional publishing step.
The notifier does not check out or execute SDK code. Its repository token has only
Actions and Contents read access for release metadata; a separate short-lived App
token has only Contents write access to the contract repository for dispatch.

The existing `RELEASE_APP_ID` and `RELEASE_APP_PRIVATE_KEY` must identify an App
installed on **agenthooksprotocol/agent-hooks-protocol** with **Contents: read/write**,
in addition to its existing SDK installation. The notifier explicitly scopes the
App token to that target repository and revokes it at job completion. Installing
this workflow does not replay earlier releases (including the initial `0.1.0`);
initialize those pins through the contract receiver's manual workflow instead of
rerunning a publishing workflow.
