# Releases

Only `packages/sdk` is published, as the public, unscoped npm package
`agenthooksprotocol`. The root, testing, and conformance packages stay private.
This SDK releases independently of the other language SDKs.

## One-time setup

1. Keep this GitHub repository public for npm provenance. Create the GitHub
   environment **release**; add required reviewers and restrict deployments to
   `main` as appropriate.
2. Add repository secret **RELEASE_PLEASE_TOKEN**: a fine-grained PAT with access
   to `agenthooksprotocol/typescript-sdk`, **Contents: read and write** and
   **Pull requests: read and write**. Approve organization access if required.
   This lets release-please PRs trigger the existing PR CI. Permit Actions to
   create PRs in repository/organization settings.
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
