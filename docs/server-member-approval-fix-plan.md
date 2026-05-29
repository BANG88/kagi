# Server Member Approval Fix Plan

The latest commit review for `73074f9 feat: add server-mode member join and approve` found two Major issues in the server-mode member join and approval flow. Both issues affect teams that use remote sync from multiple checkouts or machines.

This plan focuses on making server-side join requests visible and approvable by active members, while keeping pending approval metadata consistent with pulled project access state.

## Problems

### Remote join requests are not visible to other active clients

Server-mode member approval and listing currently consult only the local `.kagi/access.json` state. If one client creates a join request against the server, an active member working from a different checkout may not see or approve that request because it is not present in their local access metadata.

The expected behavior is that active members can list and approve pending server-side join requests even when their local checkout did not create or previously pull the request metadata.

### Pending approval metadata can survive an incompatible pull

Pending approval metadata can remain local after `pull` overwrites the approved access state. This can later desynchronize server token state from project access state: the client may believe it still has pending accepted member/token metadata, while the pulled `.kagi/access.json` no longer represents the same approval context.

The expected behavior is that pull either blocks before creating this split-brain state or robustly merges and revalidates pending approval metadata against the pulled project state.

## Areas to Inspect

- `src/cli/commands.rs`
  - Member `list` and `approve` paths around local list/approve behavior.
  - Pending metadata handling for accepted members and token ids.
  - `apply_pulled_state` behavior when access state is replaced.
  - `push` and `pull` paths that persist local and remote sync metadata.
- `src/infrastructure/key_manager.rs`
  - `list_join_requests`.
  - `approve_join_request`.
  - `approve_join_request_with_wrapped_token`.
- `src/domain/sync/remote_config.rs`
  - `pending_token_ids`.
  - `pending_accepted_member_ids`.
  - Server join request fields and serialization behavior.
- `src/server/routes.rs`
  - Server responses that include `join_requests`.
  - Approval and token-claim routes that consume approved member metadata.
- `tests/integration_tests.rs`
  - Server member join/approve tests.
  - Push/pull tests that replace local state or exercise pending metadata.

## Proposed Implementation Steps

### 1. Establish the source of truth for pending requests

Treat the server's `join_requests` response as authoritative for server-mode pending requests. Local `.kagi/access.json` may still cache trusted pending metadata, but it must not be the only source used by server-mode `member list`, `member status`, `pull`, or `member approve` flows.

Implementation options:

- Surface server-side join requests directly in member list/status output.
- Merge server-side join requests into trusted local pending member metadata during pull or status refresh.
- Use a hybrid approach: display server-side requests without persisting them until approval, then persist only the approved access state and required pending token metadata.

Prefer the approach that keeps local state minimal and avoids writing untrusted request data unless it is validated and needed for approval.

### 2. Allow active clients to approve server-side requests they did not create

Update the approval path so an active member can approve a pending request using server-side request data. The approving client should not require that the pending request already exists in its local `.kagi/access.json`.

The approval flow should:

- Fetch or use the latest server-side join request data.
- Validate that the current local member is active and has access to the project key needed to wrap approval material.
- Match the requested member by a stable identifier, not by ambiguous display text.
- Create the approved local access entry and wrapped token data from validated request fields.
- Submit approval state to the server in the same way as locally created pending requests.
- Avoid approving stale or already-resolved requests; return a clear message if the server no longer has the pending request.

### 3. Make pending approval metadata atomic with access state

Prevent `pending_token_ids` and `pending_accepted_member_ids` from surviving across a pull that overwrites the approved member state they depend on.

The preferred minimal fix is to fail fast before pull applies remote state when pending approval metadata exists locally. The error should tell the user to push or complete the approval flow first, for example:

```text
Cannot pull while member approval metadata is pending. Run `kagi push` to publish the approval, or resolve the pending member approval before pulling.
```

If a merge/revalidation approach is chosen instead, it must be robust enough to:

- Reconcile pending token ids with the pulled access state.
- Drop pending metadata that no longer has a corresponding approved member entry.
- Preserve pending metadata only when the pulled state contains the same approved member identity and recipient.
- Avoid issuing or claiming server tokens for members that are not present in the final pulled access state.

Do not silently keep pending metadata after replacing local access state unless it has been revalidated against the final state.

### 4. Keep push and pull ordering explicit

Review push and pull sequencing so state transitions are easy to reason about:

- Pull should validate local pending approval metadata before writing remote access state to disk.
- Push should publish approved access state and matching pending server token metadata together.
- Error paths should leave both access state and remote config in their previous consistent state where possible.
- Any persisted partial state should be safe to retry.

### 5. Preserve secret safety

Do not log or print sensitive values while adding diagnostics or error messages. This includes:

- Project tokens.
- Admin tokens.
- Project keys.
- Wrapped project keys or wrapped project tokens.
- Decrypted secrets.
- Claim secrets.

Output may include non-secret identifiers such as member ids, request ids, and project ids when needed for troubleshooting.

## Test Plan

### Remote pending request can be listed and approved from another checkout

Add an integration test with two separate working directories and separate `KAGI_HOME` identities:

1. Start a test server.
2. In checkout A, initialize or join a project as an active member, configure the remote, and push state.
3. In checkout B, use a different `KAGI_HOME` identity to send a server-mode member join request.
4. In checkout A, or in a third active checkout with its own `KAGI_HOME`, run the member list/status flow.
5. Assert that the remote pending request from checkout B is visible.
6. Approve the pending request from the active checkout that did not create it.
7. Assert that checkout B can complete or claim the approved access/token flow.
8. Assert that final member/access state includes the new member and remains usable after push/pull.

The test should prove that approval does not rely on local pending request metadata created by the approving checkout.

### Pull while pending approval metadata exists is safe

Add an integration test for `pull` when local pending approval metadata exists.

If using the fail-fast approach:

1. Create a local state with pending accepted member/token metadata that has not been pushed.
2. Attempt `kagi pull` from a remote that would overwrite access state.
3. Assert that pull fails before applying remote state.
4. Assert that the error clearly instructs the user to push or resolve the pending approval first.
5. Assert that local access state and remote config remain unchanged.

If using the merge/revalidation approach:

1. Create local pending approval metadata.
2. Pull remote state that either preserves or removes the matching approved member.
3. Assert that pending metadata is preserved only when it matches the final pulled access state.
4. Assert that pending metadata is removed when the pulled state no longer contains the corresponding approved member.
5. Assert that no later token claim can create server token state for a member missing from project access state.

## Verification Commands

After implementation, run:

```bash
cargo fmt -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo install --path .
```

## Acceptance Criteria

- Server-mode member list/status shows pending join requests that exist on the server, even when the active client's local checkout did not create them.
- An active member can approve a server-side pending join request from a different checkout.
- Approval uses validated server-side request data and does not require pre-existing local pending request metadata.
- Pull cannot leave `pending_token_ids` or `pending_accepted_member_ids` inconsistent with the final local access state.
- Error messages for blocked pull or stale approval are clear and actionable.
- No implementation path logs or prints project tokens, admin tokens, project keys, wrapped token material, decrypted secrets, or claim secrets.
- Integration tests cover cross-checkout approval and pull behavior with pending approval metadata.
- All required verification commands pass.

## Risks

- Merging server-side join requests into local state too early may persist untrusted or stale request data. Prefer validation at approval time or clearly mark cached data as pending server metadata.
- Matching requests by display name or other ambiguous fields can approve the wrong member. Use stable request/member identifiers and recipient keys.
- A fail-fast pull guard may interrupt legitimate workflows until users push pending approval state. The blocking message must explain the safe next step.
- A merge/revalidation implementation is more complex than fail-fast and can still desynchronize token state if any dependency is missed.
- Tests that reuse a single home directory may miss the bug. The cross-checkout test must use separate working directories and separate `KAGI_HOME` values.
