# C141 — better-auth organization Dynamic Access Control: admin can self-assign custom roles with `organization:delete` and delete the organization

**Program:** Vercel (HackerOne) — `better-auth/better-auth` (OSS Tier 1)  
**Severity (proposed):** High (privilege escalation / broken access control)  
**Component:** `better-auth` organization plugin — Dynamic Access Control + `updateMemberRole` / `inviteMember`  
**Affected:** better-auth `1.7.15` (npm latest 2026-11-01); source HEAD `0e75ddcf36489aa3a191ea902a82d1892034dc74`  
**Status:** Confirmed with local sqlite e2e (3 users). **NOT submitted** pending explicit approval.

## Summary

When `organization({ dynamicAccessControl: { enabled: true } })` is on, an organization **admin** can escalate to owner-equivalent destructive power by assigning themselves (or inviting others into) a **custom DAC role** that includes `organization:delete`.

This breaks the documented security model:

> The admin has full control over all the resources **except for deleting the organization or changing the owner**.

`create-role` correctly refuses to let an admin mint a role whose permission set exceeds the admin’s own (missing `organization:delete` → 403).  
`update-member-role` / `invite-member` only special-case the static `creatorRole` (`"owner"`). They do **not** compare the target role’s permission set to the actor’s permissions. Any custom role that already exists (commonly created by the owner for ops, e.g. `billing-admin`) is freely assignable by anyone with `member:update` / `invitation:create`.

## Impact

- Organization admin → delete entire organization (members, invitations, teams, metadata).
- Same path works via `invite-member` with `role: "<custom-with-delete>"` then accept.
- Violates documented admin≠owner boundary for every deployment that enables DAC and has at least one custom role carrying `organization:delete` (or any other permission the admin is not supposed to hold).

## Preconditions

1. `organization` plugin with `dynamicAccessControl.enabled: true` and a shared `ac` instance.
2. A custom role exists whose permissions include actions the admin must not have (e.g. `organization:delete`). Typically created earlier by an owner.
3. Attacker is an org member with `member:update` (default **admin**) and/or `invitation:create`.

## Root cause

`packages/better-auth/src/plugins/organization/routes/crud-members.ts` (`updateMemberRole`):

- Blocks only when `roleToSet` includes `creatorRole` (`owner`) and the updater is not owner.
- Then `hasPermission({ permissions: { member: ["update"] } })`.
- No call analogous to `checkIfMemberHasPermission` used by `create-role` in `crud-access-control.ts`.

`crud-invites.ts` (`createInvitation`) has the same `creatorRole`-only guard.

## Reproduction (local lab)

```bash
cd poc/r50-ba-dac-role-escalation/repro
npm install better-auth@1.7.15
node lab-c141.mjs
```

Expected console:

```
CTRL bob delete denied? 403 YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_ORGANIZATION
CTRL bob create-role org:delete denied? 403 403
owner create-role 200
ATTACK self-assign 200 billing-admin
ATTACK delete org 200 <orgId>
owner getFull after delete 400 ORGANIZATION_NOT_FOUND
CONFIRMED true
```

### HTTP sketch

1. Owner creates role `billing-admin` with `organization:["update","delete"]` (+ other resources).
2. Admin: `POST /organization/update-member-role` `{ memberId: self, role: "billing-admin" }` → **200**.
3. Admin: `POST /organization/delete` `{ organizationId }` → **200** (org destroyed).

Controls (same session before step 2): delete → 403; create-role with `organization:delete` → 403.

## Evidence

- `e2e-evidence.json` — full step log with statuses/bodies  
- `screenshots/01`–`06` — captioned control vs attack request/response and permission comparison  
- `repro/lab-c141.mjs` — standalone sqlite (`node:sqlite`) e2e  

## Suggested fix

Before accepting a target role in `updateMemberRole` / `createInvitation`:

1. Resolve the target role’s permission map (static `roles` + `organizationRole` row for DAC).
2. Reuse `checkIfMemberHasPermission` (or equivalent) so the actor must already possess every permission the target role grants.
3. Keep the existing `creatorRole` hard-block as defense in depth.
4. Regression tests: admin cannot self-assign / invite into a DAC role that includes `organization:delete`.

## Novelty

- Not covered by the 2026-10/11 better-auth GHSA batch (OAuth proxy, SCIM, SSO, SSRF, stripe org, passkey, unverified-email invite accept GHSA-fmh4-wcc4-5jm3, etc.).
- Distinct from Dokploy’s fixed “invite as owner” class: better-auth already blocks static `owner`; this is the **DAC custom-role** bypass of that boundary.
- No public advisory/issue titled for this assign-time permission-subset gap as of 2026-11-04.

## Out of scope / non-findings from Round 50 matrix

38 baseline org/team/admin/api-key IDOR tests (cross-org getFullOrganization, setActive, accept/cancel invite, api-key userId, admin impersonate/ban, team hijack, …) → all denied. See `../r50/ba-authz-matrix.json`.
