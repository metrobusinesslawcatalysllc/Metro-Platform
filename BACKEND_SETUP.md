# Isolated tenant backend setup

The gateway keeps identity and tenant routing in a control-plane D1 database.
Each Admin Owner receives a separate D1 database and a Workers for Platforms
Worker bound only to that database. D1 has no row-level security; isolation here
is provided by separate databases and by the gateway's trusted dispatch context.

## 1. Prepare the control plane

Create a D1 database for the control plane and apply [schema.sql](./schema.sql).
For example, with Wrangler configured with the relevant account:

```powershell
npx wrangler d1 execute <CONTROL_DATABASE_NAME> --remote --file=.\schema.sql
```

Insert the platform's initial Super Master in that database, using the exact
user ID that the identity provider puts in the JWT `sub` claim:

```sql
INSERT INTO platform_operators (user_id, role)
VALUES ('<SUPER_MASTER_USER_ID>', 'SUPER_MASTER');
```

The partial unique index permits only one Super Master. Provision all other
operators through the supported control-plane process; do not trust role or
tenant claims supplied by a client.

## 2. Configure and deploy the gateway

Set the real D1 database ID, dispatch namespace name, and identity-provider
issuer/audience in [wrangler.jsonc](./wrangler.jsonc), then deploy
[worker.js](./worker.js). The gateway configuration includes:

| Name | Type | Purpose |
| --- | --- | --- |
| `CONTROL_DB` | D1 binding | The control-plane database |
| `DISPATCHER` | Workers for Platforms dispatch namespace | Invokes tenant Workers |
| `AUTH_JWT_SECRET` | Secret | HS256 verification key; at least 32 UTF-8 bytes |
| `AUTH_JWT_ISSUER` | Variable | Expected JWT `iss` |
| `AUTH_JWT_AUDIENCE` | Variable | Expected JWT `aud` |
| `ALLOWED_ORIGINS` | Variable, optional | Comma-separated exact browser origins |

Replace the `REPLACE_WITH_*` values in `wrangler.jsonc` before deploying, then
set the signing secret without adding it to the configuration file:

```powershell
npx wrangler secret put AUTH_JWT_SECRET
npx wrangler deploy
```

The `DISPATCHER` dispatch namespace binding is the dynamic-routing mechanism:
the control plane looks up a tenant's trusted `worker_script_name`, then
`DISPATCHER.get()` invokes that tenant Worker. Each uploaded tenant Worker has
only its own D1 binding. Cloudflare does not expose request-time selection of
arbitrary D1 bindings through `env` or `env["DB_" + tenantId]`; do not add every
tenant D1 to the gateway. Create the dispatch namespace before deploying the
gateway. Configure the
identity provider to issue short-lived HS256 tokens with `sub`, `iss`, `aud`,
`iat`, and `exp`. The gateway resolves the role and scope from D1; token role and
tenant claims are not authoritative.

## 3. Provision a tenant

The provisioning utility requires Node.js 20.6 or newer. It reads these
environment variables at runtime; it does not print or store the API token:

- `CLOUDFLARE_ACCOUNT_ID`
- `CLOUDFLARE_API_TOKEN` (grant only the account permissions needed to manage
  D1 databases and Workers scripts)
- `CONTROL_D1_DATABASE_ID` (UUID of the control-plane D1)
- `DISPATCH_NAMESPACE` (the dispatch namespace name)
- `SUPER_MASTER_ACCESS_TOKEN` (the Super Master's short-lived HS256 JWT; may
  include the `Bearer ` prefix)
- `AUTH_JWT_SECRET`, `AUTH_JWT_ISSUER`, and `AUTH_JWT_AUDIENCE` (must match the
  gateway configuration)

Keep these values in an ignored local `.env` file or inject them through your
secret manager. With Node.js environment-file support:

```powershell
node --env-file=.env .\provision-tenant.mjs `
  --tenant-name "Example Admin Owner" `
  --admin-owner-user-id "<IDENTITY_PROVIDER_USER_ID>" `
  --super-master-user-id "<SUPER_MASTER_USER_ID>"
```

The utility verifies the JWT signature and claims, checks that its `sub` is the
specified active Super Master in the control database, creates a tenant D1, applies
[tenant-schema.sql](./tenant-schema.sql), uploads [tenant-worker.js](./tenant-worker.js)
with that D1 binding, then registers the tenant. If the final registration
request has an uncertain outcome, it retains resources and reports the IDs so
an operator can reconcile them safely instead of deleting a possibly active
tenant's infrastructure.

Tenant provisioning remains in this separate trusted operator utility; the
public gateway does not accept Cloudflare API credentials or create D1
databases. Its `/api/tenants` and `/api/tenants/:tenant_id` routes are for
authorized tenant listing and Super Master status changes only. Banking,
brokerage, binary, and management requests use separate `/api/{domain}/*`
routes and are dispatched only after tenant authorization.

After provisioning, an operator still needs a controlled process to create
tenant branches, memberships, and client account grants in the control and
tenant databases. No public API for those administrative writes is included.

## Financial requests and management reviews

The tenant Worker exposes:

- `GET /api/banking/balance` and the existing banking ledger, deposit-route,
  transaction, and entry reads.
- `POST /api/banking/transfer` to submit an internal-ledger transfer request.
- `POST /api/brokerage/order` and `POST /api/binary/contract` to submit
  non-executing trade intents.
- `GET /api/management/pending-reviews` and
  `POST /api/management/review-action` for `SUPER_MASTER`, `ADMIN_OWNER`, and
  `MANAGER` roles. Managers are limited to their branch; requesters cannot
  review their own requests.

All transfer and trade/contract requests enter the tenant's durable
`management_queue`. The default elevated-review threshold is `10000` minor
units of `USD`; change `tenant_metadata.elevated_review_threshold_minor` and
`elevated_review_currency` in each tenant database to configure it. Non-matching
currencies are marked elevated. Approval records only `APPROVED` or `DECLINED`;
it never moves funds, locks escrow, places or settles trades, or starts a timer.
Every response for a queued request reports `execution_status: NOT_EXECUTED`.

These are request and approval-record workflows, not payment or trading
integrations. Live transfers, deposits, suitability verification, brokerage
execution, binary-option escrow/settlement, and price feeds remain disabled and
require separately designed, audited, idempotent services before production use.
