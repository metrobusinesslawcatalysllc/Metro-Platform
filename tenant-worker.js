import { WorkerEntrypoint } from "cloudflare:workers";

const JSON_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store",
  "x-content-type-options": "nosniff",
};
const ROLES = new Set([
  "SUPER_MASTER",
  "ADMIN_OWNER",
  "SUBADMIN",
  "MANAGER",
  "CLIENT",
]);
const MAX_LIMIT = 100;
const MAX_OFFSET = 10000;
const MAX_BODY_BYTES = 8192;
const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const USER_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@+-]{0,127}$/;
const IDEMPOTENCY_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const MANAGEMENT_ROLES = new Set(["SUPER_MASTER", "ADMIN_OWNER", "MANAGER"]);

function json(data, status = 200) {
  return Response.json(data, { status, headers: JSON_HEADERS });
}

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function page(url) {
  const limit = url.searchParams.has("limit")
    ? Number(url.searchParams.get("limit"))
    : 50;
  const offset = url.searchParams.has("offset")
    ? Number(url.searchParams.get("offset"))
    : 0;
  if (
    !Number.isInteger(limit) ||
    limit < 1 ||
    limit > MAX_LIMIT ||
    !Number.isInteger(offset) ||
    offset < 0 ||
    offset > MAX_OFFSET
  ) {
    throw new HttpError(400, `limit must be 1-${MAX_LIMIT}; offset must be 0-${MAX_OFFSET}`);
  }
  return { limit, offset };
}

function addFilters(url, filters, values, fields) {
  for (const [parameter, column] of fields) {
    const value = url.searchParams.get(parameter);
    if (value !== null) {
      if (!ID_PATTERN.test(value)) throw new HttpError(400, `Invalid ${parameter}`);
      filters.push(`${column} = ?`);
      values.push(value);
    }
  }
}

function scope(alias, context, domain) {
  const filters = [`${alias}.tenant_id = ?`];
  const values = [context.tenantId];
  if (["SUBADMIN", "MANAGER"].includes(context.role)) {
    if (!context.branchId) throw new HttpError(403, "Branch access is not configured");
    filters.push(`${alias}.branch_id = ?`);
    values.push(context.branchId);
  } else if (context.role === "CLIENT") {
    if (!context.branchId) throw new HttpError(403, "Branch access is not configured");
    const accessTable =
      domain === "BANKING" ? "banking_account_access" : "brokerage_account_access";
    const idColumn =
      domain === "BANKING" ? "ledger_id" : "brokerage_account_id";
    const rowId =
      domain === "BANKING" ? `${alias}.ledger_id` : `${alias}.brokerage_account_id`;
    filters.push(`${alias}.branch_id = ?`);
    values.push(context.branchId);
    filters.push(
      `EXISTS (
        SELECT 1 FROM ${accessTable} AS access
        WHERE access.tenant_id = ${alias}.tenant_id
          AND access.user_id = ?
          AND access.${idColumn} = ${rowId}
      )`,
    );
    values.push(context.userId);
  }
  return { sql: filters.join(" AND "), values };
}

function requireDb(env) {
  if (!env.DB || typeof env.DB.prepare !== "function") {
    throw new HttpError(503, "Tenant database is not configured");
  }
  return env.DB;
}

function validateContext(props, env) {
  if (
    !props ||
    typeof props !== "object" ||
    typeof props.userId !== "string" ||
    !USER_ID_PATTERN.test(props.userId) ||
    !ROLES.has(props.role) ||
    typeof props.tenantId !== "string" ||
    !ID_PATTERN.test(props.tenantId) ||
    typeof env.TENANT_ID !== "string" ||
    props.tenantId !== env.TENANT_ID
  ) {
    throw new HttpError(401, "Trusted platform context is required");
  }
  if (
    ["SUBADMIN", "MANAGER", "CLIENT"].includes(props.role) &&
    (typeof props.branchId !== "string" || !ID_PATTERN.test(props.branchId))
  ) {
    throw new HttpError(403, "Branch access is not configured");
  }
  return props;
}

async function selectRows(env, sql, values, pagination) {
  const result = await requireDb(env)
    .prepare(sql)
    .bind(...values, pagination.limit, pagination.offset)
    .all();
  if (!Array.isArray(result.results)) {
    throw new Error("Tenant database returned an invalid result");
  }
  return result.results;
}

async function readJsonBody(request) {
  if (!request.headers.get("Content-Type")?.toLowerCase().startsWith("application/json")) {
    throw new HttpError(415, "Content-Type must be application/json");
  }
  const declaredLength = Number(request.headers.get("Content-Length"));
  if (Number.isFinite(declaredLength) && declaredLength > MAX_BODY_BYTES) {
    throw new HttpError(413, "Request body is too large");
  }
  if (!request.body) throw new HttpError(400, "A JSON request body is required");

  const reader = request.body.getReader();
  const chunks = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_BODY_BYTES) {
      await reader.cancel();
      throw new HttpError(413, "Request body is too large");
    }
    chunks.push(value);
  }

  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    const body = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    if (!body || typeof body !== "object" || Array.isArray(body)) {
      throw new Error("Expected an object");
    }
    return body;
  } catch {
    throw new HttpError(400, "Invalid JSON request body");
  }
}

function requireIdentifier(value, field) {
  if (typeof value !== "string" || !ID_PATTERN.test(value)) {
    throw new HttpError(400, `Invalid ${field}`);
  }
  return value;
}

function requireIdempotencyKey(value) {
  if (typeof value !== "string" || !IDEMPOTENCY_PATTERN.test(value)) {
    throw new HttpError(400, "idempotency_key must be 1-128 safe characters");
  }
  return value;
}

function requirePositiveInteger(value, field, max = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value <= 0 || value > max) {
    throw new HttpError(400, `${field} must be a positive integer`);
  }
  return value;
}

async function assertScopedLedger(context, env, ledgerId, currency) {
  const rowScope = scope("ledger", context, "BANKING");
  const ledger = await requireDb(env)
    .prepare(
      `SELECT ledger.ledger_id, ledger.currency
       FROM banking_ledgers AS ledger
       WHERE ${rowScope.sql}
         AND ledger.ledger_id = ?
         AND ledger.status = 'ACTIVE'
       LIMIT 1`,
    )
    .bind(...rowScope.values, ledgerId)
    .first();
  if (!ledger) throw new HttpError(404, "Banking ledger not found");
  if (currency && ledger.currency !== currency) {
    throw new HttpError(400, "Ledger currency does not match the request");
  }
}

async function assertScopedBrokerageAccount(context, env, accountId) {
  const rowScope = scope("account", context, "BROKERAGE");
  const account = await requireDb(env)
    .prepare(
      `SELECT account.brokerage_account_id
       FROM brokerage_accounts AS account
       WHERE ${rowScope.sql}
         AND account.brokerage_account_id = ?
         AND account.status = 'ACTIVE'
       LIMIT 1`,
    )
    .bind(...rowScope.values, accountId)
    .first();
  if (!account) throw new HttpError(404, "Brokerage account not found");
}

async function queueRequest(context, env, requestType, reviewLevel, payload, idempotencyKey) {
  const db = requireDb(env);
  const payloadJson = JSON.stringify(payload);
  const queueId = crypto.randomUUID();
  await db
    .prepare(
      `INSERT INTO management_queue (
         queue_id, tenant_id, branch_id, requester_user_id, request_type,
         review_level, idempotency_key, payload_json
       )
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT (tenant_id, requester_user_id, idempotency_key) DO NOTHING`,
    )
    .bind(
      queueId,
      context.tenantId,
      context.branchId,
      context.userId,
      requestType,
      reviewLevel,
      idempotencyKey,
      payloadJson,
    )
    .run();

  const existing = await db
    .prepare(
      `SELECT queue_id, request_type, review_level, status, payload_json
       FROM management_queue
       WHERE tenant_id = ? AND requester_user_id = ? AND idempotency_key = ?
       LIMIT 1`,
    )
    .bind(context.tenantId, context.userId, idempotencyKey)
    .first();
  if (!existing) throw new Error("Management request was not persisted");
  if (existing.request_type !== requestType || existing.payload_json !== payloadJson) {
    throw new HttpError(409, "idempotency_key was already used for a different request");
  }

  return json(
    {
      data: {
        request_id: existing.queue_id,
        status: existing.status,
        review_level: existing.review_level,
        execution_status: "NOT_EXECUTED",
      },
    },
    202,
  );
}

async function submitBankingTransfer(request, context, env) {
  const body = await readJsonBody(request);
  const sourceId = requireIdentifier(body.from_ledger_id, "from_ledger_id");
  const targetId = requireIdentifier(body.to_ledger_id, "to_ledger_id");
  if (sourceId === targetId) throw new HttpError(400, "Transfer ledgers must be different");
  const amountMinor = requirePositiveInteger(body.amount_minor, "amount_minor");
  const currency =
    typeof body.currency === "string" && /^[A-Z]{3}$/.test(body.currency)
      ? body.currency
      : null;
  if (!currency) throw new HttpError(400, "currency must be a three-letter uppercase code");
  const idempotencyKey = requireIdempotencyKey(body.idempotency_key);

  await assertScopedLedger(context, env, sourceId, currency);
  await assertScopedLedger(context, env, targetId, currency);
  const settings = await requireDb(env)
    .prepare(
      `SELECT elevated_review_threshold_minor, elevated_review_currency
       FROM tenant_metadata WHERE tenant_id = ? LIMIT 1`,
    )
    .bind(context.tenantId)
    .first();
  if (!settings) throw new HttpError(503, "Tenant configuration is unavailable");

  const reviewLevel =
    currency !== settings.elevated_review_currency ||
    amountMinor >= settings.elevated_review_threshold_minor
      ? "ELEVATED"
      : "STANDARD";
  return queueRequest(
    context,
    env,
    "BANKING_TRANSFER",
    reviewLevel,
    {
      from_ledger_id: sourceId,
      to_ledger_id: targetId,
      amount_minor: amountMinor,
      currency,
    },
    idempotencyKey,
  );
}

async function submitBrokerageOrder(request, context, env) {
  const body = await readJsonBody(request);
  const accountId = requireIdentifier(body.account_id, "account_id");
  const symbol =
    typeof body.symbol === "string" && /^[A-Za-z0-9._:-]{1,32}$/.test(body.symbol)
      ? body.symbol
      : null;
  if (!symbol) throw new HttpError(400, "Invalid symbol");
  if (!["CALL", "PUT"].includes(body.option_type)) {
    throw new HttpError(400, "option_type must be CALL or PUT");
  }
  const stakeMinor = requirePositiveInteger(body.stake_minor, "stake_minor");
  const durationSeconds = requirePositiveInteger(
    body.duration_seconds,
    "duration_seconds",
    86400,
  );
  const idempotencyKey = requireIdempotencyKey(body.idempotency_key);
  if (durationSeconds < 5) throw new HttpError(400, "duration_seconds must be at least 5");
  await assertScopedBrokerageAccount(context, env, accountId);

  return queueRequest(
    context,
    env,
    "BROKERAGE_ORDER",
    "ELEVATED",
    {
      account_id: accountId,
      symbol,
      option_type: body.option_type,
      stake_minor: stakeMinor,
      duration_seconds: durationSeconds,
    },
    idempotencyKey,
  );
}

async function submitBinaryContract(request, context, env) {
  const body = await readJsonBody(request);
  const accountId = requireIdentifier(body.account_id, "account_id");
  const asset =
    typeof body.asset === "string" && /^[A-Za-z0-9._:-]{1,32}$/.test(body.asset)
      ? body.asset
      : null;
  if (!asset) throw new HttpError(400, "Invalid asset");
  if (!["CALL", "PUT"].includes(body.direction)) {
    throw new HttpError(400, "direction must be CALL or PUT");
  }
  const amountMinor = requirePositiveInteger(body.amount_minor, "amount_minor");
  const durationSeconds = requirePositiveInteger(
    body.duration_seconds,
    "duration_seconds",
    86400,
  );
  const idempotencyKey = requireIdempotencyKey(body.idempotency_key);
  if (durationSeconds < 5) throw new HttpError(400, "duration_seconds must be at least 5");
  await assertScopedBrokerageAccount(context, env, accountId);

  return queueRequest(
    context,
    env,
    "BINARY_CONTRACT",
    "ELEVATED",
    {
      account_id: accountId,
      asset,
      direction: body.direction,
      amount_minor: amountMinor,
      duration_seconds: durationSeconds,
    },
    idempotencyKey,
  );
}

function requireManagementRole(context) {
  if (!MANAGEMENT_ROLES.has(context.role)) {
    throw new HttpError(403, "Management credentials required");
  }
}

async function listPendingReviews(url, context, env) {
  requireManagementRole(context);
  const pagination = page(url);
  const values = [context.tenantId];
  let branchFilter = "";
  if (context.role === "MANAGER") {
    if (!context.branchId) throw new HttpError(403, "Branch access is not configured");
    branchFilter = " AND branch_id = ?";
    values.push(context.branchId);
  }
  values.push(pagination.limit, pagination.offset);
  const result = await requireDb(env)
    .prepare(
      `SELECT queue_id, tenant_id, branch_id, requester_user_id, request_type,
              review_level, payload_json, requested_at
       FROM management_queue
       WHERE tenant_id = ? AND status = 'PENDING'${branchFilter}
       ORDER BY requested_at ASC, queue_id ASC
       LIMIT ? OFFSET ?`,
    )
    .bind(...values)
    .all();
  if (!Array.isArray(result.results)) {
    throw new Error("Tenant database returned an invalid review queue result");
  }
  return json({ data: result.results, pagination });
}

async function reviewRequest(request, context, env) {
  requireManagementRole(context);
  const body = await readJsonBody(request);
  const queueId = requireIdentifier(body.review_id, "review_id");
  if (!["APPROVE", "DECLINE"].includes(body.action)) {
    throw new HttpError(400, "action must be APPROVE or DECLINE");
  }
  const reviewNote =
    body.review_note === undefined ? null : body.review_note;
  if (
    reviewNote !== null &&
    (typeof reviewNote !== "string" || reviewNote.length > 1000)
  ) {
    throw new HttpError(400, "review_note must be at most 1000 characters");
  }

  const db = requireDb(env);
  const values = [context.tenantId, queueId];
  let branchFilter = "";
  if (context.role === "MANAGER") {
    if (!context.branchId) throw new HttpError(403, "Branch access is not configured");
    branchFilter = " AND branch_id = ?";
    values.push(context.branchId);
  }
  const existing = await db
    .prepare(
      `SELECT queue_id, requester_user_id, status
       FROM management_queue
       WHERE tenant_id = ? AND queue_id = ?${branchFilter}
       LIMIT 1`,
    )
    .bind(...values)
    .first();
  if (!existing) throw new HttpError(404, "Review request not found");
  if (existing.requester_user_id === context.userId) {
    throw new HttpError(403, "You cannot review your own request");
  }
  if (existing.status !== "PENDING") {
    throw new HttpError(409, "Review request has already been decided");
  }

  const result = await db
    .prepare(
      `UPDATE management_queue
       SET status = ?, reviewed_by = ?, reviewed_at = unixepoch(), review_note = ?
       WHERE tenant_id = ? AND queue_id = ? AND status = 'PENDING'
         AND requester_user_id <> ?${branchFilter}`,
    )
    .bind(
      body.action === "APPROVE" ? "APPROVED" : "DECLINED",
      context.userId,
      reviewNote,
      context.tenantId,
      queueId,
      context.userId,
      ...(context.role === "MANAGER" ? [context.branchId] : []),
    )
    .run();
  if (!result.meta || result.meta.changes !== 1) {
    throw new HttpError(409, "Review request changed; reload the queue and retry");
  }
  return json({
    data: {
      review_id: queueId,
      status: body.action === "APPROVE" ? "APPROVED" : "DECLINED",
      execution_status: "NOT_EXECUTED",
    },
  });
}

async function handleBanking(path, url, context, env) {
  const pagination = page(url);
  const filters = [];
  const values = [];
  let sql;

  if (path === "/api/banking/balance") {
    const rowScope = scope("ledger", context, "BANKING");
    sql =
      `SELECT ledger.ledger_id, ledger.currency,
              COALESCE(SUM(
                CASE WHEN txn.status = 'POSTED'
                  THEN CASE entry.entry_type WHEN 'CREDIT' THEN entry.amount_minor
                  ELSE -entry.amount_minor END
                  ELSE 0
                END
              ), 0) AS balance_minor
       FROM banking_ledgers AS ledger
       LEFT JOIN banking_ledger_entries AS entry
         ON entry.tenant_id = ledger.tenant_id
        AND entry.ledger_id = ledger.ledger_id
       LEFT JOIN banking_transactions AS txn
         ON txn.tenant_id = entry.tenant_id
        AND txn.transaction_id = entry.transaction_id
        AND txn.status = 'POSTED'
       WHERE ${rowScope.sql}
       GROUP BY ledger.ledger_id, ledger.currency
       ORDER BY ledger.ledger_id ASC LIMIT ? OFFSET ?`;
    return json({
      data: await selectRows(env, sql, rowScope.values, pagination),
      pagination,
    });
  } else if (path === "/api/banking/ledgers") {
    const rowScope = scope("ledger", context, "BANKING");
    filters.push(rowScope.sql);
    values.push(...rowScope.values);
    addFilters(url, filters, values, [
      ["ledger_id", "ledger.ledger_id"],
      ["status", "ledger.status"],
    ]);
    sql =
      `SELECT ledger_id, tenant_id, branch_id, ledger_name, ledger_type,
              currency, status, created_at
       FROM banking_ledgers AS ledger
       WHERE ${filters.join(" AND ")}
       ORDER BY created_at DESC, ledger_id ASC LIMIT ? OFFSET ?`;
  } else if (path === "/api/banking/deposit-routes") {
    const rowScope = scope("ledger", context, "BANKING");
    filters.push(rowScope.sql);
    values.push(...rowScope.values);
    addFilters(url, filters, values, [
      ["asset", "route.asset"],
      ["network", "route.network"],
      ["status", "route.status"],
    ]);
    sql =
      `SELECT route.route_id, route.tenant_id, route.ledger_id, route.asset,
              route.network, route.deposit_address, route.status,
              route.created_at, route.updated_at
       FROM deposit_routes AS route
       JOIN banking_ledgers AS ledger
         ON ledger.tenant_id = route.tenant_id
        AND ledger.ledger_id = route.ledger_id
       WHERE ${filters.join(" AND ")}
       ORDER BY route.created_at DESC, route.route_id ASC LIMIT ? OFFSET ?`;
  } else if (path === "/api/banking/transactions") {
    const rowScope = scope("ledger", context, "BANKING");
    filters.push(rowScope.sql);
    values.push(...rowScope.values);
    addFilters(url, filters, values, [
      ["transaction_id", "txn.transaction_id"],
      ["status", "txn.status"],
    ]);
    sql =
      `SELECT DISTINCT txn.transaction_id, txn.tenant_id, txn.description,
              txn.status, txn.created_at
       FROM banking_transactions AS txn
       JOIN banking_ledger_entries AS entry
         ON entry.tenant_id = txn.tenant_id
        AND entry.transaction_id = txn.transaction_id
       JOIN banking_ledgers AS ledger
         ON ledger.tenant_id = entry.tenant_id
        AND ledger.ledger_id = entry.ledger_id
       WHERE ${filters.join(" AND ")}
       ORDER BY txn.created_at DESC, txn.transaction_id ASC
       LIMIT ? OFFSET ?`;
  } else if (path === "/api/banking/entries") {
    const rowScope = scope("ledger", context, "BANKING");
    filters.push(rowScope.sql);
    values.push(...rowScope.values);
    addFilters(url, filters, values, [
      ["ledger_id", "ledger.ledger_id"],
      ["transaction_id", "entry.transaction_id"],
    ]);
    sql =
      `SELECT entry.entry_id, entry.tenant_id, entry.transaction_id,
              entry.ledger_id, entry.entry_type, entry.amount_minor,
              entry.currency, entry.created_at
       FROM banking_ledger_entries AS entry
       JOIN banking_ledgers AS ledger
         ON ledger.tenant_id = entry.tenant_id
        AND ledger.ledger_id = entry.ledger_id
       JOIN banking_transactions AS txn
         ON txn.tenant_id = entry.tenant_id
        AND txn.transaction_id = entry.transaction_id
       WHERE ${filters.join(" AND ")}
         AND txn.status = 'POSTED'
       ORDER BY entry.created_at DESC, entry.entry_id ASC LIMIT ? OFFSET ?`;
  } else {
    throw new HttpError(404, "Banking endpoint not found");
  }

  return json({ data: await selectRows(env, sql, values, pagination), pagination });
}

async function handleBrokerage(path, url, context, env) {
  const pagination = page(url);
  const filters = [];
  const values = [];
  const rowScope = scope("account", context, "BROKERAGE");
  filters.push(rowScope.sql);
  values.push(...rowScope.values);

  if (path === "/api/brokerage/accounts") {
    addFilters(url, filters, values, [
      ["brokerage_account_id", "account.brokerage_account_id"],
      ["status", "account.status"],
    ]);
    const sql =
      `SELECT account.brokerage_account_id, account.tenant_id,
              account.branch_id, account.provider, account.currency,
              account.status, account.created_at, account.updated_at
       FROM brokerage_accounts AS account
       WHERE ${filters.join(" AND ")}
       ORDER BY account.created_at DESC, account.brokerage_account_id ASC
       LIMIT ? OFFSET ?`;
    return json({
      data: await selectRows(env, sql, values, pagination),
      pagination,
    });
  }

  if (path === "/api/brokerage/trades") {
    addFilters(url, filters, values, [
      ["brokerage_account_id", "account.brokerage_account_id"],
      ["trade_order_id", "trade.trade_order_id"],
      ["status", "trade.status"],
    ]);
    const sql =
      `SELECT trade.trade_order_id, trade.tenant_id,
              trade.brokerage_account_id, trade.symbol, trade.option_type,
              trade.stake_minor, trade.payout_rate_bps, trade.opened_at,
              trade.expires_at, trade.status, trade.settlement_price_micros,
              trade.payout_minor, trade.settled_at
       FROM trade_orders AS trade
       JOIN brokerage_accounts AS account
         ON account.tenant_id = trade.tenant_id
        AND account.brokerage_account_id = trade.brokerage_account_id
       WHERE ${filters.join(" AND ")}
       ORDER BY trade.opened_at DESC, trade.trade_order_id ASC
       LIMIT ? OFFSET ?`;
    return json({
      data: await selectRows(env, sql, values, pagination),
      pagination,
    });
  }

  throw new HttpError(404, "Brokerage endpoint not found");
}

export default class TenantWorker extends WorkerEntrypoint {
  async fetch(request) {
    try {
      const context = validateContext(this.ctx.props, this.env);
      const url = new URL(request.url);

      if (url.pathname.startsWith("/api/banking/")) {
        const getPaths = [
          "/api/banking/balance",
          "/api/banking/ledgers",
          "/api/banking/deposit-routes",
          "/api/banking/transactions",
          "/api/banking/entries",
        ];
        if (request.method === "POST" && url.pathname === "/api/banking/transfer") {
          return await submitBankingTransfer(request, context, this.env);
        }
        if (request.method !== "GET" || !getPaths.includes(url.pathname)) {
          if (request.method !== "GET" && url.pathname !== "/api/banking/transfer") {
            return json({ error: "Method not allowed" }, 405);
          }
          throw new HttpError(404, "Banking endpoint not found");
        }
        return await handleBanking(url.pathname, url, context, this.env);
      }

      if (url.pathname.startsWith("/api/brokerage/")) {
        if (request.method === "POST" && url.pathname === "/api/brokerage/order") {
          return await submitBrokerageOrder(request, context, this.env);
        }
        if (
          request.method !== "GET" ||
          !["/api/brokerage/accounts", "/api/brokerage/trades"].includes(url.pathname)
        ) {
          if (request.method !== "GET" && url.pathname !== "/api/brokerage/order") {
            return json({ error: "Method not allowed" }, 405);
          }
          throw new HttpError(404, "Brokerage endpoint not found");
        }
        return await handleBrokerage(url.pathname, url, context, this.env);
      }

      if (url.pathname.startsWith("/api/binary/")) {
        if (request.method === "POST" && url.pathname === "/api/binary/contract") {
          return await submitBinaryContract(request, context, this.env);
        }
        if (url.pathname !== "/api/binary/contract") {
          throw new HttpError(404, "Binary options endpoint not found");
        }
        return json({ error: "Method not allowed" }, 405);
      }

      if (url.pathname.startsWith("/api/management/")) {
        if (url.pathname === "/api/management/pending-reviews") {
          if (request.method !== "GET") {
            return json({ error: "Method not allowed" }, 405);
          }
          return await listPendingReviews(url, context, this.env);
        }
        if (url.pathname === "/api/management/review-action") {
          if (request.method !== "POST") {
            return json({ error: "Method not allowed" }, 405);
          }
          return await reviewRequest(request, context, this.env);
        }
        throw new HttpError(404, "Management endpoint not found");
      }

      if (request.method !== "GET") {
        return json({ error: "Method not allowed" }, 405);
      }
      throw new HttpError(404, "Not found");
    } catch (error) {
      if (error instanceof HttpError) return json({ error: error.message }, error.status);
      console.error(
        JSON.stringify({
          message: "Unhandled tenant request failure",
          error_type: error instanceof Error ? error.name : "UnknownError",
        }),
      );
      return json({ error: "Internal server error" }, 500);
    }
  }
}
