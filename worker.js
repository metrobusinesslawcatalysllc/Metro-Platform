// Control-plane gateway.
// Bindings: CONTROL_DB (central registry D1), DISPATCHER (Workers for
// Platforms dispatch namespace), AUTH_JWT_SECRET, AUTH_JWT_ISSUER,
// AUTH_JWT_AUDIENCE, and optional comma-separated ALLOWED_ORIGINS.
// Each tenant's Worker receives only its own tenant D1 binding.
const HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
};

const STAFF_ROLES = new Set(["SUPER_MASTER", "ADMIN_OWNER"]);
const MEMBER_ROLES = new Set(["SUBADMIN", "MANAGER", "CLIENT"]);
const STATUSES = new Set(["ACTIVE", "SUSPENDED", "CLOSED"]);
const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const MAX_LIMIT = 100;
const MAX_OFFSET = 10000;
const MAX_REQUEST_BODY_BYTES = 8192;

class HttpError extends Error {
  constructor(status, message, headers = {}) {
    super(message);
    this.status = status;
    this.headers = headers;
  }
}

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...HEADERS, ...headers },
  });
}

function decodeBase64Url(value) {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new Error("Invalid base64url");
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const decoded = atob(base64 + "=".repeat((4 - base64.length % 4) % 4));
  return Uint8Array.from(decoded, (character) => character.charCodeAt(0));
}

function decodeJwtPart(value) {
  return JSON.parse(
    new TextDecoder("utf-8", { fatal: true }).decode(decodeBase64Url(value)),
  );
}

async function authenticate(request, env) {
  const match = /^Bearer ([^\s]{1,8192})$/i.exec(
    request.headers.get("Authorization") || "",
  );
  if (!match) throw new HttpError(401, "Authentication required");

  if (
    typeof env.AUTH_JWT_SECRET !== "string" ||
    new TextEncoder().encode(env.AUTH_JWT_SECRET).byteLength < 32 ||
    typeof env.AUTH_JWT_ISSUER !== "string" ||
    !env.AUTH_JWT_ISSUER ||
    typeof env.AUTH_JWT_AUDIENCE !== "string" ||
    !env.AUTH_JWT_AUDIENCE
  ) {
    throw new HttpError(503, "Authentication is not configured");
  }

  const parts = match[1].split(".");
  if (parts.length !== 3) throw new HttpError(401, "Invalid or expired token");

  let header;
  let claims;
  let signature;
  try {
    header = decodeJwtPart(parts[0]);
    claims = decodeJwtPart(parts[1]);
    signature = decodeBase64Url(parts[2]);
  } catch {
    throw new HttpError(401, "Invalid or expired token");
  }

  if (
    !header ||
    header.alg !== "HS256" ||
    header.typ !== "JWT" ||
    !claims ||
    typeof claims !== "object" ||
    typeof claims.sub !== "string" ||
    !ID_PATTERN.test(claims.sub) ||
    claims.iss !== env.AUTH_JWT_ISSUER ||
    !(claims.aud === env.AUTH_JWT_AUDIENCE ||
      (Array.isArray(claims.aud) && claims.aud.includes(env.AUTH_JWT_AUDIENCE))) ||
    !Number.isSafeInteger(claims.exp) ||
    !Number.isSafeInteger(claims.iat)
  ) {
    throw new HttpError(401, "Invalid or expired token");
  }

  const now = Math.floor(Date.now() / 1000);
  if (
    claims.exp <= now ||
    claims.iat > now + 60 ||
    claims.exp <= claims.iat ||
    claims.exp - claims.iat > 3600 ||
    (claims.nbf !== undefined &&
      (!Number.isSafeInteger(claims.nbf) || claims.nbf > now))
  ) {
    throw new HttpError(401, "Invalid or expired token");
  }

  let valid;
  try {
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(env.AUTH_JWT_SECRET),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"],
    );
    valid = await crypto.subtle.verify(
      "HMAC",
      key,
      signature,
      new TextEncoder().encode(`${parts[0]}.${parts[1]}`),
    );
  } catch {
    throw new HttpError(401, "Invalid or expired token");
  }
  if (!valid) throw new HttpError(401, "Invalid or expired token");
  return claims.sub;
}

function database(env) {
  if (!env.CONTROL_DB || typeof env.CONTROL_DB.prepare !== "function") {
    throw new HttpError(503, "Control database is not configured");
  }
  return env.CONTROL_DB;
}

function corsHeaders(request, env) {
  const origin = request.headers.get("Origin");
  if (!origin) return {};
  const allowedOrigins = (env.ALLOWED_ORIGINS || "")
    .split(",")
    .map((originValue) => originValue.trim())
    .filter(Boolean);
  if (!allowedOrigins.includes(origin)) {
    throw new HttpError(403, "Origin is not allowed");
  }
  return {
    "access-control-allow-origin": origin,
    "access-control-allow-methods": "GET, POST, PATCH, OPTIONS",
    "access-control-allow-headers": "authorization, content-type",
    "access-control-max-age": "600",
    vary: "Origin",
  };
}

function withHeaders(response, additions) {
  const headers = new Headers(response.headers);
  for (const [name, value] of Object.entries(additions)) {
    headers.set(name, value);
  }
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

async function resolvePrincipal(userId, env) {
  const db = database(env);
  const operator = await db
    .prepare(
      `SELECT user_id, role, is_active
       FROM platform_operators
       WHERE user_id = ?
       LIMIT 1`,
    )
    .bind(userId)
    .first();

  if (operator) {
    if (operator.is_active !== 1 || !STAFF_ROLES.has(operator.role)) {
      throw new HttpError(403, "Account is inactive or not authorized");
    }
    if (operator.role === "SUPER_MASTER") {
      return { userId, role: operator.role, tenantId: null, branchId: null };
    }

    const tenant = await db
      .prepare(
        `SELECT tenant_id, status
         FROM admin_tenants
         WHERE admin_owner_user_id = ?
         LIMIT 1`,
      )
      .bind(userId)
      .first();
    if (!tenant || tenant.status !== "ACTIVE") {
      throw new HttpError(403, "Tenant is unavailable");
    }
    return {
      userId,
      role: operator.role,
      tenantId: tenant.tenant_id,
      branchId: null,
    };
  }

  const membership = await db
    .prepare(
      `SELECT membership.tenant_id, membership.branch_id, membership.role,
              membership.is_active, branch.status AS branch_status,
              tenant.status AS tenant_status
       FROM tenant_memberships AS membership
       JOIN admin_tenants AS tenant ON tenant.tenant_id = membership.tenant_id
       JOIN tenant_branches AS branch
         ON branch.tenant_id = membership.tenant_id
        AND branch.branch_id = membership.branch_id
       WHERE membership.user_id = ?
       LIMIT 1`,
    )
    .bind(userId)
    .first();
  if (!membership || membership.is_active !== 1 || !MEMBER_ROLES.has(membership.role)) {
    throw new HttpError(403, "Account is not provisioned");
  }
  if (membership.tenant_status !== "ACTIVE" || membership.branch_status !== "ACTIVE") {
    throw new HttpError(403, "Tenant or branch is unavailable");
  }
  return {
    userId,
    role: membership.role,
    tenantId: membership.tenant_id,
    branchId: membership.branch_id,
  };
}

function pagination(url) {
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

async function boundedRequestBody(request) {
  if (!request.body) return undefined;
  const declaredLength = Number(request.headers.get("Content-Length"));
  if (Number.isFinite(declaredLength) && declaredLength > MAX_REQUEST_BODY_BYTES) {
    throw new HttpError(413, "Request body is too large");
  }

  const reader = request.body.getReader();
  const chunks = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_REQUEST_BODY_BYTES) {
      await reader.cancel();
      throw new HttpError(413, "Request body is too large");
    }
    chunks.push(value);
  }

  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return body;
}

async function listTenants(url, principal, env) {
  if (!STAFF_ROLES.has(principal.role)) {
    throw new HttpError(403, "Tenant administration is not allowed");
  }
  const page = pagination(url);
  const sql =
    principal.role === "SUPER_MASTER"
      ? `SELECT tenant_id, tenant_name, admin_owner_user_id, status, created_at
         FROM admin_tenants
         ORDER BY created_at DESC, tenant_id ASC LIMIT ? OFFSET ?`
      : `SELECT tenant_id, tenant_name, admin_owner_user_id, status, created_at
         FROM admin_tenants
         WHERE admin_owner_user_id = ?
         ORDER BY created_at DESC, tenant_id ASC LIMIT ? OFFSET ?`;
  const statement = database(env).prepare(sql);
  const result =
    principal.role === "SUPER_MASTER"
      ? await statement.bind(page.limit, page.offset).all()
      : await statement.bind(principal.userId, page.limit, page.offset).all();
  if (!Array.isArray(result.results)) {
    throw new Error("Control database returned an invalid result");
  }
  return json({ data: result.results, pagination: page });
}

async function manageTenantStatus(request, tenantId, principal, env) {
  if (principal.role !== "SUPER_MASTER") {
    throw new HttpError(403, "Only the Super Master can manage tenants");
  }
  if (!ID_PATTERN.test(tenantId)) throw new HttpError(404, "Tenant not found");
  if (!request.headers.get("Content-Type")?.toLowerCase().startsWith("application/json")) {
    throw new HttpError(415, "Content-Type must be application/json");
  }
  let body;
  try {
    body = await request.json();
  } catch {
    throw new HttpError(400, "Invalid JSON body");
  }
  if (!body || !STATUSES.has(body.status)) {
    throw new HttpError(400, "status must be ACTIVE, SUSPENDED, or CLOSED");
  }

  const result = await database(env)
    .prepare(
      `UPDATE admin_tenants
       SET status = ?, updated_at = unixepoch()
       WHERE tenant_id = ?`,
    )
    .bind(body.status, tenantId)
    .run();
  if (result.meta.changes === 0) throw new HttpError(404, "Tenant not found");
  return json({ data: { tenant_id: tenantId, status: body.status } });
}

async function dispatchTenant(request, url, principal, env) {
  const routeGroups = [
    "/api/banking/",
    "/api/brokerage/",
    "/api/binary/",
    "/api/management/",
  ];
  if (!routeGroups.some((prefix) => url.pathname.startsWith(prefix))) {
    throw new HttpError(404, "Not found");
  }
  const postPaths = new Set([
    "/api/banking/transfer",
    "/api/brokerage/order",
    "/api/binary/contract",
    "/api/management/review-action",
  ]);
  if (
    request.method !== "GET" &&
    !(request.method === "POST" && postPaths.has(url.pathname))
  ) {
    throw new HttpError(405, "Method not allowed", {
      allow: "GET, POST, OPTIONS",
    });
  }

  let tenantId = principal.tenantId;
  if (principal.role === "SUPER_MASTER") {
    tenantId = url.searchParams.get("tenant_id");
    if (!tenantId || !ID_PATTERN.test(tenantId)) {
      throw new HttpError(400, "Super Master requests must specify a tenant_id");
    }
  } else {
    const requestedTenant = url.searchParams.get("tenant_id");
    if (requestedTenant && requestedTenant !== tenantId) {
      throw new HttpError(403, "Tenant access denied");
    }
  }

  const tenant = await database(env)
    .prepare(
      `SELECT tenant_id, status, worker_script_name
       FROM admin_tenants
       WHERE tenant_id = ?
       LIMIT 1`,
    )
    .bind(tenantId)
    .first();
  if (!tenant) throw new HttpError(404, "Tenant not found");
  if (tenant.status !== "ACTIVE") throw new HttpError(403, "Tenant is unavailable");
  if (principal.role === "ADMIN_OWNER" && principal.tenantId !== tenantId) {
    throw new HttpError(403, "Tenant access denied");
  }
  if (
    MEMBER_ROLES.has(principal.role) &&
    (principal.tenantId !== tenantId ||
      (url.searchParams.has("branch_id") &&
        url.searchParams.get("branch_id") !== principal.branchId))
  ) {
    throw new HttpError(403, "Tenant or branch access denied");
  }
  if (!env.DISPATCHER || typeof env.DISPATCHER.get !== "function") {
    throw new HttpError(503, "Tenant dispatch is not configured");
  }

  const page = pagination(url);
  const dispatchUrl = new URL(request.url);
  dispatchUrl.searchParams.delete("tenant_id");
  dispatchUrl.searchParams.delete("branch_id");
  dispatchUrl.searchParams.set("limit", String(page.limit));
  dispatchUrl.searchParams.set("offset", String(page.offset));

  const incomingHeaders = new Headers(request.headers);
  incomingHeaders.delete("authorization");
  incomingHeaders.delete("cookie");
  incomingHeaders.delete("x-platform-user-id");
  incomingHeaders.delete("x-platform-role");
  incomingHeaders.delete("x-platform-tenant-id");
  incomingHeaders.delete("x-platform-branch-id");
  const forwardedOptions = {
    method: request.method,
    headers: incomingHeaders,
  };
  if (request.method !== "GET" && request.method !== "HEAD") {
    forwardedOptions.body = await boundedRequestBody(request);
  }
  const forwardedRequest = new Request(dispatchUrl, forwardedOptions);

  let response;
  try {
    const tenantWorker = env.DISPATCHER.get(tenant.worker_script_name, {
      props: {
        userId: principal.userId,
        role: principal.role,
        tenantId,
        branchId: principal.branchId,
      },
    });
    response = await tenantWorker.fetch(forwardedRequest);
  } catch (error) {
    console.error(
      JSON.stringify({
        message: "Tenant Worker dispatch failed",
        tenant_id: tenantId,
        error_type: error instanceof Error ? error.name : "UnknownError",
      }),
    );
    throw new HttpError(502, "Tenant service is unavailable");
  }
  return response;
}

async function routeRequest(request, env, cors) {
  const url = new URL(request.url);
  if (request.method === "OPTIONS") {
    if (!cors["access-control-allow-origin"]) {
      throw new HttpError(403, "A configured browser origin is required");
    }
    return new Response(null, { status: 204, headers: cors });
  }

  if (url.pathname === "/health" && request.method === "GET") {
    return json({ status: "ok" }, 200, cors);
  }
  if (!url.pathname.startsWith("/api/")) return json({ error: "Not found" }, 404, cors);

  const userId = await authenticate(request, env);
  const principal = await resolvePrincipal(userId, env);

  if (url.pathname === "/api/auth/me") {
    if (request.method !== "GET") {
      throw new HttpError(405, "Method not allowed", { allow: "GET, OPTIONS" });
    }
    return json(
      {
        data: {
          user_id: principal.userId,
          role: principal.role,
          tenant_id: principal.tenantId,
          branch_id: principal.branchId,
        },
      },
      200,
      cors,
    );
  }

  if (url.pathname === "/api/tenants") {
    if (request.method !== "GET") {
      throw new HttpError(405, "Tenant provisioning uses the trusted provisioning utility", {
        allow: "GET, OPTIONS",
      });
    }
    return withHeaders(await listTenants(url, principal, env), cors);
  }

  const tenantPath = url.pathname.match(/^\/api\/tenants\/([^/]+)$/);
  if (tenantPath) {
    if (request.method !== "PATCH") {
      throw new HttpError(405, "Method not allowed", { allow: "PATCH, OPTIONS" });
    }
    let tenantId;
    try {
      tenantId = decodeURIComponent(tenantPath[1]);
    } catch {
      throw new HttpError(404, "Tenant not found");
    }
    return withHeaders(await manageTenantStatus(request, tenantId, principal, env), cors);
  }

  const response = await dispatchTenant(request, url, principal, env);
  return withHeaders(response, cors);
}

export default {
  async fetch(request, env) {
    let cors = {};
    try {
      cors = corsHeaders(request, env);
      return await routeRequest(request, env, cors);
    } catch (error) {
      if (error instanceof HttpError) {
        return json({ error: error.message }, error.status, { ...cors, ...error.headers });
      }
      console.error(
        JSON.stringify({
          message: "Unhandled control-plane request failure",
          path: new URL(request.url).pathname,
          error_type: error instanceof Error ? error.name : "UnknownError",
        }),
      );
      return json({ error: "Internal server error" }, 500, cors);
    }
  },
};
