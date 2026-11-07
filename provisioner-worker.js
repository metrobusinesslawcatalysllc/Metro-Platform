import tenantSchema from "./tenant-schema.sql";
import tenantWorkerSource from "./tenant-worker.js";

const API_BASE = "https://api.cloudflare.com/client/v4";
const MAX_BODY_BYTES = 8192;
const MAX_RISK_LIMIT_MINOR = Number.MAX_SAFE_INTEGER;
const MAX_FEE_BASIS_POINTS = 10000;
const USER_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9.!#$%&'*+/=?^_`{|}~@:-]{0,127}$/;
const EMAIL_PATTERN =
  /^[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+$/i;

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

class CloudflareApiError extends Error {
  constructor(status) {
    super(`Cloudflare API request failed (${status})`);
    this.status = status;
  }
}

function json(data, status = 200) {
  return Response.json(data, {
    status,
    headers: {
      "cache-control": "no-store",
      "content-type": "application/json; charset=utf-8",
      "x-content-type-options": "nosniff",
    },
  });
}

function encodeBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function verifyInternalRequest(request, body, env) {
  const timestamp = request.headers.get("x-provisioner-timestamp");
  const signature = request.headers.get("x-provisioner-signature");
  const secret = env.PROVISIONER_SHARED_SECRET;
  if (
    typeof secret !== "string" ||
    new TextEncoder().encode(secret).byteLength < 32 ||
    !timestamp ||
    !/^\d{13}$/.test(timestamp) ||
    Math.abs(Date.now() - Number(timestamp)) > 60_000 ||
    !signature ||
    !/^[A-Za-z0-9_-]+$/.test(signature)
  ) {
    throw new HttpError(401, "Internal authorization required");
  }

  let valid = false;
  try {
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"],
    );
    const encodedSignature = Uint8Array.from(
      atob(signature.replace(/-/g, "+").replace(/_/g, "/") +
        "=".repeat((4 - signature.length % 4) % 4)),
      (character) => character.charCodeAt(0),
    );
    valid = await crypto.subtle.verify(
      "HMAC",
      key,
      encodedSignature,
      new TextEncoder().encode(`${timestamp}.${body}`),
    );
  } catch {
    throw new HttpError(401, "Internal authorization required");
  }
  if (!valid) throw new HttpError(401, "Internal authorization required");
}

async function readBody(request) {
  if (!request.headers.get("content-type")?.toLowerCase().startsWith("application/json")) {
    throw new HttpError(415, "Content-Type must be application/json");
  }
  const declaredLength = Number(request.headers.get("content-length"));
  if (Number.isFinite(declaredLength) && declaredLength > MAX_BODY_BYTES) {
    throw new HttpError(413, "Request body is too large");
  }

  const body = await request.text();
  if (new TextEncoder().encode(body).byteLength > MAX_BODY_BYTES) {
    throw new HttpError(413, "Request body is too large");
  }
  return body;
}

function validateProvisioningPayload(payload) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new HttpError(400, "Invalid provisioning payload");
  }
  const brokerName =
    typeof payload.broker_name === "string" ? payload.broker_name.trim() : "";
  const adminEmail =
    typeof payload.admin_email === "string" ? payload.admin_email.trim() : "";
  if (typeof brokerName !== "string" || brokerName.length < 1 || brokerName.length > 120) {
    throw new HttpError(400, "broker_name must be 1-120 characters");
  }
  if (
    typeof adminEmail !== "string" ||
    adminEmail.length > 128 ||
    !EMAIL_PATTERN.test(adminEmail) ||
    !USER_ID_PATTERN.test(adminEmail)
  ) {
    throw new HttpError(400, "admin_email must be a valid email address");
  }
  if (
    !Number.isSafeInteger(payload.risk_limit_minor) ||
    payload.risk_limit_minor < 1 ||
    payload.risk_limit_minor > MAX_RISK_LIMIT_MINOR
  ) {
    throw new HttpError(400, "risk_limit_minor must be a positive safe integer");
  }
  if (
    !Number.isSafeInteger(payload.fee_basis_points) ||
    payload.fee_basis_points < 0 ||
    payload.fee_basis_points > MAX_FEE_BASIS_POINTS
  ) {
    throw new HttpError(400, `fee_basis_points must be 0-${MAX_FEE_BASIS_POINTS}`);
  }
  if (
    typeof payload.super_master_user_id !== "string" ||
    !USER_ID_PATTERN.test(payload.super_master_user_id)
  ) {
    throw new HttpError(400, "Invalid Super Master identity");
  }
  return {
    brokerName,
    adminEmail,
    riskLimitMinor: payload.risk_limit_minor,
    feeBasisPoints: payload.fee_basis_points,
    superMasterUserId: payload.super_master_user_id,
  };
}

function requireBindings(env) {
  if (!env.CONTROL_DB || typeof env.CONTROL_DB.prepare !== "function") {
    throw new HttpError(503, "Control database is not configured");
  }
  for (const name of ["CLOUDFLARE_ACCOUNT_ID", "CLOUDFLARE_API_TOKEN", "DISPATCH_NAMESPACE"]) {
    if (typeof env[name] !== "string" || !env[name]) {
      throw new HttpError(503, "Provisioning service is not configured");
    }
  }
  if (
    !/^[A-Za-z0-9_-]{1,64}$/.test(env.CLOUDFLARE_ACCOUNT_ID) ||
    !/^[A-Za-z0-9_-]{1,64}$/.test(env.DISPATCH_NAMESPACE)
  ) {
    throw new HttpError(503, "Provisioning service is not configured");
  }
  return env.CONTROL_DB;
}

async function cloudflareRequest(env, path, { method = "GET", body, form } = {}) {
  const headers = new Headers({ Authorization: `Bearer ${env.CLOUDFLARE_API_TOKEN}` });
  if (body !== undefined) headers.set("content-type", "application/json");
  const response = await fetch(`${API_BASE}${path}`, {
    method,
    headers,
    body: form ?? (body === undefined ? undefined : JSON.stringify(body)),
    redirect: "error",
    signal: AbortSignal.timeout(30_000),
  });

  let payload;
  try {
    payload = await response.json();
  } catch {
    throw new Error(`Cloudflare API returned an invalid response (${response.status})`);
  }
  if (!response.ok || payload.success !== true) {
    throw new CloudflareApiError(response.status);
  }
  return payload.result;
}

async function executeD1(env, databaseId, sql, params = []) {
  const result = await cloudflareRequest(
    env,
    `/accounts/${env.CLOUDFLARE_ACCOUNT_ID}/d1/database/${databaseId}/query`,
    { method: "POST", body: { sql, params } },
  );
  if (!Array.isArray(result) || result.length === 0) {
    throw new Error("D1 returned no statement results");
  }
  const failed = result.find((statement) => statement.success !== true);
  if (failed) throw new Error("D1 schema or seed statement failed");
}

function safeSlug(value) {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 28) || "tenant";
}

async function deleteTenantWorker(env, scriptName) {
  try {
    await cloudflareRequest(
      env,
      `/accounts/${env.CLOUDFLARE_ACCOUNT_ID}/workers/dispatch/namespaces/${env.DISPATCH_NAMESPACE}/scripts/${scriptName}`,
      { method: "DELETE" },
    );
  } catch (error) {
    if (error instanceof CloudflareApiError && error.status === 404) return;
    throw error;
  }
}

async function deleteTenantDatabase(env, databaseId) {
  try {
    await cloudflareRequest(
      env,
      `/accounts/${env.CLOUDFLARE_ACCOUNT_ID}/d1/database/${databaseId}`,
      { method: "DELETE" },
    );
  } catch (error) {
    if (error instanceof CloudflareApiError && error.status === 404) return;
    throw error;
  }
}

async function createTenantWorker(env, scriptName, tenantId, databaseId) {
  const metadata = {
    main_module: "tenant-worker.js",
    compatibility_date: new Date().toISOString().slice(0, 10),
    bindings: [
      { type: "d1", name: "DB", id: databaseId },
      { type: "plain_text", name: "TENANT_ID", text: tenantId },
    ],
  };
  const form = new FormData();
  form.set(
    "metadata",
    new Blob([JSON.stringify(metadata)], { type: "application/json" }),
    "metadata.json",
  );
  form.set(
    "tenant-worker.js",
    new Blob([tenantWorkerSource], { type: "application/javascript+module" }),
    "tenant-worker.js",
  );
  await cloudflareRequest(
    env,
    `/accounts/${env.CLOUDFLARE_ACCOUNT_ID}/workers/dispatch/namespaces/${env.DISPATCH_NAMESPACE}/scripts/${scriptName}`,
    { method: "PUT", form },
  );
}

async function provisionTenant(env, input) {
  const db = requireBindings(env);
  const superMaster = await db
    .prepare(
      `SELECT user_id
       FROM platform_operators
       WHERE user_id = ? AND role = 'SUPER_MASTER' AND is_active = 1
       LIMIT 1`,
    )
    .bind(input.superMasterUserId)
    .first();
  if (!superMaster) throw new HttpError(403, "Super Master is not active");

  const owner = await db
    .prepare(
      `SELECT user_id FROM platform_operators WHERE user_id = ?
       UNION ALL
       SELECT user_id FROM tenant_memberships WHERE user_id = ?
       LIMIT 1`,
    )
    .bind(input.adminEmail, input.adminEmail)
    .first();
  if (owner) throw new HttpError(409, "Admin Email already exists in the control plane");

  const tenantId = crypto.randomUUID();
  const shortId = tenantId.replaceAll("-", "").slice(0, 12);
  const suffix = `${safeSlug(input.brokerName)}-${shortId}`.slice(0, 63);
  const databaseName = `tenant-${suffix}`.slice(0, 63);
  const workerScriptName = `tenant-${suffix}`.slice(0, 63);
  let databaseId;
  let workerUploadAttempted = false;
  let registrationAttempted = false;

  try {
    const createdDatabase = await cloudflareRequest(
      env,
      `/accounts/${env.CLOUDFLARE_ACCOUNT_ID}/d1/database`,
      { method: "POST", body: { name: databaseName } },
    );
    databaseId = createdDatabase?.uuid;
    if (!createdDatabase?.uuid || createdDatabase.name !== databaseName) {
      throw new Error("Cloudflare did not return the expected tenant D1 database");
    }

    await executeD1(env, databaseId, tenantSchema);
    await executeD1(
      env,
      databaseId,
      `INSERT INTO tenant_metadata (
         tenant_id, risk_limit_minor, fee_basis_points
       ) VALUES (?, ?, ?)`,
      [tenantId, input.riskLimitMinor, input.feeBasisPoints],
    );
    workerUploadAttempted = true;
    await createTenantWorker(env, workerScriptName, tenantId, databaseId);

    registrationAttempted = true;
    await db.batch([
      db
        .prepare(
          `INSERT INTO platform_operators (user_id, role, is_active)
           VALUES (?, 'ADMIN_OWNER', 1)`,
        )
        .bind(input.adminEmail),
      db
        .prepare(
          `INSERT INTO admin_tenants (
             tenant_id, tenant_name, admin_owner_user_id,
             provisioned_by_super_master_id, d1_database_id,
             d1_database_name, worker_script_name
           ) VALUES (?, ?, ?, ?, ?, ?, ?)`,
        )
        .bind(
          tenantId,
          input.brokerName,
          input.adminEmail,
          input.superMasterUserId,
          databaseId,
          databaseName,
          workerScriptName,
        ),
    ]);
  } catch (error) {
    console.error(JSON.stringify({
    message: "Tenant infrastructure provisioning failed",
    tenant_id: tenantId,
    database_name: databaseName,
    worker_script_name: workerScriptName,
    error_type: error instanceof Error ? error.name : "UnknownError",
    }));
    if (registrationAttempted) {
      let registration;
      try {
        registration = await db
          .prepare("SELECT tenant_id FROM admin_tenants WHERE tenant_id = ? LIMIT 1")
          .bind(tenantId)
          .first();
      } catch {
        throw new Error(
          `Could not verify tenant registration; resources were retained for reconciliation (${tenantId})`,
          { cause: error },
        );
      }
      if (registration) {
        throw new Error(
          `Tenant registration may have committed; resources were retained for reconciliation (${tenantId})`,
          { cause: error },
        );
      }
    }

    const cleanupFailures = [];
    if (workerUploadAttempted) {
      try {
        await deleteTenantWorker(env, workerScriptName);
      } catch {
        cleanupFailures.push("tenant Worker");
      }
    }
    if (databaseId) {
      try {
        await deleteTenantDatabase(env, databaseId);
      } catch {
        cleanupFailures.push("tenant D1 database");
      }
    }
    if (cleanupFailures.length) {
      throw new Error(
        `Provisioning failed; inspect Cloudflare for remaining ${cleanupFailures.join(" and ")}`,
        { cause: error },
      );
    }
    throw error;
  }

  return {
    tenant_id: tenantId,
    broker_name: input.brokerName,
    admin_email: input.adminEmail,
    risk_limit_minor: input.riskLimitMinor,
    fee_basis_points: input.feeBasisPoints,
    admin_login_path: "/admin-owner.html",
    client_login_path: "/client.html",
  };
}

export default {
  async fetch(request, env) {
    try {
      if (request.method !== "POST" || new URL(request.url).pathname !== "/provision") {
        throw new HttpError(404, "Not found");
      }
      const body = await readBody(request);
      await verifyInternalRequest(request, body, env);
      let payload;
      try {
        payload = JSON.parse(body);
      } catch {
        throw new HttpError(400, "Invalid JSON request body");
      }
      const input = validateProvisioningPayload(payload);
      const data = await provisionTenant(env, input);
      return json({ data }, 201);
    } catch (error) {
      if (error instanceof HttpError) return json({ error: error.message }, error.status);
      console.error(JSON.stringify({
        message: "Tenant provisioning failed",
        error_type: error instanceof Error ? error.name : "UnknownError",
      }));
      return json({ error: "Tenant provisioning failed; check the provisioner logs" }, 502);
    }
  },
};
