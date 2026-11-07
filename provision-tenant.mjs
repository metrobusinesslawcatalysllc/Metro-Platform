import { readFile } from "node:fs/promises";

const API_BASE = "https://api.cloudflare.com/client/v4";
const ACCOUNT_ID = process.env.CLOUDFLARE_ACCOUNT_ID;
const API_TOKEN = process.env.CLOUDFLARE_API_TOKEN;
const CONTROL_DATABASE_ID = process.env.CONTROL_D1_DATABASE_ID;
const DISPATCH_NAMESPACE = process.env.DISPATCH_NAMESPACE;
const SUPER_MASTER_ACCESS_TOKEN = process.env.SUPER_MASTER_ACCESS_TOKEN;
const args = new Map();

for (let index = 2; index < process.argv.length; index += 2) {
  const key = process.argv[index];
  const value = process.argv[index + 1];
  if (!key?.startsWith("--") || !value || value.startsWith("--")) {
    throw new Error("Arguments must be supplied as --name value pairs");
  }
  if (args.has(key)) throw new Error(`Duplicate argument: ${key}`);
  args.set(key, value);
}

for (const key of args.keys()) {
  if (!["--tenant-name", "--admin-owner-user-id", "--super-master-user-id"].includes(key)) {
    throw new Error(`Unknown argument: ${key}`);
  }
}

const tenantName = args.get("--tenant-name")?.trim();
const ownerUserId = args.get("--admin-owner-user-id");
const superMasterUserId = args.get("--super-master-user-id");

if (
  !ACCOUNT_ID ||
  !API_TOKEN ||
  !CONTROL_DATABASE_ID ||
  !DISPATCH_NAMESPACE ||
  !SUPER_MASTER_ACCESS_TOKEN ||
  !process.env.AUTH_JWT_SECRET ||
  !process.env.AUTH_JWT_ISSUER ||
  !process.env.AUTH_JWT_AUDIENCE
) {
  throw new Error(
    "Set CLOUDFLARE_ACCOUNT_ID, CLOUDFLARE_API_TOKEN, CONTROL_D1_DATABASE_ID, DISPATCH_NAMESPACE, SUPER_MASTER_ACCESS_TOKEN, AUTH_JWT_SECRET, AUTH_JWT_ISSUER, and AUTH_JWT_AUDIENCE",
  );
}
if (!/^[A-Za-z0-9_-]{1,64}$/.test(ACCOUNT_ID)) {
  throw new Error("CLOUDFLARE_ACCOUNT_ID has an invalid format");
}
if (
  !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
    CONTROL_DATABASE_ID,
  )
) {
  throw new Error("CONTROL_D1_DATABASE_ID must be a D1 database UUID");
}
if (!/^[A-Za-z0-9_-]{1,64}$/.test(DISPATCH_NAMESPACE)) {
  throw new Error("DISPATCH_NAMESPACE has an invalid format");
}
if (!tenantName || tenantName.length > 120) {
  throw new Error("--tenant-name must be 1-120 characters");
}
if (
  !ownerUserId ||
  ownerUserId.length > 128 ||
  !superMasterUserId ||
  superMasterUserId.length > 128
) {
  throw new Error("--admin-owner-user-id and --super-master-user-id are required");
}

function decodeBase64Url(value) {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new Error("Invalid token encoding");
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const decoded = Buffer.from(
    base64 + "=".repeat((4 - base64.length % 4) % 4),
    "base64",
  );
  return new Uint8Array(decoded);
}

async function verifyProvisioningToken(expectedUserId) {
  const tokenMatch = /^(?:Bearer\s+)?([^\s]{1,8192})$/i.exec(
    SUPER_MASTER_ACCESS_TOKEN.trim(),
  );
  if (!tokenMatch) throw new Error("SUPER_MASTER_ACCESS_TOKEN must be a JWT");
  const [headerPart, claimsPart, signaturePart, extra] = tokenMatch[1].split(".");
  if (!headerPart || !claimsPart || !signaturePart || extra !== undefined) {
    throw new Error("Invalid Super Master access token");
  }

  let header;
  let claims;
  let signature;
  try {
    header = JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(
        decodeBase64Url(headerPart),
      ),
    );
    claims = JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(
        decodeBase64Url(claimsPart),
      ),
    );
    signature = decodeBase64Url(signaturePart);
  } catch {
    throw new Error("Invalid Super Master access token");
  }

  if (
    !header ||
    header.alg !== "HS256" ||
    header.typ !== "JWT" ||
    !claims ||
    claims.sub !== expectedUserId ||
    claims.iss !== process.env.AUTH_JWT_ISSUER ||
    !(
      claims.aud === process.env.AUTH_JWT_AUDIENCE ||
      (Array.isArray(claims.aud) &&
        claims.aud.includes(process.env.AUTH_JWT_AUDIENCE))
    ) ||
    !Number.isSafeInteger(claims.iat) ||
    !Number.isSafeInteger(claims.exp)
  ) {
    throw new Error(
      "Token subject or claims do not identify the configured Super Master",
    );
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
    throw new Error("Super Master access token is expired or not yet valid");
  }

  const secret = process.env.AUTH_JWT_SECRET;
  if (
    typeof secret !== "string" ||
    new TextEncoder().encode(secret).byteLength < 32
  ) {
    throw new Error("AUTH_JWT_SECRET must contain at least 32 UTF-8 bytes");
  }

  let valid;
  try {
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"],
    );
    valid = await crypto.subtle.verify(
      "HMAC",
      key,
      signature,
      new TextEncoder().encode(`${headerPart}.${claimsPart}`),
    );
  } catch {
    throw new Error("Unable to verify Super Master access token");
  }
  if (!valid) throw new Error("Invalid Super Master access token signature");
}

async function cloudflareRequest(path, { method = "GET", body, form } = {}) {
  const headers = new Headers({ Authorization: `Bearer ${API_TOKEN}` });
  if (body !== undefined) headers.set("content-type", "application/json");
  const response = await fetch(`${API_BASE}${path}`, {
    method,
    headers,
    body: form ?? (body === undefined ? undefined : JSON.stringify(body)),
    redirect: "error",
    signal: AbortSignal.timeout(30000),
  });

  let payload;
  try {
    payload = await response.json();
  } catch {
    throw new Error(`Cloudflare API returned an invalid response (${response.status})`);
  }
  if (!response.ok || payload.success !== true) {
    const messages = Array.isArray(payload.errors)
      ? payload.errors
          .slice(0, 3)
          .map((item) => String(item.message || "Cloudflare API request failed"))
          .join("; ")
      : "Cloudflare API request failed";
    throw new Error(`Cloudflare API ${response.status}: ${messages}`);
  }
  return payload.result;
}

async function queryControl(sql, params = []) {
  const result = await executeD1(
    CONTROL_DATABASE_ID,
    sql,
    params,
  );
  return result[0];
}

async function executeD1(databaseId, sql, params = []) {
  const result = await cloudflareRequest(
    `/accounts/${ACCOUNT_ID}/d1/database/${databaseId}/query`,
    { method: "POST", body: { sql, params } },
  );
  if (!Array.isArray(result) || result.length === 0) {
    throw new Error("D1 returned no statement results");
  }
  const failedStatement = result.find((statement) => statement.success !== true);
  if (failedStatement) {
    throw new Error(
      `D1 statement failed: ${String(failedStatement.error || "unknown database error")}`,
    );
  }
  return result;
}

async function deleteTenantWorker(scriptName) {
  return cloudflareRequest(
    `/accounts/${ACCOUNT_ID}/workers/dispatch/namespaces/${DISPATCH_NAMESPACE}/scripts/${scriptName}`,
    { method: "DELETE" },
  );
}

async function deleteTenantDatabase(databaseId) {
  return cloudflareRequest(
    `/accounts/${ACCOUNT_ID}/d1/database/${databaseId}`,
    { method: "DELETE" },
  );
}

function safeSlug(value) {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 28) || "tenant";
}

async function main() {
  await verifyProvisioningToken(superMasterUserId);

  const masterResult = await queryControl(
    `SELECT user_id
     FROM platform_operators
     WHERE user_id = ? AND role = 'SUPER_MASTER' AND is_active = 1
     LIMIT 1`,
    [superMasterUserId],
  );
  if (!masterResult.results?.length) {
    throw new Error("The specified user is not an active Super Master in the control database");
  }

  const ownerResult = await queryControl(
    `SELECT user_id
     FROM platform_operators
     WHERE user_id = ?
     UNION ALL
     SELECT user_id
     FROM tenant_memberships
     WHERE user_id = ?
     LIMIT 1`,
    [ownerUserId, ownerUserId],
  );
  if (ownerResult.results?.length) {
    throw new Error("Admin Owner already exists in the control database");
  }

  const tenantId = crypto.randomUUID();
  const shortId = tenantId.replaceAll("-", "").slice(0, 12);
  const slug = safeSlug(tenantName);
  const databaseName = `tenant-${slug}-${shortId}`.slice(0, 63);
  const workerScriptName = `tenant-${slug}-${shortId}`.slice(0, 63);
  let databaseId;
  let workerUploaded = false;
  let ownerInserted = false;
  let tenantRegistrationAttempted = false;

  try {
    const createdDatabase = await cloudflareRequest(
      `/accounts/${ACCOUNT_ID}/d1/database`,
      { method: "POST", body: { name: databaseName } },
    );
    if (!createdDatabase?.uuid || createdDatabase.name !== databaseName) {
      throw new Error("Cloudflare did not return the expected tenant D1 database");
    }
    databaseId = createdDatabase.uuid;

    const schema = await readFile(new URL("./tenant-schema.sql", import.meta.url), "utf8");
    await executeD1(databaseId, schema);
    await executeD1(
      databaseId,
      "INSERT INTO tenant_metadata (tenant_id) VALUES (?)",
      [tenantId],
    );

    const tenantWorkerSource = await readFile(
      new URL("./tenant-worker.js", import.meta.url),
      "utf8",
    );
    const metadata = {
      main_module: "tenant-worker.js",
      compatibility_date: new Date().toISOString().slice(0, 10),
      bindings: [
        {
          type: "d1",
          name: "DB",
          id: databaseId,
        },
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
      `/accounts/${ACCOUNT_ID}/workers/dispatch/namespaces/${DISPATCH_NAMESPACE}/scripts/${workerScriptName}`,
      { method: "PUT", form },
    );
    workerUploaded = true;

    await queryControl(
      `INSERT INTO platform_operators (user_id, role, is_active)
       VALUES (?, 'ADMIN_OWNER', 1)`,
      [ownerUserId],
    );
    ownerInserted = true;

    tenantRegistrationAttempted = true;
    await queryControl(
      `INSERT INTO admin_tenants (
         tenant_id, tenant_name, admin_owner_user_id,
         provisioned_by_super_master_id, d1_database_id,
         d1_database_name, worker_script_name
       )
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [
        tenantId,
        tenantName,
        ownerUserId,
        superMasterUserId,
        databaseId,
        databaseName,
        workerScriptName,
      ],
    );
  } catch (error) {
    if (tenantRegistrationAttempted) {
      let registration;
      try {
        registration = await queryControl(
          "SELECT tenant_id FROM admin_tenants WHERE tenant_id = ? LIMIT 1",
          [tenantId],
        );
      } catch {
        throw new Error(
          `Could not verify tenant registration; resources were retained to avoid ` +
            `leaving a registered tenant without its database or Worker. Verify tenant ` +
            `${tenantId}, database ${databaseId}, and Worker ${workerScriptName}.`,
          { cause: error },
        );
      }
      if (registration.results?.length) {
        throw new Error(
          `Tenant registration may have committed; resources were retained. ` +
            `Verify tenant ${tenantId}, database ${databaseId}, and Worker ${workerScriptName}.`,
          { cause: error },
        );
      }
    }

    const cleanupFailures = [];
    if (ownerInserted) {
      try {
        await queryControl(
          `DELETE FROM platform_operators
           WHERE user_id = ?
             AND role = 'ADMIN_OWNER'
             AND NOT EXISTS (
               SELECT 1 FROM admin_tenants WHERE admin_owner_user_id = ?
             )`,
          [ownerUserId, ownerUserId],
        );
      } catch {
        cleanupFailures.push("orphaned operator record");
      }
    }
    if (workerUploaded) {
      try {
        await deleteTenantWorker(workerScriptName);
      } catch {
        cleanupFailures.push("tenant Worker");
      }
    }
    if (databaseId) {
      try {
        await deleteTenantDatabase(databaseId);
      } catch {
        cleanupFailures.push("tenant D1 database");
      }
    }
    if (cleanupFailures.length) {
      throw new Error(
        `Provisioning failed; cleanup also failed for ${cleanupFailures.join(", ")}. ` +
          "Inspect Cloudflare resources before retrying.",
        { cause: error },
      );
    }
    throw error;
  }

  console.log(
    JSON.stringify({
      status: "provisioned",
      tenant_id: tenantId,
      tenant_name: tenantName,
      admin_owner_user_id: ownerUserId,
      database_name: databaseName,
      database_id: databaseId,
      worker_script_name: workerScriptName,
    }),
  );
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : "Tenant provisioning failed");
  process.exitCode = 1;
});
