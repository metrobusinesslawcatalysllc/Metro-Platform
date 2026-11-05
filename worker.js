const JSON_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store",
  "x-content-type-options": "nosniff",
};

const REST_RESOURCES = new Set([
  "profiles",
  "accounts",
  "positions",
  "deposit_vaults",
  "transfers",
]);

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const AMOUNT_PATTERN = /^(?:0|[1-9]\d{0,11})(?:\.\d{1,8})?$/;
const MAX_TRANSFER_BODY_BYTES = 4096;

function jsonResponse(body, status = 200, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...JSON_HEADERS, ...headers },
  });
}

function corsHeaders(request, env) {
  const origin = request.headers.get("Origin");
  if (!origin) return {};

  const allowedOrigins = (env.ALLOWED_ORIGINS || "")
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);

  if (!allowedOrigins.includes(origin)) return null;

  return {
    "access-control-allow-origin": origin,
    "access-control-allow-methods": "GET, POST, OPTIONS",
    "access-control-allow-headers": "authorization, content-type, idempotency-key",
    "access-control-max-age": "600",
    vary: "Origin",
  };
}

function withHeaders(response, additions) {
  const headers = new Headers(response.headers);
  for (const [name, value] of Object.entries(additions)) {
    headers.set(name, value);
  }
  headers.set("x-content-type-options", "nosniff");
  headers.set("cache-control", "no-store");
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

async function authenticate(request, env) {
  const authorization = request.headers.get("Authorization") || "";
  const match = /^Bearer ([^\s]{1,8192})$/i.exec(authorization);
  if (!match) return { response: jsonResponse({ error: "Authentication required" }, 401) };

  const baseUrl = getSupabaseUrl(env);
  if (!baseUrl || !env.SUPABASE_ANON_KEY) {
    return { response: jsonResponse({ error: "Supabase is not configured" }, 503) };
  }

  let response;
  try {
    response = await fetch(new URL("/auth/v1/user", baseUrl), {
      headers: {
        apikey: env.SUPABASE_ANON_KEY,
        Authorization: `Bearer ${match[1]}`,
        Accept: "application/json",
      },
    });
  } catch {
    return { response: jsonResponse({ error: "Authentication service unavailable" }, 502) };
  }

  if (response.status === 401 || response.status === 403) {
    return { response: jsonResponse({ error: "Invalid or expired session" }, 401) };
  }
  if (!response.ok) {
    return { response: jsonResponse({ error: "Authentication service unavailable" }, 502) };
  }

  let user;
  try {
    user = await response.json();
  } catch {
    return { response: jsonResponse({ error: "Invalid authentication response" }, 502) };
  }

  if (
    !user ||
    typeof user.id !== "string" ||
    !UUID_PATTERN.test(user.id) ||
    user.is_anonymous !== false
  ) {
    return { response: jsonResponse({ error: "A registered user session is required" }, 401) };
  }

  return { token: match[1], userId: user.id, baseUrl };
}

function getSupabaseUrl(env) {
  if (!env.SUPABASE_URL) return null;
  try {
    const url = new URL(env.SUPABASE_URL);
    if (url.protocol !== "https:" || url.username || url.password) return null;
    return url;
  } catch {
    return null;
  }
}

async function readJsonBody(request) {
  const contentLength = Number(request.headers.get("Content-Length") || 0);
  if (contentLength > MAX_TRANSFER_BODY_BYTES) {
    return { error: jsonResponse({ error: "Request body is too large" }, 413) };
  }
  if (!request.body) return { error: jsonResponse({ error: "A JSON body is required" }, 400) };

  const reader = request.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_TRANSFER_BODY_BYTES) {
        await reader.cancel();
        return { error: jsonResponse({ error: "Request body is too large" }, 413) };
      }
      chunks.push(value);
    }
  } catch {
    return { error: jsonResponse({ error: "Unable to read request body" }, 400) };
  }

  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }

  try {
    return { value: JSON.parse(new TextDecoder().decode(bytes)) };
  } catch {
    return { error: jsonResponse({ error: "Invalid JSON body" }, 400) };
  }
}

function validAmount(value) {
  if (typeof value !== "string" || !AMOUNT_PATTERN.test(value)) return false;
  return /[1-9]/.test(value.replace(".", ""));
}

async function proxyRest(request, env, auth, resource) {
  const url = new URL(request.url);
  const upstreamUrl = new URL(`/rest/v1/${resource}${url.search}`, auth.baseUrl);
  let upstream;
  try {
    upstream = await fetch(upstreamUrl, {
      method: "GET",
      headers: {
        apikey: env.SUPABASE_ANON_KEY,
        Authorization: `Bearer ${auth.token}`,
        Accept: request.headers.get("Accept") || "application/json",
      },
    });
  } catch {
    return jsonResponse({ error: "Database service unavailable" }, 502);
  }

  return new Response(upstream.body, {
    status: upstream.status,
    headers: {
      "content-type": upstream.headers.get("content-type") || "application/json",
      "content-range": upstream.headers.get("content-range") || "",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
    },
  });
}

async function createTransfer(request, env, auth) {
  const bodyResult = await readJsonBody(request);
  if (bodyResult.error) return bodyResult.error;
  const body = bodyResult.value;
  const idempotencyKey = request.headers.get("Idempotency-Key");

  if (
    !body ||
    !UUID_PATTERN.test(body.source_account_id || "") ||
    !UUID_PATTERN.test(body.destination_account_id || "") ||
    body.source_account_id === body.destination_account_id ||
    !UUID_PATTERN.test(idempotencyKey || "") ||
    !validAmount(body.amount)
  ) {
    return jsonResponse(
      { error: "Provide distinct account IDs, a positive decimal amount, and an Idempotency-Key UUID" },
      400,
    );
  }

  let upstream;
  try {
    upstream = await fetch(new URL("/rest/v1/rpc/transfer_between_accounts", auth.baseUrl), {
      method: "POST",
      headers: {
        apikey: env.SUPABASE_ANON_KEY,
        Authorization: `Bearer ${auth.token}`,
        "content-type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({
        p_source_account_id: body.source_account_id,
        p_destination_account_id: body.destination_account_id,
        p_amount: body.amount,
        p_idempotency_key: idempotencyKey,
      }),
    });
  } catch {
    return jsonResponse({ error: "Transfer service unavailable" }, 502);
  }

  if (!upstream.ok) {
    if (upstream.status === 401 || upstream.status === 403) {
      return jsonResponse({ error: "Transfer is not authorized" }, upstream.status);
    }
    if (upstream.status < 500) {
      return jsonResponse({ error: "Transfer rejected; verify account ownership, status, currency, and balance" }, 400);
    }
    return jsonResponse({ error: "Transfer service unavailable" }, 502);
  }

  let transferId;
  try {
    transferId = await upstream.json();
  } catch {
    return jsonResponse({ error: "Invalid transfer service response" }, 502);
  }
  return jsonResponse({ transfer_id: transferId }, 201);
}

async function marketFeed(request, env, auth) {
  if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
    return jsonResponse({ error: "WebSocket upgrade required" }, 426);
  }

  const gatewayUrl = env.CTRADE_MARKET_GATEWAY_URL;
  const accessToken = env.CTRADE_ACCESS_TOKEN;
  const accountId = env.CTRADE_ACCOUNT_ID;
  const clientId = env.CTRADE_CLIENT_ID;
  const clientSecret = env.CTRADE_SECRET;

  if (!gatewayUrl || !accessToken || !accountId || !clientId || !clientSecret) {
    return jsonResponse(
      { error: "Market feed is disabled until the trusted cTrader market gateway and server-side credentials are configured" },
      503,
    );
  }

  let upstreamUrl;
  try {
    upstreamUrl = new URL(gatewayUrl);
  } catch {
    return jsonResponse({ error: "Invalid cTrader market gateway configuration" }, 503);
  }
  if (upstreamUrl.protocol !== "wss:" || upstreamUrl.username || upstreamUrl.password) {
    return jsonResponse({ error: "The cTrader market gateway must use a credential-free WSS URL" }, 503);
  }

  let upstream;
  try {
    upstream = await fetch(upstreamUrl, {
      headers: {
        Upgrade: "websocket",
        Authorization: `Bearer ${accessToken}`,
        "x-ctrader-account-id": accountId,
        "x-ctrader-client-id": clientId,
        "x-ctrader-client-secret": clientSecret,
        "x-application-user-id": auth.userId,
        "x-market-data-only": "true",
      },
    });
  } catch {
    return jsonResponse({ error: "cTrader market gateway unavailable" }, 502);
  }

  if (upstream.status !== 101 || !upstream.webSocket) {
    return jsonResponse({ error: "cTrader market gateway rejected the connection" }, 502);
  }

  const pair = new WebSocketPair();
  const [client, server] = Object.values(pair);
  const upstreamSocket = upstream.webSocket;
  server.accept({ allowHalfOpen: true });
  upstreamSocket.accept({ allowHalfOpen: true });

  const forward = (source, destination) => {
    source.addEventListener("message", (event) => {
      if (destination.readyState === WebSocket.OPEN) destination.send(event.data);
    });
    source.addEventListener("close", (event) => {
      if (destination.readyState < WebSocket.CLOSING) {
        destination.close(event.code, event.reason);
      }
    });
    source.addEventListener("error", () => {
      if (destination.readyState < WebSocket.CLOSING) destination.close(1011, "Market feed error");
    });
  };

  forward(upstreamSocket, server);
  server.addEventListener("message", () => {
    // The browser receives a read-only feed and cannot send cTrader trading commands.
    if (server.readyState < WebSocket.CLOSING) server.close(1008, "Market feed is read-only");
    if (upstreamSocket.readyState < WebSocket.CLOSING) {
      upstreamSocket.close(1008, "Market feed is read-only");
    }
  });
  server.addEventListener("close", () => {
    if (upstreamSocket.readyState < WebSocket.CLOSING) upstreamSocket.close();
  });

  return new Response(null, { status: 101, webSocket: client });
}

export default {
  async fetch(request, env) {
    const cors = corsHeaders(request, env);
    if (cors === null) return jsonResponse({ error: "Origin is not allowed" }, 403);

    const url = new URL(request.url);
    if (request.method === "OPTIONS") {
      if (!cors["access-control-allow-origin"]) {
        return jsonResponse({ error: "A configured browser origin is required" }, 403);
      }
      return new Response(null, { status: 204, headers: cors });
    }

    if (url.pathname === "/health" && request.method === "GET") {
      return withHeaders(jsonResponse({ status: "ok" }), cors);
    }

    if (!url.pathname.startsWith("/api/")) {
      return withHeaders(jsonResponse({ error: "Not found" }, 404), cors);
    }

    const auth = await authenticate(request, env);
    if (auth.response) return withHeaders(auth.response, cors);

    if (url.pathname === "/api/market-feed" && request.method === "GET") {
      const response = await marketFeed(request, env, auth);
      return response.status === 101 ? response : withHeaders(response, cors);
    }

    if (url.pathname === "/api/transfers" && request.method === "POST") {
      return withHeaders(await createTransfer(request, env, auth), cors);
    }

    const resource = url.pathname.match(/^\/api\/([a-z_]+)$/)?.[1];
    if (request.method === "GET" && resource && REST_RESOURCES.has(resource)) {
      return withHeaders(await proxyRest(request, env, auth, resource), cors);
    }

    return withHeaders(jsonResponse({ error: "Not found" }, 404), cors);
  },
};
