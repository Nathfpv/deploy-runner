const ISSUER = "https://token.actions.githubusercontent.com";
const JWKS_URL = "https://token.actions.githubusercontent.com/.well-known/jwks";
const UPSTREAM = "https://api.cloudflare.com/client/v4";

function b64urlDecode(input) {
  const s = input.replace(/-/g, "+").replace(/_/g, "/");
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  return Uint8Array.from(atob(s + pad), (c) => c.charCodeAt(0));
}

function decodeJson(segment) {
  return JSON.parse(new TextDecoder().decode(b64urlDecode(segment)));
}

async function importRsaJwk(jwk) {
  return crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"],
  );
}

async function verifyGithubOidc(token, env) {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("malformed JWT");
  const [h, p, s] = parts;
  const header = decodeJson(h);
  const claims = decodeJson(p);

  if (header.alg !== "RS256" || !header.kid) throw new Error("unexpected JWT algorithm");
  const now = Math.floor(Date.now() / 1000);
  if (claims.iss !== ISSUER) throw new Error("unexpected issuer");
  if (claims.aud !== env.EXPECTED_AUDIENCE) throw new Error("unexpected audience");
  if (!claims.exp || claims.exp < now) throw new Error("expired token");
  if (claims.nbf && claims.nbf > now + 30) throw new Error("token not active");
  if (claims.repository !== env.EXPECTED_REPOSITORY) throw new Error("unexpected repository");
  if (String(claims.repository_id) !== env.EXPECTED_REPOSITORY_ID) throw new Error("unexpected repository id");
  if (claims.ref !== env.EXPECTED_REF) throw new Error("unexpected ref");
  if (claims.workflow_ref !== env.EXPECTED_WORKFLOW_REF) throw new Error("unexpected workflow");
  if (!["push", "workflow_dispatch"].includes(claims.event_name)) throw new Error("unexpected event");

  const jwksResp = await fetch(JWKS_URL, { cf: { cacheTtl: 300, cacheEverything: true } });
  if (!jwksResp.ok) throw new Error("cannot load GitHub JWKS");
  const jwks = await jwksResp.json();
  const jwk = (jwks.keys || []).find((k) => k.kid === header.kid);
  if (!jwk) throw new Error("unknown signing key");

  const key = await importRsaJwk(jwk);
  const ok = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    key,
    b64urlDecode(s),
    new TextEncoder().encode(`${h}.${p}`),
  );
  if (!ok) throw new Error("invalid JWT signature");
  return claims;
}

function allowedPath(url, env) {
  const p = url.pathname;
  if (!p.startsWith("/client/v4/")) return false;
  const apiPath = p.slice("/client/v4".length);

  if (apiPath === "/user/tokens/verify") return true;
  if (apiPath === `/accounts/${env.CLOUDFLARE_ACCOUNT_ID}`) return true;
  if (apiPath.startsWith(`/accounts/${env.CLOUDFLARE_ACCOUNT_ID}/workers/`)) return true;

  // Wrangler resolves the maffeo.ch zone before updating Worker routes.
  if (apiPath === "/zones" && url.searchParams.get("name") === "maffeo.ch") return true;
  if (/^\/zones\/[0-9a-f]{32}(?:\/workers\/routes)?$/.test(apiPath)) return true;

  return false;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/health") {
      return Response.json({ ok: true, auth: "github-oidc", upstream: "cloudflare" });
    }

    if (!env.UPSTREAM_CLOUDFLARE_API_TOKEN) {
      return new Response("Relay secret missing", { status: 503 });
    }

    const auth = request.headers.get("Authorization") || "";
    if (!auth.startsWith("Bearer ")) return new Response("Unauthorized", { status: 401 });

    try {
      await verifyGithubOidc(auth.slice(7), env);
    } catch (err) {
      return new Response(`Unauthorized: ${err.message}`, { status: 401 });
    }

    if (!allowedPath(url, env)) {
      return new Response("Forbidden API path", { status: 403 });
    }

    const upstreamUrl = UPSTREAM + url.pathname.slice("/client/v4".length) + url.search;
    const headers = new Headers(request.headers);
    headers.set("Authorization", `Bearer ${env.UPSTREAM_CLOUDFLARE_API_TOKEN}`);
    headers.set("Host", "api.cloudflare.com");
    headers.delete("cf-connecting-ip");
    headers.delete("cf-ipcountry");
    headers.delete("cf-ray");
    headers.delete("x-forwarded-for");

    return fetch(upstreamUrl, {
      method: request.method,
      headers,
      body: ["GET", "HEAD"].includes(request.method) ? undefined : request.body,
      redirect: "manual",
    });
  },
};
