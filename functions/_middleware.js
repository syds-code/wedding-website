// functions/_middleware.js
// Gatekeeper for the whole site. Runs on every request before any page loads.
// Requires an environment variable named SITE_PASSWORD to be set in the
// Cloudflare Pages dashboard (Settings > Environment variables) — NOT in this file.

const COOKIE_NAME = "sw_access";
const COOKIE_MAX_AGE_SECONDS = 60 * 60 * 24 * 30; // 30 days

export async function onRequest(context) {
  const { request, env, next } = context;
  const url = new URL(request.url);

  // Let the correct-password cookie value through
  const expectedToken = await hashPassword(env.SITE_PASSWORD || "");
  const cookieHeader = request.headers.get("Cookie") || "";
  const hasValidCookie = cookieHeader
    .split(";")
    .map((c) => c.trim())
    .some((c) => c === `${COOKIE_NAME}=${expectedToken}`);

  if (hasValidCookie) {
    return next();
  }

  // Handle password submission
  if (request.method === "POST" && url.pathname === "/__gate") {
    const formData = await request.formData();
    const submitted = formData.get("password") || "";

    if (submitted === env.SITE_PASSWORD) {
      const token = await hashPassword(submitted);
      const response = new Response(null, {
        status: 303,
        headers: {
          Location: "/",
          "Set-Cookie": `${COOKIE_NAME}=${token}; Max-Age=${COOKIE_MAX_AGE_SECONDS}; Path=/; HttpOnly; Secure; SameSite=Lax`,
        },
      });
      return response;
    }

    return new Response(renderLockPage({ error: true }), {
      status: 401,
      headers: { "Content-Type": "text/html; charset=UTF-8" },
    });
  }

  // Otherwise, show the lock screen for any page on the site
  return new Response(renderLockPage({ error: false }), {
    status: 200,
    headers: { "Content-Type": "text/html; charset=UTF-8" },
  });
}

async function hashPassword(password) {
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

function renderLockPage({ error }) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex, nofollow">
<title>Sydney &amp; Drew</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Fraunces:ital,wght@1,500&family=EB+Garamond:ital@1&display=swap" rel="stylesheet">
<style>
  @font-face {
    font-family: 'Sewell Wedding';
    src: url('/assets/SewellWedding-Regular.ttf') format('truetype');
    font-weight: normal;
    font-style: normal;
  }

  :root {
    --sand: #F5F2EA;
    --tulum: #AEA078;
    --cacao: #49391F;
    --caribbean: #6E92C4;
    --shoreline: #D0E2F4;
    --jungle: #848F5C;
    --agave: #C7D0A9;
  }

  * { box-sizing: border-box; }

  body {
    margin: 0;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    background: var(--shoreline);
    font-family: 'EB Garamond', Georgia, serif;
    color: var(--cacao);
    padding: 24px;
  }

  .gate {
    max-width: 420px;
    width: 100%;
    text-align: center;
  }

  .kicker {
    font-family: 'Fraunces', Georgia, serif;
    font-style: italic;
    font-weight: 500;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    font-size: 15px;
    color: var(--cacao);
    margin: 0 0 4px;
  }

  .script-line {
    font-family: 'Sewell Wedding', cursive;
    font-size: 44px;
    color: var(--cacao);
    margin: 4px 0;
    line-height: 1.2;
  }

  .sub {
    margin: 4px 0 36px;
  }

  form {
    display: flex;
    flex-direction: column;
    gap: 14px;
  }

  input[type="password"] {
    font-family: 'EB Garamond', Georgia, serif;
    font-style: italic;
    font-size: 16px;
    padding: 12px 16px;
    border: 1px solid var(--cacao);
    background: var(--sand);
    border-radius: 2px;
    color: var(--cacao);
    text-align: center;
  }

  input[type="password"]::placeholder {
    font-style: italic;
    color: var(--cacao);
    opacity: 0.6;
  }

  input[type="password"]:focus {
    outline: none;
    border-color: var(--caribbean);
  }

  button {
    font-family: 'EB Garamond', Georgia, serif;
    font-size: 15px;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    padding: 12px 20px;
    background: var(--caribbean);
    color: var(--sand);
    border: none;
    border-radius: 2px;
    cursor: pointer;
    transition: background 0.2s ease;
  }

  button:hover {
    background: var(--cacao);
  }

  .error {
    color: #a94442;
    font-size: 14px;
    margin: -6px 0 0;
    letter-spacing: 0.02em;
    font-style: italic;
  }
</style>
</head>
<body>
  <div class="gate">
    <p class="kicker">Welcome to the</p>
    <p class="script-line">Sewell Wedding</p>
    <p class="kicker sub">Website</p>
    <form method="POST" action="/__gate">
      <input
        type="password"
        name="password"
        placeholder="Please enter password"
        autofocus
        required
      >
      ${error ? '<p class="error">That password didn\'t work — try again.</p>' : ""}
      <button type="submit">Enter</button>
    </form>
  </div>
</body>
</html>`;
}
