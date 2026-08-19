// functions/_middleware.js
// Gatekeeper for the whole site. Runs on every request before any page loads.
// The lock screen markup itself lives at /lock-screen.html — this file only
// handles the password check, cookie, and injecting the error message.
// Requires an environment variable named SITE_PASSWORD to be set in the
// Cloudflare Pages dashboard (Settings > Environment variables) — NOT in this file.

const COOKIE_NAME = "sw_access";
// Session-only for now while testing — closing the browser clears it, so you'll
// see the lock screen again next time. Swap back to a Max-Age (e.g. 60*60*24*30
// for 30 days) once you're ready to stop re-testing constantly.

export async function onRequest(context) {
  const { request, env, next } = context;
  const url = new URL(request.url);

  // Let static assets through untouched — otherwise the lock page's own
  // fonts/css/images (and lock-screen.html itself) get swallowed by the gate
  // before they can load.
  const isAsset = /\.(html|ttf|otf|woff2?|css|js|png|jpe?g|gif|svg|webp|ico)$/i.test(
    url.pathname
  );
  if (isAsset) {
    return next();
  }

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
      return new Response(null, {
        status: 303,
        headers: {
          Location: "/",
          "Set-Cookie": `${COOKIE_NAME}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax`,
        },
      });
    }

    return renderLockPage(context, { error: true, status: 401 });
  }

  // Otherwise, show the lock screen for any page on the site
  return renderLockPage(context, { error: false, status: 200 });
}

async function hashPassword(password) {
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function renderLockPage({ request, env }, { error, status }) {
  const assetUrl = new URL("/lock-screen.html", request.url);
  const assetResponse = await env.ASSETS.fetch(assetUrl);
  let html = await assetResponse.text();

  const errorMarkup = error
    ? '<p class="error">That password didn\'t work — try again.</p>'
    : "";
  html = html.replace("{{ERROR}}", errorMarkup);

  return new Response(html, {
    status,
    headers: { "Content-Type": "text/html; charset=UTF-8" },
  });
}
