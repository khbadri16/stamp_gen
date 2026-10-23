// Password lock for the whole site (Vercel Routing Middleware, runs before every request).
// The password is read from the SITE_PASSWORD environment variable set in Vercel
// (Project → Settings → Environment Variables), never from the code.
// A correct password gets an HttpOnly cookie "<expiry>.<HMAC of expiry keyed by the password>",
// so changing SITE_PASSWORD signs every browser out.

const COOKIE = "site_auth";
const MAX_AGE = 60 * 60 * 24 * 30;   // stay signed in for 30 days
const LOGIN_PATH = "/__login";
const LOGOUT_PATH = "/logout";

export default async function middleware(request) {
  const password = process.env.SITE_PASSWORD;
  if (!password) {   // fail closed: no password configured means nobody gets in
    return html(page("Site verrouillé", "<p class=\"err\">Le mot de passe n’est pas configuré (variable SITE_PASSWORD).</p>"), 503);
  }

  const url = new URL(request.url);

  if (url.pathname === LOGOUT_PATH) {
    return redirect("/", cookie("", 0));
  }

  if (url.pathname === LOGIN_PATH && request.method === "POST") {
    const form = await request.formData().catch(() => null);
    const given = form ? String(form.get("password") || "") : "";
    const back = safePath(form && form.get("next"));
    if (await same(given, password)) {
      const exp = Math.floor(Date.now() / 1000) + MAX_AGE;
      return redirect(back, cookie(`${exp}.${await sign(password, exp)}`, MAX_AGE));
    }
    return html(loginPage(back, true), 401);
  }

  if (await validCookie(request, password)) {
    // same as next() from @vercel/functions: let the request through to the static files
    return new Response(null, { headers: { "x-middleware-next": "1" } });
  }

  return html(loginPage(safePath(url.pathname + url.search), false), 401);
}

async function validCookie(request, password) {
  const raw = (request.headers.get("cookie") || "")
    .split(";").map((c) => c.trim())
    .find((c) => c.startsWith(COOKIE + "="));
  if (!raw) return false;
  const [exp, sig] = decodeURIComponent(raw.slice(COOKIE.length + 1)).split(".");
  if (!/^\d+$/.test(exp || "") || Number(exp) < Date.now() / 1000) return false;
  return same(sig || "", await sign(password, exp));
}

async function sign(password, exp) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const mac = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(`${COOKIE}:${exp}`));
  return [...new Uint8Array(mac)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// Constant-time comparison: hash both sides so neither length nor content leaks through timing.
async function same(a, b) {
  const enc = new TextEncoder();
  const [x, y] = await Promise.all([a, b].map((s) => crypto.subtle.digest("SHA-256", enc.encode(s))));
  const ua = new Uint8Array(x), ub = new Uint8Array(y);
  let diff = 0;
  for (let i = 0; i < ua.length; i++) diff |= ua[i] ^ ub[i];
  return diff === 0;
}

// Only same-site paths after login, so the form can't be used to bounce people to another site.
function safePath(p) {
  p = typeof p === "string" ? p : "";
  if (!p.startsWith("/") || p.startsWith("//") || p.startsWith("/\\") || p.startsWith(LOGIN_PATH)) return "/";
  return p;
}

function cookie(value, maxAge) {
  return `${COOKIE}=${encodeURIComponent(value)}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Lax`;
}

function redirect(location, setCookie) {
  return new Response(null, {
    status: 303,
    headers: { Location: location, "Set-Cookie": setCookie, "Cache-Control": "no-store" },
  });
}

function html(body, status) {
  return new Response(body, {
    status,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Robots-Tag": "noindex, nofollow",
    },
  });
}

function esc(s) {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function loginPage(next, wrong) {
  return page("Accès protégé", `
    <form method="post" action="${LOGIN_PATH}">
      <input type="hidden" name="next" value="${esc(next)}">
      <label for="pw">Mot de passe</label>
      <input id="pw" name="password" type="password" autocomplete="current-password" required autofocus
        ${wrong ? 'aria-invalid="true" aria-describedby="err"' : ""}>
      ${wrong ? '<p class="err" id="err" role="alert">Mot de passe incorrect.</p>' : ""}
      <button type="submit">Entrer</button>
    </form>`);
}

// Same palette as index.html so the lock screen looks like part of the site.
function page(heading, content) {
  return `<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="robots" content="noindex, nofollow">
<title>Générateur de Cachets</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Ccircle cx='32' cy='32' r='27' fill='none' stroke='%2324318f' stroke-width='6'/%3E%3Ccircle cx='32' cy='32' r='15' fill='none' stroke='%2324318f' stroke-width='3'/%3E%3C/svg%3E">
<style>
  :root {
    --bg: #ece8df; --panel: #f7f5ef; --ink: #22201b; --muted: #6d675b; --line: #d8d2c4;
    --accent: #24318f; --on-accent: #fff; --field: #fffdf8; --focus: #b45309; --err: #b42318;
    color-scheme: light;
  }
  @media (prefers-color-scheme: dark) {
    :root:not([data-theme="light"]) {
      --bg: #1a1813; --panel: #242019; --ink: #efe9dc; --muted: #a39b89; --line: #39342a;
      --accent: #8e9cff; --on-accent: #12131f; --field: #1f1c15; --focus: #f0a450; --err: #ff8a7a;
      color-scheme: dark;
    }
  }
  :root[data-theme="dark"] {
    --bg: #1a1813; --panel: #242019; --ink: #efe9dc; --muted: #a39b89; --line: #39342a;
    --accent: #8e9cff; --on-accent: #12131f; --field: #1f1c15; --focus: #f0a450; --err: #ff8a7a;
    color-scheme: dark;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; min-height: 100vh; min-height: 100dvh; display: grid; place-items: center;
    padding: 24px max(16px, env(safe-area-inset-right, 0px)) 24px max(16px, env(safe-area-inset-left, 0px));
    background: var(--bg); color: var(--ink); line-height: 1.5;
    font-family: "Segoe UI", system-ui, -apple-system, sans-serif;
  }
  main {
    width: 100%; max-width: 360px; background: var(--panel); border: 1px solid var(--line);
    border-radius: 10px; padding: 24px;
  }
  .seal { display: block; width: 44px; height: 44px; margin-bottom: 12px; color: var(--accent); }
  h1 { font-family: Georgia, "Times New Roman", serif; font-size: 1.4rem; margin: 0 0 4px; letter-spacing: -0.01em; }
  .sub { color: var(--muted); font-size: 0.88rem; margin: 0 0 18px; }
  label { display: block; font-size: 0.82rem; font-weight: 600; margin-bottom: 5px; }
  input[type=password] {
    width: 100%; font: inherit; font-size: 1rem; padding: 9px 10px; min-height: 42px;
    background: var(--field); color: var(--ink); border: 1px solid var(--line); border-radius: 6px;
  }
  input[aria-invalid=true] { border-color: var(--err); }
  input:focus-visible, button:focus-visible { outline: 2px solid var(--focus); outline-offset: 1px; }
  .err { color: var(--err); font-size: 0.84rem; margin: 8px 0 0; }
  button {
    width: 100%; margin-top: 16px; min-height: 42px; font: inherit; font-weight: 600; font-size: 0.9rem;
    padding: 10px 16px; border-radius: 7px; cursor: pointer;
    border: 1px solid var(--accent); background: var(--accent); color: var(--on-accent);
  }
  button:active { transform: translateY(1px); }
</style>
</head>
<body>
<main>
  <svg class="seal" viewBox="0 0 64 64" aria-hidden="true"><circle cx="32" cy="32" r="27" fill="none" stroke="currentColor" stroke-width="5"/><circle cx="32" cy="32" r="15" fill="none" stroke="currentColor" stroke-width="3"/></svg>
  <h1>${heading}</h1>
  <p class="sub">Générateur de Cachets</p>
  ${content}
</main>
</body>
</html>`;
}
