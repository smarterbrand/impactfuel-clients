const LOGIN_PATH = "/_auth/login";
const COOKIE_NAME = "if_auth";

// Paths served without authentication. The logo must be public so the login
// page can render it — the gate runs before static files are served.
const PUBLIC_PATHS = ["/impactfuel-logo.png", "/favicon.ico"];

async function hashToken(password, secret) {
  const data = new TextEncoder().encode(password + ":" + secret);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function getCookie(request, name) {
  const cookies = request.headers.get("cookie") || "";
  const match = cookies.match(new RegExp("(?:^|;\\s*)" + name + "=([^;]*)"));
  return match ? match[1] : null;
}

function escapeAttr(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/"/g, "&quot;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function loginPage(error, next) {
  const errorHtml = error
    ? '<p class="error">That password is not right. Try again.</p>'
    : "";
  const action = LOGIN_PATH + "?next=" + encodeURIComponent(next || "/");

  return new Response(
    `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sign In — Impactfuel</title>
  <meta name="robots" content="noindex,nofollow">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@400;600;700;800&family=Poppins:wght@300;400;500&display=swap" rel="stylesheet">
  <style>
    :root{
      --ink:#000;
      --pink:#ff7bac;
      --pink-hover:#ff96be;
      --pink-tint:#fff0f6;
      --bg:#fff;
      --bg-alt:#f5f5f5;
      --muted:#86868b;
      --line:rgba(0,0,0,.12);
      --red:#c81e4c;
      --red-bg:#fdf2f5;
    }
    *,*::before,*::after{box-sizing:border-box;margin:0;padding:0;}
    html,body{height:100%;}
    body{
      font-family:"Poppins",system-ui,-apple-system,sans-serif;
      background:var(--bg-alt);
      color:var(--ink);
      display:flex;align-items:center;justify-content:center;
      min-height:100vh;padding:24px;
      -webkit-font-smoothing:antialiased;
    }
    .container{width:100%;max-width:400px;}
    .card{
      background:var(--bg);
      border:1px solid var(--line);
      border-radius:20px;
      padding:40px 32px 32px;
      box-shadow:0 1px 2px rgba(0,0,0,.04), 0 12px 40px rgba(0,0,0,.07);
    }
    .logo-wrap{text-align:center;margin-bottom:30px;}
    .logo-wrap img{height:32px;display:block;margin:0 auto 22px;}
    .logo-wrap h1{
      font-family:"Outfit",sans-serif;
      font-size:1.4rem;font-weight:700;letter-spacing:-.02em;
      margin-bottom:6px;
    }
    .logo-wrap h1 .dot{color:var(--pink);}
    .logo-wrap p{font-size:13.5px;color:var(--muted);font-weight:300;}
    label{
      display:block;font-size:11px;font-weight:600;
      letter-spacing:.09em;text-transform:uppercase;
      color:var(--muted);margin-bottom:8px;
    }
    input[type="password"]{
      width:100%;padding:13px 15px;
      border:1px solid var(--line);border-radius:12px;
      font-family:"Poppins",sans-serif;font-size:15px;
      color:var(--ink);background:var(--bg-alt);
      outline:none;transition:border-color .2s, background .2s;
    }
    input[type="password"]:focus{border-color:var(--pink);background:var(--bg);}
    button{
      width:100%;margin-top:20px;padding:14px;
      background:var(--ink);color:#fff;
      border:none;border-radius:12px;
      font-family:"Outfit",sans-serif;font-size:15px;font-weight:600;
      cursor:pointer;transition:background .2s, transform .1s;
    }
    button:hover{background:var(--pink);color:#000;}
    button:active{transform:scale(.985);}
    .error{
      background:var(--red-bg);color:var(--red);
      font-size:13px;font-weight:500;
      padding:11px 14px;border-radius:10px;
      margin-bottom:20px;text-align:center;
    }
    .footer{text-align:center;margin-top:22px;font-size:12px;color:var(--muted);}
    .footer a{color:var(--pink);text-decoration:none;}
    .footer a:hover{text-decoration:underline;}
  </style>
</head>
<body>
  <div class="container">
    <div class="card">
      <div class="logo-wrap">
        <img src="/impactfuel-logo.png" alt="Impactfuel">
        <h1>Client Workspaces<span class="dot">.</span></h1>
        <p>Enter the password to continue.</p>
      </div>
      ${errorHtml}
      <form method="POST" action="${escapeAttr(action)}">
        <label for="password">Password</label>
        <input type="password" id="password" name="password" placeholder="••••••••" required autofocus>
        <button type="submit">Sign In</button>
      </form>
    </div>
    <div class="footer">
      &copy; ${new Date().getFullYear()} <a href="https://impactfuel.org">Impactfuel</a>
    </div>
  </div>
</body>
</html>`,
    {
      status: error ? 401 : 200,
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "no-store",
        "X-Robots-Tag": "noindex, nofollow",
      },
    }
  );
}

function safeNext(raw) {
  // Only allow same-origin relative paths, so ?next= cannot be used as an open redirect.
  if (!raw || raw[0] !== "/" || raw.slice(0, 2) === "//") return "/";
  return raw;
}

export default async function middleware(request) {
  const url = new URL(request.url);
  const expectedPassword = process.env.AUTH_PASSWORD;
  const secret = process.env.AUTH_SECRET || process.env.AUTH_PASSWORD || "fallback";

  if (PUBLIC_PATHS.includes(url.pathname)) return;

  // Login form submission
  if (url.pathname === LOGIN_PATH && request.method === "POST") {
    const formData = await request.formData();
    const password = formData.get("password") || "";
    const next = safeNext(url.searchParams.get("next"));

    if (expectedPassword && password === expectedPassword) {
      const token = await hashToken(password, secret);
      return new Response(null, {
        status: 302,
        headers: {
          Location: next,
          "Set-Cookie": `${COOKIE_NAME}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=86400`,
        },
      });
    }

    return loginPage(true, next);
  }

  // Login page
  if (url.pathname === LOGIN_PATH) {
    return loginPage(false, safeNext(url.searchParams.get("next")));
  }

  // Every other path: require a valid session cookie
  const token = getCookie(request, COOKIE_NAME);
  if (token && expectedPassword) {
    const expected = await hashToken(expectedPassword, secret);
    if (token === expected) return;
  }

  return loginPage(false, url.pathname + url.search);
}

export const config = {
  matcher: "/(.*)",
};
