"""RedHive practice target — an INTENTIONALLY VULNERABLE demo app.

⚠️  This app is deliberately insecure. It exists only so RedHive has a rich,
local, legal target to scan during demos. NEVER deploy it anywhere public.

It serves many cross-linked pages, forms, and parameterized endpoints (so the
recon crawler + path-discovery map a wide attack surface and the probe swarm
fans out to dozens of agents), and it ships with planted weaknesses:

  - no security headers anywhere (CSP/HSTS/X-Frame-Options/…)
  - reflected XSS on /search?q=
  - open redirect on /redirect?url=
  - SQL-error reflection on /product?id=  (error-based SQLi signal)
  - an exposed /.env with fake secrets
  - cookies without HttpOnly/Secure/SameSite

Run it:  uvicorn demo_target.app:app --port 8780
Scan it: target = http://localhost:8780   (localhost is in the allowlist)
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse

app = FastAPI(title="VulnShop (RedHive practice target)", docs_url=None, redoc_url=None)

_NAV = """
<nav>
  <a href="/">Home</a> · <a href="/products">Products</a> ·
  <a href="/product?id=1">Product 1</a> · <a href="/search?q=phone">Search</a> ·
  <a href="/login">Login</a> · <a href="/register">Register</a> ·
  <a href="/profile?id=1">Profile</a> · <a href="/account">Account</a> ·
  <a href="/dashboard">Dashboard</a> · <a href="/admin">Admin</a> ·
  <a href="/users">Users</a> · <a href="/contact">Contact</a> ·
  <a href="/feedback">Feedback</a> · <a href="/about">About</a> ·
  <a href="/redirect?url=/">Go</a> · <a href="/api/users">API</a>
</nav><hr/>
"""


def _page(title: str, body: str) -> HTMLResponse:
    """Render a page WITHOUT any security headers (intentional)."""
    html = f"<!doctype html><html><head><title>{title}</title></head><body>{_NAV}{body}</body></html>"
    return HTMLResponse(html)


@app.get("/", response_class=HTMLResponse)
def home():
    return _page(
        "VulnShop",
        """
        <h1>VulnShop</h1>
        <p>A deliberately insecure demo store for RedHive.</p>
        <form action="/search" method="get">
          <input name="q" placeholder="Search products"/>
          <button type="submit">Search</button>
        </form>
        <form action="/login" method="post">
          <input name="username"/><input name="password" type="password"/>
          <button type="submit">Sign in</button>
        </form>
        """,
    )


@app.get("/search", response_class=HTMLResponse)
def search(q: str = ""):
    # VULN: reflects user input unescaped -> reflected XSS.
    return _page("Search", f"<h2>Results for: {q}</h2><p>No products matched.</p>")


@app.get("/products", response_class=HTMLResponse)
def products():
    items = "".join(f'<li><a href="/product?id={i}">Product {i}</a></li>' for i in range(1, 6))
    return _page("Products", f"<h2>Catalog</h2><ul>{items}</ul>")


@app.get("/product", response_class=HTMLResponse)
def product(id: str = "1"):
    # VULN: non-numeric id leaks a SQL error string -> error-based SQLi signal.
    if not id.isdigit():
        return _page(
            "Error",
            f"<pre>SQL error near '{id}': "
            "You have an error in your SQL syntax (MySQL) at line 1</pre>",
        )
    return _page("Product", f"<h2>Product {id}</h2><p>$ {int(id) * 9}.99</p>")


@app.get("/redirect")
def redirect(url: str = "/"):
    # VULN: open redirect — no allowlist on the destination.
    return RedirectResponse(url)


@app.get("/login", response_class=HTMLResponse)
def login_form():
    return _page(
        "Login",
        '<form method="post" action="/login"><input name="username"/>'
        '<input name="password" type="password"/><button>Sign in</button></form>',
    )


@app.post("/login")
def login():
    # VULN: session cookie with no HttpOnly/Secure/SameSite flags.
    response = PlainTextResponse("Welcome")
    response.set_cookie("session", "abc123")
    return response


@app.get("/register", response_class=HTMLResponse)
def register():
    return _page(
        "Register",
        '<form method="post" action="/register"><input name="email"/>'
        '<input name="password" type="password"/><button>Create account</button></form>',
    )


@app.get("/profile", response_class=HTMLResponse)
def profile(id: str = "1"):
    # VULN: IDOR-style — any id returns that user's data.
    return _page("Profile", f"<h2>User #{id}</h2><p>email: user{id}@vulnshop.test</p>")


@app.get("/account", response_class=HTMLResponse)
def account():
    return _page("Account", "<h2>Your account</h2><p>Balance: $42.00</p>")


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    return _page("Dashboard", "<h2>Dashboard</h2><p>3 recent orders.</p>")


@app.get("/admin", response_class=HTMLResponse)
def admin():
    # VULN: admin panel with no authentication.
    return _page("Admin", "<h2>Admin Panel</h2><p>Manage users, orders, settings.</p>")


@app.get("/users", response_class=HTMLResponse)
def users():
    rows = "".join(f'<li><a href="/profile?id={i}">user{i}</a></li>' for i in range(1, 4))
    return _page("Users", f"<ul>{rows}</ul>")


@app.get("/contact", response_class=HTMLResponse)
def contact():
    return _page(
        "Contact",
        '<form method="post" action="/contact"><input name="name"/>'
        '<textarea name="message"></textarea><button>Send</button></form>',
    )


@app.get("/feedback", response_class=HTMLResponse)
def feedback(comment: str = ""):
    # VULN: reflects the comment param unescaped.
    return _page("Feedback", f"<h2>Thanks!</h2><p>You said: {comment}</p>")


@app.get("/about", response_class=HTMLResponse)
def about():
    return _page("About", "<h2>About VulnShop</h2><p>Demo only.</p>")


@app.get("/api/users")
def api_users():
    return [{"id": 1, "email": "user1@vulnshop.test"}, {"id": 2, "email": "user2@vulnshop.test"}]


@app.get("/.env", response_class=PlainTextResponse)
def dotenv():
    # VULN: exposed secrets file.
    return (
        "DB_PASSWORD=hunter2\nAWS_SECRET_ACCESS_KEY=AKIAFAKEFAKEFAKE\n"
        "JWT_SECRET=supersecret123\n"
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("demo_target.app:app", host="0.0.0.0", port=8780)
