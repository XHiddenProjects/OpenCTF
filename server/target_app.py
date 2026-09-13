"""
OpenCTF isolated target server.

This is deliberately separate from app.py and runs on port 5001. It serves
local-only vulnerable lab sites for web challenges. Never expose this process
outside the CTF lab network.

Run from server/:
    python target_app.py
"""

import html
import json
import os
import sqlite3
import hashlib
import hmac
import struct
import zlib
from urllib.parse import quote

from flask import Flask, abort, jsonify, request

try:
    # Installed as the `openctf-server` PyPI package.
    from openctf_server.app import Challenge, TARGET_ACCESS_SECRET, app as ctf_app, team_challenge_flag
except ImportError:
    # Running directly from a cloned copy of the repo (`python target_app.py`).
    from app import Challenge, TARGET_ACCESS_SECRET, app as ctf_app, team_challenge_flag


target_app = Flask(__name__)
TARGET_PORT = int(os.environ.get("TARGET_PORT", "5001"))


@target_app.after_request
def apache_headers(response):
    response.headers["Server"] = "Apache/2.4.58 (Ubuntu)"
    response.headers["X-Powered-By"] = "PHP/8.2.10"
    response.headers["Cache-Control"] = "no-store, max-age=0"
    return response

BASE_CSS = """
<style>
:root { color-scheme: light; --ink: #18212b; --muted: #667382; --line: #dce3ea; --blue: #2563eb; --surface: #ffffff; }
* { box-sizing: border-box; }
body { margin: 0; background: #f3f6f9; color: var(--ink); font: 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
.site-shell { max-width: 980px; margin: 0 auto; padding: 0 24px 48px; }
.site-nav { display: flex; align-items: center; justify-content: space-between; padding: 22px 0; border-bottom: 1px solid var(--line); }
.brand { font-weight: 700; letter-spacing: -.02em; }
.nav-links { display: flex; gap: 18px; color: var(--muted); font-size: 13px; }
a { color: var(--blue); text-decoration: none; } a:hover { text-decoration: underline; }
.hero { padding: 58px 0 34px; max-width: 700px; } h1 { font-size: 42px; line-height: 1.08; margin: 0 0 14px; letter-spacing: -.04em; } h2 { margin-top: 0; }
.eyebrow { color: var(--blue); text-transform: uppercase; letter-spacing: .12em; font-size: 11px; font-weight: 700; }
.muted { color: var(--muted); } .grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 14px; }
.card, .panel { background: var(--surface); border: 1px solid var(--line); border-radius: 8px; padding: 22px; box-shadow: 0 8px 24px rgba(28, 44, 64, .05); }
.card h3 { margin: 0 0 6px; font-size: 16px; } .card p { color: var(--muted); font-size: 13px; }
form { display: grid; gap: 12px; max-width: 480px; } label { display: grid; gap: 6px; color: var(--muted); font-size: 13px; } input { border: 1px solid #cbd5df; border-radius: 5px; padding: 11px 12px; font: inherit; } button { border: 0; border-radius: 5px; padding: 11px 16px; background: var(--blue); color: white; font-weight: 600; cursor: pointer; }
.alert { border-left: 3px solid var(--blue); background: #eef4ff; padding: 14px 16px; white-space: pre-wrap; } .danger { border-color: #dc2626; background: #fff1f2; }
.file-card { display: flex; align-items: center; gap: 14px; border: 1px solid var(--line); border-radius: 7px; padding: 14px; background: #f8fafc; } .file-card p { margin: 2px 0 0; } .file-icon { display: grid; place-items: center; width: 42px; height: 42px; border-radius: 6px; background: #dbeafe; color: #1d4ed8; font: 700 11px ui-monospace, monospace; } .download-link { margin-left: auto; background: var(--blue); color: white; border-radius: 5px; padding: 9px 12px; font-size: 13px; } .download-link:hover { text-decoration: none; background: #1d4ed8; }
.lab-terminal { margin-top: 22px; border-radius: 7px; overflow: hidden; background: #080b0f; color: #d7e0e8; } .terminal-title { padding: 9px 12px; border-bottom: 1px solid #26313b; color: #75d49a; font: 12px ui-monospace, monospace; } .lab-terminal pre { height: 170px; overflow: auto; margin: 0; padding: 14px; } .lab-terminal form { display: flex; flex-direction: row; align-items: center; gap: 8px; max-width: none; padding: 10px 12px; border-top: 1px solid #26313b; } .lab-terminal form span { color: #75d49a; font: 13px ui-monospace, monospace; } .lab-terminal input { flex: 1; min-width: 0; background: transparent; border: 0; color: white; font: 13px ui-monospace, monospace; outline: 0; } .lab-terminal button { padding: 7px 10px; font-size: 12px; }
.dir { border-collapse: collapse; width: 100%; background: white; } .dir th, .dir td { text-align: left; border-bottom: 1px solid var(--line); padding: 12px; } .dir th { background: #f8fafc; font-size: 12px; color: var(--muted); }
pre { white-space: pre-wrap; font: 13px/1.6 ui-monospace, SFMono-Regular, Consolas, monospace; } footer { color: var(--muted); font-size: 12px; margin-top: 48px; }
@media (max-width: 700px) { .grid { grid-template-columns: 1fr; } .nav-links { display: none; } h1 { font-size: 34px; } .site-shell { padding: 0 16px 32px; } }
</style>
"""


def get_challenge(challenge_id):
    with ctf_app.app_context():
        challenge = Challenge.query.get(challenge_id)
        if not challenge or not challenge.is_active or challenge.type != "web":
            abort(404)
        try:
            config = json.loads(challenge.web_config or "{}")
        except json.JSONDecodeError:
            abort(500)
        access = request.args.get("access", "")
        payload, _, signature = access.rpartition(":")
        valid_access = bool(payload and signature) and hmac.compare_digest(
            signature,
            hmac.new(TARGET_ACCESS_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest(),
        )
        team_id = int(payload.split(":", 1)[0]) if valid_access and ":" in payload else None
        # Each team gets its own flag baked into the sandboxed site (same
        # mechanism as terminal/AI challenges), so a flag one team finds
        # can't just be copy-pasted by another team.
        config["_team_flag"] = team_challenge_flag(team_id, challenge) if team_id else None
        config["_access"] = access
        return challenge, config


def layout(config, content, path="/"):
    title = html.escape(config.get("title") or "Acme Internal Portal")
    access = config.get("_access")
    query = f"?access={quote(access)}" if access else ""
    path = f"{path}{query}"
    return f"""<!doctype html><html><head><meta charset='utf-8'><title>{title}</title>{BASE_CSS}</head>
<body><div class='site-shell'><nav class='site-nav'><div class='brand'>{title}</div>
<div class='nav-links'><a href='{path}'>Home</a><a href='{path}status'>Status</a><a href='{path}about'>About</a></div></nav>{content}
<footer>Acme Systems &middot; Internal preview environment</footer></div>
<script>
function reportLocation() {{ parent.postMessage({{ type: 'target-location', path: location.pathname + location.search }}, '*'); }}
window.addEventListener('load', reportLocation);
window.addEventListener('popstate', reportLocation);
window.addEventListener('message', function (event) {{
    if (!event.data || event.data.type !== 'target-navigation') return;
    if (event.data.action === 'back') history.back();
    if (event.data.action === 'forward') history.forward();
    if (event.data.action === 'reload') location.reload();
}});
window.addEventListener('DOMContentLoaded', function () {{
    const access = new URLSearchParams(location.search).get('access');
    if (!access) return;
    document.querySelectorAll('a[href], form[action]').forEach(function (element) {{
        const attribute = element.tagName === 'FORM' ? 'action' : 'href';
        const url = new URL(element.getAttribute(attribute), location.href);
        if (url.origin !== location.origin) return;
        url.searchParams.set('access', access);
        element.setAttribute(attribute, url.pathname + url.search);
    }});
}});
</script></body></html>"""


def challenge_secret(config):
    return str(config.get("_team_flag") or config.get("secret") or "OCTF{configure_the_web_challenge}")


@target_app.route("/target/<int:challenge_id>/", methods=["GET"])
def landing(challenge_id):
    _, config = get_challenge(challenge_id)
    base = f"/target/{challenge_id}/"
    behavior = config.get("behavior", "hidden_path")
    landing_text = html.escape(config.get("landing_text") or "Welcome to the internal site.")
    if behavior == "xss":
        return xss_page(challenge_id, config)
    if behavior == "sql_injection":
        return sql_page(challenge_id, config)
    if behavior == "sql_injection_report":
        return report_page(challenge_id, config)
    if behavior == "apache_directory":
        return apache_page(challenge_id, config)
    if behavior == "idor":
        return invoice_page(challenge_id, config)
    if behavior == "metadata":
        return metadata_page(challenge_id, config)
    content = f"""<main class='hero'><div class='eyebrow'>Internal portal</div><h1>Work smarter, together.</h1>
<p class='muted'>{landing_text}</p><div class='grid'><div class='card'><h3>Operations</h3><p>Service health and deployment notes.</p><a href='{base}status'>View status</a></div>
<div class='card'><h3>Knowledge base</h3><p>Guides for the internal team.</p><a href='{base}about'>Browse articles</a></div>
<div class='card'><h3>Staff login</h3><p>Restricted tools for employees.</p><a href='{base}admin'>Open console</a></div></div></main>"""
    return layout(config, content, base)


@target_app.route("/target/<int:challenge_id>", methods=["GET"])
def landing_without_slash(challenge_id):
    return landing(challenge_id)


@target_app.route("/target/<int:challenge_id>/status")
def status(challenge_id):
    _, config = get_challenge(challenge_id)
    return layout(config, "<main class='hero'><div class='eyebrow'>System status</div><h1>All systems operational.</h1><p class='muted'>Last checked 2 minutes ago.</p></main>", f"/target/{challenge_id}/")


@target_app.route("/target/<int:challenge_id>/about")
def about(challenge_id):
    _, config = get_challenge(challenge_id)
    return layout(config, "<main class='hero'><div class='eyebrow'>About Acme</div><h1>Tools for people doing serious work.</h1><p class='muted'>This internal preview is maintained by the platform team.</p></main>", f"/target/{challenge_id}/")


def png_chunk(kind, data):
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xffffffff)


def incident_png(metadata):
    width, height = 960, 540
    rows = []
    for y in range(height):
        row = bytearray([0])
        for x in range(width):
            if 44 <= x < 916 and 44 <= y < 496:
                color = (36, 55, 70, 255)
            elif ((x - 210) ** 2 + (y - 260) ** 2) < 104 ** 2:
                color = (216, 227, 234, 255)
            else:
                color = (23, 33, 43, 255)
            row.extend(color)
        rows.append(bytes(row))
    raw_pixels = b"".join(rows)
    png = b"\x89PNG\r\n\x1a\n"
    png += png_chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0))
    for key, value in metadata.items():
        png += png_chunk(b"tEXt", f"{key}\x00{value}".encode("latin-1", "replace"))
    png += png_chunk(b"IDAT", zlib.compress(raw_pixels, 6))
    return png + png_chunk(b"IEND", b"")


@target_app.route("/target/<int:challenge_id>/assets/incident-photo.png")
def metadata_asset(challenge_id):
    _, config = get_challenge(challenge_id)
    if config.get("behavior") != "metadata":
        abort(404)
    access = quote(config.get("_access", ""))
    flag = html.escape(challenge_secret(config))
    png = incident_png({
        "Title": "Acme deployment room",
        "Author": "m.ortiz",
        "Description": "Exported support evidence",
        "Comment": challenge_secret(config),
    })
    return target_app.response_class(png, mimetype="image/png", headers={"Content-Disposition": "attachment; filename=incident-photo.png"})


def metadata_page(challenge_id, config):
    base = f"/target/{challenge_id}/"
    access = quote(config.get("_access", ""))
    asset = f"{base}assets/incident-photo.png?access={access}"
    content = f"""<main class='hero'><div class='eyebrow'>Digital evidence</div><h1>Incident photo review</h1>
<p class='muted'>{html.escape(config.get('landing_text', 'Inspect the supplied asset metadata.'))}</p>
<div class='panel'><div class='file-card'><span class='file-icon'>PNG</span><div><strong>incident-photo.png</strong><p class='muted'>Deployment evidence image · 4 KB</p></div><a class='download-link' href='{asset}'>Download image</a></div>
<p class='muted'>Download the image</p></div></main>"""
    return layout(config, content, base)


@target_app.route("/target/<int:challenge_id>/invoices/<int:invoice_id>/download")
def invoice_page(challenge_id, invoice_id):
    _, config = get_challenge(challenge_id)
    if config.get("behavior") != "idor":
        abort(404)
    if invoice_id == 8842:
        content = f"<main class='hero'><div class='eyebrow'>Invoice viewer</div><h1>Invoice {invoice_id}</h1><div class='alert'>Invoice owner: finance-team<br>Download ready.<br>{html.escape(challenge_secret(config))}</div></main>"
    else:
        content = f"<main class='hero'><h1>Invoice {invoice_id}</h1><p class='muted'>Invoice not found.</p></main>"
    return layout(config, content, f"/target/{challenge_id}/")


@target_app.route("/target/<int:challenge_id>/admin")
def admin_panel(challenge_id):
    _, config = get_challenge(challenge_id)
    if config.get("behavior") != "hidden_path":
        abort(404)
    content = f"""<main class='hero'><div class='eyebrow'>Restricted console</div><h1>Admin panel</h1>
<div class='alert'>Access granted.\n\nAudit export ready.\n{html.escape(challenge_secret(config))}</div></main>"""
    return layout(config, content, f"/target/{challenge_id}/")


@target_app.route("/target/<int:challenge_id>/search")
def xss_page(challenge_id, config=None):
    if config is None:
        _, config = get_challenge(challenge_id)
    query = request.args.get("q", "")
    # Intentional vulnerability: q is reflected without escaping for XSS labs.
    reflected = query
    exploit_notice = ""
    if "<script" in query.lower() or "onerror" in query.lower() or "onload" in query.lower():
        exploit_notice = f"<div class='alert'>Client-side execution confirmed.<br>{html.escape(challenge_secret(config))}</div>"
    base = f"/target/{challenge_id}/"
    content = f"""<main class='hero'><div class='eyebrow'>Knowledge search</div><h1>Find an article</h1>
<form method='get' action='{base}search'><label>Search the knowledge base<input name='q' value='{html.escape(query, quote=True)}' placeholder='Try deployment'></label><button>Search</button></form>
<div class='panel' style='margin-top:22px'><strong>Search results for: </strong>{reflected or 'all articles'}<p class='muted'>Showing 3 internal articles.</p></div>{exploit_notice}</main>"""
    return layout(config, content, base)


@target_app.route("/target/<int:challenge_id>/login", methods=["GET", "POST"])
def sql_page(challenge_id, config=None):
    if config is None:
        _, config = get_challenge(challenge_id)
    username = request.values.get("username", "")
    password = request.values.get("password", "")
    connection = sqlite3.connect(":memory:")
    connection.execute("CREATE TABLE users (username TEXT, password TEXT, note TEXT)")
    connection.execute("INSERT INTO users VALUES (?, ?, ?)", ("analyst", "winter2026", "Quarterly reports"))
    connection.execute("INSERT INTO users VALUES (?, ?, ?)", ("admin", "not-for-production", challenge_secret(config)))
    # Intentional vulnerability: direct string interpolation for SQLi labs.
    query = "SELECT username, note FROM users WHERE username = '%s' AND password = '%s'" % (username, password)
    message = "Enter your credentials to continue."
    try:
        row = connection.execute(query).fetchone()
        if row:
            message = f"Welcome, {html.escape(row[0])}.\n{html.escape(row[1])}"
        elif username or password:
            message = "Invalid username or password."
    except sqlite3.Error as error:
        message = f"Database error: {html.escape(str(error))}"
    base = f"/target/{challenge_id}/"
    content = f"""<main class='hero'><div class='eyebrow'>Employee access</div><h1>Sign in to reports</h1>
<form method='post' action='{base}login'><label>Username<input name='username' value='{html.escape(username, quote=True)}'></label><label>Password<input type='password' name='password'></label><button>Sign in</button></form>
<div class='alert' style='margin-top:22px'>{message}</div></main>"""
    return layout(config, content, base)


@target_app.route("/target/<int:challenge_id>/reports", methods=["GET"])
def report_page(challenge_id, config=None):
    if config is None:
        _, config = get_challenge(challenge_id)
    name = request.values.get("name", "")
    connection = sqlite3.connect(":memory:")
    connection.execute("CREATE TABLE reports (name TEXT, department TEXT, note TEXT)")
    # The confidential row is inserted first on purpose: an always-true
    # WHERE clause returns it as the "first matching row" the challenge
    # description talks about. Its name is never shown anywhere in the UI.
    connection.execute(
        "INSERT INTO reports VALUES (?, ?, ?)",
        ("Q4 Board Briefing", "Executive", challenge_secret(config)),
    )
    connection.execute(
        "INSERT INTO reports VALUES (?, ?, ?)",
        ("Marketing Overview", "Marketing", "Campaign performance is up 4% quarter over quarter."),
    )
    connection.execute(
        "INSERT INTO reports VALUES (?, ?, ?)",
        ("Support Ticket Trends", "Support", "Ticket volume is flat; no action needed."),
    )
    # Intentional vulnerability: name is concatenated straight into the
    # query string instead of being bound as a parameter, so a value that
    # closes the quote early can change the query's intended logic.
    query = "SELECT name, department, note FROM reports WHERE name = '%s' LIMIT 1" % name
    result_html = ""
    error_html = ""
    try:
        row = connection.execute(query).fetchone()
        if row:
            result_html = (
                f"<div class='panel' style='margin-top:22px'>"
                f"<strong>{html.escape(row[0])}</strong>"
                f"<p class='muted'>Department: {html.escape(row[1])}</p>"
                f"<p>{html.escape(row[2])}</p></div>"
            )
        elif name:
            result_html = "<p class='muted' style='margin-top:22px'>No report found for that name.</p>"
    except sqlite3.Error as error:
        error_html = f"<div class='alert danger' style='margin-top:22px'>Database error: {html.escape(str(error))}</div>"
    base = f"/target/{challenge_id}/"
    content = f"""<main class='hero'><div class='eyebrow'>Reports center</div><h1>Find a report</h1>
<p class='muted'>Try a known report name, like Marketing Overview or Support Ticket Trends.</p>
<form method='get' action='{base}reports'><label>Report name<input name='name' value='{html.escape(name, quote=True)}' placeholder='Marketing Overview'></label><button>Search</button></form>
{result_html}{error_html}</main>"""
    return layout(config, content, base)


@target_app.route("/target/<int:challenge_id>/files/")
def apache_page(challenge_id, config=None):
    if config is None:
        _, config = get_challenge(challenge_id)
    base = f"/target/{challenge_id}/files/"
    content = f"""<main class='hero'><div class='eyebrow'>Index of /files/</div><h1>Directory listing</h1>
<p class='muted'>Apache/2.4.58 (Ubuntu) Server at intranet.local Port 80</p><table class='dir'><tr><th>Name</th><th>Last modified</th><th>Size</th></tr>
<tr><td><a href='{base}../'>Parent Directory</a></td><td></td><td>-</td></tr><tr><td><a href='{base}assets/'>assets/</a></td><td>2026-02-04</td><td>-</td></tr>
<tr><td><a href='{base}backup/'>backup/</a></td><td>2026-02-01</td><td>-</td></tr></table></main>"""
    return layout(config, content, f"/target/{challenge_id}/")


@target_app.route("/target/<int:challenge_id>/files/backup/")
def apache_backup(challenge_id):
    _, config = get_challenge(challenge_id)
    base = f"/target/{challenge_id}/files/backup/"
    content = f"""<main class='hero'><div class='eyebrow'>Index of /files/backup/</div><h1>Backup files</h1>
<table class='dir'><tr><th>Name</th><th>Last modified</th><th>Size</th></tr><tr><td><a href='{base}notes.txt'>notes.txt</a></td><td>2026-01-12</td><td>4 KB</td></tr>
<tr><td><a href='{base}.env.bak'>.env.bak</a></td><td>2026-01-12</td><td>1 KB</td></tr></table></main>"""
    return layout(config, content, f"/target/{challenge_id}/files/")


@target_app.route("/target/<int:challenge_id>/files/assets/")
def apache_assets(challenge_id):
    _, config = get_challenge(challenge_id)
    content = "<main class='hero'><div class='eyebrow'>Index of /files/assets/</div><h1>Assets</h1><p class='muted'>No public assets are currently published.</p></main>"
    return layout(config, content, f"/target/{challenge_id}/files/")


@target_app.route("/target/<int:challenge_id>/files/backup/.env.bak")
def apache_secret(challenge_id):
    _, config = get_challenge(challenge_id)
    return f"APP_ENV=production\nBACKUP_ENABLED=true\nSECRET_TOKEN={challenge_secret(config)}\n"


if __name__ == "__main__":
    target_app.run(host="0.0.0.0", port=TARGET_PORT, debug=False, use_reloader=False)
