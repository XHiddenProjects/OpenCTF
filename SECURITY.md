# Security Policy

OpenCTF is a **lab CTF platform**: a Flask API/scoreboard/admin backend plus an
isolated target server (`target_app.py`) that intentionally hosts vulnerable
web pages (SQL injection, XSS, IDOR, etc.) for players to exploit as
challenges. That intentional vulnerability surface is scoped to
`server/target_app.py` and the sandboxed pages it serves under `/target/*`.
Everything else in this repo — the auth system, admin panel, flag checking,
scoreboard, and Electron client — is meant to be solid, and issues there are
treated as real security bugs, not "part of the game."

## Scope

| Component | Intentionally vulnerable? |
|---|---|
| `server/target_app.py` sandboxed pages (`/target/<id>/...`) | **Yes** — this is the challenge content itself |
| `server/app.py` (auth, JWT, flag checking, admin API) | No — report bugs here |
| Terminal challenge interpreter (`run_terminal_command`) | No — it's a toy command parser over a JSON tree, not a real shell; it should never be able to touch the host filesystem |
| AI conversation challenges (`/api/challenges/<id>/ai`) | No — the model should never be able to leak the real flag or execute anything; jailbreaks that make the persona say things it shouldn't (outside the intended "clearance phrase" mechanic) are worth reporting |
| Electron client (`client/`) | No — report bugs here |

If you find a way to exploit `app.py`, the admin panel, the JWT/auth flow, or
break out of the terminal/AI sandboxes, that's a real vulnerability. If you
find a new way to SQL-inject the practice login page, that's just... the
challenge working as intended. 🙂

## Reporting a Vulnerability

For a real bug in the platform itself (not the intentional lab challenges):

1. **Do not open a public GitHub issue** describing the exploit if this repo
   is public or shared with active players — it could let players cheat
   before it's fixed.
2. Email the maintainer directly, or open a private security advisory if
   your git host supports one, with:
   - What you found and where (file/endpoint)
   - Steps to reproduce
   - What you think the impact is (e.g., "any team can read other teams'
     flags", "unauthenticated admin access")
3. Expect an acknowledgment within a few days for a small lab project like
   this. There's no bug bounty — this is a teaching tool, not a product.

If you're an instructor/operator running this for a class or event and find
a problem *during* a live competition, prioritize taking the affected
challenge offline (`is_active: false` in the admin panel) over public
disclosure until the event is over.

## Before You Deploy This Anywhere Real

This ships with lab-friendly defaults that are **not safe for anything
beyond your own laptop**. Before pointing multiple hosts at it:

- [ ] **Turn off Flask debug mode.** `app.py`'s `app.run(...)` call has
      `debug=True`. Flask's debugger allows remote code execution if it's
      network-reachable and an exception is triggered. Set this to `False`
      for any shared deployment.
- [ ] **Replace every default secret.** `SECRET_KEY`, `JWT_SECRET_KEY`,
      `FLAG_PEPPER`, `TARGET_ACCESS_SECRET`, and `ADMIN_PASSWORD` all fall
      back to obvious placeholder values (`change-me-dev-secret`,
      `changeme123`, etc.) if not set. Generate real random values for each
      and set them as actual environment variables — `.env` is **not**
      auto-loaded by `app.py`, so a filled-in `.env` sitting on disk does
      nothing unless you export it (e.g. via systemd's `EnvironmentFile=`).
- [ ] **Change the default admin password** immediately after first login —
      the auto-created `admin` account is meant purely to get you into the
      admin panel to set things up.
- [ ] **Lock down `CORS_ORIGINS`.** It defaults to `*`. Fine for local dev,
      not fine once real credentials are flowing over it.
- [ ] **Set `TARGET_SERVER_URL` to the server's real address**, not
      `localhost`. It's embedded directly into API responses and loaded as
      an iframe by every client, so if it's wrong, every remote host's
      "Target site" tab breaks (or worse, silently points somewhere you
      didn't intend).
- [ ] **Firewall both ports to the lab's own network**, not the open
      internet — port 5000 (API) and port 5001 (the intentionally
      vulnerable target server). Port 5001 in particular should never be
      internet-facing; it's designed to be exploitable.
- [ ] **Back up `server/instance/ctf.db`** regularly if this is running a
      real event — it's the only copy of every team's progress and scores,
      and there's no automated backup built in.
- [ ] **Don't reuse this admin password or these secrets anywhere else.**
      They exist only to run this lab instance.

## Design Notes (why some things look "insecure" but aren't bugs)

- **Flags are per-team, not global**, for `terminal`, `web`, and `ai`
  challenges — each team gets a unique flag baked into the interactive
  experience so one team can't just hand another team a working flag for
  those types. `standard` and `quiz` challenges use a single shared flag by
  design (there's no interactive surface to personalize).
- **The terminal challenge "shell" is not real.** It walks a JSON dict
  server-side; there is no code execution, and no path traversal can escape
  the configured tree (`..` is collapsed, and any path outside the given
  dict tree returns "not found").
- **AI challenges never send the flag to the model.** The system prompt
  explicitly instructs the model not to discuss, guess, or encode the flag,
  and the flag itself is never included in the model's context — only a
  "success marker" phrase is checked for in the reply, and the real flag is
  attached separately by the server only after that phrase is detected.
- **Passwords are hashed** with Werkzeug's `generate_password_hash` /
  `check_password_hash` (PBKDF2) — never stored or logged in plaintext.
- **Submission rate-limiting** (10 attempts per user per challenge) exists
  to slow down brute-forcing a flag, not to make it impossible — flags are
  intentionally long enough that brute-forcing isn't practical regardless.

## Supported Versions

This is a lab/teaching project without formal releases. Security fixes are
applied to the current `main`/default branch only — there's no LTS branch to
back-port to. If you've forked this for your own course or event, pull
latest before each run.
