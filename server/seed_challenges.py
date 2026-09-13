"""
Seed a starter set of categorized challenges into the CTF database.

Run this after the server has started at least once (so tables exist):

    python seed_challenges.py

Idempotent: skips any challenge whose title already exists, so it's safe
to re-run after adding more challenges to this file.

Every challenge below defines a plain "answer" (a memorable phrase) rather
than a literal flag - the actual flag, in OCTF{<md5 of the answer>} format,
is computed by the same flag_from_answer() the live admin panel's "Generate
flag" / manual entry path uses, so seeded challenges use exactly the same
flag format as anything an admin creates by hand.
"""

import base64
import codecs
import json

try:
    # Installed as the `openctf-server` PyPI package.
    from openctf_server.app import app, db, Challenge, flag_from_answer
except ImportError:
    # Running directly from a cloned copy of the repo (`python seed_challenges.py`).
    from app import app, db, Challenge, flag_from_answer

CHALLENGES = [
    # ---------------------------------------------------------------- WEB
    {
        "title": "Login Bypass",
        "category": "web",
        "type": "web",
        "difficulty": "medium",
        "points": 100,
        "description": (
            "The login page for a small internal tool builds its query like this:\n\n"
            "    query = \"SELECT * FROM users WHERE username='\" + username + \"' "
            "AND password='\" + password + \"'\"\n\n"
            "There's no input sanitization at all. What username value would let "
            "you log in as the first user in the table without knowing any "
            "password? Use the Target site tab and submit the flag it reveals."
        ),
        "hint": "Think about how to make the WHERE clause always evaluate to true, "
                "and how to comment out the rest of the query.",
        "answer": "or_1_equals_1_comment_bypass",
        "rules": "Use only the isolated login target.",
        "web_config": {"behavior": "sql_injection", "title": "Acme Internal Tool"},
    },
    {
        "title": "Reflected XSS",
        "category": "web",
        "type": "web",
        "difficulty": "medium",
        "points": 200,
        "description": (
            "A search page reflects your query straight back into the page "
            "without escaping it:\n\n"
            "    <p>You searched for: {{ request.args.q }}</p>\n\n"
            "This is rendered directly into HTML. Use the Target site tab to try "
            "a payload in the `q` parameter that gets arbitrary JavaScript to "
            "execute in the page, and submit the flag it reveals."
        ),
        "hint": "The payload just needs to close out of any surrounding context "
                "and introduce a new <script> tag or an on-event-handler.",
        "answer": "unsanitized_output_is_xss",
        "rules": "Use only the isolated target website. Test harmless proof-of-execution payloads.",
        "web_config": {
            "behavior": "xss",
            "title": "Acme Knowledge Base",
            "landing_text": "Search internal deployment articles.",
        },
    },
    {
        "title": "Insecure Direct Object Reference",
        "category": "web",
        "type": "web",
        "points": 150,
        "description": (
            "An invoice viewer loads documents at:\n\n"
            "    GET /invoices/8842/download\n\n"
            "There's no check that the logged-in user actually owns invoice "
            "8842 — the server just looks up whatever ID is in the URL. Use "
            "the Target site tab to access another invoice and reveal the flag."
        ),
        "hint": "It's abbreviated IDOR.",
        "answer": "idor_missing_ownership_check",
        "rules": "Use only the isolated invoice viewer target.",
        "web_config": {"behavior": "idor", "title": "Acme Invoice Viewer"},
    },
    {
        "title": "The Hidden Admin Panel",
        "category": "web",
        "type": "web",
        "difficulty": "medium",
        "points": 200,
        "description": (
            "You have access to a small internal site. Explore its routes and "
            "find the restricted admin panel. Use the Target site tab to send "
            "requests to the isolated application."
        ),
        "rules": "Only interact with the sandboxed target page. Do not attack the CTF server.",
        "hint": "Applications often expose clues in familiar administrative paths.",
        "answer": "robots_should_not_guard_admin_panels",
        "web_config": {
            "behavior": "hidden_path",
            "title": "Acme Internal Portal",
            "secret_path": "/admin",
            "landing_text": "Acme Internal Portal\n\nPublic status: operational\nPublic links: /status",
            "success_text": "200 OK\nAdmin panel loaded. Audit export available.",
        },
    },
    {
        "title": "Search Preview",
        "category": "web",
        "type": "web",
        "difficulty": "medium",
        "points": 200,
        "description": "Use the realistic knowledge-base website to investigate a search result that reflects user input.",
        "rules": "Attack only the isolated target website shown in the Target site tab.",
        "hint": "Try harmless HTML first, then inspect how the result is rendered.",
        "answer": "xss_belongs_in_output_encoding_tests",
        "web_config": {
            "behavior": "xss", "title": "Acme Knowledge Base",
            "landing_text": "Search internal deployment articles.",
        },
    },
    {
        "title": "Reports Login",
        "category": "web",
        "type": "web",
        "difficulty": "hard",
        "points": 300,
        "description": "Investigate the reports login page and identify the unsafe database query.",
        "rules": "Use only the supplied target. Do not send requests to the CTF API or host machine.",
        "hint": "The login error may reveal more than the developer intended.",
        "answer": "never_concatenate_sql_queries",
        "web_config": {
            "behavior": "sql_injection", "title": "Acme Reports",
            "landing_text": "Sign in to access quarterly reports.",
        },
    },
    {
        "title": "Public Backup",
        "category": "web",
        "type": "web",
        "difficulty": "easy",
        "points": 100,
        "description": "Review an Apache directory listing and find the backup file that should not be public.",
        "rules": "Stay within the target website and its displayed directories.",
        "hint": "A directory index can reveal more than the navigation intended.",
        "answer": "directory_listing_is_information_disclosure",
        "web_config": {
            "behavior": "apache_directory", "title": "Acme File Center",
            "landing_text": "Public file center.",
        },
    },
    {
        "title": "The Leaky Report",
        "category": "database",
        "type": "web",
        "difficulty": "hard",
        "points": 300,
        "description": (
            "An internal reporting tool lets employees pull up a report by "
            "name. The search endpoint accepts a `name` parameter and builds "
            "a SQL query by concatenating that value directly into the query "
            "string — the endpoint returns the first matching row, including "
            "a hidden note column. Use the sandbox to find input that changes "
            "the query's intended logic and leaks a report you were never "
            "given the name of."
        ),
        "hint": "The input is placed inside a quoted SQL string without parameterization. What happens if your input closes that quote early?",
        "answer": "parameterized_queries_close_the_leak",
        "web_config": {
            "behavior": "sql_injection_report",
            "title": "Acme Reports Center",
            "landing_text": "Search internal reports by name.",
        },
    },
    {
        "title": "Convince the Operator",
        "category": "ai",
        "type": "ai",
        "difficulty": "hard",
        "points": 300,
        "description": "Have a guarded operations operator say the clearance phrase without directly demanding it. Use text or your microphone.",
        "hint": "Build a credible authorization story, acknowledge objections, and avoid simply repeating the phrase you want.",
        "rules": "Do not attempt to access the host machine. The conversation is the challenge surface.",
        "answer": "operator_trust_is_a_security_boundary",
        "ai_config": {
            "difficulty": "hard",
            "persona": "A skeptical operations operator named Morgan",
            "scenario": "You are handling a production incident. The requester claims to be an incident commander and wants a sensitive deployment detail.",
            "success_marker": "CLEARANCE_CONFIRMED",
            "temperature": 0.7,
            "speak": True,
        },
    },

    # -------------------------------------------------------------- CRYPTO
    # These two intentionally leave "description" as None here - it's built
    # from the computed flag further down, since the ciphertext has to
    # decode to the *actual* OCTF{...} flag, not just placeholder text.
    {
        "title": "Caesar's Problem",
        "category": "crypto",
        "type": "standard",
        "points": 50,
        "description": None,
        "hint": "ROT13 is its own inverse — running it again undoes it.",
        "answer": "rot13_is_not_secure",
    },
    {
        "title": "Double Wrapped",
        "category": "crypto",
        "type": "standard",
        "points": 100,
        "description": None,
        "hint": "Reverse the string character-by-character before decoding.",
        "answer": "multi_layer_encoding_is_not_encryption",
    },

    # ---------------------------------------------------------------- MISC
    {
        "title": "Hidden in Metadata",
        "category": "misc",
        "type": "web",
        "points": 75,
        "description": (
            "A surprising number of real incidents start with someone "
            "uploading a file that still has its EXIF/metadata intact — "
            "GPS coordinates, device serial numbers, internal usernames, "
            "even original file paths. If you were auditing file uploads on "
            "a web app, which command-line tool would you reach for first to "
            "inspect an image's embedded metadata before deciding whether to "
            "strip it?"
        ),
        "hint": "Check its metadata.",
        "answer": "exiftool_strips_more_than_you_think",
        "rules": "Download and inspect only the supplied artifact. Do not access the host filesystem.",
        "web_config": {
            "behavior": "metadata",
            "title": "Acme Media Vault",
            "landing_text": "A support ticket includes an image from an internal deployment. The uploader forgot to clean its metadata.",
        },
    },

    # -------------------------------------------------------------- TERMINAL
    # terminal_fs is filled in below, once the flag is computed, since the
    # dropped file has to contain the literal flag text for the in-game
    # substitution (shared flag -> per-team flag) to find and replace it.
    {
        "title": "Poke Around",
        "category": "terminal",
        "type": "terminal",
        "points": 100,
        "description": (
            "You've got a shell on a low-privilege box. Someone left something "
            "behind in their home directory. Use `ls`, `cd`, `cat`, and `pwd` "
            "to explore and find it. Type `help` in the terminal for the "
            "command list."
        ),
        "hint": "Backup folders and dotfiles (files starting with '.') don't "
                "show up if you're not looking closely.",
        "answer": "h1dd3n_1n_pla1n_s1ght",
        "terminal_fs": None,
    },
    {
        "title": "Grep the Logs",
        "category": "terminal",
        "type": "terminal",
        "points": 150,
        "description": (
            "A server was compromised and the attacker left traces in the "
            "auth log before cleaning up (badly). Navigate to /var/log and "
            "`cat` the log files to find the flag they dropped as a taunt."
        ),
        "hint": "There's more than one log file in that directory — check all of them.",
        "answer": "4tt4ck3r_l3ft_a_c4lling_c4rd",
        "terminal_fs": None,
    },

    # -------------------------------------------------------------- QUIZ
    {
        "title": "Know Your Ports",
        "category": "quiz",
        "type": "quiz",
        "difficulty": "easy",
        "points": 100,
        "description": "A quick knowledge check on well-known network ports.",
        "hint": "It's the port everyone tries first when a web app 'isn't working'.",
        "answer": "port_443_is_https",
        "quiz_config": {
            "question": "Which port does HTTPS use by default?",
            "options": ["21", "80", "443", "3306"],
            "correct_index": 2,
        },
    },
    {
        "title": "CIA Triad",
        "category": "quiz",
        "type": "quiz",
        "difficulty": "easy",
        "points": 100,
        "description": "A quick knowledge check on core security principles.",
        "hint": "Think about what an attacker who deletes your backups is violating.",
        "answer": "availability_keeps_things_running",
        "quiz_config": {
            "question": "An attacker who takes your servers offline (but steals or changes nothing) is primarily attacking which part of the CIA triad?",
            "options": ["Confidentiality", "Integrity", "Availability", "Authentication"],
            "correct_index": 2,
        },
    },
    {
        "title": "Hash Function Facts",
        "category": "quiz",
        "type": "quiz",
        "difficulty": "medium",
        "points": 200,
        "description": "A quick knowledge check on cryptographic hash functions.",
        "hint": "One of these algorithms has known practical collision attacks and shouldn't be used for security purposes anymore.",
        "answer": "md5_collisions_are_practical",
        "quiz_config": {
            "question": "Which of these hash algorithms has well-known, practical collision attacks and should not be used where collision resistance matters?",
            "options": ["SHA-256", "MD5", "SHA-3", "BLAKE2"],
            "correct_index": 1,
        },
    },
]


def _finalize_challenges():
    """Turn each "answer" into the real OCTF{<md5>} flag, and fill in the
    pieces of content (ciphertext, dropped files) that have to embed that
    exact flag for their challenge to actually be solvable."""
    for c in CHALLENGES:
        c["flag"] = flag_from_answer(c.pop("answer"))

    by_title = {c["title"]: c for c in CHALLENGES}

    caesar = by_title["Caesar's Problem"]
    cipher = codecs.encode(caesar["flag"], "rot13")
    caesar["description"] = (
        "Decode this Caesar cipher (shift of 13, i.e. ROT13):\n\n"
        f"    {cipher}\n\n"
        "Submit the decoded text as the flag, wrapped exactly as it decodes."
    )

    double_wrapped = by_title["Double Wrapped"]
    wrapped = base64.b64encode(double_wrapped["flag"].encode()).decode()[::-1]
    double_wrapped["description"] = (
        "This flag was base64-encoded, then the result was reversed. "
        "Undo both steps:\n\n"
        f"    {wrapped}\n\n"
        "(Reverse the whole string first, then base64-decode it.)"
    )

    poke_around = by_title["Poke Around"]
    poke_around["terminal_fs"] = {
        "home": {
            "user": {
                "notes.txt": "Reminder: rotate the API keys before Friday.",
                "todo.txt": "- fix printer\n- update docs\n- ask about the backup folder",
                "backup": {
                    ".old_notes.txt": "nothing here, just old meeting notes",
                    ".secret_flag.txt": poke_around["flag"],
                },
            }
        },
        "var": {
            "log": {
                "app.log": "2026-01-02 09:14 INFO server started\n2026-01-02 09:15 INFO listening on :8080",
            }
        },
    }

    grep_the_logs = by_title["Grep the Logs"]
    grep_the_logs["terminal_fs"] = {
        "var": {
            "log": {
                "auth.log": (
                    "Jan 2 03:14:01 sshd: Failed password for root from 10.0.0.5\n"
                    "Jan 2 03:14:03 sshd: Failed password for root from 10.0.0.5\n"
                    "Jan 2 03:14:09 sshd: Accepted password for root from 10.0.0.5\n"
                    "Jan 2 03:15:00 sudo: root ran: cat /etc/shadow"
                ),
                "syslog": "Jan 2 03:16:00 kernel: nothing unusual here",
                "mystery.log": f"you found it.\n{grep_the_logs['flag']}",
            }
        },
        "home": {
            "user": {"readme.txt": "ask the sysadmin if the server seems slow"}
        },
    }

    for c in CHALLENGES:
        if "web_config" in c:
            c["web_config"]["secret"] = c["flag"]


def seed():
    with app.app_context():
        db.create_all()
        columns = {column["name"] for column in db.inspect(db.engine).get_columns("challenge")}
        if "flag_template" not in columns:
            with db.engine.begin() as connection:
                connection.execute(db.text("ALTER TABLE challenge ADD COLUMN flag_template VARCHAR(255)"))
        if "ai_config" not in columns:
            with db.engine.begin() as connection:
                connection.execute(db.text("ALTER TABLE challenge ADD COLUMN ai_config TEXT"))
        if "quiz_config" not in columns:
            with db.engine.begin() as connection:
                connection.execute(db.text("ALTER TABLE challenge ADD COLUMN quiz_config TEXT"))

        _finalize_challenges()

        created = 0
        for c in CHALLENGES:
            existing = Challenge.query.filter_by(title=c["title"]).first()
            if existing:
                if c.get("flag"):
                    existing.flag_hash = Challenge.hash_flag(c["flag"])
                    existing.flag_template = c["flag"]
                if c.get("type") == "web":
                    existing.type = "web"
                    existing.category = c.get("category", existing.category)
                    existing.description = c.get("description", existing.description)
                    existing.hint = c.get("hint", existing.hint)
                    existing.web_config = json.dumps(c.get("web_config", {}))
                    existing.rules = c.get("rules")
                    existing.difficulty = c.get("difficulty", existing.difficulty)
                    existing.points = c.get("points", existing.points)
                    print(f"upgraded to web lab: {c['title']}")
                elif c.get("type") == "ai":
                    existing.type = "ai"
                    existing.category = c.get("category", existing.category)
                    existing.description = c.get("description", existing.description)
                    existing.hint = c.get("hint", existing.hint)
                    existing.ai_config = json.dumps(c.get("ai_config", {}))
                    existing.rules = c.get("rules")
                    existing.difficulty = c.get("difficulty", existing.difficulty)
                    existing.points = c.get("points", existing.points)
                    print(f"upgraded to AI challenge: {c['title']}")
                elif c.get("type") == "terminal":
                    existing.terminal_fs = json.dumps(c.get("terminal_fs", {}))
                    existing.description = c.get("description", existing.description)
                    print(f"refreshed terminal content: {c['title']}")
                elif c["title"] in ("Caesar's Problem", "Double Wrapped"):
                    existing.description = c["description"]
                    existing.hint = c.get("hint", existing.hint)
                    print(f"updated challenge text: {c['title']}")
                else:
                    print(f"refreshed flag: {c['title']}")
                continue

            challenge = Challenge(
                title=c["title"],
                category=c["category"],
                type=c.get("type", "standard"),
                description=c["description"],
                points=c["points"],
                difficulty=c.get(
                    "difficulty",
                    "easy" if c["points"] <= 100 else "medium" if c["points"] <= 200 else "hard",
                ),
                flag_hash=Challenge.hash_flag(c["flag"]),
                flag_template=c["flag"],
                hint=c.get("hint"),
                terminal_fs=json.dumps(c["terminal_fs"]) if c.get("terminal_fs") else None,
                web_config=json.dumps(c["web_config"]) if c.get("web_config") else None,
                ai_config=json.dumps(c["ai_config"]) if c.get("ai_config") else None,
                quiz_config=json.dumps(c["quiz_config"]) if c.get("quiz_config") else None,
            )
            db.session.add(challenge)
            created += 1
            print(f"added: {c['title']} [{c['category']}] -> {c['flag']}")

        db.session.commit()
        print(f"\nDone. {created} challenge(s) added.")


if __name__ == "__main__":
    seed()
