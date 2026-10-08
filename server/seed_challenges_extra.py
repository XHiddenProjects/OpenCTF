"""Additional starter challenges (v1.3.0), kept apart from seed_challenges.py.

`seed_challenges.py` appends EXTRA_CHALLENGES to its own list and calls
`finalize_extra()` once every challenge's "answer" has become a real flag.

  * 12 coding challenges (type "code", built with the same JSON the admin
    Code challenge builder produces). Every expected value is computed here
    with plain-Python reference functions, never typed by hand, and
    REFERENCE_SOLUTIONS holds working solutions that tests/test_seed_challenges.py
    runs through the real runner - so a typo can't ship an unsolvable challenge.
  * 4 crypto/encoding puzzles whose ciphertext is derived from the real flag.
  * 3 terminal challenges (virtual filesystem, flag embedded as the literal flag).
  * 4 quizzes.

Pure data + small helpers: no app imports, safe to import anywhere.
"""

import json

# --------------------------------------------------------------------------
# Reference implementations (the source of truth for expected test values)
# --------------------------------------------------------------------------


def _fizz_buzz_value(n):
    if n % 15 == 0:
        return "FizzBuzz"
    if n % 3 == 0:
        return "Fizz"
    if n % 5 == 0:
        return "Buzz"
    return str(n)


def _reverse_words(sentence):
    return " ".join(sentence.split(" ")[::-1])


def _second_largest(nums):
    distinct = sorted(set(nums), reverse=True)
    return distinct[1] if len(distinct) > 1 else -1


def _count_set_bits(n):
    return bin(n).count("1")


def _run_length_encode(text):
    out, i = [], 0
    while i < len(text):
        j = i
        while j < len(text) and text[j] == text[i]:
            j += 1
        out.append(f"{text[i]}{j - i}")
        i = j
    return "".join(out)


def _count_primes(n):
    return sum(1 for k in range(2, n + 1) if all(k % d for d in range(2, int(k ** 0.5) + 1)))


def _to_roman(n):
    out = ""
    for value, symbol in ((1000, "M"), (900, "CM"), (500, "D"), (400, "CD"), (100, "C"), (90, "XC"),
                          (50, "L"), (40, "XL"), (10, "X"), (9, "IX"), (5, "V"), (4, "IV"), (1, "I")):
        while n >= value:
            out += symbol
            n -= value
    return out


def _shift(text, amount):
    def move(ch):
        if "a" <= ch <= "z":
            return chr((ord(ch) - 97 + amount) % 26 + 97)
        if "A" <= ch <= "Z":
            return chr((ord(ch) - 65 + amount) % 26 + 65)
        return ch
    return "".join(move(c) for c in text)


def _shift_decode(text, shift):
    return _shift(text, -shift)


def _diagonal_sum(matrix):
    n = len(matrix)
    total = sum(matrix[i][i] + matrix[i][n - 1 - i] for i in range(n))
    return total - matrix[n // 2][n // 2] if n % 2 else total


def _two_sum(nums, target):
    for i in range(len(nums)):
        for j in range(i + 1, len(nums)):
            if nums[i] + nums[j] == target:
                return [i, j]
    raise ValueError("no solution")


def _word_count(text):
    import re
    counts = {}
    for word in re.findall(r"[a-z]+", text.lower()):
        counts[word] = counts.get(word, 0) + 1
    return counts


def _flatten(items):
    out = []
    for item in items:
        out.extend(_flatten(item) if isinstance(item, list) else [item])
    return out


def _tests(fn, cases, hidden_from=None):
    """Build test dicts from argument tuples; the last `hidden_from..` cases are hidden."""
    tests = []
    for index, args in enumerate(cases):
        test = {"args": list(args), "expect": fn(*args)}
        if hidden_from is not None and index >= hidden_from:
            test["hidden"] = True
        tests.append(test)
    return tests


_ALL_LANGS = ["javascript", "python", "php", "ruby", "c", "cpp", "java"]
_NO_C = ["javascript", "python", "php", "ruby", "cpp", "java"]
_DYNAMIC = ["javascript", "python", "php", "ruby"]


def _code(title, difficulty, points, description, hint, answer, fn_name, names, types, ret,
          languages, instructions, tests):
    config = {
        "function_name": fn_name, "language": "javascript", "languages": languages,
        "parameter_names": names, "instructions": instructions, "tests": tests,
    }
    if types is not None:
        config["parameter_types"] = types
        config["return_type"] = ret
    return {
        "title": title, "category": "coding", "type": "code", "difficulty": difficulty,
        "points": points, "description": description, "hint": hint, "answer": answer,
        "rules": "Code runs on the CTF server in a limited sandbox. Use Run to test, then Submit the flag once every test passes.",
        "code_config": config,
    }


EXTRA_CHALLENGES = [
    # ------------------------------------------------------------ CODING
    _code("FizzBuzz Value", "easy", 75,
          "The classic, one number at a time. Write `fizzBuzzValue(n)` and every test must pass.",
          "Check divisibility by 15 first - otherwise 15 would stop at the \"Fizz\" rule.",
          "check_fifteen_before_three_and_five", "fizzBuzzValue", ["n"], ["int"], "string", _ALL_LANGS,
          "Return \"FizzBuzz\" if n is divisible by 15, \"Fizz\" if by 3, \"Buzz\" if by 5, otherwise n as a string.",
          _tests(_fizz_buzz_value, [(1,), (3,), (5,), (7,), (15,), (30,), (98,), (99,), (100,)], hidden_from=6)),
    _code("Reverse Words", "easy", 100,
          "Flip a sentence around without reversing the letters inside each word.",
          "Split on spaces, reverse the list, join it back.",
          "split_reverse_join", "reverseWords", ["sentence"], ["string"], "string", _ALL_LANGS,
          "Words are separated by single spaces. Return the words in reverse order, separated by single spaces. An empty string stays empty.",
          _tests(_reverse_words, [("the sky is blue",), ("hello",), ("a b",), ("",), ("one two three four five",),
                                  ("never gonna give you up",)], hidden_from=4)),
    _code("Second Largest", "easy", 100,
          "Find the runner-up in a list of numbers - duplicates don't count twice.",
          "Distinct values only: [7, 7, 7] has no second largest.",
          "second_place_among_distinct_values", "secondLargest", ["nums"], ["int[]"], "int", _ALL_LANGS,
          "Return the second largest DISTINCT value in nums, or -1 if there are fewer than two distinct values.",
          _tests(_second_largest, [([3, 1, 4, 1, 5],), ([7, 7, 7],), ([2, 1],), ([10],), ([5, 5, 4, 4, 3],),
                                   ([-1, -2, -3],), ([9, 9, 8, 1, 8, 2],)], hidden_from=5)),
    _code("Count Set Bits", "easy", 75,
          "How many 1s are in the binary form of a number?",
          "n & 1 looks at the lowest bit; shift right to move to the next one.",
          "shift_and_mask_the_low_bit", "countSetBits", ["n"], ["int"], "int", _ALL_LANGS,
          "Return how many bits are set to 1 in n (n is never negative).",
          _tests(_count_set_bits, [(0,), (1,), (7,), (8,), (255,), (1023,), (2147483647,)], hidden_from=5)),
    _code("Run-Length Encode", "medium", 125,
          "Compress repeated characters the old-school way.",
          "Walk the string once, counting how long the current run is before writing it out.",
          "count_each_run_then_emit", "runLengthEncode", ["text"], ["string"], "string", _ALL_LANGS,
          "Replace every run of the same character with the character followed by the run length: \"aaabcc\" becomes \"a3b1c2\". Single characters get a 1. An empty string stays empty.",
          _tests(_run_length_encode, [("aaabcc",), ("",), ("x",), ("zzzzzzzzzzzz",), ("abab",),
                                      ("mmmmnnnnnnnnnnnoo",), ("aabbbbbbbbbbbbaa",)], hidden_from=5)),
    _code("Prime Counter", "medium", 125,
          "How many primes are there up to n? Your code has to stay fast on bigger inputs.",
          "A sieve of Eratosthenes counts primes up to 10,000 instantly; trial division by every number is slower but fine here.",
          "sieve_of_eratosthenes_rocks", "countPrimes", ["n"], ["int"], "int", _ALL_LANGS,
          "Return how many prime numbers are less than or equal to n.",
          _tests(_count_primes, [(0,), (1,), (2,), (10,), (100,), (1000,), (10000,)], hidden_from=5)),
    _code("Roman Numerals", "medium", 150,
          "Convert numbers to Roman numerals (1 to 3999).",
          "Walk down a table of values - 1000, 900, 500, 400 ... 4, 1 - subtracting as many as fit.",
          "greedy_table_of_roman_values", "toRoman", ["n"], ["int"], "string", _ALL_LANGS,
          "Return the Roman numeral for n (1 <= n <= 3999), using subtractive forms such as IV, IX, XL, XC, CD and CM.",
          _tests(_to_roman, [(1,), (4,), (9,), (14,), (58,), (1994,), (3999,), (444,)], hidden_from=6)),
    _code("Shift Decode", "medium", 150,
          "A Caesar-style message arrives with its shift amount. Decode it.",
          "Letters wrap around: shifting 'a' back by 1 gives 'z'. Keep upper and lower case, and leave everything else alone.",
          "wrap_around_with_modulo", "shiftDecode", ["text", "shift"], ["string", "int"], "string", _ALL_LANGS,
          "Shift every letter BACK by `shift` places (a-z and A-Z wrap around), keeping its case. Digits, spaces and punctuation stay as they are.",
          _tests(_shift_decode, [("Khoor, Zruog!", 3), ("Uryyb", 13), ("abc", 0), ("Bzmp 2 Zmzp", 25),
                                 ("Ymj vznhp gwtbs ktc", 5), ("Wkh txlfn eurzq ira 42!", 3)], hidden_from=4)),
    _code("Diagonal Sum", "medium", 150,
          "Add up both diagonals of a square grid.",
          "For an n x n grid the diagonals are matrix[i][i] and matrix[i][n-1-i]. In odd-sized grids they share the centre cell.",
          "count_the_centre_only_once", "diagonalSum", ["matrix"], ["int[][]"], "int", _NO_C,
          "Return the sum of the main diagonal and the anti-diagonal of a square matrix. If they cross at a centre cell, count it once.",
          _tests(_diagonal_sum, [([[1, 2], [3, 4]],), ([[5]],), ([[1, 2, 3], [4, 5, 6], [7, 8, 9]],),
                                 ([[1, 0, 0, 2], [0, 3, 4, 0], [0, 5, 6, 0], [7, 0, 0, 8]],),
                                 ([[2, 9, 1, 3, 7], [4, 8, 6, 2, 1], [5, 3, 9, 4, 6], [8, 2, 7, 1, 5], [6, 4, 3, 9, 2]],)],
                 hidden_from=3)),
    _code("Two Sum Indices", "hard", 200,
          "Find the two positions whose values add up to a target.",
          "A dictionary of value -> index lets you solve this in one pass.",
          "one_pass_with_a_hash_map", "twoSum", ["nums", "target"], ["int[]", "int"], "int[]", _NO_C,
          "Return [i, j] with i < j such that nums[i] + nums[j] == target. Exactly one pair exists in every test.",
          _tests(_two_sum, [([2, 7, 11, 15], 9), ([3, 2, 4], 6), ([3, 3], 6), ([-3, 4, 3, 90], 0),
                            ([1, 5, 9, 14, 20, 31, 40], 54), ([10, 20, 30, 40, 50, 60], 110)], hidden_from=4)),
    _code("Word Counter", "hard", 200,
          "Count how often each word appears. This one returns an object, so it's JavaScript, Python, PHP or Ruby.",
          "Lowercase first, then pull out runs of letters - punctuation just separates words.",
          "lowercase_then_count_letter_runs", "wordCount", ["text"], None, None, _DYNAMIC,
          "Return an object (dictionary / hash) mapping each lowercase word to how many times it appears. Words are runs of letters a-z (any case); every other character separates words.",
          _tests(_word_count, [("the cat and the hat",), ("Hello, hello!",), ("To be, or not to be: that is the question.",),
                               ("Red RED red... blue? Blue!",), ("It's a dog-eat-dog world",)], hidden_from=3)),
    _code("Flatten It", "hard", 200,
          "Un-nest a list that can be nested to any depth. Returns a list, so it's JavaScript, Python, PHP or Ruby.",
          "Recursion fits perfectly: if an item is a list, flatten it too; otherwise keep it.",
          "recurse_when_the_item_is_a_list", "flatten", ["items"], None, None, _DYNAMIC,
          "Return a flat list of all the numbers in items, in their original left-to-right order.",
          _tests(_flatten, [([1, [2, [3, [4]]], 5],), ([[], [[]]],), ([1, 2, 3],), ([[[[9]]], 8, [7, [6, [5]]]],),
                            ([[1, [2]], [[3], 4], [[[5, 6]]]],)], hidden_from=3)),

    # ------------------------------------------------------------ CRYPTO / ENCODING
    {"title": "Atbash Whisper", "category": "crypto", "type": "standard", "difficulty": "easy", "points": 75,
     "description": None, "hint": "Atbash swaps the alphabet end-for-end: A<->Z, B<->Y, C<->X... Applying it twice gives you the original.",
     "answer": "atbash_is_its_own_inverse", "rules": ""},
    {"title": "Binary Beacon", "category": "general", "type": "standard", "difficulty": "easy", "points": 75,
     "description": None, "hint": "Each group of 8 digits is one ASCII character. Convert groups to decimal, then to characters.",
     "answer": "eight_bits_make_a_byte", "rules": ""},
    {"title": "Morse Dispatch", "category": "crypto", "type": "standard", "difficulty": "easy", "points": 100,
     "description": None, "hint": "Letters are separated by a space. Digits are five signals long; letters at most four.",
     "answer": "dots_and_dashes_travel_far", "rules": ""},
    {"title": "Rail Fence Rails", "category": "crypto", "type": "standard", "difficulty": "medium", "points": 150,
     "description": None, "hint": "Write the text in a zig-zag across three rows, then read row by row. To decode, work out how many characters land on each row first.",
     "answer": "zigzag_across_three_rails", "rules": ""},

    # ------------------------------------------------------------ TERMINAL
    {"title": "Cron Trail", "category": "general", "type": "terminal", "difficulty": "easy", "points": 100,
     "description": "A scheduled job keeps running on this box and nobody remembers who set it up. Follow the trail from the system's job schedule to whatever it runs, and find the secret it guards. Type `help` for the command list.",
     "hint": "Scheduled jobs live in /etc/crontab. Read what they run - and what those scripts mention.",
     "answer": "cron_jobs_leave_footprints", "rules": "The filesystem is an isolated simulation.", "terminal_fs": None},
    {"title": "Config Hunt", "category": "general", "type": "terminal", "difficulty": "medium", "points": 125,
     "description": "A web app was deployed with its settings scattered across several files. Somewhere under /srv there is an API key. `grep -r` is your friend.",
     "hint": "Try: grep -r -i api /srv   (decoys exist - the real key is the one marked production).",
     "answer": "grep_recursively_for_secrets", "rules": "The filesystem is an isolated simulation.", "terminal_fs": None},
    {"title": "Shell History", "category": "forensics", "type": "terminal", "difficulty": "easy", "points": 100,
     "description": "An administrator logged out in a hurry. Their shell remembers everything they typed, including things they shouldn't have. See what they left behind.",
     "hint": "Look around /home. A shell stores what you typed in a hidden file whose name starts with .bash",
     "answer": "history_remembers_everything", "rules": "The filesystem is an isolated simulation.", "terminal_fs": None},

    # ------------------------------------------------------------ QUIZZES
    {"title": "Port Patrol", "category": "quiz", "type": "quiz", "difficulty": "easy", "points": 100,
     "description": "A quick networking knowledge check.", "hint": "It starts with a remote shell, and it's the one port every sysadmin knows by heart.",
     "answer": "ssh_listens_on_port_22",
     "quiz_config": {"question": "Which TCP port does SSH use by default?", "options": ["21", "22", "23", "25"], "correct_index": 1}},
    {"title": "Hash or Encrypt", "category": "quiz", "type": "quiz", "difficulty": "easy", "points": 100,
     "description": "Two ideas people often mix up.", "hint": "Think about whether you can ever get the original input back from the output.",
     "answer": "hashes_are_one_way",
     "quiz_config": {"question": "What is the key difference between hashing and encryption?",
                     "options": ["A hash is one-way; encryption can be reversed with the key", "Hashes need a key to be reversed",
                                 "Encryption always produces shorter output", "Hashing is only used for images"], "correct_index": 0}},
    {"title": "Forbidden Status", "category": "quiz", "type": "quiz", "difficulty": "easy", "points": 100,
     "description": "HTTP status codes, decoded.", "hint": "The server heard you perfectly well. It just isn't going to do it.",
     "answer": "403_means_not_allowed",
     "quiz_config": {"question": "What does an HTTP 403 response mean?",
                     "options": ["The page does not exist", "The server understood the request but refuses to authorize it",
                                 "The server crashed", "The request was redirected"], "correct_index": 1}},
    {"title": "Why Salt?", "category": "quiz", "type": "quiz", "difficulty": "medium", "points": 150,
     "description": "A password-storage classic.", "hint": "What do attackers precompute so they can reverse hashes instantly?",
     "answer": "salts_defeat_rainbow_tables",
     "quiz_config": {"question": "What is the main purpose of adding a unique salt before hashing a password?",
                     "options": ["To make the hash shorter", "To defeat precomputed rainbow tables and identical-hash matching",
                                 "To encrypt the password", "To make logins faster"], "correct_index": 1}},
]


# --------------------------------------------------------------------------
# Content that must embed the real flag (called after answers become flags)
# --------------------------------------------------------------------------

_MORSE = {
    "0": "-----", "1": ".----", "2": "..---", "3": "...--", "4": "....-", "5": ".....", "6": "-....",
    "7": "--...", "8": "---..", "9": "----.", "a": ".-", "b": "-...", "c": "-.-.", "d": "-..", "e": ".", "f": "..-.",
}


def atbash(text):
    def flip(ch):
        if "a" <= ch <= "z":
            return chr(219 - ord(ch))
        if "A" <= ch <= "Z":
            return chr(155 - ord(ch))
        return ch
    return "".join(flip(c) for c in text)


def rail_fence_encrypt(text, rails=3):
    rows = [[] for _ in range(rails)]
    row, step = 0, 1
    for ch in text:
        rows[row].append(ch)
        if row == 0:
            step = 1
        elif row == rails - 1:
            step = -1
        row += step
    return "".join("".join(r) for r in rows)


def rail_fence_decrypt(cipher, rails=3):
    pattern, row, step = [], 0, 1
    for _ in cipher:
        pattern.append(row)
        if row == 0:
            step = 1
        elif row == rails - 1:
            step = -1
        row += step
    counts = [pattern.count(r) for r in range(rails)]
    rows, start = [], 0
    for c in counts:
        rows.append(list(cipher[start:start + c]))
        start += c
    return "".join(rows[r].pop(0) for r in pattern)


def _file(path_parts, content):
    return path_parts, content


def _tree(files):
    root = {}
    for parts, content in files:
        node = root
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node[parts[-1]] = content
    return root


def finalize_extra(by_title):
    """Fill in challenge text/filesystems that must contain each real flag."""
    flag = lambda title: by_title[title]["flag"]  # noqa: E731

    f = flag("Atbash Whisper")
    by_title["Atbash Whisper"]["description"] = (
        "Intercepted note, encoded with the Atbash cipher (the alphabet written backwards: A<->Z, B<->Y ...). "
        "Numbers, braces and underscores are untouched.\n\n"
        f"    {atbash(f)}\n\n"
        "Decode it to recover the flag."
    )

    f = flag("Binary Beacon")
    by_title["Binary Beacon"]["description"] = (
        "A blinking light on the roof spells out a message in binary - eight signals per character:\n\n"
        f"    {' '.join(format(ord(c), '08b') for c in f)}\n\n"
        "Translate it back to text to get the flag."
    )

    f = flag("Morse Dispatch")
    inner = f[f.index("{") + 1:f.rindex("}")]
    by_title["Morse Dispatch"]["description"] = (
        "A radio operator sent the 32-character code inside the flag in Morse code (letters are separated by spaces; "
        "the code only uses the digits 0-9 and the letters a-f):\n\n"
        f"    {' '.join(_MORSE[c] for c in inner)}\n\n"
        "Decode it, then wrap the result as OCTF{...} to get the flag."
    )

    f = flag("Rail Fence Rails")
    by_title["Rail Fence Rails"]["description"] = (
        "This whole flag was scrambled with a rail fence cipher using 3 rails: the text is written diagonally "
        "down and up across three rows, then read off row by row.\n\n"
        f"    {rail_fence_encrypt(f, 3)}\n\n"
        "Undo it to recover the flag."
    )

    f = flag("Cron Trail")
    by_title["Cron Trail"]["terminal_fs"] = _tree([
        (["etc", "crontab"], "# m h dom mon dow user  command\n17 *  * * *  root  cd / && run-parts --report /etc/cron.hourly\n"
                             "*/5 * * * *  deploy  /opt/scripts/nightly_sync.sh\n"),
        (["opt", "scripts", "nightly_sync.sh"], "#!/bin/sh\n# Sync reports to the archive host.\n"
                                                "# Credentials for the archive live in /var/backups/.vault/archive_token\n"
                                                "rsync -a /srv/reports/ archive:/data/\n"),
        (["opt", "scripts", "cleanup.sh"], "#!/bin/sh\n# Not scheduled any more.\nrm -rf /tmp/old_reports\n"),
        (["var", "backups", ".vault", "archive_token"], f"{f}\n"),
        (["var", "backups", "readme.txt"], "Nothing to see here.\n"),
        (["home", "player", "notes.txt"], "Start with /etc/crontab.\n"),
    ])

    f = flag("Config Hunt")
    by_title["Config Hunt"]["terminal_fs"] = _tree([
        (["srv", "app", "config", "development.ini"], "[server]\nport = 8080\napi_key = dev-key-not-secret\n"),
        (["srv", "app", "config", "staging.ini"], "[server]\nport = 8081\napi_key = staging-key-123\n"),
        (["srv", "app", "config", "production.ini"], f"[server]\nport = 443\napi_key = {f}\n# environment: production\n"),
        (["srv", "app", "README.md"], "Config files live in config/. Do not commit real keys.\n"),
        (["srv", "app", "logs", "app.log"], "INFO started\nINFO loaded api module\nWARN api latency high\n"),
        (["home", "player", "todo.txt"], "grep -r -i api /srv\n"),
    ])

    f = flag("Shell History")
    by_title["Shell History"]["terminal_fs"] = _tree([
        (["home", "player", "readme.txt"], "This account belonged to the previous administrator.\n"),
        (["home", "admin", ".bash_history"],
         "ls\ncd /var/www\nsudo systemctl restart nginx\n"
         f"curl -s -H \"X-Admin-Token: {f}\" https://internal.example/api/status\n"
         "clear\nexit\n"),
        (["home", "admin", "notes.txt"], "Rotate the admin token after the migration.\n"),
        (["var", "www", "index.html"], "<h1>It works</h1>\n"),
    ])


# --------------------------------------------------------------------------
# Reference solutions: used by tests/test_seed_challenges.py to prove every
# new coding challenge is solvable in at least these languages.
# --------------------------------------------------------------------------

REFERENCE_SOLUTIONS = {
    "FizzBuzz Value": {
        "javascript": 'function fizzBuzzValue(n) { if (n % 15 === 0) return "FizzBuzz"; if (n % 3 === 0) return "Fizz"; if (n % 5 === 0) return "Buzz"; return String(n); }',
        "python": 'def fizzBuzzValue(n):\n    if n % 15 == 0: return "FizzBuzz"\n    if n % 3 == 0: return "Fizz"\n    if n % 5 == 0: return "Buzz"\n    return str(n)\n',
        "php": 'function fizzBuzzValue($n) { if ($n % 15 == 0) return "FizzBuzz"; if ($n % 3 == 0) return "Fizz"; if ($n % 5 == 0) return "Buzz"; return strval($n); }',
        "ruby": 'def fizzBuzzValue(n)\n  return "FizzBuzz" if n % 15 == 0\n  return "Fizz" if n % 3 == 0\n  return "Buzz" if n % 5 == 0\n  n.to_s\nend\n',
        "c": '#include <string.h>\nconst char *fizzBuzzValue(int n) { static char buf[16]; if (n % 15 == 0) return "FizzBuzz"; if (n % 3 == 0) return "Fizz"; if (n % 5 == 0) return "Buzz"; sprintf(buf, "%d", n); return buf; }',
        "cpp": 'std::string fizzBuzzValue(int n) { if (n % 15 == 0) return "FizzBuzz"; if (n % 3 == 0) return "Fizz"; if (n % 5 == 0) return "Buzz"; return std::to_string(n); }',
        "java": 'public static String fizzBuzzValue(int n) { if (n % 15 == 0) return "FizzBuzz"; if (n % 3 == 0) return "Fizz"; if (n % 5 == 0) return "Buzz"; return String.valueOf(n); }',
    },
    "Reverse Words": {
        "javascript": 'function reverseWords(s) { return s.split(" ").reverse().join(" "); }',
        "python": 'def reverseWords(sentence):\n    return " ".join(sentence.split(" ")[::-1])\n',
        "cpp": '#include <sstream>\nstd::string reverseWords(std::string s) { std::istringstream in(s); std::vector<std::string> w; std::string x; while (in >> x) w.push_back(x); std::string out; for (int i = (int)w.size() - 1; i >= 0; --i) { out += w[i]; if (i) out += " "; } return out; }',
    },
    "Second Largest": {
        "javascript": "function secondLargest(nums) { const d = [...new Set(nums)].sort((a, b) => b - a); return d.length > 1 ? d[1] : -1; }",
        "python": "def secondLargest(nums):\n    d = sorted(set(nums), reverse=True)\n    return d[1] if len(d) > 1 else -1\n",
        "cpp": "#include <set>\nint secondLargest(std::vector<int> nums) { std::set<int, std::greater<int>> d(nums.begin(), nums.end()); if (d.size() < 2) return -1; auto it = d.begin(); ++it; return *it; }",
    },
    "Count Set Bits": {
        "javascript": "function countSetBits(n) { let c = 0; while (n > 0) { c += n & 1; n >>>= 1; } return c; }",
        "python": "def countSetBits(n):\n    return bin(n).count('1')\n",
        "cpp": "int countSetBits(int n) { int c = 0; while (n) { c += n & 1; n >>= 1; } return c; }",
    },
    "Run-Length Encode": {
        "javascript": "function runLengthEncode(t) { let o = '', i = 0; while (i < t.length) { let j = i; while (j < t.length && t[j] === t[i]) j++; o += t[i] + (j - i); i = j; } return o; }",
        "python": "def runLengthEncode(text):\n    out, i = '', 0\n    while i < len(text):\n        j = i\n        while j < len(text) and text[j] == text[i]: j += 1\n        out += text[i] + str(j - i)\n        i = j\n    return out\n",
        "cpp": "std::string runLengthEncode(std::string t) { std::string o; size_t i = 0; while (i < t.size()) { size_t j = i; while (j < t.size() && t[j] == t[i]) j++; o += t[i]; o += std::to_string(j - i); i = j; } return o; }",
    },
    "Prime Counter": {
        "javascript": "function countPrimes(n) { if (n < 2) return 0; const s = new Array(n + 1).fill(true); s[0] = s[1] = false; for (let i = 2; i * i <= n; i++) if (s[i]) for (let j = i * i; j <= n; j += i) s[j] = false; return s.filter(Boolean).length; }",
        "python": "def countPrimes(n):\n    if n < 2: return 0\n    s = [True] * (n + 1); s[0] = s[1] = False\n    for i in range(2, int(n ** 0.5) + 1):\n        if s[i]:\n            for j in range(i * i, n + 1, i): s[j] = False\n    return sum(s)\n",
        "cpp": "int countPrimes(int n) { if (n < 2) return 0; std::vector<bool> s(n + 1, true); s[0] = s[1] = false; for (long long i = 2; i * i <= n; i++) if (s[i]) for (long long j = i * i; j <= n; j += i) s[j] = false; int c = 0; for (bool b : s) c += b; return c; }",
    },
    "Roman Numerals": {
        "javascript": "function toRoman(n) { const t = [[1000,'M'],[900,'CM'],[500,'D'],[400,'CD'],[100,'C'],[90,'XC'],[50,'L'],[40,'XL'],[10,'X'],[9,'IX'],[5,'V'],[4,'IV'],[1,'I']]; let o = ''; for (const [v, s] of t) while (n >= v) { o += s; n -= v; } return o; }",
        "python": "def toRoman(n):\n    t = [(1000,'M'),(900,'CM'),(500,'D'),(400,'CD'),(100,'C'),(90,'XC'),(50,'L'),(40,'XL'),(10,'X'),(9,'IX'),(5,'V'),(4,'IV'),(1,'I')]\n    o = ''\n    for v, s in t:\n        while n >= v:\n            o += s; n -= v\n    return o\n",
        "cpp": "std::string toRoman(int n) { std::vector<std::pair<int, std::string>> t = {{1000,\"M\"},{900,\"CM\"},{500,\"D\"},{400,\"CD\"},{100,\"C\"},{90,\"XC\"},{50,\"L\"},{40,\"XL\"},{10,\"X\"},{9,\"IX\"},{5,\"V\"},{4,\"IV\"},{1,\"I\"}}; std::string o; for (auto& p : t) while (n >= p.first) { o += p.second; n -= p.first; } return o; }",
    },
    "Shift Decode": {
        "javascript": "function shiftDecode(text, shift) { return text.replace(/[a-z]/gi, (c) => { const b = c <= 'Z' ? 65 : 97; return String.fromCharCode(((c.charCodeAt(0) - b - shift) % 26 + 26) % 26 + b); }); }",
        "python": "def shiftDecode(text, shift):\n    out = ''\n    for c in text:\n        if c.isascii() and c.isalpha():\n            b = 65 if c.isupper() else 97\n            out += chr((ord(c) - b - shift) % 26 + b)\n        else:\n            out += c\n    return out\n",
        "cpp": "std::string shiftDecode(std::string text, int shift) { for (char& c : text) { if (c >= 'a' && c <= 'z') c = (char)((c - 'a' - shift % 26 + 26) % 26 + 'a'); else if (c >= 'A' && c <= 'Z') c = (char)((c - 'A' - shift % 26 + 26) % 26 + 'A'); } return text; }",
    },
    "Diagonal Sum": {
        "javascript": "function diagonalSum(m) { const n = m.length; let s = 0; for (let i = 0; i < n; i++) s += m[i][i] + m[i][n - 1 - i]; if (n % 2) s -= m[(n - 1) / 2][(n - 1) / 2]; return s; }",
        "python": "def diagonalSum(matrix):\n    n = len(matrix)\n    s = sum(matrix[i][i] + matrix[i][n-1-i] for i in range(n))\n    return s - matrix[n//2][n//2] if n % 2 else s\n",
        "cpp": "int diagonalSum(std::vector<std::vector<int>> m) { int n = m.size(), s = 0; for (int i = 0; i < n; i++) s += m[i][i] + m[i][n-1-i]; if (n % 2) s -= m[n/2][n/2]; return s; }",
    },
    "Two Sum Indices": {
        "javascript": "function twoSum(nums, target) { const seen = new Map(); for (let j = 0; j < nums.length; j++) { if (seen.has(target - nums[j])) return [seen.get(target - nums[j]), j]; seen.set(nums[j], j); } return []; }",
        "python": "def twoSum(nums, target):\n    seen = {}\n    for j, x in enumerate(nums):\n        if target - x in seen: return [seen[target - x], j]\n        seen[x] = j\n    return []\n",
        "cpp": "#include <unordered_map>\nstd::vector<int> twoSum(std::vector<int> nums, int target) { std::unordered_map<int,int> seen; for (int j = 0; j < (int)nums.size(); j++) { auto it = seen.find(target - nums[j]); if (it != seen.end()) return {it->second, j}; seen[nums[j]] = j; } return {}; }",
    },
    "Word Counter": {
        "javascript": "function wordCount(text) { const c = {}; for (const w of (text.toLowerCase().match(/[a-z]+/g) || [])) c[w] = (c[w] || 0) + 1; return c; }",
        "python": "import re\ndef wordCount(text):\n    c = {}\n    for w in re.findall(r'[a-z]+', text.lower()):\n        c[w] = c.get(w, 0) + 1\n    return c\n",
        "php": "function wordCount($text) { preg_match_all('/[a-z]+/', strtolower($text), $m); return array_count_values($m[0]); }",
        "ruby": "def wordCount(text)\n  text.downcase.scan(/[a-z]+/).tally\nend\n",
    },
    "Flatten It": {
        "javascript": "function flatten(items) { return items.flat(Infinity); }",
        "python": "def flatten(items):\n    out = []\n    for x in items:\n        out.extend(flatten(x) if isinstance(x, list) else [x])\n    return out\n",
        "php": "function flatten($items) { $out = []; array_walk_recursive($items, function ($x) use (&$out) { $out[] = $x; }); return $out; }",
        "ruby": "def flatten(items)\n  items.flatten\nend\n",
    },
}
