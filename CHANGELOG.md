# Changelog

Format loosely follows [Keep a Changelog](https://keepachangelog.com/).
Versions apply to the platform as a whole (client + server move together).

## 1.2.1

### Fixed

- Completed localization coverage across the player interface, admin screens,
  challenge builder, and generated challenge feedback in the shipped English,
  Spanish, French, and German packs. Existing language-pack customizations are
  preserved while new built-in translation keys are added during startup.
- Completed translations for shipped addon and theme catalog text, filled the
  missing code-challenge strings, and localized the certifications addon UI.
  Translated addon views now refresh their generated text when the active
  language changes.

## 1.2.0

### Added

- **Code Challenge Editor: Judge0 execution in seven languages.** Every
  Run action now executes in Judge0, including JavaScript, Python, PHP,
  Ruby, C, C++, and Java, with the same full test suite and sandbox
  limits. C, C++, and Java use per-task `parameter_names`,
  `parameter_types`, and `return_type` metadata to generate typed test
  drivers; C supports integer-array inputs, while C++ and Java also
  support nested integer-array results. A challenge can restrict the
  language dropdown with `languages` and provide dynamic-language
  starters with `starter_code_by_language`. Requires a reachable
  `JUDGE0_CE_ENDPOINT` (and optional `JUDGE0_CE_AUTH_HEADERS`); see
  `server/addons/code-challenge/AUTHORING.md`.
- **Code Challenge Editor addon: syntax highlighting, plus 7 new coding
  challenges.** The addon's in-browser editor now colors comments,
  strings, numbers, keywords, and called function names live as the
  player types, via a small built-in tokenizer - still no external
  library. A `[[coding-task]]` block can now set an optional `language`
  field (`javascript` by default, plus `typescript`, `python`, `java`,
  `c`, `cpp`, `csharp`, `go`, `rust`, `ruby`, `php`, `bash`, `sql`,
  `json`, `html`, `css`, common aliases, and a few more) to pick which
  ruleset the editor colors with; unset or unrecognized falls back to
  the plain, uncolored text this addon always had. The selected language
  controls both syntax highlighting and its Judge0 harness. See
  `AUTHORING.md` for supported runtimes and typed-signature requirements.
  Selected language shows in the language
  selector next to the panel title. Also seeds **7 new coding challenges** under
  a new **Coding** category (Array Summation, Palindrome Check, FizzBuzz
  Counter, Anagram Match, Balanced Brackets, Binary Search Index,
  Longest Increasing Run), spanning easy through hard so the editor gets
  exercised end to end - a one-loop warm-up up through an O(log n)
  search and a single-pass streak tracker - plus 2 more *themed* around
  Python and C (Ported From Python: Batch It Up, Ported From C:
  Fixed-Width Hex): the problem is inspired by an idiom from that
  language, and can now be solved in any runtime enabled for that task.
  Brings the project's total
  challenge count to 59. Also fixes a real editor layout bug where the
  line-number gutter and the highlighted-text overlay could grow taller
  than, and scroll independently of, the actual `<textarea>` the player
  types into - so the visible colored text could belong to a different
  scroll position than the cursor, making it unclear where you were
  actually typing. Root cause: the gutter and the textarea only had
  their height kept in sync via a fragile combination of flexbox
  stretching, and once the gutter's own line-number list got long
  enough it could win that fight and drag the overlay's height away
  from the textarea's real, independently-scrolling box. That fix
  turned out to be incomplete - matching numbers wasn't enough, because
  removing height caps entirely (an interim attempt) hit a *different*
  flexbox quirk: with no explicit height, the gutter's own always-lists-
  every-line content could still become the tallest thing in the row and
  drag the highlight overlay's height away from the textarea's real one.
  The actual fix replaces the sync-two-independent-scroll-positions
  approach entirely: the gutter, the highlighted-text layer, and the
  textarea are now CSS Grid-stacked and grow together with the content
  (no internal per-element scrolling, no manual resize handle), with
  only the *whole* editor scrolling as one unit past a height cap - so
  there's exactly one scroll position, not two that can drift apart, and
  the caret is always visually where the browser's native "keep the
  caret in view" behavior puts it. Two follow-up fixes landed on top of
  that same rework: the `<textarea>` needed an explicit `height: 100%`
  to actually fill its grid cell (textareas don't auto-size to their own
  text content the way a normal block element does, so it silently
  stayed small and grew a second, un-synced native scrollbar of its
  own - the real cause of "two scrollbars"); and the app's global
  `textarea:focus-visible` outline (which applies site-wide, including
  here) is now overridden with a selector of equal-or-higher specificity
  instead of a plain class that was quietly losing that fight the whole
  time, replaced with a single soft focus ring around the whole editor.
  And the editor's colors (background,
  border, gutter, caret, and every highlighted token kind) are now
  themeable: a `server/themes/<id>/theme.css` can override any of the
  new `--cc-*` custom properties on `:root` and the editor picks it up
  automatically, with no addon changes needed - see the comment above
  the token-color rules in `style.css` and the "Themes" section of
  `docs/ADDON_DEVELOPMENT.md`. Bumps the addon to `1.1.4`. See
  `server/addons/code-challenge/AUTHORING.md` and
  `server/seed_challenges.py`.
- **Code Challenge Editor addon** (`server/addons/code-challenge/`) - a
  dependency-free, line-numbered editor integrated into the standard
  challenge modal, with syntax highlighting, keyboard editing, and a
  language selector. Task metadata is loaded from an authenticated API
  route, and all player code runs through Judge0. The UI reports each
  test result and fills the flag input only after the server confirms
  every test passed. Editor font size is configurable; the Judge0 runner
  applies per-test CPU, wall-time, and memory limits. Ships
  `en`/`de`/`es`/`fr` translations.
- **Stats addon: responsive charts with clearer values.** The chart
  wrapper is now watched with a `ResizeObserver` that switches into a
  compact layout (shorter team-name truncation, smaller label/value font,
  tighter row spacing) once it drops below ~460px wide, on top of the
  chart's existing fluid `viewBox` scaling - so it stays readable from a
  full-width admin screen down to a narrow sidebar or phone, with a
  horizontal-scroll fallback on the chart card itself as a last resort
  for an unusually large team count. Every value label (on bars, and
  above each point on the line/area charts) now renders with a themed
  stroke halo (`paint-order: stroke fill`) so the number stays legible
  over a bar fill, a line, or the area chart's shaded region at any
  width, without hand-measuring a background pill per label; a leading
  team's value label on the line/area charts is also clamped so it can
  no longer get clipped off the chart's top edge. Chart strokes use
  `vector-effect="non-scaling-stroke"` so line/axis width stays crisp
  at any scale factor instead of thinning out on a very wide render.
- **Stats addon** (`server/addons/stats/`) - a new example addon adding
  its own "Stats" sidebar tab that renders the `/api/scoreboard` data as
  a live chart instead of a plain table. Switchable at runtime between
  three **chart types** (bar, line, area - all inline SVG, styled off the
  host app's own `--accent`/`--ok`/etc CSS custom properties so it
  follows whichever theme is active) and two **metrics** (score, solve
  count), plus a gear-button config screen for an admin to set the
  default chart type, default metric, and how many top teams get
  plotted. Refreshes on the player's own `"challenge:solved"` event so it
  doesn't go stale while the tab is open. Ships with `en`/`de`/`es`/`fr`
  translations in its own `lang/` folder.
- **German (`de`) language pack**, installed automatically on first boot
  alongside the existing Spanish/French example packs, at full key parity
  with the English baseline (all keys in `BASE_TRANSLATIONS`) - same
  "nothing silently falls back to English out of the box" guarantee the
  `es`/`fr` packs already had. German is now also the fourth language
  applied consistently across **every** bundled addon and theme, not just
  the core UI: `certifications`, `confetti-solve`, `core`, `ctf-countdown`,
  `motd-banner`, `sound-effects`, and the new `stats` addon, plus all 4
  bundled themes (`crimson-ops`, `forest-dawn`, `midnight-purple`,
  `ocean-breeze`) each ship a `lang/de.json` translating their own
  `addon.*`/`theme.*` keys (nav labels, config screen fields, catalog
  `meta.name`/`meta.description`), at full parity with their existing
  `en`/`es`/`fr` files - the same convention introduced for those two
  languages earlier in this release (see "Addon/theme catalog listings
  and config screens are now translatable too" below).
- **DevTools access on the sandboxed web-challenge target.** The
  in-app mini browser (back/forward/reload/address bar around the
  `#web-target-frame` iframe) now has an explicit Inspect/DevTools
  button, a right-click "Inspect Element" context menu (Electron shows
  none by default), and an F12 shortcut alongside the existing
  Ctrl+Shift+I - the same tools a real browser gives you for the web
  exploitation challenges.
- **Addons and themes can use the translation system**, and can now own
  their strings entirely instead of needing them added to the central
  catalog. Addon scripts get `window.OpenCTF.t()` / `getLanguage()` /
  `getLanguages()` and a `"language:changed"` event; `data-i18n`/
  `-placeholder`/`-title` markup inside an addon's own `render()` output
  is translated automatically too. On top of that, any addon or theme can
  now drop its own `lang/<code>.json` file(s) right next to its manifest
  (e.g. `server/addons/core/lang/en.json`) and those keys are merged into
  every player's translations automatically while that addon is enabled
  (or that theme is active) - no central registration needed, and a key
  already in a language pack always wins the merge so an admin can still
  override the default. The `core`, `motd-banner`, and `certifications`
  addons were switched over to this - their `addon.*` keys now live in
  their own `lang/` folders instead of `BASE_TRANSLATIONS`/the example
  `es`/`fr` packs. See "Addons and themes" in `docs/LOCALIZATION.md` and
  the folder-layout section of `docs/ADDON_DEVELOPMENT.md`.
- A terminal challenge can now disable specific commands for itself via
  `terminal_disabled_commands` (admins: a JSON array of command names in
  the challenge editor). Used on the new **John the Ripper 101** so `cat`
  can't just be used to read the flag straight out of the wordlist file,
  forcing an actual `john` run - every other terminal challenge keeps the
  full command set. `help` stops advertising whatever's disabled for that
  challenge but is itself never blockable.
- **28 new challenges** spanning every category from the project overview:
  General Skills, Cryptography, Web Exploitation, Forensics, Reverse
  Engineering, Binary Exploitation, and the new **Blockchain** and
  **Network** categories (smart contract vulnerabilities and network
  recon, respectively). Total challenge count: 50. See
  `server/seed_challenges.py`.
- **Two new virtual-terminal commands, `john` and `nmap`**, so
  challenge builders can put password cracking and network recon
  challenges in front of players without shelling out to real tools:
  - `john --wordlist=<file> <hashfile>` runs a dictionary attack
    against a sandboxed `user:hash` file using a sandboxed wordlist
    file, auto-detecting md5/sha1/sha256 from the hash length, and
    prints cracked results in the same `password  (user)` format the
    real tool uses.
  - `nmap [-p <ports>] [-sV] <target>` prints a scan report for a
    target the challenge author pre-authored at
    `/network/scans/<target>.nmap` in the challenge's filesystem;
    unlisted targets get a realistic "Host seems down" response,
    `-p` filters by port, and `-sV` is required to reveal the
    version/banner column - handy for hiding a flag in a service
    banner behind version detection.
  - New seed challenges **John the Ripper 101** (forensics) and
    **Nmap Know-How** (network) exercise both end to end. (There was
    already an older, unrelated "Password Cracking 101" challenge
    under Cryptography that just narrates a pre-run crack log rather
    than using the terminal - the new one is named differently to
    avoid confusion with it and actually requires running `john`
    yourself.) Both new commands are available in every terminal-type
    challenge, existing or new - run `help` inside the terminal for
    the full command reference.
- **Multi-language UI.** Players pick a language from a dropdown on the
  login screen or in the sidebar; missing translations fall back to
  English automatically. Admins install, update, or remove language
  packs from **Admin -> Languages** by uploading a JSON translation
  file - re-uploading the same language code updates it in place, same
  convenience as addons/themes. Ships with English (the fallback) plus
  ready-to-use Spanish, French, and (new in this release) German packs,
  all three kept at full key parity with English - nothing in any of
  them silently falls back to English out of the box. See
  `docs/LOCALIZATION.md` for the file format and how to extend
  translation coverage further into the UI.
- **Addon/theme catalog listings and config screens are now
  translatable too.** An addon or theme can translate its own name and
  description as shown in **Admin -> Addons & Themes** via
  `addon.<id>.meta.name` / `.meta.description` (or `theme.<id>.meta.*`)
  in its own `lang/` file, and its config-screen field labels via
  `addon.<id>.config.<field>` - both fall back to the raw manifest text
  when untranslated. All bundled addons and themes now ship real
  `es`/`fr`/`de` translations for these. The admin catalog
  (name, description, toggle labels, tooltips, delete-confirm dialogs,
  the config modal's title, and the "Loading.../Saved - live..." chrome
  every config screen reuses) re-renders live on every language switch,
  the same as the rest of the admin panel.

### Fixed

- `input[type="date"]` was styled to match every other form control, but
  `time` and `datetime-local` weren't - both fell back to the browser's
  unstyled default (light background, a barely-visible icon on a dark
  page). All three now share the same box styling, plus `color-scheme:
  dark` and a restyled calendar/clock icon so the native picker itself
  isn't jarring against the rest of the UI (used by the new CTF
  Countdown example addon's config screen, among others).

- `registerView({label, ...})`'s nav/admin-tab button text was translated
  (if at all) only once, at registration time - a language switch
  afterward never reached it, unlike everything else on the page,
  because it wasn't wired through `[data-i18n]`/`applyTranslations()`
  like static HTML is. This is why the Certifications addon's own sidebar
  tab stayed in whatever language was active when its script first
  loaded. `registerView` now takes an optional `labelKey`, which puts a
  real `data-i18n` attribute on the button instead of baking a
  translation in once; the certifications addon was updated to use it.
  See `docs/ADDON_DEVELOPMENT.md` and `docs/LOCALIZATION.md`.
- The Admin panel's stats row (Users/Teams/Challenges/Correct solves/
  Total attempts) and the Ollama status line were never run through the
  translation system at all - plain English strings baked straight into
  `loadAdminStats()`/`loadOllamaStatus()`. Both now use real translation
  keys and re-render live on every language switch, the same as the
  Addons & Themes catalog already did.

- Addon/theme translation overlays only ever merged an **enabled**
  addon's or the **active** theme's own `lang/` files, so anything that
  needed to show a disabled addon's or an inactive theme's strings -
  like the admin catalog listing every extension regardless of its
  current state - had nothing to translate with and silently stayed in
  English. The overlay now merges every *discovered* addon and theme,
  not just the running ones; a disabled/inactive one's keys just sit
  unused, same as any addon's own runtime UI already does while it's
  off.
- `GET /api/themes/<theme_id>/<filename>` - the route the client uses to
  actually fetch a theme's CSS - had no route registered at all, so
  every theme's stylesheet 404'd and switching themes silently did
  nothing. Discovered while wiring up per-theme `lang/` files, which
  hit the same dead route.

### Changed

- **Most of the new challenges from 1.2.0 are now hands-on, not
  multiple-choice.** The virtual terminal went from 4 commands
  (`ls`/`cd`/`cat`/`pwd`) to a real toolset - `grep` (`-i`/`-r`/`-n`),
  `find -name`, `file`, `strings`, `head`/`tail`, `wc`, `chmod`, and
  now `john` and `nmap` (see above) - and 25 challenges across General,
  Web, Forensics, Reverse Engineering, Binary Exploitation, Blockchain,
  and Network were rebuilt or added around it: explore a virtual
  filesystem, read real (if simplified) vulnerable source code and
  incident logs, and dig the flag out yourself. Only 2 challenges
  (hash cracking, RSA math) remain multiple-choice.
- Bumped bundled dependency versions: Flask, Flask-SQLAlchemy,
  Flask-Cors, Flask-JWT-Extended, Werkzeug, gunicorn (server), Electron
  (client), and the Docker base image (`python:3.13-slim`).
- **Coding challenge answers are no longer sent in the challenge listing.**
  The task metadata endpoint omits the flag, and the Judge0 run endpoint
  returns it only when every test passes. Seeded PHP and Ruby starters are
  stubs rather than completed solutions; reseeding refreshes the typed
  task metadata without changing existing challenge flags.
- **Code editor placement and interaction fixes.** Highlighted tokens no
  longer use bold/italic styles that shift visible text relative to the
  transparent input layer, and clicking a line number places the caret at
  that line. The editor keeps its line gutter, highlight, and input aligned.
- **Judge0 PHP harness fix.** Generated PHP submissions now include the
  opening tag so Judge0 executes the harness instead of treating it as
  plain text.
- **Default first-install admin password is `changeme123`.** This applies
  when the initial admin account is created; changing `ADMIN_PASSWORD`
  later does not reset an existing account's stored password hash.

## 1.1.0

### Added

- **Addon and theme system.** Admins can now customize the platform for
  every player from **Admin -> Addons & Themes**:
  - One active **theme** (a CSS file overriding the app's color variables)
    applies platform-wide, including the login screen.
  - Any number of **addons** (JavaScript, via a small `window.OpenCTF` API)
    can be enabled at once.
  - Developers build their own by dropping a folder with a manifest into
    `server/addons/` or `server/themes/` - no core code changes required.
    See `docs/ADDON_DEVELOPMENT.md` for the full guide.
  - Ships with two working examples: the `motd-banner` addon and the
    `midnight-purple` theme.
- New server endpoints: `GET /api/site-config`, `GET /api/themes/<id>/...`,
  `GET /api/addons/<id>/...`, `GET/POST /api/admin/addons`,
  `GET/POST /api/admin/theme`.
- New `window.OpenCTF` client-side API for addon scripts (`api()`,
  `getUser()`, `on()`/`off()` for `ready`, `auth:login`, `auth:logout`,
  `view:change`, and `challenge:solved` events).

## 1.0.1

### Updated 
- README.md

## 1.0.0
### Added
- authorization **(default admin account)**
  - Username: `admin`
  - Password: `changeme123`
- interactive tools (i.e. terminal, webpage)
- quiz mode
- teams/individual mode
- 17 default challenges
- Supports [Ollama](http://ollama.com/) and _TTS_ read aloud
```bash
ollama pull llama3.2
```
> **Note: you can use any model of your choice, I just set it to that because it lightweight.**
- Added scoreboard: **(teams/users)**
- Supports Linux, Windows, and/or Mac
