# Localization

OpenCTF ships with a multi-language UI. Players pick a language from the
dropdown on the login screen or in the sidebar; admins install, update, or
remove language packs from **Admin -> Languages**.

## How it works

- **English (`en`) is the built-in fallback.** Every other language pack is
  a flat JSON object of `{ "key": "translated string" }`. It never has to
  be 100% complete - any key it doesn't translate falls back to English
  automatically, both on the server and in the client. That said, the two
  packs shipped with OpenCTF (`es`, `fr`) are kept at full parity with
  every key in `BASE_TRANSLATIONS` on purpose, so a fresh install has
  nothing silently falling back to English out of the box.
- Language packs live in the database (table `language`), not on disk, so
  they survive container rebuilds and sync across every gunicorn worker.
- Two example packs (Spanish `es`, French `fr`) install automatically on
  first boot, the same convenience as the example addon/theme.

## Adding or updating a language (as an admin)

1. Go to **Admin -> Languages**.
2. Click **Download English template** to get a starting `.json` file with
   every known key and its English text.
3. Translate the values (not the keys) into the target language.
4. Fill in the **code** (e.g. `de`, `pt-br`, `zh-cn` - two letters, optionally
   with a region suffix), the **English name** (e.g. "German"), and the
   **native name** (e.g. "Deutsch").
5. Upload the `.json` file. Re-uploading the same code later updates that
   language in place - handy for fixing a typo or adding newly-translated
   keys without starting over.

Every connected browser picks up a newly-added or newly-updated language
immediately (no refresh needed), the same live-update mechanism used for
themes and addons.

## Translation file format

```json
{
  "nav.challenges": "Herausforderungen",
  "auth.signin_btn": "Anmelden",
  "challenge.submit_flag": "Flagge einreichen"
}
```

- Keys are dotted strings grouped by area (`nav.*`, `auth.*`, `challenge.*`,
  `admin.*`, `common.*`, `scoreboard.*`, `profile.*`, `settings.*`).
- Values must be plain strings - no nesting, no HTML.
- A file over 2MB or containing non-string values is rejected.
- The built-in `en` pack can't be deleted or overwritten (it's the
  fallback everything else depends on), but a fresh upload of any other
  code either creates a new pack or updates an existing one.

## Addons and themes

Addons can use the same translation system. `window.OpenCTF.t(key, fallback,
vars)` works from any addon script exactly like the built-in `t()` does -
active pack -> English baseline -> `fallback` -> the key itself - and
supports `{placeholder}` interpolation via the optional `vars` object.
`window.OpenCTF.getLanguage()` returns the active code, and a
`"language:changed"` event (detail `{code}`) fires whenever it changes, so
an addon can re-render text that depends on it.

If an addon's own `render(container)` markup uses plain `data-i18n` /
`data-i18n-placeholder` / `data-i18n-title` attributes, they're
re-applied automatically every time that view is shown - no `t()` calls
needed for static text.

`window.OpenCTF.registerView({..., label, labelKey})`'s own nav/admin-tab
button text needs the same care, for a reason that's easy to miss: if you
translate `label` yourself with `window.OpenCTF.t()` before passing it
in, that only happens *once*, at registration time, and the button then
stays frozen in whatever language was active right then - it has no way
to find out a language switch happened later, unlike everything else on
the page. Pass that same key as `labelKey` instead (`label` stays the
plain English fallback) and `registerView` puts a `[data-i18n]`
attribute on the button itself, so it's kept in sync by the same
`applyTranslations()` pass as everything else. See
`server/addons/certifications/addon.js` for a working example, and
`docs/ADDON_DEVELOPMENT.md` for the full `registerView` reference.

Pick a namespaced key for your own strings (e.g. `addon.motd-banner.dismiss`)
so it can't collide with another addon's or the built-in UI's keys.

### Owning your own `lang/` folder

An addon or theme doesn't need its strings added to the central English
baseline (`BASE_TRANSLATIONS` in `server/app.py`) or to every language
pack in the database at all. Instead, it can ship its own `lang/` folder
right next to its manifest:

```
server/addons/motd-banner/
  addon.json
  addon.js
  lang/
    en.json
    es.json
    fr.json
server/themes/crimson-ops/
  theme.json
  theme.css
  lang/          <- optional, themes are usually pure CSS with nothing
    en.json         to translate, but the mechanism works identically
```

Each file is the same flat `{ "key": "translated string" }` format as a
regular language pack - see `server/addons/core/lang/en.json` for a real,
shipped example. Whenever a player (or an admin browsing the catalog)
requests a language, the server merges in:

- every **discovered** addon's `lang/<code>.json`, and
- every **discovered** theme's own `lang/<code>.json`,

on top of that language's own stored translations - deliberately not
scoped to "enabled" or "active" only (more on why below). A key already
present in the database pack always wins the merge, so an admin can still
override an addon's default wording for a specific language just by
including that same key in their own upload; the addon/theme file only
fills in whatever the pack doesn't already define. A file for a language
code nobody has installed is simply never read.

This merge is why the shipped `core`, `motd-banner`, and `certifications`
addons don't need their `addon.*` keys sitting in `BASE_TRANSLATIONS` or
the `es`/`fr` example packs at all - each one owns its keys in its own
`lang/` folder instead. The merge doesn't care whether that addon is
currently enabled or that theme currently active (see "every discovered
addon and theme" above) - a disabled addon's keys sit in
`CURRENT_TRANSLATIONS` unused and harmless, since its own runtime UI
isn't rendered while it's off anyway. That's also exactly what makes the
catalog case below work: **Admin -> Addons & Themes** needs a disabled
addon's and an inactive theme's own strings translated too, and since the
merge was never scoped to "enabled/active only" to begin with, there's
nothing special to do for that - the same overlay just already has them.

### Catalog listing: name, description, and config screens

Two more spots use this same convention, by pure naming discipline (the
server doesn't enforce or even know about these two specific suffixes -
they're just regular keys, merged and looked up exactly like any other):

- **`addon.<id>.meta.name`** / **`addon.<id>.meta.description`** (or
  `theme.<id>.meta.name` / `theme.<id>.meta.description`) - the title and
  description shown for that addon/theme in **Admin -> Addons & Themes**.
  The client looks these up with the raw manifest `name`/`description` as
  the fallback, so a translation is optional: an addon/theme with no
  `meta.*` keys at all still shows its plain manifest text, exactly as
  before.
- **`addon.<id>.config.<field>`** - labels inside that addon's own config
  screen (opened from the gear button). There's no fixed suffix list
  here; name each one however makes sense for your fields (see
  `server/addons/certifications/lang/en.json` for a config screen with
  several labels, or `server/addons/core/config.js` for how a config
  script actually uses one: `window.OpenCTF.t()` to build the label text,
  plus a matching `data-i18n` attribute so it keeps translating live if
  the admin switches language while the modal is still open).

Switching the active theme or toggling an addon still refreshes every
connected browser's translations live, same as editing a language pack
does - `Admin -> Addons & Themes` itself also re-renders on every
language switch (its name/description text is built from a JS template,
not `[data-i18n]` markup, so it needs an explicit re-render rather than
`applyTranslations()`'s usual DOM scan).

One exception: admin-authored *content* an addon displays - like the
motd-banner's actual message text, set by an admin from its config
screen - isn't run through this system, for the same reason challenge
descriptions aren't (see "Note for players" below): it's content, not UI
chrome, and translating it isn't this system's job.

Themes are usually pure CSS with no text of their own to translate, but
the bundled ones each ship a small `lang/` folder anyway just to
translate their own catalog `meta.name`/`meta.description` (see above) -
a theme is otherwise free to skip `lang/` entirely if it has nothing to
say, the same as an addon can. The mechanism is identical either way, and
a theme that does add real UI text somewhere (via an addon it's paired
with, say) can supply translations for it the same way. The
**Admin -> Addons & Themes** interface that manages both is itself
regular UI chrome and already goes through the standard `data-i18n`
system as the rest of the admin panel.

## Current UI coverage

Only a representative slice of the interface is wired up to translation
keys today: the login/register screen, the main sidebar nav, the admin
tab bar, and the most common challenge/scoreboard/profile labels. The
rest of the app (challenge descriptions and answers themselves, most
modal/admin-form copy, toasts) is still English-only text baked into
`client/src/index.html` and `client/src/renderer.js`.

This is deliberate scope, not a limitation of the system - the
translation infrastructure (server storage, upload/validation, live
updates, the client-side `t()` / `applyTranslations()` engine) is
complete and covers every key it's given. Extending coverage is
incremental, plain HTML/JS work:

1. **Static text** - add `data-i18n="your.key"` to the element in
   `client/src/index.html` (or `data-i18n-placeholder="your.key"` for an
   `<input placeholder>`, or `data-i18n-title="your.key"` for a `title`
   tooltip). `applyTranslations()` picks it up automatically on every
   language change; no other wiring needed.
2. **Text built dynamically in JavaScript** (challenge cards, toasts,
   `confirm()` dialogs, etc.) - wrap it with `t("your.key", "English
   fallback")` in `client/src/renderer.js` instead of a plain string
   literal.
3. **Register the new key's English text.** For a key that belongs to the
   core app UI, add it to `BASE_TRANSLATIONS` in `server/app.py`, so it
   has a real fallback and shows up in the "Download English template"
   file for translators. For a key that belongs to a specific addon or
   theme, put it in that extension's own `lang/en.json` instead (see
   "Addons and themes" above) rather than the central catalog. Either
   way, existing language packs simply fall back to English for the new
   key until someone translates it - nothing breaks in the meantime.

There's no build step - a key you add is live for every player as soon
as the server restarts and they reload the client.

## Note for players

Challenge titles, descriptions, hints, and rules are written and stored
by whoever built the challenge set and aren't run through this
translation system - they're gameplay content, not UI chrome, and
machine-translating them could change what a challenge is actually
asking for. Only the surrounding interface is localized.
