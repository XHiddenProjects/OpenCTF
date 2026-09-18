# Building addons and themes for OpenCTF

OpenCTF has a small extension system that lets a developer ship two kinds
of platform-wide customization without forking the core app:

- **Themes** - a CSS file that overrides the color variables the whole
  client is already built on. One theme is active at a time, and it applies
  to every player, including the login screen.
- **Addons** - a JavaScript file that runs inside the client. Any number
  can be enabled at once. Used for things like banners, extra widgets,
  sound effects on solves, custom scoreboard views, analytics, etc.

An admin turns these on and off from **Admin -> Addons & Themes** in the
client. A folder can get onto the server one of two ways: a developer
copies one into place directly, or an admin uploads a `.zip` of one right
from that same screen (see [Installing via upload](#installing-via-upload)
below) - either way it becomes available for an admin to enable. There's no
code review step built into the platform, so only enable addons/themes you
trust (see [Security notes](#security-notes) below).

Two more pieces build on top of the base system:

- **Addon configuration** - an addon can declare its own settings screen,
  opened from a gear button next to its toggle, instead of hardcoding
  values in its script (see [Addon configuration](#addon-configuration)).
- **Live updates** - a theme change, addon toggle, or config save reaches
  every open client immediately, no refresh needed (see
  [Live updates](#live-updates)).

## Folder layout

```text
server/
├── addons/
│   └── <addon-id>/
│       ├── addon.json      # manifest
│       └── addon.js        # entry script (name is up to you, see below)
└── themes/
    └── <theme-id>/
        ├── theme.json       # manifest
        └── theme.css        # entry stylesheet (name is up to you, see below)
```

`<addon-id>` and `<theme-id>` are just the folder name - that's what the
platform uses as the stable identifier (in the API, in storage, in the
admin panel's toggle state), so don't rename a folder after it's been
enabled by anyone, or it'll show up as a brand-new, disabled entry.

A minimal **theme** manifest looks like this (`theme.json` - addons are
shown separately below since, unlike themes, they have a required `core`
field):

```json
{
  "name": "Midnight Purple",
  "version": "1.0.0",
  "author": "your name or handle",
  "description": "One sentence describing what this does.",
  "entry": "theme.css"
}
```

| Field         | Required | Notes                                                              |
| ------------- | -------- | ------------------------------------------------------------------- |
| `name`        | yes      | Shown in the admin panel.                                          |
| `version`     | yes      | Free-form string, but use [semver](#versioning) - see below.        |
| `entry`       | yes      | Filename of the script/stylesheet inside this same folder.          |
| `core`        | **addons: yes** | A version requirement against the running OpenCTF version, e.g. `">=1.0.0"` - see [Compatibility](#compatibility). Not used on themes. |
| `author`      | no       | Shown in the admin panel if present.                                |
| `description` | no       | Shown in the admin panel if present. Keep it to one sentence.       |
| `can_disable`     | no | Addons only. `false` means always-enabled and can't be toggled off from the admin panel - see [Always-on addons](#always-on-addons). Defaults to `true`. |
| `configurable`     | no | Addons only. `true` shows a gear button that opens this addon's config screen - see [Addon configuration](#addon-configuration). Requires `config_entry`. |
| `config_entry`     | no | Addons only. Filename of the script (inside this same folder) that builds the config screen. |
| `default_config`   | no | Addons only. An object of default settings, used until an admin saves something different. |

An **addon** manifest (`addon.json`) has one more required field than a
theme's: `core`, a version requirement (see
[Compatibility](#compatibility) below) - so a minimal one looks like this:

```json
{
  "name": "MOTD Banner",
  "version": "1.0.0",
  "entry": "addon.js",
  "core": ">=1.0.0",
  "author": "your name or handle",
  "description": "One sentence describing what this does."
}
```

An addon/theme missing `name`, `version`, or `entry` (or, for an addon,
`core`), or with unparsable JSON, is silently skipped - it just won't show
up in the admin panel. A bad manifest can never take down the platform,
but it does mean "I dropped in a folder and it's not showing up" is almost
always a manifest problem; check your JSON is valid first.

The examples shipped with OpenCTF are working, minimal templates - copy
whichever is closest to what you're building as a starting point:

- `server/addons/motd-banner/` - a configurable banner, the fullest
  example of the config-screen contract below.
- `server/addons/core/` - always-on (`"can_disable": false`), also
  configurable, and the one addon whose `version` the server pins to
  `OPENCTF_VERSION` itself rather than trusting its manifest - see
  [Always-on addons](#always-on-addons).
- `server/addons/confetti-solve/` and `server/addons/sound-effects/` -
  smaller configurable addons reacting to solve/wrong events. Note that
  neither has an "enabled" field in its own config screen even though
  both are configurable - whether an addon runs at all is always the
  toggle in the addon list, never a second setting duplicated inside its
  own config (see [Addon configuration](#addon-configuration)).
- `server/addons/certifications/` - the fullest example overall: its own
  sidebar tab and view via `registerView` (see
  [Tabs, panels, and chrome slots](#tabs-panels-and-chrome-slots)), its own backend routes and
  database model in `server/app.py` (see
  [Reaching your own backend](#reaching-your-own-backend)), a stylesheet
  loaded from its own folder (see
  [Loading additional assets](#loading-additional-assets-from-your-own-folder)),
  and a live-updates event (`"server:certification_issued"`) it defines
  itself rather than one the host app already knows about.
- `server/themes/midnight-purple/`, `server/themes/forest-dawn/`,
  `server/themes/crimson-ops/` - three different palettes, dark and light.

## Themes

A theme is a CSS file. Every rule in `client/src/styles.css` is already
written against the CSS custom properties declared in its `:root` block,
so a theme only needs to override those variables - no need to fight
specificity or re-declare component styles:

| Variable       | Default   | Used for                                  |
| -------------- | --------- | ------------------------------------------ |
| `--bg`         | `#0b0e14` | Page background                            |
| `--bg-raised`  | `#121722` | Sidebar, modals, raised surfaces           |
| `--bg-card`    | `#161c29` | Cards (stat cards, extension cards, etc.)  |
| `--border`     | `#232b3b` | Borders and dividers                       |
| `--text`       | `#e7ebf3` | Primary text                               |
| `--text-dim`   | `#8b93a7` | Secondary/muted text                       |
| `--accent`     | `#e8a33d` | Primary accent (buttons, highlights)       |
| `--accent-dim` | `#a97627` | Hover/pressed accent, focus rings          |
| `--ok`         | `#4fae7a` | Success state (correct flag, active badge) |
| `--err`        | `#d9645b` | Error state (wrong flag, delete buttons)   |
| `--radius`     | `6px`     | Corner radius used throughout              |

```css
/* your-theme/theme.css */
:root {
  --bg: #100b1a;
  --accent: #b98af5;
  /* ...override only what you want to change... */
}
```

The theme stylesheet is loaded *after* the base stylesheet, so these
overrides win without needing `!important` anywhere. You can also add
brand-new rules in a theme (e.g. a custom font import) if you need more
than a palette swap - it's a normal stylesheet, nothing stops you.

## Addons

An addon is a plain `<script>` loaded into the page once it's enabled. It
runs with full DOM access - it is not sandboxed - and gets a small
`window.OpenCTF` API to work with instead of having to poke at the app's
internals directly:

```js
window.OpenCTF.api(path, options)
```
Calls the same authenticated fetch helper the app itself uses (adds the
`Authorization` header automatically when logged in, throws on a non-OK
response). Example: `await OpenCTF.api("/api/scoreboard")`.

```js
window.OpenCTF.getUser()
```
Returns `{ username, display_name, team, is_admin, ... }` for the logged-in
player, or `null` if nobody's logged in yet.

```js
window.OpenCTF.on(event, handler)
window.OpenCTF.off(event, handler)
```
Subscribe/unsubscribe from platform events. Events fired:

| Event                     | When                                                                 | Detail passed to handler                     |
| -------------------------- | --------------------------------------------------------------------- | ----------------------------------------------- |
| `"ready"`                  | Once, right after the app finishes its own startup                    | none                                             |
| `"auth:login"`             | After a successful login or registration                              | none (call `getUser()` for who)                  |
| `"auth:logout"`            | After the player logs out                                              | none                                             |
| `"view:change"`            | Whenever the player switches tabs (Challenges/Scoreboard/etc.)         | the view name, e.g. `"scoreboard"`               |
| `"challenge:solved"`       | Right after a correct flag submission, for any challenge type          | `{ id, title, category, points }`                |
| `"challenge:wrong"`        | Right after an incorrect flag submission, for any challenge type       | `{ id, title, category }`                        |
| `"live:connected"`         | The live-updates connection (see [Live updates](#live-updates)) is up  | none                                             |
| `"live:disconnected"`      | The live-updates connection dropped (it retries on its own)            | none                                             |
| `"site:theme_changed"`     | An admin changed the active theme, from any client                     | `{ active_theme, theme_entry }`                  |
| `"addon:enabled"`          | An admin enabled an addon, from any client                             | `{ id, name }`                                   |
| `"addon:disabled"`         | An admin disabled an addon, from any client - see note below           | `{ id, name }`                                   |
| `"addon:config_changed"`   | An admin saved *any* addon's config, from any client - check `id`      | `{ id, config }`                                 |
| `"server:<type>"`          | Any other server-pushed event - see [Reaching your own backend](#reaching-your-own-backend) | whatever that event's data was                   |

Addon scripts aren't unloaded once the browser has fetched them, so
`"addon:disabled"` is the well-behaved way to actually go away when an
admin turns your addon off on someone else's already-open client - see
`server/addons/motd-banner/addon.js` for an example that removes its own
DOM on both `"auth:logout"` and `"addon:disabled"`.

`"ready"` and `"live:connected"`/`"live:disconnected"` are *replayed*: if
your script finishes loading and calls `on()` for one of these after it
already happened (addon scripts load asynchronously - this is a real race,
not a hypothetical one), your handler still gets called, one microtask
later, as if it had fired right then. You don't need to guess at load
order or poll `isLive()` yourself to work around it - just subscribe
normally, whenever your script happens to finish loading.

```js
window.OpenCTF.isLive()
```
Returns whether the live-updates connection is currently up (`true`/`false`).

```js
window.OpenCTF.getAddonConfig(addonId)
```
Returns a `Promise` resolving to another addon's - or your own - current
saved config (merged over its `default_config`). Unauthenticated, same
trust boundary as the addon script itself. This is how an addon reads
whatever an admin configured for it at runtime - see
[Addon configuration](#addon-configuration) below.

```js
window.OpenCTF.emitLocal(event, detail)
```
Fires a platform event locally, without any server round trip. Mainly
useful from a config screen's own "preview" button (e.g. firing a fake
`"challenge:solved"` to preview a solve effect without actually solving
anything) - see `server/addons/confetti-solve/config.js`.

```js
window.OpenCTF.registerView({ id, label, render(container) { ... } })
```
Adds a top-level sidebar tab and its own full-page view - see
[Tabs, panels, and chrome slots](#tabs-panels-and-chrome-slots) below.

A minimal addon:

```js
// your-addon/addon.js
(function () {
  window.OpenCTF.on("challenge:solved", (challenge) => {
    console.log(`Solved "${challenge.title}" for ${challenge.points} points!`);
  });
})();
```

Wrap your addon in an IIFE (as above) so it doesn't leak variables into
the global scope and collide with another enabled addon.

### Tabs, panels, and chrome slots

A gear-button config screen or a small DOM injection into an existing
element (see [Extension points](#extension-points-in-the-host-page)
below) both work inside the existing app; sometimes what you're building
needs its own place instead - a whole new destination, or a persistent
bit of chrome visible everywhere. `registerView` is how, and `location`
picks which kind:

```js
window.OpenCTF.registerView({
  id: "certifications",       // used as the button's data-view/data-admin-tab and the view/item element's id
  label: "Certifications",    // the button's text (ignored for "header"/"footer" - see below)
  render(container) { ... },  // see the render-timing note for each location below
  target: "everyone",         // optional - who can see it, see below (default: everyone logged in)
  location: "sidebar",        // optional - "sidebar" (default), "admin", "header", or "footer"
});
```

**`location: "sidebar"`** (the default) - the Certifications addon
(`server/addons/certifications/`) is the fullest example. Adds a
`.nav-btn` to the sidebar (before the built-in Admin tab if there is one,
alongside Challenges/Scoreboard/Profile) and an empty `.view` container in
the main content area - the exact same DOM shape the built-in tabs use, so
it gets the same layout and switching behavior for free. `render(container)`
is called every time the tab is switched to, matching how the built-in
views already reload their own data on every visit (Scoreboard re-fetches
standings each time, for instance) - if your view is expensive to rebuild
from scratch, check `container.children` or keep your own module-level
flag and only refresh the data, not the whole DOM, on repeat calls.

**`location: "admin"`** - adds a tab *inside* the existing Admin panel's
own tab bar (alongside Challenges/Users/Teams/Addons & Themes there),
for admin-only tooling that doesn't need its own top-level place in the
main sidebar - same idea, just a `.admin-tab-btn`/`.admin-tab` pair
instead of a `.nav-btn`/`.view` pair, and `render(container)` is called
every time *that* tab is opened. Only ever reachable by an admin
regardless of `target` (the Admin panel itself already is), but `target`
still narrows it further if given.

**`location: "header"` / `"footer"`** - not a tab at all: a small,
persistent item dropped into a shared strip that's visible above (header)
or below (footer) whichever view is currently showing, the same way the
sidebar's own `#sidebar-status-slot` works (see
[Extension points](#extension-points-in-the-host-page)) but built through
`registerView` instead of a raw `getElementById`, so it gets the same
`target` and auto-hide-on-disable handling every other location does.
Several addons' items can sit in the same header or footer at once, laid
out in a row (see `.addon-chrome-slot` in `styles.css`) - a whole strip
collapses to no space at all when nothing currently visible is inside it.
Because there's no tab to switch to, `render(container)` is called
**once**, immediately, rather than repeatedly - update the container
yourself afterward (e.g. from other `OpenCTF.on(...)` handlers) if it
needs to change over time. There's also no button for these - the
`label` option is ignored, and the object `registerView` returns only has
a `container`, no `button`.

**`target`** - who can see the entry point at all: `"everyone"` (default,
anyone logged in), `"admin"`, a function `(user) => boolean` for arbitrary
logic, an array of usernames, or `{ usernames: [...] }` and/or
`{ teams: [...] }` for specific people and/or specific teams. `user` is
whatever `OpenCTF.getUser()` returns (or `null`) - this is re-evaluated on
login, so it's safe to call `registerView` before knowing who's logged in
yet. The Certifications addon's own "Manage" sub-tab doesn't use `target`
for its admin-only content, though - since it lives *inside* an
already-`"everyone"` view (players need the same tab for their own
certificates and for verification), it branches on
`OpenCTF.getUser().is_admin` itself instead, inside its own `render()`,
the way any admin-only *portion* of a broader view should.

The entry point is also automatically hidden while the addon that
registered it is disabled, and shown again once it's re-enabled - **as
long as the view's own `id` is the same as the addon's own id** (every
shipped example follows this - it's how the host app knows which view
belongs to which addon without you having to say so separately). A view
registered under a different id doesn't get this for free; listen for
`"addon:disabled"`/`"addon:enabled"` yourself and toggle `.hidden` on
whatever `registerView` returned (`button` for `"sidebar"`/`"admin"`,
`container` for `"header"`/`"footer"`) if you need it under a different
id.

It doesn't restrict what you put inside `container` at all - a full
custom layout, your own sub-tabs, forms, a fetch-and-render list,
whatever the view needs.

Each `id` can only be registered once (across every enabled addon) -
calling `registerView` again with an id already in use logs an error and
returns `null` instead of adding a second tab.

### Loading additional assets from your own folder

An addon isn't limited to its single `entry` script - any other file
sitting in its folder is servable too, at
`/api/addons/<your-addon-id>/<filename>` (same route `entry` itself is
served from), as long as the addon is enabled. A stylesheet is the common
case: `server/addons/certifications/style.css` holds everything that
addon's view needs, loaded like this from `addon.js`:

```js
// document.currentScript is only valid during this script's own
// synchronous top-level execution - capture it immediately, don't wait
// until inside an event handler or a Promise .then().
const SCRIPT_URL = document.currentScript.src; // e.g. "http://host:5000/api/addons/certifications/addon.js"
const ADDON_BASE_URL = SCRIPT_URL.replace(/\/addon\.js(\?.*)?$/, "");

const link = document.createElement("link");
link.rel = "stylesheet";
link.href = `${ADDON_BASE_URL}/style.css`;
document.head.appendChild(link);
```

This is also the only reliable way for an addon to recover the server's
own base URL (for building an absolute link to a public route like
`/api/certifications/verify/<uid>`, say) - there's no `OpenCTF.serverUrl`
or similar, on purpose, since `document.currentScript.src` already has it
and doesn't need the host app to expose a second copy of the same value.

### Extension points in the host page

Floating a fixed-position element over the page (a badge, a status dot,
etc.) is usually the wrong tool - it has no idea what else is on screen
and tends to end up overlapping something. Where the host app has a
sensible place for that kind of thing already, it exposes an empty
container for an addon to render into instead:

| Element ID                | Where it is                          | Notes |
| --------------------------- | --------------------------------------- | ------- |
| `#sidebar-status-slot`      | Sidebar, between the account block and "Server settings" | Empty and collapsed (no layout space) until something renders into it. Only exists once a player is logged in - the sidebar itself doesn't exist before that, so check `getElementById` returns non-null, or just render on `"auth:login"` too. See `server/addons/core/addon.js` for the live-updates status row that uses this. |

If you do need to float something (a toast, say), keep it out of corners
the app already uses - the toast host in `server/addons/core/addon.js`
sits bottom-right, `#sidebar-status-slot` covers the bottom-left sidebar
area, so pick a different spot (or reuse `#core-toast-host` by emitting
through the same pattern) rather than stacking a third thing in either of
those corners.

### Reaching your own backend

If your addon needs server-side logic beyond what `OpenCTF.api()` already
exposes (the regular player-facing API) - its own database table, its own
validation, anything stateful - that's outside what the addon system
itself provides: the addon script is just static JS served by OpenCTF, it
isn't a Flask blueprint, and it can't add new server routes on its own.

In practice this means adding ordinary first-party routes (and, if
needed, a `db.Model`) to `server/app.py` itself, the same way the rest of
the app is built, and calling them from your addon's JS with
`OpenCTF.api()` like any other endpoint. The Certifications addon is the
example: `server/addons/certifications/addon.js` is UI and branding only
(no certificate ever lives in the browser) - the actual `Certification`
model and every `/api/certifications/*` and `/api/admin/certifications/*`
route live in `server/app.py`. If your route wants to push a live update
the way the built-in ones do (see [Live updates](#live-updates)), call the
same `broadcast_event(event_type, data)` used there - any `event_type` you
haven't seen elsewhere in this doc reaches your addon's own JS as
`"server:<event_type>"` (see the events table above), no changes to the
event-dispatch code needed.

## Compatibility

Every addon's manifest must declare `"core"`: a version requirement
against the OpenCTF version actually running, using one of `>`, `>=`, `<`,
`<=` (or `=<`), or `==` followed by a version number - e.g. `">=1.0.0"`,
`"<2.0.0"`, `"==1.1.0"`. This isn't optional decoration: it's checked on
the server every time the effective enabled-addon list is computed
(`enabled_addon_ids()` in `server/app.py`), against `OPENCTF_VERSION` -
read straight from `server/__init__.py`'s own `__version__` (the same
constant that makes this directory installable as the `openctf_server`
PyPI package), not duplicated as a separate number in `app.py`.

An addon whose requirement isn't met by the running version is **auto
disabled** - left out of the effective enabled list regardless of what's
stored, with its toggle shown disabled and a short reason (e.g. "requires
OpenCTF >=1.2.0, this server runs 1.1.0") next to it in the admin panel.
This isn't a one-time check at install time: it's re-evaluated on every
request, so if the server is later upgraded into an addon's declared
range, that addon comes back on its own - no admin action needed. The
`POST /api/admin/addons/<id>/toggle` route enforces the same check
server-side, so this can't be bypassed by calling the API directly either.

Uploading (see [Installing via upload](#installing-via-upload)) only
requires the field be *present and well-formed* - it doesn't reject an
addon whose range doesn't happen to include the current version. It
installs, just auto-disabled, ready for whenever the server catches up to
its declared range.

A missing or malformed `"core"` field is treated as incompatible with
every version, not as "compatible with everything" - an addon is required
to state what it supports, and silently assuming compatibility for one
that doesn't would defeat the point of the check.

## Always-on addons

An addon with `"can_disable": false` in its manifest is always enabled (as
long as it's still [compatible](#compatibility) - see above) - it's
included in `enabled_addon_ids()` on the server regardless of what's
stored, its toggle is shown disabled ("Always on") in the admin panel, and
`POST /api/admin/addons/<id>/toggle` refuses to change it (`400`). This
isn't limited to the platform's own bundled addon - any addon can opt into
it. Uploading a zip whose folder name would overwrite one is rejected.

`server/addons/core/` (id `core`, name "Core Toolkit") ships with
`"can_disable": false` and is otherwise a normal addon built on the same
`window.OpenCTF` API any other addon gets - it's just one a lab operator
can't accidentally switch off, for functionality worth guaranteeing is
always present (see `server/addons/core/addon.js`: solve toasts, a
live-updates status row in the sidebar, and reacting to theme/addon
changes as they happen). It has one more thing special about it: the
server always reports its `version` as whatever `OPENCTF_VERSION` is
right now (i.e. `server/__init__.py`'s `__version__` - see
`discover_addons()`), overriding whatever its own `addon.json` says - it
ships with the platform itself, so the two are never allowed to drift
apart. No other addon gets this treatment; give every other addon
(including your own always-on ones) a real version you bump yourself.

## Addon configuration

An addon can declare its own settings screen instead of hardcoding values
in its script. Two manifest fields opt in:

```json
{
  "name": "MOTD Banner",
  "version": "1.1.0",
  "entry": "addon.js",
  "core": ">=1.0.0",
  "configurable": true,
  "config_entry": "config.js",
  "default_config": { "message": "Welcome!", "color": "#e8a33d" }
}
```

With `configurable: true` and a `config_entry`, a gear button appears next
to the addon's toggle in **Admin -> Addons & Themes**. Clicking it loads
your `config_entry` script into a modal. That script builds whatever form
it wants using a small `window.OpenCTFAdmin` object the host sets up
*before* your script loads:

```js
window.OpenCTFAdmin.addonId          // your addon's id, e.g. "motd-banner"
window.OpenCTFAdmin.get()            // Promise<config> - current saved config, merged over default_config
window.OpenCTFAdmin.save(config)     // Promise<config> - POSTs config, returns the merged result
window.OpenCTFAdmin.mount(renderFn)  // call once: renderFn(container) builds your UI into the modal
```

Don't put an "enabled"/"on-off" field in your own config screen - whether
the addon runs at all is already the toggle it's listed under in **Admin
-> Addons & Themes**; duplicating that as a setting inside the config
screen too just gives two controls that can disagree with each other. The
config screen is for the *settings* an enabled addon needs, nothing about
whether it's enabled. `server/addons/sound-effects/` demonstrates this: its
gear button holds only a volume slider, no on/off toggle.

A minimal config script:

```js
// your-addon/config.js
(function () {
  window.OpenCTFAdmin.mount(async (container) => {
    const config = await window.OpenCTFAdmin.get();
    container.innerHTML = `
      <label>Message <input type="text" id="cfg-message" /></label>
      <button type="button" id="cfg-save">Save</button>
    `;
    container.querySelector("#cfg-message").value = config.message || "";
    container.querySelector("#cfg-save").addEventListener("click", () => {
      window.OpenCTFAdmin.save({ message: container.querySelector("#cfg-message").value });
    });
  });
})();
```

See `server/addons/motd-banner/config.js` for a fuller example with error
handling and a result message, or `server/addons/core/config.js` for one
using the shared `.toggle-row`/`.toggle-switch` checkbox styling.

Your addon's own runtime script (the `entry` file, not `config_entry`)
reads whatever was saved via `window.OpenCTF.getAddonConfig(addonId)` (see
above), and should listen for `"addon:config_changed"` to pick up a change
live rather than waiting for a reload - every shipped example addon does
this.

On the server, config is stored per-addon under `addon_config:<id>` in the
same generic settings table as the active theme, and exposed at:

| Route | Auth | Purpose |
| ----- | ---- | ------- |
| `GET /api/addons/<id>/config` | none | Runtime read for the addon's own `entry` script. Only reachable for a currently-*enabled* addon. |
| `GET /api/addons/<id>/config-script` | none | Serves the `config_entry` file specifically - reachable even while the addon is disabled, so an admin can configure it before switching it on. |
| `GET /api/admin/addons/<id>/config` | admin | Returns `{ id, name, config }` for the gear button's modal. |
| `POST /api/admin/addons/<id>/config` | admin | Body is the new config object (replaces it entirely - send the full config, not a partial patch). Broadcasts `addon_config_changed` (see below). |

## Live updates

Every client - including the still-logged-out login screen, since a theme
has to apply there too - keeps one connection open to
`GET /api/events` (Server-Sent Events). When an admin changes the active
theme, toggles an addon, saves an addon's config, or installs an
addon/theme by upload, the corresponding admin route calls
`broadcast_event()` on the server, and every open client applies the
change immediately:

| Server event            | Client reaction                                                        |
| ------------------------- | -------------------------------------------------------------------- |
| `theme_changed`           | Swaps the `<link>` for the new theme (or removes it for Default) and fires `"site:theme_changed"`. |
| `addon_toggled`            | Injects the addon's `<script>` if just enabled and fires `"addon:enabled"`, or fires `"addon:disabled"` if just disabled. |
| `addon_config_changed`     | Fires `"addon:config_changed"` with the new config - it's up to that addon's own script to react. |
| `addon_installed` / `theme_installed` | Any open admin panel refreshes its Addons/Themes list. |

This is an in-memory pub/sub scoped to a single Python process - it works
out of the box for the single dev-server process this ships with
(`python app.py`), but under a multi-worker WSGI server (e.g.
`gunicorn -w 4`) each worker only sees its own subscribers, so a change
made against one worker won't reach a client whose SSE connection landed
on a different worker. Put a real pub/sub (Redis, etc.) behind
`broadcast_event()` in `server/app.py` if you need this to work correctly
behind multiple workers.

An addon doesn't need to do anything to benefit from this - the host app
already re-applies theme/addon changes on its own. Only react directly to
these events if your addon has its own state to refresh (like
`"addon:config_changed"` above).

## Installing via upload

Besides copying a folder onto the server by hand, an admin can install an
addon or theme from **Admin -> Addons & Themes** by uploading a `.zip` of
it - `POST /api/admin/addons/upload` or `/api/admin/themes/upload`
(`multipart/form-data`, field name `file`). The zip can be shaped either
way:

- The manifest (`addon.json`/`theme.json`) at the zip's root, alongside
  its entry file(s) - i.e. a zip of a folder's *contents*.
- A single top-level folder containing the manifest - i.e. a zip of the
  folder itself. The id used is that folder's name, so re-uploading a zip
  built from an existing install updates that same addon/theme rather than
  creating a duplicate.

Either way, the manifest must have `name`, `version`, and `entry`; an
addon's manifest must also have a well-formed `core` field (see
[Compatibility](#compatibility) - it doesn't have to currently be
satisfied, just present and parseable); and the declared `entry` (and
`config_entry`, if `configurable` is set) must actually be present in the
zip - the upload is rejected with a `400` and an explanation otherwise. A
few things are also always enforced server-side, not just relied on from a
well-behaved zip tool:

- No zip-slip - any entry whose path would land outside the destination
  folder (e.g. via `../`) is rejected.
- No symlinks.
- Uncompressed contents are capped at 40 MB, independent of the upload's
  compressed size (a zip-bomb guard).
- A zip that would overwrite an [always-on addon](#always-on-addons)
  (`"can_disable": false`) is rejected.

A successful upload broadcasts `addon_installed`/`theme_installed` (see
[Live updates](#live-updates)) so it shows up in every open admin panel,
not just the one that uploaded it - it still needs to be enabled (or set
as the active theme) same as one dropped in by hand.

## Enabling an addon or theme

1. Get the folder onto the server - either copy it into `server/addons/`
   or `server/themes/` directly (same machine/container the Flask API
   runs on - see the `volumes:` entries in `docker-compose.yml` if you're
   running via Docker and want to add one without rebuilding the image),
   or upload a `.zip` of it from the admin panel (see
   [Installing via upload](#installing-via-upload)). No server restart
   needed either way - folders are scanned fresh every time the admin
   panel or site config is fetched.
2. As an admin, go to **Admin -> Addons & Themes** and toggle the addon on
   (or pick it from the theme dropdown and hit **Save**).
3. Every other open client picks up the change immediately via
   [live updates](#live-updates) - no refresh needed.

## Versioning

Use [semantic versioning](https://semver.org/) (`MAJOR.MINOR.PATCH`) for
your addon/theme's own `version` field:

- **PATCH** (`1.0.0` -> `1.0.1`): bug fixes, no behavior change a player
  or admin would notice.
- **MINOR** (`1.0.0` -> `1.1.0`): new functionality that doesn't break
  existing config (e.g. a new manifest field your addon reads, with a
  sensible default when it's absent).
- **MAJOR** (`1.0.0` -> `2.0.0`): breaking changes - e.g. you renamed the
  folder (which changes its id), require a newer OpenCTF version, or
  removed something another addon might have depended on via `OpenCTF.on`.

This is tracked per-addon/theme, independently of the core OpenCTF
platform version (in `server/__init__.py` and both `package.json`s) - bump
your own manifest's `version` whenever you change your addon or theme, and
mention what changed in its `description` or your own changelog. The core
platform version only changes for changes to OpenCTF itself, like this
extension system.

## Security notes

- Addons run with the same DOM access as the rest of the app - they can
  read anything on the page, make requests with the logged-in player's
  token via `OpenCTF.api()`, and modify the UI. There is no sandbox.
  **Only enable addons you've reviewed or written yourself.** The same
  applies to a `config_entry` script - it also runs with full DOM access
  once its modal is open.
- Themes are plain CSS and can't execute script, but a CSS file can still
  make network requests (e.g. `background: url(...)`) - review third-party
  themes the same way you'd review any other CSS you didn't write.
- Both addon and theme files (and an addon's `config_entry`) are served
  publicly (unauthenticated) so they can apply before login - don't put
  secrets in any of them. Per-addon *config values* an admin saves are
  also public (`GET /api/addons/<id>/config`) for the same reason a
  currently-enabled addon's own script needs to read them without being
  logged in - don't store secrets there either.
- The server only ever serves an addon/theme's declared `entry` file, its
  `config_entry` file, or any other file inside that same folder you
  `fetch()` by relative path from your script/stylesheet - it can't reach
  outside that folder.
- Uploading a zip is an admin-only action and doesn't change the trust
  model above - an admin could already enable arbitrary unsandboxed JS via
  the existing toggle. What the upload endpoint guards against is purely
  filesystem mischief in the zip itself (path traversal, symlinks, zip
  bombs; see [Installing via upload](#installing-via-upload)), not the
  addon's own behavior once installed.
