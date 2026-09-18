# Changelog

Format loosely follows [Keep a Changelog](https://keepachangelog.com/).
Versions apply to the platform as a whole (client + server move together).

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
