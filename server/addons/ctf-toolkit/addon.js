// CTF Toolkit addon
//
// Adds a "Toolkit" tab (window.OpenCTF.registerView) with the small tools
// players reach for constantly during a CTF: a converter with automatic
// ("magic") multi-layer decoding, classical ciphers, hashing and hash
// identification, a JWT decoder, a file inspector and frequency analysis.
//
// Everything runs locally in the browser - nothing a player pastes or drops
// in is sent anywhere - so it works on an offline lab network too. The logic
// lives in core.js (pure functions, unit-tested in Node); this file is the UI.
(function () {
  const ADDON_ID = "ctf-toolkit";
  const SCRIPT_URL = document.currentScript ? document.currentScript.src : "";
  const BASE_URL = SCRIPT_URL.replace(/\/addon\.js(\?.*)?$/, "");
  const t = window.OpenCTF.t;
  const T = (key, fallback, vars) => t(`addon.${ADDON_ID}.${key}`, fallback, vars);

  const MAX_FILE_BYTES = 8 * 1024 * 1024; // scanning is O(size); keep it snappy

  function injectStylesheet() {
    if (document.getElementById("ctf-toolkit-styles") || !BASE_URL) return;
    const link = document.createElement("link");
    link.id = "ctf-toolkit-styles";
    link.rel = "stylesheet";
    link.href = `${BASE_URL}/style.css`;
    document.head.appendChild(link);
  }

  let corePromise = null;
  function loadCore() {
    if (window.OpenCTFToolkitCore) return Promise.resolve(window.OpenCTFToolkitCore);
    if (!corePromise) {
      corePromise = new Promise((resolve, reject) => {
        const script = document.createElement("script");
        script.src = `${BASE_URL}/core.js`;
        script.onload = () => resolve(window.OpenCTFToolkitCore);
        script.onerror = () => reject(new Error("couldn't load core.js"));
        document.head.appendChild(script);
      });
    }
    return corePromise;
  }

  // ---- tiny DOM helpers (text goes in via textContent, never innerHTML) -----
  function el(tag, attrs, ...children) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(attrs || {})) {
      if (value === false || value == null) continue;
      if (key === "class") node.className = value;
      else if (key === "text") node.textContent = value;
      else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
      else node.setAttribute(key, value === true ? "" : value);
    }
    for (const child of children.flat()) {
      if (child == null || child === false) continue;
      node.append(child.nodeType ? child : document.createTextNode(String(child)));
    }
    return node;
  }

  async function copyText(text, button) {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const tmp = el("textarea", { style: "position:fixed;opacity:0" });
      tmp.value = text;
      document.body.append(tmp);
      tmp.select();
      try { document.execCommand("copy"); } catch { /* nothing more to try */ }
      tmp.remove();
    }
    if (button) {
      const original = button.textContent;
      button.textContent = T("copied", "Copied!");
      setTimeout(() => { button.textContent = original; }, 1100);
    }
  }

  const copyButton = (getText) => {
    const btn = el("button", { type: "button", class: "btn-ghost small tk-copy", text: T("copy", "Copy") });
    btn.addEventListener("click", () => copyText(getText(), btn));
    return btn;
  };

  const field = (label, control) => el("label", { class: "tk-field" }, el("span", { text: label }), control);
  const area = (id, rows, placeholder) => el("textarea", { id, rows, class: "tk-area", spellcheck: "false", placeholder: placeholder || "" });
  const select = (id, options) => el("select", { id, class: "tk-select" }, options.map(([value, label]) => el("option", { value, text: label })));
  const number = (id, value, min, max) => el("input", { id, type: "number", class: "tk-number", value, min, max });
  const errorBox = () => el("div", { class: "tk-error", role: "alert", hidden: true });

  function showError(box, message) {
    box.textContent = message || "";
    box.hidden = !message;
  }

  // ---- Tool: Converter ----------------------------------------------------------------
  function converterTool(core) {
    const FORMAT_LABELS = [
      ["base64", "Base64"], ["base32", "Base32"], ["hex", "Hex"], ["binary", "Binary"], ["decimal", T("fmt_decimal", "Decimal bytes")],
      ["url", "URL"], ["rot13", "ROT13"], ["html", T("fmt_html", "HTML entities")], ["morse", "Morse"],
    ];
    const labelFor = (id) => (FORMAT_LABELS.find(([key]) => key === id) || [id, id])[1];
    const input = area("tk-conv-in", 5, T("conv_placeholder", "Paste text or an encoded string..."));
    const format = select("tk-conv-format", FORMAT_LABELS);
    const output = area("tk-conv-out", 5);
    output.readOnly = true;
    const err = errorBox();
    const magicList = el("div", { class: "tk-magic-list" });

    const run = (mode) => {
      showError(err, "");
      try {
        output.value = core.FORMATS[format.value][mode](input.value);
      } catch (e) {
        output.value = "";
        showError(err, mode === "decode"
          ? T("err_decode", "That doesn't look like valid {format}.", { format: labelFor(format.value) })
          : e.message);
      }
    };

    const magic = () => {
      showError(err, "");
      magicList.replaceChildren();
      const text = input.value.trim();
      if (!text) { showError(err, T("err_empty", "Enter something first.")); return; }
      const results = core.magicDecode(text);
      if (!results.length) {
        magicList.append(el("p", { class: "tk-note", text: T("magic_none", "Nothing readable came out of any decoder. Try the Ciphers tab.") }));
        return;
      }
      results.forEach((r) => {
        const use = el("button", { type: "button", class: "btn-ghost small", text: T("use_as_input", "Use as input") });
        use.addEventListener("click", () => { input.value = r.text; magicList.replaceChildren(); output.value = ""; });
        magicList.append(el("div", { class: "tk-magic-item" },
          el("div", { class: "tk-magic-path", text: r.path.map(labelFor).join(" → ") }),
          el("pre", { class: "tk-pre", text: r.text }),
          el("div", { class: "tk-row" }, copyButton(() => r.text), use)));
      });
    };

    return el("div", { class: "tk-tool" },
      field(T("input", "Input"), input),
      el("div", { class: "tk-row" },
        field(T("format", "Format"), format),
        el("button", { type: "button", class: "btn-primary small", text: T("encode", "Encode"), onclick: () => run("encode") }),
        el("button", { type: "button", class: "btn-primary small", text: T("decode", "Decode"), onclick: () => run("decode") }),
        el("button", { type: "button", class: "btn-ghost small", text: T("swap", "Output → input"), onclick: () => { input.value = output.value; output.value = ""; } }),
        el("button", { type: "button", class: "btn-ghost small tk-magic-btn", text: T("magic", "✨ Magic: try every decoder"), onclick: magic })),
      err,
      field(T("output", "Output"), output),
      el("div", { class: "tk-row" }, copyButton(() => output.value)),
      magicList);
  }

  // ---- Tool: Ciphers -------------------------------------------------------------------------
  function ciphersTool(core) {
    const kind = select("tk-cipher-kind", [
      ["caesar", T("cipher_caesar", "Caesar / ROT-N")], ["atbash", "Atbash"], ["vigenere", "Vigenère"],
      ["xor", "XOR"], ["rail", T("cipher_rail", "Rail fence")],
    ]);
    const input = area("tk-cipher-in", 4, T("cipher_placeholder", "Ciphertext or plaintext..."));
    const output = area("tk-cipher-out", 4);
    output.readOnly = true;
    const err = errorBox();
    const results = el("div", { class: "tk-magic-list" });

    const shift = number("tk-caesar-shift", 3, -25, 25);
    const vkey = el("input", { id: "tk-vig-key", type: "text", class: "tk-text", placeholder: "KEY", spellcheck: "false" });
    const rails = number("tk-rail-count", 3, 2, 12);
    const xorKey = el("input", { id: "tk-xor-key", type: "text", class: "tk-text", placeholder: "key", spellcheck: "false" });
    const xorKeyFormat = select("tk-xor-keyfmt", [["text", T("xor_text", "Text")], ["hex", "Hex"]]);
    const xorInFormat = select("tk-xor-infmt", [["text", T("xor_in_text", "Input is text")], ["hex", T("xor_in_hex", "Input is hex")]]);

    const panels = {
      caesar: el("div", { class: "tk-row" }, field(T("shift", "Shift"), shift),
        el("button", { type: "button", class: "btn-primary small", text: T("encode", "Encode"), onclick: () => apply("caesar", 1) }),
        el("button", { type: "button", class: "btn-primary small", text: T("decode", "Decode"), onclick: () => apply("caesar", -1) }),
        el("button", { type: "button", class: "btn-ghost small", text: T("brute", "Brute force all shifts"), onclick: brute })),
      atbash: el("div", { class: "tk-row" },
        el("button", { type: "button", class: "btn-primary small", text: T("apply", "Apply"), onclick: () => apply("atbash") })),
      vigenere: el("div", { class: "tk-row" }, field(T("key", "Key"), vkey),
        el("button", { type: "button", class: "btn-primary small", text: T("encrypt", "Encrypt"), onclick: () => apply("vigenere", false) }),
        el("button", { type: "button", class: "btn-primary small", text: T("decrypt", "Decrypt"), onclick: () => apply("vigenere", true) })),
      xor: el("div", { class: "tk-row" }, field(T("input_type", "Input type"), xorInFormat), field(T("key", "Key"), xorKey), field(T("key_type", "Key type"), xorKeyFormat),
        el("button", { type: "button", class: "btn-primary small", text: T("apply", "Apply"), onclick: () => apply("xor") }),
        el("button", { type: "button", class: "btn-ghost small", text: T("brute_xor", "Brute force 1-byte key"), onclick: bruteXor })),
      rail: el("div", { class: "tk-row" }, field(T("rails", "Rails"), rails),
        el("button", { type: "button", class: "btn-primary small", text: T("encrypt", "Encrypt"), onclick: () => apply("rail", false) }),
        el("button", { type: "button", class: "btn-primary small", text: T("decrypt", "Decrypt"), onclick: () => apply("rail", true) })),
    };
    const showPanel = () => {
      Object.entries(panels).forEach(([key, node]) => { node.hidden = key !== kind.value; });
      results.replaceChildren();
      showError(err, "");
    };
    kind.addEventListener("change", showPanel);

    function apply(name, arg) {
      showError(err, "");
      results.replaceChildren();
      try {
        const text = input.value;
        if (name === "caesar") output.value = core.caesar(text, (Number(shift.value) || 0) * arg);
        else if (name === "atbash") output.value = core.atbash(text);
        else if (name === "vigenere") output.value = core.vigenere(text, vkey.value, arg);
        else if (name === "rail") output.value = arg ? core.railDecode(text, Number(rails.value) || 2) : core.railEncode(text, Number(rails.value) || 2);
        else if (name === "xor") {
          const data = xorInFormat.value === "hex" ? core.hexToBytes(text) : core.toBytes(text);
          const key = xorKeyFormat.value === "hex" ? core.hexToBytes(xorKey.value) : core.toBytes(xorKey.value);
          const out = core.xorBytes(data, key);
          output.value = `${core.fromBytes(out)}\n\nhex: ${core.bytesToHex(out)}`;
        }
      } catch (e) {
        output.value = "";
        showError(err, e.message);
      }
    }

    function listResult(label, text, extra) {
      const use = el("button", { type: "button", class: "btn-ghost small", text: T("use_as_input", "Use as input") });
      use.addEventListener("click", () => { input.value = text; });
      return el("div", { class: `tk-magic-item${extra ? " tk-best" : ""}` },
        el("div", { class: "tk-magic-path", text: label }), el("pre", { class: "tk-pre", text }),
        el("div", { class: "tk-row" }, copyButton(() => text), use));
    }

    function brute() {
      results.replaceChildren();
      if (!input.value.trim()) { showError(err, T("err_empty", "Enter something first.")); return; }
      showError(err, "");
      core.caesarBrute(input.value).forEach((r) => {
        results.append(listResult(`${T("shift", "Shift")} ${r.shift}${r.best ? ` ★ ${T("likely", "most English-like")}` : ""}`, r.text, r.best));
      });
    }

    function bruteXor() {
      results.replaceChildren();
      showError(err, "");
      try {
        const data = xorInFormat.value === "hex" ? core.hexToBytes(input.value) : core.toBytes(input.value);
        const rows = core.xorBrute(data);
        if (!rows.length) { results.append(el("p", { class: "tk-note", text: T("brute_none", "No single-byte key gives readable text.") })); return; }
        rows.forEach((r, i) => results.append(listResult(`${T("key", "Key")} 0x${r.key.toString(16).padStart(2, "0")} (${r.key}${r.key >= 32 && r.key < 127 ? `, '${String.fromCharCode(r.key)}'` : ""})${i === 0 ? ` ★` : ""}`, r.text, i === 0)));
      } catch (e) { showError(err, e.message); }
    }

    showPanel();
    return el("div", { class: "tk-tool" },
      field(T("cipher", "Cipher"), kind), field(T("input", "Input"), input), ...Object.values(panels), err,
      field(T("output", "Output"), output), el("div", { class: "tk-row" }, copyButton(() => output.value)), results);
  }

  // ---- Tool: Hashing -----------------------------------------------------------------------------
  function hashTool(core) {
    const input = area("tk-hash-in", 3, T("hash_placeholder", "Text to hash..."));
    const file = el("input", { type: "file", id: "tk-hash-file", class: "tk-file" });
    const table = el("div", { class: "tk-hash-table" });
    const err = errorBox();
    const ident = el("input", { id: "tk-ident", type: "text", class: "tk-text", spellcheck: "false", placeholder: T("ident_placeholder", "Paste a hash to identify it...") });
    const identOut = el("div", { class: "tk-chips" });
    let computed = {};

    async function run() {
      showError(err, "");
      table.replaceChildren();
      try {
        const bytes = file.files[0] ? new Uint8Array(await file.files[0].arrayBuffer()) : core.toBytes(input.value);
        computed = await core.hashAll(bytes);
        Object.entries(computed).forEach(([name, value]) => {
          table.append(el("div", { class: "tk-hash-row", "data-algo": name },
            el("b", { text: name }), el("code", { text: value }), copyButton(() => value)));
        });
        identify();
      } catch (e) {
        showError(err, e.message || String(e));
      }
    }

    function identify() {
      identOut.replaceChildren();
      const value = ident.value.trim();
      if (!value) return;
      const guesses = core.identifyHash(value);
      if (!guesses.length) identOut.append(el("span", { class: "tk-note", text: T("ident_none", "Doesn't match a common hash format.") }));
      guesses.forEach((g) => identOut.append(el("span", { class: "tk-chip", text: g })));
      const match = Object.entries(computed).find(([, hash]) => hash === value.toLowerCase());
      if (match) identOut.append(el("span", { class: "tk-chip tk-chip-ok", text: T("ident_match", "Matches the {algo} of your input above", { algo: match[0] }) }));
    }
    ident.addEventListener("input", identify);

    return el("div", { class: "tk-tool" },
      field(T("input", "Input"), input), field(T("or_file", "…or a file"), file),
      el("div", { class: "tk-row" }, el("button", { type: "button", class: "btn-primary small", text: T("hash_it", "Hash it"), onclick: run })),
      err, table, el("h4", { class: "tk-h", text: T("ident_title", "Identify a hash") }), ident, identOut);
  }

  // ---- Tool: JWT --------------------------------------------------------------------------------------
  function jwtTool(core) {
    const input = area("tk-jwt-in", 4, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...");
    const out = el("div", { class: "tk-jwt-out" });
    function decode() {
      out.replaceChildren();
      if (!input.value.trim()) return;
      try {
        const r = core.jwtDecode(input.value);
        out.append(
          el("h4", { class: "tk-h", text: T("jwt_header", "Header") }), el("pre", { class: "tk-pre", text: JSON.stringify(r.header, null, 2) }),
          el("h4", { class: "tk-h", text: T("jwt_payload", "Payload") }), el("pre", { class: "tk-pre", text: JSON.stringify(r.payload, null, 2) }));
        const times = Object.entries(r.times);
        if (times.length) out.append(el("ul", { class: "tk-list" }, times.map(([claim, iso]) => el("li", {}, el("code", { text: claim }), ` = ${iso}`))));
        r.notes.forEach((n) => out.append(el("p", { class: "tk-note tk-warn", text: n })));
        out.append(el("p", { class: "tk-note", text: T("jwt_unverified", "The signature is shown but NOT verified - decoding a token doesn't prove it's genuine.") }),
          el("h4", { class: "tk-h", text: T("jwt_signature", "Signature") }), el("code", { class: "tk-break", text: r.signature || "(empty)" }));
      } catch (e) {
        out.append(el("div", { class: "tk-error", text: T("jwt_bad", "That isn't a valid JWT: {error}", { error: e.message }) }));
      }
    }
    input.addEventListener("input", decode);
    return el("div", { class: "tk-tool" }, field(T("jwt_token", "Token"), input), out);
  }

  // ---- Tool: File inspector -------------------------------------------------------------------------------
  function fileTool(core) {
    const picker = el("input", { type: "file", id: "tk-file-in", class: "tk-file" });
    const out = el("div", { class: "tk-file-out" });
    const drop = el("div", { class: "tk-drop", tabindex: "0", role: "button" },
      el("strong", { text: T("file_drop", "Drop a file here or click to choose") }),
      el("span", { text: T("file_local", "It's analysed in your browser and never uploaded.") }));

    async function inspect(file) {
      out.replaceChildren(el("p", { class: "tk-note", text: T("file_reading", "Reading...") }));
      let buffer = await file.slice(0, MAX_FILE_BYTES).arrayBuffer();
      const data = new Uint8Array(buffer);
      buffer = null;
      const type = core.detectType(data);
      const trailing = core.trailingData(data);
      const embedded = core.findEmbedded(data);
      const strings = core.extractStrings(data);
      const ext = (file.name.split(".").pop() || "").toLowerCase();
      const rows = [
        [T("file_name", "Name"), file.name], [T("file_size", "Size"), `${file.size.toLocaleString()} bytes`],
        [T("file_type", "Detected type"), type || T("file_unknown", "unknown / plain data")],
      ];
      out.replaceChildren(
        el("table", { class: "tk-kv" }, rows.map(([k, v]) => el("tr", {}, el("th", { text: k }), el("td", { text: v })))),
        file.size > MAX_FILE_BYTES ? el("p", { class: "tk-note tk-warn", text: T("file_truncated", "Only the first {mb} MB were analysed.", { mb: MAX_FILE_BYTES / 1024 / 1024 }) }) : null,
        type && ext && !type.toLowerCase().includes(ext) && !["bin", "dat", ""].includes(ext)
          ? el("p", { class: "tk-note tk-warn", text: T("file_ext_mismatch", "The extension .{ext} doesn't obviously match the detected type - worth a closer look.", { ext }) }) : null,
        trailing && trailing.extra > 0
          ? el("p", { class: "tk-note tk-warn", text: T("file_trailing", "{extra} bytes follow the end of the {kind} image (offset {end}). Data is often hidden there.", { extra: trailing.extra, kind: trailing.kind, end: trailing.end }) }) : null,
        el("h4", { class: "tk-h", text: T("file_embedded", "Other file signatures inside") }),
        embedded.length
          ? el("ul", { class: "tk-list" }, embedded.map((e) => el("li", {}, el("code", { text: `0x${e.offset.toString(16)} (${e.offset})` }), ` ${e.label}`)))
          : el("p", { class: "tk-note", text: T("file_none", "None found.") }),
        el("h4", { class: "tk-h", text: T("file_hex", "Hex dump (first 256 bytes)") }), el("pre", { class: "tk-pre tk-hex", text: core.hexDump(data) }),
        el("h4", { class: "tk-h", text: T("file_strings", "Readable strings") }),
        strings.length
          ? el("pre", { class: "tk-pre tk-strings", text: strings.join("\n") }) : el("p", { class: "tk-note", text: T("file_none", "None found.") }),
        el("div", { class: "tk-row" }, copyButton(() => strings.join("\n"))));
    }

    const handle = (file) => { if (file) inspect(file).catch((e) => out.replaceChildren(el("div", { class: "tk-error", text: e.message }))); };
    picker.addEventListener("change", () => handle(picker.files[0]));
    drop.addEventListener("click", () => picker.click());
    drop.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); picker.click(); } });
    ["dragenter", "dragover"].forEach((n) => drop.addEventListener(n, (e) => { e.preventDefault(); drop.classList.add("over"); }));
    ["dragleave", "drop"].forEach((n) => drop.addEventListener(n, (e) => { e.preventDefault(); drop.classList.remove("over"); }));
    drop.addEventListener("drop", (e) => handle(e.dataTransfer.files[0]));
    return el("div", { class: "tk-tool" }, drop, picker, out);
  }

  // ---- Tool: Frequency ----------------------------------------------------------------------------------------
  function frequencyTool(core) {
    const input = area("tk-freq-in", 5, T("freq_placeholder", "Paste ciphertext to analyse..."));
    const chart = el("div", { class: "tk-freq" });
    const summary = el("p", { class: "tk-note" });
    const ENGLISH = [8.2, 1.5, 2.8, 4.3, 12.7, 2.2, 2.0, 6.1, 7.0, 0.15, 0.77, 4.0, 2.4, 6.7, 7.5, 1.9, 0.095, 6.0, 6.3, 9.1, 2.8, 0.98, 2.4, 0.15, 2.0, 0.074];

    function update() {
      chart.replaceChildren();
      const { counts, letters, ioc } = core.frequency(input.value);
      if (!letters) { summary.textContent = ""; return; }
      const top = Math.max(...counts.map((n) => (n / letters) * 100), ...ENGLISH);
      counts.forEach((n, i) => {
        const pct = (n / letters) * 100;
        const letter = String.fromCharCode(65 + i);
        chart.append(el("div", { class: "tk-bar", tabindex: "0", title: `${letter}: ${n} (${pct.toFixed(1)}%)`, "aria-label": `${letter}: ${n}, ${pct.toFixed(1)}%` },
          el("div", { class: "tk-bar-track" },
            el("div", { class: "tk-bar-english", style: `height:${(ENGLISH[i] / top) * 100}%` }),
            el("div", { class: "tk-bar-fill", style: `height:${(pct / top) * 100}%` })),
          el("span", { text: letter })));
      });
      const verdict = ioc > 0.06 ? T("freq_english", "close to English or another single-alphabet cipher (Caesar, Atbash, substitution)")
        : ioc < 0.045 ? T("freq_flat", "flat - looks polyalphabetic (e.g. Vigenère) or random") : T("freq_between", "in between - short text or a mixed cipher");
      summary.textContent = T("freq_summary", "{letters} letters · index of coincidence {ioc} - {verdict}", { letters, ioc: ioc.toFixed(3), verdict });
    }
    input.addEventListener("input", update);
    return el("div", { class: "tk-tool" }, field(T("input", "Input"), input), summary, chart,
      el("p", { class: "tk-note", text: T("freq_legend", "Bars: your text. Outlined markers: typical English.") }));
  }

  // ---- Shell ----------------------------------------------------------------------------------------------------------
  const TOOLS = [
    ["convert", () => T("tool_convert", "Convert"), converterTool],
    ["ciphers", () => T("tool_ciphers", "Ciphers"), ciphersTool],
    ["hash", () => T("tool_hash", "Hash"), hashTool],
    ["jwt", () => "JWT", jwtTool],
    ["file", () => T("tool_file", "File"), fileTool],
    ["frequency", () => T("tool_frequency", "Frequency"), frequencyTool],
  ];

  // render() runs every time the tab is opened. Keep the existing DOM (and so
  // whatever the player pasted into the tools) unless the language changed.
  let currentContainer = null;
  let stale = false;

  async function render(container) {
    injectStylesheet();
    currentContainer = container;
    if (!stale && container.querySelector(".tk-tabs")) return;
    stale = false;
    container.replaceChildren(el("header", { class: "view-header" }, el("h2", { text: T("title", "Toolkit") })));
    let core;
    try {
      core = await loadCore();
    } catch (e) {
      container.append(el("div", { class: "tk-error", text: e.message }));
      return;
    }
    container.append(el("p", { class: "field-note", text: T("intro", "Handy tools for CTF challenges. Everything runs locally in your browser - nothing you paste or open here leaves this window.") }));
    const tabs = el("div", { class: "tk-tabs", role: "tablist" });
    const panels = el("div", { class: "tk-panels" });
    const built = {};
    const buttons = {};

    function show(id) {
      TOOLS.forEach(([toolId, , build]) => {
        const active = toolId === id;
        buttons[toolId].classList.toggle("active", active);
        buttons[toolId].setAttribute("aria-selected", String(active));
        if (active && !built[toolId]) {
          built[toolId] = el("div", { class: "tk-panel", role: "tabpanel", "data-tool": toolId }, build(core));
          panels.append(built[toolId]);
        }
        if (built[toolId]) built[toolId].hidden = !active;
      });
    }
    TOOLS.forEach(([id, label]) => {
      buttons[id] = el("button", { type: "button", class: "tk-tab", role: "tab", "data-tool": id, text: label(), onclick: () => show(id) });
      tabs.append(buttons[id]);
    });
    container.append(tabs, panels);
    show("convert");
  }

  window.OpenCTF.on("language:changed", () => {
    stale = true;
    if (currentContainer && currentContainer.isConnected && !currentContainer.classList.contains("hidden")) render(currentContainer);
  });

  window.OpenCTF.registerView({ id: ADDON_ID, label: "Toolkit", labelKey: `addon.${ADDON_ID}.nav_label`, render });
})();
