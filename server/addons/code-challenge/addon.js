// Code Challenge Editor addon
//
// Adds an in-browser, sandboxed code editor to any standard challenge
// whose description contains a [[coding-task]] block (see AUTHORING.md).
// Needs no backend/database changes: it reads the same Description field
// every challenge already has, over the same GET /api/challenges every
// player already calls, and injects its panel into the existing standard
// challenge modal (#modal-challenge) via plain DOM access - the addon
// system gives every addon full access to the host page (see
// docs/ADDON_DEVELOPMENT.md), there's no special "challenge modal" hook
// needed for this.
//
// The editor is a small, dependency-free line-numbered textarea. All
// submitted code runs server-side through the Judge0 endpoint.
(function () {
  const ADDON_ID = "code-challenge";
  const SCRIPT_URL = document.currentScript ? document.currentScript.src : "";
  const ADDON_BASE_URL = SCRIPT_URL.replace(/\/addon\.js(\?.*)?$/, "");

  const t = window.OpenCTF.t;

  const FALLBACK_CONFIG = { editor_font_size: 13 };
  const RUNNABLE_LANGUAGES = ["javascript", "python", "php", "ruby", "c", "cpp", "java"];
  let CONFIG = { ...FALLBACK_CONFIG };

  const TASK_RE = /\[\[coding-task\]\]([\s\S]*?)\[\[\/coding-task\]\]/;

  // Per-challenge in-progress code, kept in memory only (lost on reload,
  // same as everything else in this addon - nothing here is persisted
  // server-side), so switching tabs or re-opening the same challenge
  // doesn't throw away what the player already typed.
  const draftByTitle = new Map();

  let challengesCache = null;
  let activeTask = null;
  let activeTitle = null;

  function injectStylesheet() {
    if (document.getElementById("code-challenge-styles") || !ADDON_BASE_URL) return;
    const link = document.createElement("link");
    link.id = "code-challenge-styles";
    link.rel = "stylesheet";
    link.href = `${ADDON_BASE_URL}/style.css`;
    document.head.appendChild(link);
  }

  function escapeHtml(str) {
    return String(str ?? "").replace(/[&<>"']/g, (c) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    })[c]);
  }

  async function loadConfig() {
    try {
      CONFIG = { ...FALLBACK_CONFIG, ...(await window.OpenCTF.getAddonConfig(ADDON_ID)) };
    } catch {
      CONFIG = { ...FALLBACK_CONFIG };
    }
  }

  function parseTask(task) {
    if (!task || typeof task !== "object") return null;
    try {
      if (typeof task.function_name !== "string" || !Array.isArray(task.tests) || !task.tests.length) return null;
      task.starter_code = typeof task.starter_code === "string" ? task.starter_code : `function ${task.function_name}() {\n\n}\n`;
      task.language = typeof task.language === "string" && task.language.trim() ? task.language.trim() : "javascript";
      const hasTypedSignature = Array.isArray(task.parameter_types) && typeof task.return_type === "string";
      const availableLanguages = hasTypedSignature
        ? RUNNABLE_LANGUAGES
        : RUNNABLE_LANGUAGES.filter((language) => !["c", "cpp", "java"].includes(language));
      const requestedLanguages = Array.isArray(task.languages)
        ? task.languages.filter((l) => typeof l === "string" && l.trim()).map((l) => l.trim())
        : availableLanguages;
      const initialLanguage = normalizeLanguage(task.language);
      task.languages = Array.from(new Set([initialLanguage, ...requestedLanguages.map(normalizeLanguage)]))
        .filter((language) => availableLanguages.includes(language));
      if (!task.languages.length) task.languages = ["javascript"];
      task.language = task.languages.includes(initialLanguage) ? initialLanguage : task.languages[0];
      task.starter_code_by_language =
        task.starter_code_by_language && typeof task.starter_code_by_language === "object"
          ? task.starter_code_by_language
          : {};
      return task;
    } catch {
      return null;
    }
  }

  function stripTask(description) {
    return (description || "").replace(TASK_RE, "").trim();
  }

  function nativeStarterCode(task, language) {
    const types = task.parameter_types || [];
    const names = task.parameter_names || types.map((_type, index) => `arg${index + 1}`);
    const cTypes = { int: "int", double: "double", bool: "bool", string: "const char *" };
    const cppTypes = { int: "int", double: "double", bool: "bool", string: "std::string", "int[]": "std::vector<int>", "int[][]": "std::vector<std::vector<int>>" };
    const javaTypes = { int: "int", double: "double", bool: "boolean", string: "String", "int[]": "int[]", "int[][]": "int[][]" };
    const returnType = task.return_type || "int";
    let parameters;
    let resultType;
    let emptyReturn;
    if (language === "c") {
      parameters = types.map((type, index) => type === "int[]"
        ? `const int *${names[index]}, size_t ${names[index]}_length`
        : `${cTypes[type] || "int"} ${names[index]}`).join(", ");
      resultType = cTypes[returnType] || "int";
      emptyReturn = returnType === "string" ? '""' : returnType === "bool" ? "false" : "0";
      return `#include <stdbool.h>\n#include <stddef.h>\n${resultType} ${task.function_name}(${parameters}) {\n    return ${emptyReturn};\n}\n`;
    }
    if (language === "cpp") {
      parameters = types.map((type, index) => `${cppTypes[type] || "int"} ${names[index]}`).join(", ");
      resultType = cppTypes[returnType] || "int";
      emptyReturn = returnType.endsWith("[]") ? "{}" : returnType === "string" ? '""' : returnType === "bool" ? "false" : "0";
      return `${resultType} ${task.function_name}(${parameters}) {\n    return ${emptyReturn};\n}\n`;
    }
    parameters = types.map((type, index) => `${javaTypes[type] || "int"} ${names[index]}`).join(", ");
    resultType = javaTypes[returnType] || "int";
    emptyReturn = returnType === "int[]" ? "new int[0]" : returnType === "int[][]" ? "new int[0][]" : returnType === "string" ? '""' : returnType === "bool" ? "false" : "0";
    return `public static ${resultType} ${task.function_name}(${parameters}) {\n    return ${emptyReturn};\n}\n`;
  }

  // --- Syntax highlighting --------------------------------------------
  // A small, dependency-free, regex-based tokenizer covering the language
  // families a challenge author is likely to want (see LANG_DEFS below).
  // It's intentionally generic (comment/string/number/keyword rules driven
  // by a per-language data table, one dedicated pass each for HTML/CSS)
  // rather than a full parser, and never touches the network. The selected
  // runnable language also determines which Judge0 harness executes the
  // code; see AUTHORING.md for the supported runtimes.
  const LANG_ALIASES = {
    js: "javascript", jsx: "javascript", mjs: "javascript", cjs: "javascript",
    ts: "typescript", tsx: "typescript",
    py: "python", py3: "python",
    "c++": "cpp", "cplusplus": "cpp",
    "c#": "csharp", cs: "csharp",
    golang: "go",
    rb: "ruby",
    sh: "bash", shell: "bash", zsh: "bash",
    yml: "yaml",
    txt: "plaintext", text: "plaintext", none: "plaintext",
  };

  // Keyword/literal/comment/string shape for every "identifier + keyword"
  // style language. HTML and CSS don't fit this shape (tag/property
  // structure, not keyword streams) and get their own tokenizers below.
  const LANG_DEFS = {
    javascript: {
      line: "//", block: ["/*", "*/"], strings: ["\"", "'", "`"],
      keywords: ["break","case","catch","class","const","continue","debugger","default","delete","do","else","export","extends","finally","for","function","if","import","in","instanceof","let","new","of","return","static","switch","throw","try","typeof","var","void","while","yield","async","await","get","set"],
      literals: ["true","false","null","undefined","NaN","Infinity","this","super"],
    },
    typescript: {
      line: "//", block: ["/*", "*/"], strings: ["\"", "'", "`"],
      keywords: ["break","case","catch","class","const","continue","debugger","default","delete","do","else","export","extends","finally","for","function","if","import","in","instanceof","let","new","of","return","static","switch","throw","try","typeof","var","void","while","yield","async","await","get","set","interface","type","enum","implements","namespace","readonly","public","private","protected","abstract","declare","as","is","keyof","module"],
      literals: ["true","false","null","undefined","NaN","Infinity","this","super","unknown","never","any"],
    },
    python: {
      line: "#", block: null, strings: ["\"", "'"],
      keywords: ["and","as","assert","async","await","break","class","continue","def","del","elif","else","except","finally","for","from","global","if","import","in","is","lambda","nonlocal","not","or","pass","raise","return","try","while","with","yield"],
      literals: ["True","False","None","self"],
    },
    java: {
      line: "//", block: ["/*", "*/"], strings: ["\"", "'"],
      keywords: ["abstract","assert","boolean","break","byte","case","catch","char","class","const","continue","default","do","double","else","enum","extends","final","finally","float","for","goto","if","implements","import","instanceof","int","interface","long","native","new","package","private","protected","public","return","short","static","strictfp","super","switch","synchronized","this","throw","throws","transient","try","void","volatile","while"],
      literals: ["true","false","null"],
    },
    c: {
      line: "//", block: ["/*", "*/"], strings: ["\"", "'"],
      keywords: ["auto","break","case","char","const","continue","default","do","double","else","enum","extern","float","for","goto","if","int","long","register","return","short","signed","sizeof","static","struct","switch","typedef","union","unsigned","void","volatile","while","include","define"],
      literals: ["NULL","true","false"],
    },
    cpp: {
      line: "//", block: ["/*", "*/"], strings: ["\"", "'"],
      keywords: ["auto","break","case","char","class","const","constexpr","continue","default","delete","do","double","else","enum","explicit","extern","final","float","for","friend","goto","if","inline","int","long","mutable","namespace","new","noexcept","operator","override","private","protected","public","register","return","short","signed","sizeof","static","struct","switch","template","this","throw","try","typedef","typename","union","unsigned","using","virtual","void","volatile","while","include","define"],
      literals: ["nullptr","true","false"],
    },
    csharp: {
      line: "//", block: ["/*", "*/"], strings: ["\"", "'"],
      keywords: ["abstract","as","base","break","case","catch","checked","class","const","continue","default","delegate","do","else","enum","event","explicit","extern","finally","fixed","for","foreach","goto","if","implicit","in","interface","internal","is","lock","namespace","new","operator","out","override","params","private","protected","public","readonly","ref","return","sealed","sizeof","stackalloc","static","struct","switch","this","throw","try","typeof","unchecked","unsafe","using","virtual","void","volatile","while","var","async","await","get","set"],
      literals: ["true","false","null"],
    },
    go: {
      line: "//", block: ["/*", "*/"], strings: ["\"", "`"],
      keywords: ["break","case","chan","const","continue","default","defer","else","fallthrough","for","func","go","goto","if","import","interface","map","package","range","return","select","struct","switch","type","var"],
      literals: ["true","false","nil","iota"],
    },
    rust: {
      line: "//", block: ["/*", "*/"], strings: ["\""],
      keywords: ["as","break","const","continue","crate","dyn","else","enum","extern","fn","for","if","impl","in","let","loop","match","mod","move","mut","pub","ref","return","self","Self","static","struct","super","trait","type","unsafe","use","where","while","async","await"],
      literals: ["true","false"],
    },
    ruby: {
      line: "#", block: null, strings: ["\"", "'"],
      keywords: ["begin","break","case","class","def","defined?","do","else","elsif","end","ensure","for","if","in","module","next","not","or","redo","rescue","retry","return","then","undef","unless","until","when","while","yield","require","require_relative","attr_accessor","attr_reader","attr_writer"],
      literals: ["true","false","nil","self"],
    },
    php: {
      line: "//", block: ["/*", "*/"], strings: ["\"", "'"],
      keywords: ["abstract","and","array","as","break","callable","case","catch","class","clone","const","continue","declare","default","do","echo","else","elseif","empty","extends","final","finally","fn","for","foreach","function","global","goto","if","implements","include","include_once","instanceof","interface","isset","list","match","namespace","new","or","print","private","protected","public","require","require_once","return","static","switch","throw","trait","try","unset","use","var","while","xor","yield"],
      literals: ["true","false","null","this"],
    },
    bash: {
      line: "#", block: null, strings: ["\"", "'"],
      keywords: ["if","then","else","elif","fi","for","while","until","do","done","case","esac","function","return","exit","local","export","readonly","declare","in","select","break","continue","echo"],
      literals: ["true","false"],
    },
    sql: {
      line: "--", block: ["/*", "*/"], strings: ["'"], caseInsensitiveKeywords: true,
      keywords: ["select","insert","update","delete","from","where","join","inner","outer","left","right","full","on","group","by","order","having","as","and","or","not","null","in","like","limit","offset","create","table","alter","drop","primary","key","foreign","references","values","into","set","distinct","union","all","exists","between","case","when","then","end","default","index","view","trigger"],
      literals: ["true","false","null"],
    },
    json: {
      line: null, block: null, strings: ["\""],
      keywords: [],
      literals: ["true","false","null"],
    },
  };

  function escapeRegExp(str) {
    return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }

  // Builds one master regex per language def (cached) with a named group
  // per token kind, so a single exec-loop can classify every match.
  const tokenizerCache = new Map();
  function getTokenizer(def) {
    if (tokenizerCache.has(def)) return tokenizerCache.get(def);
    const parts = [];
    if (def.block) parts.push(`(?<blockcomment>${escapeRegExp(def.block[0])}[\\s\\S]*?${escapeRegExp(def.block[1] )})`);
    if (def.line) parts.push(`(?<linecomment>${escapeRegExp(def.line)}.*)`);
    def.strings.forEach((q, i) => {
      const qe = escapeRegExp(q);
      parts.push(`(?<string${i}>${qe}(?:\\\\.|[^${qe}\\\\])*${qe}?)`);
    });
    parts.push(`(?<number>\\b0[xX][0-9a-fA-F]+\\b|\\b\\d+(?:\\.\\d+)?(?:[eE][+-]?\\d+)?\\b)`);
    parts.push(`(?<ident>[A-Za-z_$][A-Za-z0-9_$]*[!?]?)`);
    const re = new RegExp(parts.join("|"), "g");
    tokenizerCache.set(def, re);
    return re;
  }

  function highlightGeneric(code, def) {
    const re = getTokenizer(def);
    const fold = def.caseInsensitiveKeywords ? (s) => s.toLowerCase() : (s) => s;
    const keywordSet = new Set(def.keywords.map(fold));
    const literalSet = new Set(def.literals.map(fold));
    let out = "";
    let last = 0;
    let match;
    re.lastIndex = 0;
    while ((match = re.exec(code))) {
      if (match.index > last) out += escapeHtml(code.slice(last, match.index));
      const g = match.groups || {};
      const text = match[0];
      if (g.blockcomment || g.linecomment) {
        out += `<span class="tok-comment">${escapeHtml(text)}</span>`;
      } else if (g.number) {
        out += `<span class="tok-number">${escapeHtml(text)}</span>`;
      } else if (g.ident) {
        if (keywordSet.has(fold(text))) out += `<span class="tok-keyword">${escapeHtml(text)}</span>`;
        else if (literalSet.has(fold(text))) out += `<span class="tok-literal">${escapeHtml(text)}</span>`;
        else if (code[re.lastIndex] === "(") out += `<span class="tok-function">${escapeHtml(text)}</span>`;
        else if (text[0] === "$") out += `<span class="tok-variable">${escapeHtml(text)}</span>`;
        else out += escapeHtml(text);
      } else {
        // One of the string# groups.
        out += `<span class="tok-string">${escapeHtml(text)}</span>`;
      }
      last = re.lastIndex;
    }
    out += escapeHtml(code.slice(last));
    return out;
  }

  const HTML_RE = /(?<comment><!--[\s\S]*?-->)|(?<tag><\/?[a-zA-Z][a-zA-Z0-9-]*)|(?<attr>[a-zA-Z-]+)(?<eq>=)(?<value>"[^"]*"|'[^']*')|(?<close>\/?>)/g;
  function highlightHtml(code) {
    let out = "";
    let last = 0;
    let match;
    HTML_RE.lastIndex = 0;
    while ((match = HTML_RE.exec(code))) {
      if (match.index > last) out += escapeHtml(code.slice(last, match.index));
      const g = match.groups || {};
      if (g.comment) out += `<span class="tok-comment">${escapeHtml(g.comment)}</span>`;
      else if (g.tag) out += `<span class="tok-keyword">${escapeHtml(g.tag)}</span>`;
      else if (g.attr) out += `<span class="tok-function">${escapeHtml(g.attr)}</span>=<span class="tok-string">${escapeHtml(g.value)}</span>`;
      else if (g.close) out += escapeHtml(g.close);
      last = HTML_RE.lastIndex;
    }
    out += escapeHtml(code.slice(last));
    return out;
  }

  const CSS_RE = /(?<comment>\/\*[\s\S]*?\*\/)|(?<string>"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')|(?<selector>[.#]?[a-zA-Z][a-zA-Z0-9_-]*)(?=\s*\{)|(?<prop>[a-zA-Z-]+)(?=\s*:)|(?<number>-?\d+(?:\.\d+)?(?:px|em|rem|%|vh|vw|s|ms)?)/g;
  function highlightCss(code) {
    let out = "";
    let last = 0;
    let match;
    CSS_RE.lastIndex = 0;
    while ((match = CSS_RE.exec(code))) {
      if (match.index > last) out += escapeHtml(code.slice(last, match.index));
      const g = match.groups || {};
      if (g.comment) out += `<span class="tok-comment">${escapeHtml(g.comment)}</span>`;
      else if (g.string) out += `<span class="tok-string">${escapeHtml(g.string)}</span>`;
      else if (g.selector) out += `<span class="tok-keyword">${escapeHtml(g.selector)}</span>`;
      else if (g.prop) out += `<span class="tok-function">${escapeHtml(g.prop)}</span>`;
      else if (g.number) out += `<span class="tok-number">${escapeHtml(g.number)}</span>`;
      last = CSS_RE.lastIndex;
    }
    out += escapeHtml(code.slice(last));
    return out;
  }

  const LANG_DISPLAY_NAMES = {
    javascript: "JavaScript", typescript: "TypeScript", python: "Python", java: "Java",
    c: "C", cpp: "C++", csharp: "C#", go: "Go", rust: "Rust", ruby: "Ruby", php: "PHP",
    bash: "Bash", sql: "SQL", json: "JSON", html: "HTML", css: "CSS", plaintext: "Plain text",
  };
  function languageDisplayName(language) {
    const id = normalizeLanguage(language);
    return LANG_DISPLAY_NAMES[id] || id;
  }

  function normalizeLanguage(language) {
    const id = String(language || "javascript").toLowerCase().trim();
    return LANG_ALIASES[id] || id;
  }

  function highlightCode(code, language) {
    const id = normalizeLanguage(language);
    if (id === "html") return highlightHtml(code);
    if (id === "css") return highlightCss(code);
    const def = LANG_DEFS[id];
    if (!def) return escapeHtml(code); // plaintext / unknown language: no coloring
    return highlightGeneric(code, def);
  }

  // --- CodeEditor ----------------------------------------------------
  // A minimal, dependency-free line-numbered code editor: a <textarea>
  // for input, a <div> gutter, Tab inserting two spaces instead of
  // moving focus, and live syntax highlighting. The highlighting uses
  // the classic transparent-textarea trick: a <pre><code> layer with
  // highlightCode()'s markup sits exactly behind the real,
  // fully-functional (but text-transparent) <textarea> - the textarea
  // is still what the player actually types into and what
  // getValue()/setValue() read and write, the highlight layer is purely
  // decorative. Both, plus the gutter, grow together with the content
  // (no fixed-height internal scrolling, no manual resize handle): the
  // gutter and the highlight/textarea pair are CSS Grid-stacked (see
  // .cc-editor/.cc-code-wrap in style.css) rather than kept in sync via
  // JS-driven scrollTop/scrollLeft mirroring, which is what this used to
  // do and which could drift - grid stacking makes the browser's normal
  // layout engine responsible for keeping all three the same size, so
  // there's no separate scroll state that can fall out of sync in the
  // first place, and the browser's native "keep the caret in view"
  // behavior handles bringing a distant line into view as the player
  // types past the visible area of the editor panel.
  class CodeEditor {
    constructor(container, { value = "", fontSize = 13, language = "javascript", onChange } = {}) {
      this.container = container;
      this.onChange = onChange;
      this.language = language;
      container.innerHTML = `
        <div class="cc-editor">
          <div class="cc-gutter" aria-hidden="true"></div>
          <div class="cc-code-wrap">
            <pre class="cc-highlight" aria-hidden="true"><code class="cc-highlight-code"></code></pre>
            <textarea class="cc-textarea" spellcheck="false" autocapitalize="off" autocomplete="off"></textarea>
          </div>
        </div>
      `;
      this.gutter = container.querySelector(".cc-gutter");
      this.textarea = container.querySelector(".cc-textarea");
      this.highlightPre = container.querySelector(".cc-highlight");
      this.highlightCode = container.querySelector(".cc-highlight-code");
      this.textarea.style.fontSize = `${fontSize}px`;
      this.gutter.style.fontSize = `${fontSize}px`;
      this.highlightPre.style.fontSize = `${fontSize}px`;
      this.textarea.value = value;

      // No scroll-position syncing needed (and there used to be a
      // "scroll" listener here for exactly that): the gutter and the
      // highlight layer are grid-stacked with the textarea in CSS and
      // all three grow together with the content (see .cc-editor's
      // comment in style.css), so there's no separate scroll state to
      // keep in sync in the first place - only one element (the whole
      // panel's nearest scrollable ancestor, if any) ever scrolls, and
      // the browser's native "keep the caret in view" behavior handles
      // that on its own.
      this.textarea.addEventListener("input", () => {
        this.renderGutter();
        this.renderHighlight();
        if (this.onChange) this.onChange(this.textarea.value);
      });
      this.textarea.addEventListener("keydown", (event) => {
        if (event.key !== "Tab") return;
        event.preventDefault();
        const { selectionStart, selectionEnd, value: current } = this.textarea;
        this.textarea.value = `${current.slice(0, selectionStart)}  ${current.slice(selectionEnd)}`;
        this.textarea.selectionStart = this.textarea.selectionEnd = selectionStart + 2;
        this.renderGutter();
        this.renderHighlight();
        if (this.onChange) this.onChange(this.textarea.value);
      });
      this.gutter.addEventListener("click", (event) => {
        const style = getComputedStyle(this.textarea);
        const lineHeight = parseFloat(style.lineHeight) || 1;
        const paddingTop = parseFloat(style.paddingTop) || 0;
        const lineIndex = Math.max(0, Math.floor((event.clientY - this.textarea.getBoundingClientRect().top - paddingTop) / lineHeight));
        const lineStarts = [0];
        for (let i = 0; i < this.textarea.value.length; i++) {
          if (this.textarea.value[i] === "\n") lineStarts.push(i + 1);
        }
        this.textarea.focus();
        const caret = lineStarts[Math.min(lineIndex, lineStarts.length - 1)];
        this.textarea.setSelectionRange(caret, caret);
      });

      this.renderGutter();
      this.renderHighlight();
    }

    renderGutter() {
      const lineCount = this.textarea.value.split("\n").length;
      let out = "";
      for (let i = 1; i <= lineCount; i++) out += `${i}\n`;
      this.gutter.textContent = out;
    }

    renderHighlight() {
      // A trailing newline collapses in a <pre>, which would leave the
      // highlight layer one line short of the gutter/textarea - pad the
      // markup with a blank line so all three always agree on the line
      // count (this is what actually keeps them the same height now,
      // not scroll-position syncing - see the constructor's comment).
      const value = this.textarea.value;
      this.highlightCode.innerHTML = highlightCode(value, this.language) + "\n";
    }

    setLanguage(language) {
      this.language = language;
      this.renderHighlight();
    }

    getValue() {
      return this.textarea.value;
    }

    setValue(value) {
      this.textarea.value = value;
      this.renderGutter();
      this.renderHighlight();
    }
  }

  function deepEqual(a, b) {
    if (a === b) return true;
    try {
      return JSON.stringify(a) === JSON.stringify(b);
    } catch {
      return false;
    }
  }

  // Map Judge0 statuses into the editor's per-test result shape.
  function mapJudge0Results(serverResults) {
    return serverResults.map((r) => {
      if (r.status !== "Accepted" && r.status !== "Wrong Answer") {
        return { ok: false, error: [r.status, r.compile_output || r.stderr].filter(Boolean).join(": ") };
      }
      return { ok: true, actual: r.actual, passed: r.passed };
    });
  }

  // --- Panel wiring -------------------------------------------------

  function ensurePanel() {
    let panel = document.getElementById("code-challenge-panel");
    if (panel) return panel;
    const form = document.getElementById("form-submit-flag");
    if (!form || !form.parentNode) return null;
    panel = document.createElement("div");
    panel.id = "code-challenge-panel";
    panel.className = "cc-panel hidden";
    form.parentNode.insertBefore(panel, form);
    return panel;
  }

  function renderPanel(panel, task, title, challengeId) {
    injectStylesheet();
    const hasLanguageChoice = task.languages.length > 1;
    panel.innerHTML = `
      <div class="cc-header">
        <h4>${escapeHtml(t("addon.code-challenge.panel_title", "Code Challenge"))}
          ${hasLanguageChoice
            ? `<select class="cc-lang-select" id="cc-lang-select" aria-label="${escapeHtml(t("addon.code-challenge.language_label", "Language"))}">
                ${task.languages.map((l) => `<option value="${escapeHtml(l)}">${escapeHtml(languageDisplayName(l))}</option>`).join("")}
              </select>`
            : `<span class="cc-lang-badge">${escapeHtml(languageDisplayName(task.language))}</span>`}
        </h4>
        ${task.instructions ? `<p class="field-note cc-instructions">${escapeHtml(task.instructions)}</p>` : ""}
      </div>
      <div class="cc-editor-host"></div>
      <div class="cc-toolbar">
        <button type="button" class="btn-primary small" id="cc-run-btn">${escapeHtml(t("addon.code-challenge.run_btn", "Run"))}</button>
        <button type="button" class="cc-reset-btn" id="cc-reset-btn">${escapeHtml(t("addon.code-challenge.reset_btn", "Reset"))}</button>
        <span class="cc-status" id="cc-status"></span>
      </div>
      <div class="cc-columns">
        <div class="cc-console">
          <h5>${escapeHtml(t("addon.code-challenge.console_title", "Console output"))}</h5>
          <pre class="cc-console-body" id="cc-console-body">${escapeHtml(t("addon.code-challenge.console_empty", "Nothing logged yet - click Run."))}</pre>
        </div>
        <div class="cc-tests" id="cc-tests"></div>
      </div>
    `;

    let currentLanguage = task.language;

    // Drafts are kept per (challenge, language) - switching the dropdown
    // doesn't lose what you'd written in the other language, and doesn't
    // show it as if it were the current one either.
    const draftKey = (lang) => `${title}::${lang}`;
    const starterFor = (lang) => {
      if (task.starter_code_by_language[lang]) return task.starter_code_by_language[lang];
      if (lang === task.language) return task.starter_code;
      if (["c", "cpp", "java"].includes(lang)) return nativeStarterCode(task, lang);
      const names = task.parameter_names || [];
      if (lang === "python") return `def ${task.function_name}(${names.join(", ") || "*args"}):\n    pass\n`;
      if (lang === "php") return `function ${task.function_name}(...$args) {\n}\n`;
      if (lang === "ruby") return `def ${task.function_name}(*args)\nend\n`;
      return `function ${task.function_name}(...args) {\n}\n`;
    };
    const draftFor = (lang) => (draftByTitle.has(draftKey(lang)) ? draftByTitle.get(draftKey(lang)) : starterFor(lang));

    const editor = new CodeEditor(panel.querySelector(".cc-editor-host"), {
      value: draftFor(currentLanguage),
      fontSize: Number(CONFIG.editor_font_size) || FALLBACK_CONFIG.editor_font_size,
      language: currentLanguage,
      onChange: (value) => draftByTitle.set(draftKey(currentLanguage), value),
    });

    const statusEl = panel.querySelector("#cc-status");
    const consoleEl = panel.querySelector("#cc-console-body");
    const testsEl = panel.querySelector("#cc-tests");
    const runBtn = panel.querySelector("#cc-run-btn");
    const resetBtn = panel.querySelector("#cc-reset-btn");
    const langSelect = panel.querySelector("#cc-lang-select");

    function renderTests(results, tests) {
      testsEl.innerHTML = `<h5>${escapeHtml(t("addon.code-challenge.tests_title", "Tests"))}</h5>` + tests
        .map((tc, i) => {
          const r = results[i];
          let state = "pending";
          let actualText = "";
          if (r) {
            if (!r.ok) {
              state = "error";
              actualText = r.error;
            } else {
              state = (r.passed === true || (r.passed === undefined && deepEqual(r.actual, tc.expect))) ? "pass" : "fail";
              actualText = JSON.stringify(r.actual);
            }
          }
          const badgeText = state === "pass"
            ? t("addon.code-challenge.test_passed", "Passed")
            : state === "fail"
              ? t("addon.code-challenge.test_failed", "Failed")
              : state === "error"
                ? t("addon.code-challenge.test_error", "Error")
                : "";
          return `
            <div class="cc-test-row cc-test-${state}">
              <span class="cc-test-badge">${state === "pending" ? "…" : escapeHtml(badgeText)}</span>
              <code class="cc-test-call">${escapeHtml(task.function_name)}(${tc.args.map((a) => JSON.stringify(a)).join(", ")})</code>
              ${r ? `<span class="cc-test-detail">${escapeHtml(t("addon.code-challenge.expected_label", "expected"))}: <code>${escapeHtml(JSON.stringify(tc.expect))}</code> · ${escapeHtml(t("addon.code-challenge.actual_label", "actual"))}: <code>${escapeHtml(actualText)}</code></span>` : ""}
            </div>`;
        })
        .join("");
    }
    renderTests([], task.tests);

    function doRun() {
      runBtn.disabled = true;
      statusEl.textContent = t("addon.code-challenge.running", "Running...");
      statusEl.className = "cc-status";

      // Every language runs through Judge0 so the exact same test cases
      // and sandbox limits apply to every submission.
      consoleEl.textContent = t("addon.code-challenge.console_server_run", "(server-side execution - no local console output)");
      window.OpenCTF.api(`/api/challenges/${challengeId}/code-run`, {
        method: "POST",
        body: JSON.stringify({ language: currentLanguage, code: editor.getValue() }),
      })
        .then((data) => {
          runBtn.disabled = false;
          finishRun(mapJudge0Results(data.results), data.all_passed ? data.flag : null);
        })
        .catch((err) => {
          runBtn.disabled = false;
          statusEl.textContent = t("addon.code-challenge.define_error", "Couldn't run your code: {error}", { error: String((err && err.message) || err) });
          statusEl.className = "cc-status cc-status-err";
          renderTests([], task.tests);
        });
    }

    function finishRun(results, completionFlag) {
      renderTests(results, task.tests);
      const passed = task.tests.filter((tc, i) => results[i] && results[i].ok && (results[i].passed === true || (results[i].passed === undefined && deepEqual(results[i].actual, tc.expect)))).length;
      const total = task.tests.length;
      if (passed === total) {
        statusEl.textContent = t("addon.code-challenge.all_passed", "All tests passed! Flag filled in below - submit when ready.");
        statusEl.className = "cc-status cc-status-ok";
        const flagInput = document.getElementById("flag-input");
        if (flagInput && typeof completionFlag === "string" && completionFlag) {
          flagInput.value = completionFlag;
          flagInput.classList.add("cc-flag-filled");
          setTimeout(() => flagInput.classList.remove("cc-flag-filled"), 1200);
        }
      } else {
        statusEl.textContent = t("addon.code-challenge.some_failed", "{passed}/{total} tests passed. Keep going.", { passed, total });
        statusEl.className = "cc-status";
      }
    }

    runBtn.addEventListener("click", doRun);
    resetBtn.addEventListener("click", () => {
      editor.setValue(starterFor(currentLanguage));
      draftByTitle.set(draftKey(currentLanguage), starterFor(currentLanguage));
      statusEl.textContent = "";
      consoleEl.textContent = t("addon.code-challenge.console_empty", "Nothing logged yet - click Run.");
      renderTests([], task.tests);
    });

    if (langSelect) {
      langSelect.value = currentLanguage;
      langSelect.addEventListener("change", () => {
        currentLanguage = langSelect.value;
        editor.setLanguage(currentLanguage);
        editor.setValue(draftFor(currentLanguage));
        statusEl.textContent = "";
        consoleEl.textContent = t("addon.code-challenge.console_empty", "Nothing logged yet - click Run.");
        renderTests([], task.tests);
      });
    }
  }

  async function refreshChallengesCache() {
    try {
      challengesCache = await window.OpenCTF.api("/api/challenges");
    } catch {
      challengesCache = challengesCache || [];
    }
  }

  function findChallenge(title, category) {
    if (!challengesCache) return null;
    const byTitle = challengesCache.filter((c) => c.title === title);
    if (byTitle.length <= 1) return byTitle[0] || null;
    return byTitle.find((c) => c.category === category) || byTitle[0];
  }

  async function onModalShown() {
    const modalTitleEl = document.getElementById("modal-title");
    const modalDescEl = document.getElementById("modal-desc");
    const modalCategoryEl = document.getElementById("modal-category");
    if (!modalTitleEl || !modalDescEl) return;

    // Only the standard challenge modal has #flag-input directly (the
    // web/ai/quiz/terminal types each open a different modal entirely -
    // see openChallenge() in client/src/renderer.js) - if it's hidden,
    // this open wasn't a standard-type challenge, so there's nothing
    // for this addon to do.
    const standardModal = document.getElementById("modal-challenge");
    if (!standardModal || standardModal.classList.contains("hidden")) return;

    await refreshChallengesCache();
    const title = modalTitleEl.textContent;
    const category = modalCategoryEl ? modalCategoryEl.textContent : "";
    const challenge = findChallenge(title, category);
    let taskData = null;
    if (challenge) {
      try {
        taskData = await window.OpenCTF.api(`/api/challenges/${challenge.id}/coding-task`);
      } catch {
        taskData = null;
      }
    }
    const task = parseTask(taskData);

    const panel = ensurePanel();
    if (!panel) return;

    if (!task) {
      panel.classList.add("hidden");
      activeTask = null;
      activeTitle = null;
      return;
    }

    if (challenge) modalDescEl.textContent = stripTask(challenge.description);
    activeTask = task;
    activeTitle = title;
    panel.classList.remove("hidden");
    renderPanel(panel, task, title, challenge.id);
  }

  function onModalHidden() {
    activeTask = null;
    activeTitle = null;
  }

  function watchModal() {
    const modal = document.getElementById("modal-challenge");
    if (!modal) {
      // Sidebar/challenges view may not be mounted yet on first "ready" -
      // retry shortly rather than silently never wiring up.
      setTimeout(watchModal, 500);
      return;
    }
    const observer = new MutationObserver(() => {
      if (modal.classList.contains("hidden")) onModalHidden();
      else onModalShown();
    });
    observer.observe(modal, { attributes: true, attributeFilter: ["class"] });
  }

  window.OpenCTF.on("ready", () => {
    loadConfig();
    refreshChallengesCache();
    watchModal();
  });
  window.OpenCTF.on("addon:config_changed", ({ id, config }) => {
    if (id !== ADDON_ID) return;
    CONFIG = { ...FALLBACK_CONFIG, ...config };
  });
})();
