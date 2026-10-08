// CTF Toolkit - pure logic (no DOM, no network). Loaded before addon.js and
// exposed as window.OpenCTFToolkitCore; also loadable in Node for tests
// (see server/tests/toolkit_core.test.js).
(function (root) {
  "use strict";

  const enc = new TextEncoder();
  const dec = new TextDecoder("utf-8", { fatal: false });

  const toBytes = (text) => enc.encode(text);
  const fromBytes = (bytes) => dec.decode(bytes);
  const bytesToHex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

  function hexToBytes(text) {
    const clean = text.replace(/0x/gi, "").replace(/\\x/gi, "").replace(/[\s:,-]/g, "");
    if (!clean.length || clean.length % 2 || /[^0-9a-f]/i.test(clean)) throw new Error("not hex");
    const out = new Uint8Array(clean.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
    return out;
  }

  // ---- Base64 / Base32 ------------------------------------------------------
  const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  function base64Encode(bytes) {
    let out = "";
    for (let i = 0; i < bytes.length; i += 3) {
      const n = (bytes[i] << 16) | ((bytes[i + 1] || 0) << 8) | (bytes[i + 2] || 0);
      out += B64[(n >> 18) & 63] + B64[(n >> 12) & 63]
        + (i + 1 < bytes.length ? B64[(n >> 6) & 63] : "=") + (i + 2 < bytes.length ? B64[n & 63] : "=");
    }
    return out;
  }
  function base64Decode(text) {
    let s = text.replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
    if (!s.length || /[^A-Za-z0-9+/=]/.test(s)) throw new Error("not base64");
    s = s.replace(/=+$/, "");
    if (s.length % 4 === 1) throw new Error("not base64");
    const out = [];
    let buffer = 0;
    let bits = 0;
    for (const ch of s) {
      buffer = (buffer << 6) | B64.indexOf(ch);
      bits += 6;
      if (bits >= 8) { bits -= 8; out.push((buffer >> bits) & 255); buffer &= (1 << bits) - 1; }
    }
    return Uint8Array.from(out);
  }

  const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  function base32Encode(bytes) {
    let out = "";
    let buffer = 0;
    let bits = 0;
    for (const b of bytes) {
      buffer = (buffer << 8) | b;
      bits += 8;
      while (bits >= 5) { bits -= 5; out += B32[(buffer >> bits) & 31]; buffer &= (1 << bits) - 1; }
    }
    if (bits) out += B32[(buffer << (5 - bits)) & 31];
    while (out.length % 8) out += "=";
    return out;
  }
  function base32Decode(text) {
    const s = text.replace(/\s+/g, "").toUpperCase().replace(/=+$/, "");
    if (!s.length || /[^A-Z2-7]/.test(s)) throw new Error("not base32");
    const out = [];
    let buffer = 0;
    let bits = 0;
    for (const ch of s) {
      buffer = (buffer << 5) | B32.indexOf(ch);
      bits += 5;
      if (bits >= 8) { bits -= 8; out.push((buffer >> bits) & 255); buffer &= (1 << bits) - 1; }
    }
    return Uint8Array.from(out);
  }

  // ---- Morse ----------------------------------------------------------------
  const MORSE = {
    A: ".-", B: "-...", C: "-.-.", D: "-..", E: ".", F: "..-.", G: "--.", H: "....", I: "..", J: ".---",
    K: "-.-", L: ".-..", M: "--", N: "-.", O: "---", P: ".--.", Q: "--.-", R: ".-.", S: "...", T: "-",
    U: "..-", V: "...-", W: ".--", X: "-..-", Y: "-.--", Z: "--..", 0: "-----", 1: ".----", 2: "..---",
    3: "...--", 4: "....-", 5: ".....", 6: "-....", 7: "--...", 8: "---..", 9: "----.",
    ".": ".-.-.-", ",": "--..--", "?": "..--..", "!": "-.-.--", "/": "-..-.", ":": "---...", "=": "-...-",
    "-": "-....-", "(": "-.--.", ")": "-.--.-", "@": ".--.-.", "'": ".----.", '"': ".-..-.", "&": ".-...", "+": ".-.-.",
  };
  const MORSE_REVERSE = Object.fromEntries(Object.entries(MORSE).map(([k, v]) => [v, k]));
  const morseEncode = (text) => text.toUpperCase().split("").map((c) => (c === " " ? "/" : MORSE[c] || "?")).join(" ");
  function morseDecode(text) {
    if (!/^[.\-/\s|_]+$/.test(text) || !/[.-]/.test(text)) throw new Error("not morse");
    return text.trim().replace(/_/g, "-").split(/\s*[/|]\s*|\s{3,}/).map((word) =>
      word.trim().split(/\s+/).map((sym) => {
        if (!(sym in MORSE_REVERSE)) throw new Error("unknown morse symbol");
        return MORSE_REVERSE[sym];
      }).join("")).join(" ");
  }

  // ---- Misc encodings ---------------------------------------------------------
  const rot = (text, shift) => text.replace(/[a-z]/gi, (c) => {
    const base = c <= "Z" ? 65 : 97;
    return String.fromCharCode(((c.charCodeAt(0) - base + shift) % 26 + 26) % 26 + base);
  });

  const ENTITY_NAMES = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: "\u00a0", copy: "\u00a9" };
  const htmlEncode = (text) => Array.from(text).map((c) => {
    if (c === "&") return "&amp;";
    if (c === "<") return "&lt;";
    if (c === ">") return "&gt;";
    if (c === '"') return "&quot;";
    if (c === "'") return "&#39;";
    return c.codePointAt(0) > 126 ? `&#${c.codePointAt(0)};` : c;
  }).join("");
  function htmlDecode(text) {
    if (!/&(#x?[0-9a-f]+|[a-z]+);/i.test(text)) throw new Error("no entities");
    return text.replace(/&(#x([0-9a-f]+)|#(\d+)|([a-z]+));/gi, (m, _all, hex, num, name) => {
      if (hex) return String.fromCodePoint(parseInt(hex, 16));
      if (num) return String.fromCodePoint(parseInt(num, 10));
      return ENTITY_NAMES[name.toLowerCase()] ?? m;
    });
  }

  function binaryDecode(text) {
    const clean = text.replace(/[\s,]/g, "");
    if (!clean.length || clean.length % 8 || /[^01]/.test(clean)) throw new Error("not binary");
    const out = new Uint8Array(clean.length / 8);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 8, 8), 2);
    return out;
  }
  function decimalDecode(text) {
    const parts = text.trim().split(/[\s,]+/);
    if (!parts.length || parts.some((p) => !/^\d{1,3}$/.test(p) || Number(p) > 255)) throw new Error("not decimal bytes");
    return Uint8Array.from(parts.map(Number));
  }

  /** id -> {encode(text)->string, decode(text)->string}. decode throws on bad input. */
  const FORMATS = {
    base64: { encode: (t) => base64Encode(toBytes(t)), decode: (t) => fromBytes(base64Decode(t)) },
    base32: { encode: (t) => base32Encode(toBytes(t)), decode: (t) => fromBytes(base32Decode(t)) },
    hex: { encode: (t) => bytesToHex(toBytes(t)), decode: (t) => fromBytes(hexToBytes(t)) },
    binary: {
      encode: (t) => Array.from(toBytes(t), (b) => b.toString(2).padStart(8, "0")).join(" "),
      decode: (t) => fromBytes(binaryDecode(t)),
    },
    decimal: { encode: (t) => Array.from(toBytes(t)).join(" "), decode: (t) => fromBytes(decimalDecode(t)) },
    url: {
      encode: (t) => encodeURIComponent(t).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`),
      decode: (t) => { if (!/%[0-9a-f]{2}/i.test(t) && !t.includes("+")) throw new Error("no escapes"); return decodeURIComponent(t.replace(/\+/g, " ")); },
    },
    rot13: { encode: (t) => rot(t, 13), decode: (t) => rot(t, 13) },
    html: { encode: htmlEncode, decode: htmlDecode },
    morse: { encode: morseEncode, decode: morseDecode },
  };

  /** Share of characters that look like readable text (0..1). */
  function printableRatio(text) {
    if (!text.length) return 0;
    let good = 0;
    for (const ch of text) {
      const c = ch.codePointAt(0);
      if ((c >= 32 && c < 127) || c === 9 || c === 10 || c === 13 || (c > 160 && c !== 0xfffd)) good++;
    }
    return good / Array.from(text).length;
  }

  /** Try every decoder, up to `depth` layers deep. Returns best candidates first. */
  function magicDecode(input, depth = 3) {
    const results = [];
    const seen = new Set([input]);
    const queue = [{ text: input, path: [] }];
    while (queue.length) {
      const { text, path } = queue.shift();
      if (path.length >= depth) continue;
      for (const [id, fmt] of Object.entries(FORMATS)) {
        let out;
        try { out = fmt.decode(text); } catch { continue; }
        if (!out || out === text || seen.has(out)) continue;
        if (printableRatio(out) < 0.85) continue;
        seen.add(out);
        const entry = { text: out, path: [...path, id] };
        results.push(entry);
        queue.push(entry);
      }
    }
    // Prefer results that look like words / flags, then shorter chains.
    const score = (r) => (/[A-Za-z]{3,}/.test(r.text) ? 1 : 0) + (/\w+\{.+\}/.test(r.text) ? 2 : 0) - r.path.length * 0.1;
    return results.sort((a, b) => score(b) - score(a)).slice(0, 10);
  }

  // ---- Classical ciphers ---------------------------------------------------------
  const ENGLISH_FREQ = [8.2, 1.5, 2.8, 4.3, 12.7, 2.2, 2.0, 6.1, 7.0, 0.15, 0.77, 4.0, 2.4, 6.7, 7.5, 1.9, 0.095, 6.0, 6.3, 9.1,
    2.8, 0.98, 2.4, 0.15, 2.0, 0.074];

  /** Lower = more English-like: chi-squared of the letter frequencies (per
   *  letter) plus a penalty for text that isn't mostly letters and spaces.
   *  Without that penalty, a wrong key that turns most bytes into punctuation
   *  leaves a handful of letters that can fit by luck and outrank the truth. */
  function englishScore(text) {
    const counts = new Array(26).fill(0);
    let letters = 0;
    let spaces = 0;
    let total = 0;
    for (const ch of text.toLowerCase()) {
      total++;
      const i = ch.charCodeAt(0) - 97;
      if (i >= 0 && i < 26) { counts[i]++; letters++; } else if (ch === " ") spaces++;
    }
    if (!letters) return Infinity;
    const chi = counts.reduce((sum, n, i) => {
      const expected = (ENGLISH_FREQ[i] / 100) * letters;
      return sum + ((n - expected) ** 2) / expected;
    }, 0) / letters;
    return chi + 40 * (1 - (letters + spaces) / total);
  }

  const caesar = (text, shift) => rot(text, shift);
  const atbash = (text) => text.replace(/[a-z]/gi, (c) => String.fromCharCode((c <= "Z" ? 155 : 219) - c.charCodeAt(0)));

  function caesarBrute(text) {
    const rows = [];
    for (let shift = 1; shift < 26; shift++) {
      const out = rot(text, -shift);
      rows.push({ shift, text: out, score: englishScore(out) });
    }
    const best = Math.min(...rows.map((r) => r.score));
    rows.forEach((r) => { r.best = r.score === best; });
    return rows;
  }

  function vigenere(text, key, decrypt) {
    const shifts = key.toLowerCase().replace(/[^a-z]/g, "").split("").map((c) => c.charCodeAt(0) - 97);
    if (!shifts.length) throw new Error("key must contain letters");
    let k = 0;
    return text.replace(/[a-z]/gi, (c) => {
      const s = shifts[k++ % shifts.length] * (decrypt ? -1 : 1);
      return rot(c, s);
    });
  }

  function xorBytes(data, key) {
    if (!key.length) throw new Error("empty key");
    return Uint8Array.from(data, (b, i) => b ^ key[i % key.length]);
  }

  /** Try all 256 single-byte keys; best printable/English results first. */
  function xorBrute(data) {
    const rows = [];
    for (let k = 0; k < 256; k++) {
      const out = fromBytes(Uint8Array.from(data, (b) => b ^ k));
      const ratio = printableRatio(out);
      if (ratio < 0.9) continue;
      rows.push({ key: k, text: out, ratio, score: englishScore(out) });
    }
    return rows.sort((a, b) => a.score - b.score).slice(0, 8);
  }

  function railPattern(length, rails) {
    const pattern = [];
    let row = 0;
    let step = 1;
    for (let i = 0; i < length; i++) {
      pattern.push(row);
      if (rails > 1) {
        if (row === 0) step = 1; else if (row === rails - 1) step = -1;
        row += step;
      }
    }
    return pattern;
  }
  function railEncode(text, rails) {
    const chars = Array.from(text);
    const pattern = railPattern(chars.length, rails);
    return Array.from({ length: rails }, (_, r) => chars.filter((_c, i) => pattern[i] === r).join("")).join("");
  }
  function railDecode(text, rails) {
    const chars = Array.from(text);
    const pattern = railPattern(chars.length, rails);
    const rows = [];
    let start = 0;
    for (let r = 0; r < rails; r++) {
      const count = pattern.filter((p) => p === r).length;
      rows.push(chars.slice(start, start + count));
      start += count;
    }
    return pattern.map((r) => rows[r].shift()).join("");
  }

  // ---- Hashing ---------------------------------------------------------------------
  function md5(bytes) {
    const K = new Uint32Array(64).map((_, i) => Math.floor(Math.abs(Math.sin(i + 1)) * 2 ** 32) >>> 0);
    const S = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21];
    const length = bytes.length;
    const padded = new Uint8Array(((length + 8) >> 6 << 6) + 64);
    padded.set(bytes);
    padded[length] = 0x80;
    const view = new DataView(padded.buffer);
    view.setUint32(padded.length - 8, (length * 8) >>> 0, true);
    view.setUint32(padded.length - 4, Math.floor((length * 8) / 2 ** 32), true);
    let a0 = 0x67452301; let b0 = 0xefcdab89; let c0 = 0x98badcfe; let d0 = 0x10325476;
    for (let off = 0; off < padded.length; off += 64) {
      const M = new Uint32Array(16).map((_, i) => view.getUint32(off + i * 4, true));
      let A = a0; let B = b0; let C = c0; let D = d0;
      for (let i = 0; i < 64; i++) {
        let F; let g;
        if (i < 16) { F = (B & C) | (~B & D); g = i; }
        else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
        else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16; }
        else { F = C ^ (B | ~D); g = (7 * i) % 16; }
        F = (F + A + K[i] + M[g]) >>> 0;
        A = D; D = C; C = B;
        const s = S[(i >> 4) * 4 + (i % 4)];
        B = (B + ((F << s) | (F >>> (32 - s)))) >>> 0;
      }
      a0 = (a0 + A) >>> 0; b0 = (b0 + B) >>> 0; c0 = (c0 + C) >>> 0; d0 = (d0 + D) >>> 0;
    }
    const out = new Uint8Array(16);
    const outView = new DataView(out.buffer);
    [a0, b0, c0, d0].forEach((v, i) => outView.setUint32(i * 4, v, true));
    return bytesToHex(out);
  }

  async function digest(algorithm, bytes) {
    const buffer = await root.crypto.subtle.digest(algorithm, bytes);
    return bytesToHex(new Uint8Array(buffer));
  }

  async function hashAll(bytes) {
    return {
      MD5: md5(bytes),
      "SHA-1": await digest("SHA-1", bytes),
      "SHA-256": await digest("SHA-256", bytes),
      "SHA-512": await digest("SHA-512", bytes),
    };
  }

  /** Best guesses for what produced a hash string. */
  function identifyHash(raw) {
    const h = raw.trim();
    const guesses = [];
    const hex = /^[0-9a-f]+$/i.test(h);
    const bylen = { 32: ["MD5", "NTLM", "MD4"], 40: ["SHA-1", "RIPEMD-160"], 56: ["SHA-224"], 64: ["SHA-256", "SHA3-256", "BLAKE2s"],
      96: ["SHA-384"], 128: ["SHA-512", "SHA3-512", "Whirlpool"] };
    if (hex && bylen[h.length]) guesses.push(...bylen[h.length]);
    if (/^\$2[abxy]\$\d\d\$[./A-Za-z0-9]{53}$/.test(h)) guesses.push("bcrypt");
    if (/^\$1\$/.test(h)) guesses.push("MD5-crypt");
    if (/^\$5\$/.test(h)) guesses.push("SHA-256-crypt");
    if (/^\$6\$/.test(h)) guesses.push("SHA-512-crypt");
    if (/^\$argon2(id|i|d)\$/.test(h)) guesses.push("Argon2");
    if (/^\$pbkdf2/.test(h) || /^pbkdf2_/.test(h)) guesses.push("PBKDF2");
    if (/^[0-9a-f]{32}:[0-9a-f]+$/i.test(h)) guesses.push("salted MD5 (hash:salt)");
    return guesses;
  }

  // ---- JWT -----------------------------------------------------------------------------
  function jwtDecode(token) {
    const parts = token.trim().split(".");
    if (parts.length !== 3) throw new Error("a JWT has three dot-separated parts");
    const parse = (part) => JSON.parse(fromBytes(base64Decode(part)));
    const header = parse(parts[0]);
    const payload = parse(parts[1]);
    const times = {};
    for (const claim of ["iat", "nbf", "exp"]) {
      if (typeof payload[claim] === "number") times[claim] = new Date(payload[claim] * 1000).toISOString();
    }
    const notes = [];
    if (String(header.alg).toLowerCase() === "none") notes.push("alg is \"none\": the token is unsigned.");
    if (/^HS/.test(header.alg)) notes.push("HMAC-signed: if the secret is weak it can be brute-forced.");
    if (header.kid) notes.push("Has a kid header - check how the server uses it.");
    return { header, payload, times, signature: parts[2], notes };
  }

  // ---- File inspection ---------------------------------------------------------------------
  const SIGNATURES = [
    ["89504E470D0A1A0A", "PNG image", 0], ["FFD8FF", "JPEG image", 0], ["474946383761", "GIF image", 0], ["474946383961", "GIF image", 0],
    ["25504446", "PDF document", 0], ["504B0304", "ZIP archive (also docx/xlsx/jar/apk)", 0], ["1F8B08", "gzip data", 0],
    ["377ABCAF271C", "7-Zip archive", 0], ["526172211A07", "RAR archive", 0], ["7F454C46", "ELF executable", 0],
    ["4D5A", "Windows PE/DOS executable", 0], ["53514C69746520666F726D6174203300", "SQLite database", 0],
    ["494433", "MP3 audio (ID3)", 0], ["424D", "BMP image", 0], ["49492A00", "TIFF image", 0], ["4D4D002A", "TIFF image", 0],
    ["4F676753", "Ogg media", 0], ["CAFEBABE", "Java class file", 0], ["FD377A585A00", "XZ archive", 0], ["425A68", "bzip2 data", 0],
    ["D4C3B2A1", "pcap capture", 0], ["A1B2C3D4", "pcap capture", 0], ["0A0D0D0A", "pcapng capture", 0],
    ["7573746172", "tar archive", 257], ["664C6143", "FLAC audio", 0], ["52494646", "RIFF container (WAV/AVI/WebP)", 0],
    ["667479", "MP4/MOV video (ftyp)", 4], ["1A45DFA3", "Matroska/WebM video", 0], ["23212F", "script (#! shebang)", 0],
  ].map(([hex, label, offset]) => ({ bytes: hexToBytes(hex), label, offset }));

  const matchesAt = (data, sig, at) => sig.length + at <= data.length && sig.every((b, i) => data[at + i] === b);

  function detectType(data) {
    for (const s of SIGNATURES) if (matchesAt(data, s.bytes, s.offset)) return s.label;
    return null;
  }

  /** Other known signatures appearing deeper in the file (binwalk-lite). */
  function findEmbedded(data, limit = 20) {
    const targets = SIGNATURES.filter((s) => s.offset === 0 && s.bytes.length >= 3 && s.label !== "script (#! shebang)"
      && s.label !== "MP3 audio (ID3)" && s.label !== "BMP image" && s.label !== "RIFF container (WAV/AVI/WebP)");
    const found = [];
    for (let i = 1; i < data.length && found.length < limit; i++) {
      for (const s of targets) {
        if (data[i] === s.bytes[0] && matchesAt(data, s.bytes, i)) { found.push({ offset: i, label: s.label }); break; }
      }
    }
    return found;
  }

  /** Bytes after the real end of a PNG/JPEG (a classic place to hide data). */
  function trailingData(data) {
    if (matchesAt(data, SIGNATURES[0].bytes, 0)) {
      for (let i = 8; i + 8 <= data.length; i++) {
        if (data[i] === 0x49 && data[i + 1] === 0x45 && data[i + 2] === 0x4e && data[i + 3] === 0x44) {
          const end = i + 8; // IEND + CRC
          return { kind: "PNG", end, extra: Math.max(0, data.length - end) };
        }
      }
    }
    if (matchesAt(data, [0xff, 0xd8, 0xff], 0)) {
      for (let i = data.length - 2; i > 2; i--) {
        if (data[i] === 0xff && data[i + 1] === 0xd9) return { kind: "JPEG", end: i + 2, extra: data.length - (i + 2) };
      }
    }
    return null;
  }

  function hexDump(data, length = 256) {
    const lines = [];
    for (let off = 0; off < Math.min(length, data.length); off += 16) {
      const chunk = data.slice(off, off + 16);
      const hex = Array.from(chunk, (b) => b.toString(16).padStart(2, "0")).join(" ").padEnd(47, " ");
      const ascii = Array.from(chunk, (b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : ".")).join("");
      lines.push(`${off.toString(16).padStart(8, "0")}  ${hex}  ${ascii}`);
    }
    return lines.join("\n");
  }

  function extractStrings(data, minLength = 6, limit = 300) {
    const out = [];
    let run = "";
    for (let i = 0; i <= data.length; i++) {
      const b = data[i];
      if (b >= 32 && b < 127) { run += String.fromCharCode(b); continue; }
      if (run.length >= minLength) { out.push(run); if (out.length >= limit) break; }
      run = "";
    }
    return out;
  }

  // ---- Frequency analysis -----------------------------------------------------------------------
  function frequency(text) {
    const counts = new Array(26).fill(0);
    let letters = 0;
    for (const ch of text.toLowerCase()) {
      const i = ch.charCodeAt(0) - 97;
      if (i >= 0 && i < 26) { counts[i]++; letters++; }
    }
    const ioc = letters > 1 ? counts.reduce((s, n) => s + n * (n - 1), 0) / (letters * (letters - 1)) : 0;
    return { counts, letters, ioc };
  }

  const core = {
    toBytes, fromBytes, bytesToHex, hexToBytes, base64Encode, base64Decode, base32Encode, base32Decode,
    FORMATS, printableRatio, magicDecode, englishScore, caesar, atbash, caesarBrute, vigenere, xorBytes, xorBrute,
    railEncode, railDecode, md5, hashAll, identifyHash, jwtDecode, detectType, findEmbedded, trailingData, hexDump,
    extractStrings, frequency, rot, morseEncode, morseDecode,
  };
  root.OpenCTFToolkitCore = core;
  if (typeof module !== "undefined" && module.exports) module.exports = core;
})(typeof window !== "undefined" ? window : globalThis);
