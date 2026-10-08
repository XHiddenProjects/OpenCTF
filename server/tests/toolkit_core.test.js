// Tests for the CTF Toolkit addon's pure logic.   node tests/toolkit_core.test.js
const assert = require("assert");
const nodeCrypto = require("crypto");
const path = require("path");
const core = require(path.join(__dirname, "..", "addons", "ctf-toolkit", "core.js"));
let passed = 0;
const test = async (name, fn) => { try { await fn(); passed++; console.log("ok   " + name); } catch (e) { console.log("FAIL " + name + "\n     " + e.message); process.exitCode = 1; } };
const rnd = (n) => Uint8Array.from(nodeCrypto.randomBytes(n));

(async () => {
  await test("md5 matches Node crypto for every length 0..200 (padding boundaries)", () => {
    for (let n = 0; n <= 200; n++) { const d = rnd(n); assert.strictEqual(core.md5(d), nodeCrypto.createHash("md5").update(d).digest("hex"), "len " + n); }
  });
  await test("md5 known vectors", () => {
    assert.strictEqual(core.md5(core.toBytes("")), "d41d8cd98f00b204e9800998ecf8427e");
    assert.strictEqual(core.md5(core.toBytes("hello")), "5d41402abc4b2a76b9719d911017c592");
    assert.strictEqual(core.md5(core.toBytes("password")), "5f4dcc3b5aa765d61d8327deb882cf99");
  });
  await test("SHA-1/256/512 match Node crypto", async () => {
    const d = rnd(1000), h = await core.hashAll(d);
    for (const [k, a] of [["SHA-1", "sha1"], ["SHA-256", "sha256"], ["SHA-512", "sha512"]]) assert.strictEqual(h[k], nodeCrypto.createHash(a).update(d).digest("hex"));
  });
  await test("base64 matches Buffer both ways, incl. url-safe and missing padding", () => {
    for (let n = 1; n < 60; n++) { const d = rnd(n); const b = Buffer.from(d).toString("base64"); assert.strictEqual(core.base64Encode(d), b); assert.deepStrictEqual(Array.from(core.base64Decode(b)), Array.from(d)); }
    assert.strictEqual(core.fromBytes(core.base64Decode("aGVsbG8")), "hello");
    assert.strictEqual(core.fromBytes(core.base64Decode("a-_a")).length > 0, true);
    assert.throws(() => core.base64Decode("not base64!"));
  });
  await test("base32 RFC 4648 vectors + roundtrip", () => {
    assert.strictEqual(core.base32Encode(core.toBytes("foobar")), "MZXW6YTBOI======");
    assert.strictEqual(core.fromBytes(core.base32Decode("MZXW6YTBOI======")), "foobar");
    for (let n = 0; n < 40; n++) { const d = rnd(n); assert.deepStrictEqual(Array.from(core.base32Decode(core.base32Encode(d) || "AA")), n ? Array.from(d) : [0]); }
  });
  await test("every format round-trips text (incl. unicode)", () => {
    for (const [id, f] of Object.entries(core.FORMATS)) {
      const sample = id === "morse" ? "HELLO WORLD 123" : id === "html" ? "a<b>&\"c\" é€" : "Hello, World! é€ 123";
      assert.strictEqual(f.decode(f.encode(sample)).toLowerCase(), sample.toLowerCase(), id);
    }
  });
  await test("hex decoder accepts 0x / \\x / spaces and rejects junk", () => {
    assert.strictEqual(core.fromBytes(core.hexToBytes("0x48 0x69")), "Hi");
    assert.strictEqual(core.fromBytes(core.hexToBytes("\\x48\\x69")), "Hi");
    assert.throws(() => core.hexToBytes("abc")); assert.throws(() => core.hexToBytes("zz"));
  });
  await test("caesar / rot13 / atbash", () => {
    assert.strictEqual(core.caesar("Hello, World!", 3), "Khoor, Zruog!");
    assert.strictEqual(core.caesar("Khoor, Zruog!", -3), "Hello, World!");
    assert.strictEqual(core.rot("Uryyb", 13), "Hello");
    assert.strictEqual(core.atbash("Hello"), "Svool"); assert.strictEqual(core.atbash(core.atbash("Round Trip!")), "Round Trip!");
  });
  await test("caesar brute force ranks the true plaintext first", () => {
    const plain = "The quick brown fox jumps over the lazy dog and keeps running through the forest";
    const rows = core.caesarBrute(core.caesar(plain, 11));
    assert.strictEqual(rows.find((r) => r.best).text, plain); assert.strictEqual(rows.find((r) => r.best).shift, 11);
  });
  await test("vigenere textbook vector", () => {
    assert.strictEqual(core.vigenere("ATTACKATDAWN", "LEMON", false), "LXFOPVEFRNHR");
    assert.strictEqual(core.vigenere("LXFOPVEFRNHR", "LEMON", true), "ATTACKATDAWN");
    assert.strictEqual(core.vigenere("Attack at dawn!", "Lemon", true).length, 15);
    assert.throws(() => core.vigenere("x", "123", false));
  });
  await test("rail fence textbook vector + roundtrip for many shapes", () => {
    assert.strictEqual(core.railEncode("WEAREDISCOVEREDFLEEATONCE", 3), "WECRLTEERDSOEEFEAOCAIVDEN");
    for (const rails of [2, 3, 4, 5]) for (const t of ["A", "AB", "HELLO WORLD", "The quick brown fox!"]) assert.strictEqual(core.railDecode(core.railEncode(t, rails), rails), t, `${rails}/${t}`);
  });
  await test("single-byte xor brute force recovers key", () => {
    const plain = core.toBytes("Meet me at the old bridge at midnight, bring the documents"); const key = 0x5a;
    const best = core.xorBrute(core.xorBytes(plain, [key]))[0]; assert.strictEqual(best.key, key); assert.strictEqual(best.text, core.fromBytes(plain));
    assert.deepStrictEqual(Array.from(core.xorBytes(core.xorBytes(plain, [1, 2, 3]), [1, 2, 3])), Array.from(plain));
  });
  await test("magic decode unwraps base64(hex(text)) and finds the flag", () => {
    const flag = "OCTF{0123456789abcdef0123456789abcdef}";
    const layered = core.FORMATS.base64.encode(core.FORMATS.hex.encode(flag));
    const top = core.magicDecode(layered)[0]; assert.strictEqual(top.text, flag); assert.deepStrictEqual(top.path, ["base64", "hex"]);
  });
  await test("magic decode does not invent output for plain text", () => {
    assert.deepStrictEqual(core.magicDecode("just some ordinary words here, nothing encoded").map((r) => r.text).filter((t) => /ordinary/.test(t)), []);
  });
  await test("morse decode handles word gaps", () => { assert.strictEqual(core.morseDecode("... --- ... / .-- .. -.."), "SOS WID"); assert.throws(() => core.morseDecode("hello")); });
  await test("hash identification", () => {
    assert.ok(core.identifyHash("5f4dcc3b5aa765d61d8327deb882cf99").includes("MD5"));
    assert.ok(core.identifyHash("a".repeat(40)).includes("SHA-1")); assert.ok(core.identifyHash("a".repeat(64)).includes("SHA-256"));
    assert.deepStrictEqual(core.identifyHash("$2b$12$" + "a".repeat(53)), ["bcrypt"]); assert.deepStrictEqual(core.identifyHash("not a hash"), []);
  });
  await test("jwt decode (header, payload, times, notes)", () => {
    const b64u = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
    const t = `${b64u({ alg: "none", typ: "JWT" })}.${b64u({ sub: "admin", exp: 1893456000 })}.`;
    const r = core.jwtDecode(t); assert.strictEqual(r.payload.sub, "admin"); assert.strictEqual(r.times.exp, "2030-01-01T00:00:00.000Z"); assert.ok(r.notes[0].includes("none"));
    assert.throws(() => core.jwtDecode("only.two"));
  });
  await test("file type detection, embedded files and trailing data", () => {
    const png = Buffer.concat([Buffer.from("89504E470D0A1A0A", "hex"), Buffer.from("0000000D49484452", "hex"), Buffer.alloc(13), Buffer.from("0000000049454E44AE426082", "hex")]);
    assert.strictEqual(core.detectType(Uint8Array.from(png)), "PNG image");
    assert.deepStrictEqual(core.trailingData(Uint8Array.from(png)), { kind: "PNG", end: png.length, extra: 0 });
    const withZip = Buffer.concat([png, Buffer.from("PK\x03\x04hidden-archive-bytes", "binary")]);
    assert.strictEqual(core.trailingData(Uint8Array.from(withZip)).extra, 4 + 20);
    const emb = core.findEmbedded(Uint8Array.from(withZip)); assert.ok(emb.some((e) => e.offset === png.length && /ZIP/.test(e.label)), JSON.stringify(emb));
    assert.strictEqual(core.detectType(Uint8Array.from(Buffer.from("hello world"))), null);
    assert.strictEqual(core.detectType(Uint8Array.from(Buffer.concat([Buffer.alloc(4), Buffer.from("ftypisom")]))), "MP4/MOV video (ftyp)");
  });
  await test("hex dump and strings extraction", () => {
    const d = Uint8Array.from(Buffer.from("Hello\x00\x01secret_value\xff\xfeab"));
    assert.ok(core.hexDump(d).startsWith("00000000  48 65 6c 6c 6f 00 01 73")); assert.deepStrictEqual(core.extractStrings(d, 5), ["Hello", "secret_value"]);
  });
  await test("frequency analysis and index of coincidence", () => {
    const f = core.frequency("Hello World"); assert.strictEqual(f.letters, 10); assert.strictEqual(f.counts[11], 3);
    const english = core.frequency("it was the best of times it was the worst of times it was the age of wisdom"); assert.ok(english.ioc > 0.055 && english.ioc < 0.09, "ioc " + english.ioc);
  });
  console.log(`\n${passed} passed${process.exitCode ? ", SOME FAILED" : ""}`);
})();
