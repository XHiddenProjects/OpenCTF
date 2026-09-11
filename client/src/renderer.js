let SERVER_URL = "";
let TOKEN = null;
let ME = { username: null, team: null, is_admin: false, display_name: null, bio: "", avatar: "🛡️" };
let CHALLENGES = [];
let ACTIVE_CHALLENGE = null;

// terminal state for the currently open terminal challenge
let TERMINAL_CWD = "/";
let TERMINAL_CHALLENGE = null;
let AI_CHALLENGE = null;
let AI_MESSAGES = [];
let AI_RECOGNITION = null;
let TARGET_HISTORY = [];
let TARGET_HISTORY_INDEX = -1;
let TARGET_NAVIGATING = false;

// admin state
let ADMIN_CHALLENGES = [];
let ADMIN_USERS = [];
let EDITING_CHALLENGE_ID = null;

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

async function api(path, options = {}) {
  const res = await fetch(SERVER_URL + path, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(TOKEN ? { Authorization: `Bearer ${TOKEN}` } : {}),
      ...(options.headers || {}),
    },
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error || `request failed (${res.status})`);
  return body;
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

async function init() {
  const config = await window.ctfConfig.get();
  SERVER_URL = config.serverUrl;
  $("#settings-url").value = SERVER_URL;
  wireEvents();
}

function wireEvents() {
  // Auth tabs
  $$(".tab-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      $$(".tab-btn").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      const tab = btn.dataset.tab;
      $("#form-login").classList.toggle("hidden", tab !== "login");
      $("#form-register").classList.toggle("hidden", tab !== "register");
    });
  });

  $("#form-login").addEventListener("submit", onLogin);
  $("#form-register").addEventListener("submit", onRegister);
  $("#logout").addEventListener("click", onLogout);

  // Nav
  $$(".nav-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      $$(".nav-btn").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      const view = btn.dataset.view;
      $$(".view").forEach((v) => v.classList.add("hidden"));
      $(`#view-${view}`).classList.remove("hidden");
      if (view === "scoreboard") loadScoreboard();
      if (view === "profile") loadProfileForm();
      if (view === "admin") loadAdmin();
    });
  });

  $("#refresh-challenges").addEventListener("click", loadChallenges);
  $("#refresh-scoreboard").addEventListener("click", loadScoreboard);

  // Challenge modal (standard)
  $("#modal-close").addEventListener("click", () => $("#modal-challenge").classList.add("hidden"));
  $("#form-submit-flag").addEventListener("submit", onSubmitFlag);

  // Terminal challenge modal
  $("#terminal-close").addEventListener("click", () => $("#modal-terminal").classList.add("hidden"));
  $("#form-terminal-cmd").addEventListener("submit", onTerminalCommand);
  $("#form-submit-flag-terminal").addEventListener("submit", onSubmitFlagTerminal);
  $("#ai-close").addEventListener("click", () => $("#modal-ai").classList.add("hidden"));
  $("#form-ai-chat").addEventListener("submit", onAiChatSubmit);
  $("#form-submit-flag-ai").addEventListener("submit", onSubmitFlagAi);
  $("#ai-mic").addEventListener("click", startAiSpeechInput);

  // Quiz challenge modal
  $("#quiz-close").addEventListener("click", () => $("#modal-quiz").classList.add("hidden"));
  $("#form-submit-flag-quiz").addEventListener("submit", onSubmitFlagQuiz);

  // Settings modal
  $("#open-settings").addEventListener("click", () => $("#modal-settings").classList.remove("hidden"));
  $("#open-settings-2").addEventListener("click", () => $("#modal-settings").classList.remove("hidden"));
  $("#settings-close").addEventListener("click", () => $("#modal-settings").classList.add("hidden"));
  $("#settings-save").addEventListener("click", onSaveSettings);

  // Profile view
  $("#form-profile").addEventListener("submit", onSaveProfile);
  $("#form-password").addEventListener("submit", onChangePassword);
  $("#reset-progress").addEventListener("click", onResetProgress);
  $$("[data-web-tab]").forEach((btn) => {
    btn.addEventListener("click", () => switchWebTab(btn.dataset.webTab));
  });
  $("#web-back").addEventListener("click", () => postTargetNavigation("back"));
  $("#web-forward").addEventListener("click", () => postTargetNavigation("forward"));
  $("#web-reload").addEventListener("click", () => postTargetNavigation("reload"));
  $("#form-web-address").addEventListener("submit", onTargetAddressSubmit);
  window.addEventListener("message", onTargetMessage);

  // Admin: tab switching
  $$(".admin-tab-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      $$(".admin-tab-btn").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      const tab = btn.dataset.adminTab;
      $$(".admin-tab").forEach((t) => t.classList.add("hidden"));
      $(`#admin-tab-${tab}`).classList.remove("hidden");
    });
  });

  // Admin: challenge form
  $("#new-challenge-btn").addEventListener("click", () => openChallengeForm(null));
  $("#challenge-form-close").addEventListener("click", () => $("#modal-challenge-form").classList.add("hidden"));
  $("#cf-type").addEventListener("change", (e) => {
    $("#cf-terminal-fs-wrap").classList.toggle("hidden", e.target.value !== "terminal");
    $("#cf-web-wrap").classList.toggle("hidden", e.target.value !== "web");
    $("#cf-ai-wrap").classList.toggle("hidden", e.target.value !== "ai");
    $("#cf-quiz-wrap").classList.toggle("hidden", e.target.value !== "quiz");
  });
  $("#cf-preset").addEventListener("change", (e) => applyChallengePreset(e.target.value));
  $("#cf-difficulty").addEventListener("change", updatePointsForDifficulty);
  $("#form-challenge").addEventListener("submit", onSaveChallenge);
  $("#cf-delete").addEventListener("click", onDeleteChallenge);
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

async function onLogin(e) {
  e.preventDefault();
  $("#login-error").textContent = "";
  try {
    const body = await api("/api/login", {
      method: "POST",
      body: JSON.stringify({
        username: $("#login-username").value,
        password: $("#login-password").value,
      }),
    });
    onAuthed(body);
  } catch (err) {
    $("#login-error").textContent = err.message;
  }
}

async function onRegister(e) {
  e.preventDefault();
  $("#register-error").textContent = "";
  try {
    const body = await api("/api/register", {
      method: "POST",
      body: JSON.stringify({
        username: $("#reg-username").value,
        team_name: $("#reg-team").value,
        password: $("#reg-password").value,
      }),
    });
    onAuthed(body);
  } catch (err) {
    $("#register-error").textContent = err.message;
  }
}

async function onAuthed(body) {
  TOKEN = body.token;
  ME = { username: body.username, team: body.team, is_admin: !!body.is_admin };
  $("#screen-auth").classList.add("hidden");
  $("#screen-main").classList.remove("hidden");
  $("#nav-admin").classList.toggle("hidden", !ME.is_admin);

  // pull full profile (avatar, display name, bio) now that we have a token
  try {
    const profile = await api("/api/me");
    ME = { ...ME, ...profile };
  } catch {
    /* non-fatal - sidebar just shows defaults */
  }
  $("#who-team").textContent = ME.team || "no team";
  $("#who-user").textContent = ME.display_name || ME.username;
  $("#who-avatar").textContent = ME.avatar || "🛡️";

  loadChallenges();
}

function onLogout() {
  TOKEN = null;
  ME = { username: null, team: null, is_admin: false, display_name: null, bio: "", avatar: "🛡️" };
  $("#nav-admin").classList.add("hidden");
  $("#screen-main").classList.add("hidden");
  $("#screen-auth").classList.remove("hidden");
  // reset to the challenges tab for next login
  $$(".nav-btn").forEach((b) => b.classList.remove("active"));
  $('.nav-btn[data-view="challenges"]').classList.add("active");
  $$(".view").forEach((v) => v.classList.add("hidden"));
  $("#view-challenges").classList.remove("hidden");
}

// ---------------------------------------------------------------------------
// Challenges
// ---------------------------------------------------------------------------

async function loadChallenges() {
  const list = $("#challenge-list");
  list.innerHTML = `<p style="color:var(--text-dim)">Loading…</p>`;
  try {
    CHALLENGES = await api("/api/challenges");
    renderChallenges();
  } catch (err) {
    list.innerHTML = `<p class="form-error">${err.message}</p>`;
  }
}

function renderChallenges() {
  const list = $("#challenge-list");
  list.innerHTML = "";
  CHALLENGES.forEach((c) => {
    const card = document.createElement("div");
    card.className = "challenge-card" + (c.solved ? " solved" : "");
    card.innerHTML = `
      <p class="card-category">${c.category}${c.type === "terminal" ? " · &gt;_ interactive" : c.type === "web" ? " · &lt;/&gt; sandbox" : c.type === "ai" ? " · \u{1F5E3}\uFE0F conversation" : c.type === "quiz" ? " · \u2753 quiz" : ""}</p>
      <p class="card-title">${c.title}</p>
      <p class="card-points">${c.points} pts</p>
      ${c.solved ? `<p class="card-solved-tag">✓ solved</p>` : ""}
    `;
    card.addEventListener("click", () => openChallenge(c));
    list.appendChild(card);
  });
}

function openChallenge(c) {
  if (c.type === "terminal") {
    openTerminalChallenge(c);
    return;
  }
  if (c.type === "web") {
    openWebChallenge(c);
    return;
  }
  if (c.type === "ai") {
    openAiChallenge(c);
    return;
  }
  if (c.type === "quiz") {
    openQuizChallenge(c);
    return;
  }
  $("#web-tabs").classList.add("hidden");
  $("#web-site-pane").classList.add("hidden");
  $("#web-brief-pane").classList.remove("hidden");
  ACTIVE_CHALLENGE = c;
  $("#modal-category").textContent = c.category;
  $("#modal-title").textContent = c.title;
  $("#modal-desc").textContent = c.description;
  $("#modal-meta").textContent = `${c.difficulty || "medium"} difficulty`;
    $("#modal-meta").textContent = `${c.difficulty || "medium"} difficulty`;
  $("#modal-rules-wrap").classList.toggle("hidden", !c.rules);
  $("#modal-rules").textContent = c.rules || "";
  $("#modal-result").textContent = "";
  $("#modal-result").className = "modal-result";
  $("#flag-input").value = "";

  const hintWrap = $("#modal-hint-wrap");
  if (c.hint) {
    hintWrap.classList.remove("hidden");
    $("#modal-hint").textContent = c.hint;
  } else {
    hintWrap.classList.add("hidden");
  }

  $("#modal-challenge").classList.remove("hidden");
}

function openAiChallenge(c) {
  AI_CHALLENGE = c;
  AI_MESSAGES = [];
  $("#ai-category").textContent = c.category;
  $("#ai-title").textContent = c.title;
  $("#ai-points").textContent = `${c.points} points`;
    $("#ai-status").textContent = `${c.difficulty || "medium"} conversation`;
  $("#ai-result").textContent = c.description;
  $("#ai-result").className = "modal-result";
  $("#ai-input").value = "";
  $("#ai-flag-input").value = "";
  $("#form-submit-flag-ai").classList.remove("hidden");
  renderAiTranscript();
  $("#modal-ai").classList.remove("hidden");
  $("#ai-input").focus();
}

function renderAiTranscript() {
  const transcript = $("#ai-transcript");
  transcript.innerHTML = AI_MESSAGES.length
    ? AI_MESSAGES.map((message) => `<div class="ai-message ${message.role}"><span>${message.role === "user" ? "You" : "Persona"}</span><p>${escapeHtml(message.content)}</p></div>`).join("")
    : `<p class="ai-empty">The persona is waiting. Try a convincing request, not just a demand.</p>`;
  transcript.scrollTop = transcript.scrollHeight;
}

function escapeHtml(value) {
  return value.replace(/[&<>'"]/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" }[character]));
}

async function onAiChatSubmit(event) {
  event.preventDefault();
  const input = $("#ai-input");
  const content = input.value.trim();
  if (!content || !AI_CHALLENGE) return;
  AI_MESSAGES.push({ role: "user", content });
  input.value = "";
  renderAiTranscript();
  $("#ai-result").textContent = "The persona is thinking...";
  try {
    const body = await api(`/api/challenges/${AI_CHALLENGE.id}/ai`, {
      method: "POST",
      body: JSON.stringify({ messages: AI_MESSAGES }),
    });
    AI_MESSAGES.push({ role: "assistant", content: body.reply });
    renderAiTranscript();
    if (body.speak && "speechSynthesis" in window) {
      window.speechSynthesis.cancel();
      const speech = new SpeechSynthesisUtterance(body.reply);
      const voiceConfig = body.voice || {};
      speech.lang = voiceConfig.language || "en-US";
      const voiceStyles = {
        neutral: { pitch: 1, rate: 1 },
        warm: { pitch: 1.08, rate: 0.96 },
        authoritative: { pitch: 0.88, rate: 0.92 },
        calm: { pitch: 0.96, rate: 0.82 },
      };
      const style = voiceStyles[voiceConfig.style] || voiceStyles.neutral;
      speech.pitch = Math.min(2, Math.max(0.5, (Number(voiceConfig.pitch) || 1) * style.pitch));
      speech.rate = Math.min(2, Math.max(0.5, (Number(voiceConfig.rate) || 1) * style.rate));
      const voices = window.speechSynthesis.getVoices();
      const preferredVoice = voices.find((voice) => voice.lang.toLowerCase().startsWith(speech.lang.toLowerCase()));
      if (preferredVoice) speech.voice = preferredVoice;
      window.speechSynthesis.speak(speech);
    }
      if (body.solved && body.flag) {
        $("#ai-result").textContent = `The persona disclosed your team's flag and encoded ID: ${body.flag}`;
      $("#ai-result").className = "modal-result ok";
        $("#ai-flag-input").value = "";
        $("#form-submit-flag-ai").classList.remove("hidden");
    } else {
      $("#ai-result").textContent = "Keep working the conversation.";
    }
  } catch (err) {
    $("#ai-result").textContent = err.message;
    $("#ai-result").className = "modal-result err";
  }
}

async function onSubmitFlagAi(event) {
  event.preventDefault();
  const result = $("#ai-result");
  try {
    const body = await api("/api/submit", {
      method: "POST",
      body: JSON.stringify({
        challenge_id: AI_CHALLENGE.id,
        flag: $("#ai-flag-input").value,
      }),
    });
    result.textContent = body.correct ? "Correct! Challenge solved." : "Incorrect flag.";
    result.className = `modal-result ${body.correct ? "ok" : "err"}`;
    if (body.correct) await loadChallenges();
  } catch (err) {
    result.textContent = err.message;
    result.className = "modal-result err";
  }
}

function startAiSpeechInput() {
  const Recognition = window.SpeechRecognition || window.webkitSpeechRecognition;
  if (!Recognition) {
    $("#ai-result").textContent = "Speech input is not available here. Type your message instead.";
    $("#ai-result").className = "modal-result err";
    return;
  }
  if (AI_RECOGNITION) AI_RECOGNITION.stop();
  AI_RECOGNITION = new Recognition();
  AI_RECOGNITION.lang = "en-US";
  AI_RECOGNITION.interimResults = false;
  AI_RECOGNITION.onresult = (event) => {
    $("#ai-input").value = event.results[0][0].transcript;
    $("#ai-input").focus();
  };
  AI_RECOGNITION.onerror = () => {
    $("#ai-result").textContent = "Microphone input was unavailable. Type your message instead.";
  };
  AI_RECOGNITION.start();
}

let QUIZ_CHALLENGE = null;

function openQuizChallenge(c) {
  QUIZ_CHALLENGE = c;
  $("#quiz-category").textContent = c.category;
  $("#quiz-title").textContent = c.title;
  $("#quiz-points").textContent = `${c.points} points`;
  $("#quiz-desc").textContent = c.description;
  const hintWrap = $("#quiz-hint-wrap");
  if (c.hint) {
    hintWrap.classList.remove("hidden");
    $("#quiz-hint").textContent = c.hint;
  } else {
    hintWrap.classList.add("hidden");
  }
  $("#quiz-question").textContent = c.quiz_question || "";
  $("#quiz-flag-input").value = "";
  $("#form-submit-flag-quiz").classList.add("hidden");
  $("#quiz-result").textContent = c.solved ? "Already solved by your team." : "";
  $("#quiz-result").className = c.solved ? "modal-result ok" : "modal-result";

  const optionsWrap = $("#quiz-options");
  optionsWrap.innerHTML = "";
  (c.quiz_options || []).forEach((optionText, index) => {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "quiz-option";
    btn.textContent = optionText;
    btn.disabled = !!c.solved;
    btn.addEventListener("click", () => onQuizOptionPicked(index, optionsWrap));
    optionsWrap.appendChild(btn);
  });

  $("#modal-quiz").classList.remove("hidden");
}

async function onQuizOptionPicked(selectedIndex, optionsWrap) {
  const buttons = Array.from(optionsWrap.children);
  buttons.forEach((btn) => (btn.disabled = true));
  const result = $("#quiz-result");
  result.textContent = "Checking...";
  result.className = "modal-result";
  try {
    const body = await api(`/api/challenges/${QUIZ_CHALLENGE.id}/quiz`, {
      method: "POST",
      body: JSON.stringify({ selected_index: selectedIndex }),
    });
    buttons[selectedIndex].classList.add(body.correct ? "correct" : "incorrect");
    if (body.correct && body.flag) {
      result.textContent = "Correct! Submit the flag below to score it.";
      result.className = "modal-result ok";
      $("#quiz-flag-input").value = body.flag;
      $("#form-submit-flag-quiz").classList.remove("hidden");
    } else {
      result.textContent = "Not quite - take another look and try again.";
      result.className = "modal-result err";
      buttons.forEach((btn) => (btn.disabled = false));
    }
  } catch (err) {
    result.textContent = err.message;
    result.className = "modal-result err";
    buttons.forEach((btn) => (btn.disabled = false));
  }
}

async function onSubmitFlagQuiz(event) {
  event.preventDefault();
  const result = $("#quiz-result");
  try {
    const body = await api("/api/submit", {
      method: "POST",
      body: JSON.stringify({
        challenge_id: QUIZ_CHALLENGE.id,
        flag: $("#quiz-flag-input").value,
      }),
    });
    result.textContent = body.correct ? "Correct! Challenge solved." : "Incorrect flag.";
    result.className = `modal-result ${body.correct ? "ok" : "err"}`;
    if (body.correct) await loadChallenges();
  } catch (err) {
    result.textContent = err.message;
    result.className = "modal-result err";
  }
}

async function onSubmitFlag(e) {
  e.preventDefault();
  const result = $("#modal-result");
  try {
    const body = await api("/api/submit", {
      method: "POST",
      body: JSON.stringify({
        challenge_id: ACTIVE_CHALLENGE.id,
        flag: $("#flag-input").value,
      }),
    });
    if (body.correct) {
      result.textContent = "Correct! Challenge solved.";
      result.className = "modal-result ok";
      await loadChallenges();
    } else {
      result.textContent = "Incorrect flag, try again.";
      result.className = "modal-result err";
    }
  } catch (err) {
    result.textContent = err.message;
    result.className = "modal-result err";
  }
}

function switchWebTab(tab) {
  const site = tab === "site";
  $("#web-brief-pane").classList.toggle("hidden", site);
  $("#web-site-pane").classList.toggle("hidden", !site);
  $$("[data-web-tab]").forEach((btn) => btn.classList.toggle("active", btn.dataset.webTab === tab));
}

async function openWebChallenge(c) {
  ACTIVE_CHALLENGE = c;
  $("#modal-category").textContent = c.category;
  $("#modal-title").textContent = c.title;
  $("#modal-desc").textContent = c.description;
  $("#modal-meta").textContent = `${c.difficulty || "medium"} difficulty`;
  $("#modal-points").textContent = `${c.points} points`;
  $("#modal-rules-wrap").classList.toggle("hidden", !c.rules);
  $("#modal-rules").textContent = c.rules || "";
  $("#web-tabs").classList.remove("hidden");
  switchWebTab("brief");
  $("#modal-result").textContent = "";
  const hintWrap = $("#modal-hint-wrap");
  hintWrap.classList.toggle("hidden", !c.hint);
  if (c.hint) $("#modal-hint").textContent = c.hint;
  $("#modal-challenge").classList.remove("hidden");
  const targetUrl = c.target_url || `${SERVER_URL.replace(/:\d+$/, ":5001")}/target/${c.id}/`;
  const freshTargetUrl = new URL(targetUrl);
  freshTargetUrl.searchParams.set("_ctf_refresh", Date.now().toString());
  TARGET_HISTORY = [new URL(targetUrl).pathname];
  TARGET_HISTORY_INDEX = 0;
  TARGET_NAVIGATING = true;
  $("#web-address").value = TARGET_HISTORY[0];
  $("#web-target-frame").src = freshTargetUrl.toString();
}

function postTargetNavigation(action) {
  if (action === "reload") {
    $("#web-target-frame").contentWindow?.location.reload();
    return;
  }
  const nextIndex = TARGET_HISTORY_INDEX + (action === "back" ? -1 : 1);
  if (nextIndex < 0 || nextIndex >= TARGET_HISTORY.length) return;
  TARGET_HISTORY_INDEX = nextIndex;
  TARGET_NAVIGATING = true;
  navigateTargetPath(TARGET_HISTORY[TARGET_HISTORY_INDEX]);
}

function onTargetMessage(event) {
  if (!event.data || event.data.type !== "target-location") return;
  const path = event.data.path || "/";
  if (!TARGET_NAVIGATING) {
    TARGET_HISTORY = TARGET_HISTORY.slice(0, TARGET_HISTORY_INDEX + 1);
    TARGET_HISTORY.push(path);
    TARGET_HISTORY_INDEX += 1;
  }
  TARGET_NAVIGATING = false;
  $("#web-address").value = path;
}

function onTargetAddressSubmit(event) {
  event.preventDefault();
  let path = $("#web-address").value.trim();
  if (!path.startsWith("/")) path = `/${path}`;
  if (!ACTIVE_CHALLENGE || !/^\/target\/\d+(\/|$)/.test(path)) {
    path = `/target/${ACTIVE_CHALLENGE.id}/`;
  }
  TARGET_HISTORY = TARGET_HISTORY.slice(0, TARGET_HISTORY_INDEX + 1);
  TARGET_HISTORY.push(path);
  TARGET_HISTORY_INDEX += 1;
  TARGET_NAVIGATING = true;
  navigateTargetPath(path);
}

function navigateTargetPath(path) {
  const targetUrl = new URL($("#web-target-frame").src);
  const requested = new URL(path, targetUrl.origin);
  targetUrl.pathname = requested.pathname;
  targetUrl.search = requested.search;
  $("#web-target-frame").src = targetUrl.toString();
}

// ---------------------------------------------------------------------------
// Scoreboard
// ---------------------------------------------------------------------------

async function loadScoreboard() {
  const body = $("#score-body");
  body.innerHTML = `<tr><td colspan="4" style="color:var(--text-dim)">Loading…</td></tr>`;
  try {
    const rows = await api("/api/scoreboard");
    body.innerHTML = rows
      .map(
        (r, i) => `
      <tr>
        <td>${i + 1}</td>
        <td>${r.team}</td>
        <td>${r.score}</td>
        <td>${r.solves}</td>
      </tr>`
      )
      .join("");
  } catch (err) {
    body.innerHTML = `<tr><td colspan="4" class="form-error">${err.message}</td></tr>`;
  }
}

// ---------------------------------------------------------------------------
// Settings (server URL)
// ---------------------------------------------------------------------------

async function onSaveSettings() {
  const url = $("#settings-url").value.trim().replace(/\/$/, "");
  const status = $("#settings-status");
  if (!url) {
    status.textContent = "Enter a server URL.";
    status.className = "modal-result err";
    return;
  }
  const config = await window.ctfConfig.set({ serverUrl: url });
  SERVER_URL = config.serverUrl;
  status.textContent = "Saved.";
  status.className = "modal-result ok";
}

// ---------------------------------------------------------------------------
// Interactive terminal challenges
// ---------------------------------------------------------------------------

function openTerminalChallenge(c) {
  TERMINAL_CHALLENGE = c;
  TERMINAL_CWD = "/";

  $("#terminal-category").textContent = c.category;
  $("#terminal-title").textContent = c.title;
  $("#terminal-points").textContent = `${c.points} points`;
  $("#terminal-result").textContent = "";
  $("#terminal-result").className = "modal-result";
  $("#terminal-flag-input").value = "";
  $("#terminal-prompt").textContent = "/ $";

  const hintWrap = $("#terminal-hint-wrap");
  if (c.hint) {
    hintWrap.classList.remove("hidden");
    $("#terminal-hint").textContent = c.hint;
  } else {
    hintWrap.classList.add("hidden");
  }

  const out = $("#terminal-output");
  out.innerHTML = "";
  appendTerminalLine(
    `Connected. Type 'help' for a list of commands.\n${c.description}`,
    "info"
  );

  $("#modal-terminal").classList.remove("hidden");
  $("#terminal-cmd-input").value = "";
  $("#terminal-cmd-input").focus();
}

function appendTerminalLine(text, kind) {
  const out = $("#terminal-output");
  const line = document.createElement("div");
  if (kind === "cmd") line.className = "terminal-line-cmd";
  if (kind === "err") line.className = "terminal-line-err";
  line.textContent = text;
  out.appendChild(line);
  out.scrollTop = out.scrollHeight;
}

async function onTerminalCommand(e) {
  e.preventDefault();
  const input = $("#terminal-cmd-input");
  const command = input.value;
  if (!command.trim()) return;

  appendTerminalLine(`${TERMINAL_CWD} $ ${command}`, "cmd");
  input.value = "";

  try {
    const body = await api(`/api/challenges/${TERMINAL_CHALLENGE.id}/terminal`, {
      method: "POST",
      body: JSON.stringify({ cwd: TERMINAL_CWD, command }),
    });
    if (body.output) appendTerminalLine(body.output);
    TERMINAL_CWD = body.cwd;
    $("#terminal-prompt").textContent = `${TERMINAL_CWD} $`;
  } catch (err) {
    appendTerminalLine(err.message, "err");
  }
}

async function onSubmitFlagTerminal(e) {
  e.preventDefault();
  const result = $("#terminal-result");
  try {
    const body = await api("/api/submit", {
      method: "POST",
      body: JSON.stringify({
        challenge_id: TERMINAL_CHALLENGE.id,
        flag: $("#terminal-flag-input").value,
      }),
    });
    if (body.correct) {
      result.textContent = "Correct! Challenge solved.";
      result.className = "modal-result ok";
      await loadChallenges();
    } else {
      result.textContent = "Incorrect flag, try again.";
      result.className = "modal-result err";
    }
  } catch (err) {
    result.textContent = err.message;
    result.className = "modal-result err";
  }
}

// ---------------------------------------------------------------------------
// Profile / settings view
// ---------------------------------------------------------------------------

async function loadProfileForm() {
  try {
    const profile = await api("/api/me");
    ME = { ...ME, ...profile };
    $("#profile-display-name").value = profile.display_name || "";
    $("#profile-avatar").value = profile.avatar || "🛡️";
    $("#profile-bio").value = profile.bio || "";
  } catch (err) {
    $("#profile-result").textContent = err.message;
    $("#profile-result").className = "form-result err";
  }
}

async function onSaveProfile(e) {
  e.preventDefault();
  const result = $("#profile-result");
  try {
    const profile = await api("/api/me", {
      method: "PUT",
      body: JSON.stringify({
        display_name: $("#profile-display-name").value,
        avatar: $("#profile-avatar").value,
        bio: $("#profile-bio").value,
      }),
    });
    ME = { ...ME, ...profile };
    $("#who-user").textContent = ME.display_name || ME.username;
    $("#who-avatar").textContent = ME.avatar || "🛡️";
    result.textContent = "Saved.";
    result.className = "form-result ok";
  } catch (err) {
    result.textContent = err.message;
    result.className = "form-result err";
  }
}

async function onResetProgress() {
  if (!confirm("Reset your team's solve and attempt history? This cannot be undone.")) return;
  const result = $("#reset-result");
  try {
    await api("/api/me/reset-progress", { method: "POST" });
    result.textContent = "Progress reset.";
    result.className = "form-result ok";
    await loadChallenges();
  } catch (err) {
    result.textContent = err.message;
    result.className = "form-result err";
  }
}

async function onChangePassword(e) {
  e.preventDefault();
  const result = $("#password-result");
  try {
    await api("/api/me/password", {
      method: "POST",
      body: JSON.stringify({
        current_password: $("#pw-current").value,
        new_password: $("#pw-new").value,
      }),
    });
    result.textContent = "Password updated.";
    result.className = "form-result ok";
    $("#pw-current").value = "";
    $("#pw-new").value = "";
  } catch (err) {
    result.textContent = err.message;
    result.className = "form-result err";
  }
}

// ---------------------------------------------------------------------------
// Admin: stats, challenges, users
// ---------------------------------------------------------------------------

async function loadAdmin() {
  await Promise.all([loadAdminStats(), loadAdminChallenges(), loadAdminUsers(), loadOllamaStatus()]);
}

async function loadOllamaStatus() {
  const status = $("#ollama-status");
  try {
    const body = await api("/api/admin/ollama");
    status.textContent = body.available && body.model_available
      ? `Ollama ready · ${body.model}${body.models.length ? ` · ${body.models.length} model(s)` : ""}`
      : body.available
        ? `Ollama online, model missing · run: ollama pull ${body.model}`
      : `Ollama offline · start Ollama at ${body.url} and pull ${body.model}`;
    status.className = `ollama-status ${body.available && body.model_available ? "ok" : "err"}`;
  } catch (err) {
    status.textContent = err.message;
    status.className = "ollama-status err";
  }
}

async function loadAdminStats() {
  const el = $("#admin-stats");
  try {
    const s = await api("/api/admin/stats");
    const cards = [
      ["Users", s.users],
      ["Teams", s.teams],
      ["Challenges", `${s.active_challenges}/${s.challenges}`],
      ["Correct solves", s.correct_submissions],
      ["Total attempts", s.total_submissions],
    ];
    el.innerHTML = cards
      .map(
        ([label, value]) => `
      <div class="stat-card">
        <div class="stat-value">${value}</div>
        <div class="stat-label">${label}</div>
      </div>`
      )
      .join("");
  } catch (err) {
    el.innerHTML = `<p class="form-error">${err.message}</p>`;
  }
}

async function loadAdminChallenges() {
  const body = $("#admin-challenge-body");
  try {
    ADMIN_CHALLENGES = await api("/api/admin/challenges");
    body.innerHTML = ADMIN_CHALLENGES.map(
      (c) => `
      <tr>
        <td>${c.title}</td>
        <td>${c.category}</td>
        <td>${c.type}</td>
        <td>${c.points}</td>
        <td>${c.is_active ? '<span class="tag-active">active</span>' : '<span class="tag-inactive">hidden</span>'}</td>
        <td><button class="row-action-btn" data-edit-id="${c.id}">Edit</button></td>
      </tr>`
    ).join("");
    $$("[data-edit-id]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const c = ADMIN_CHALLENGES.find((x) => x.id === Number(btn.dataset.editId));
        openChallengeForm(c);
      });
    });
  } catch (err) {
    body.innerHTML = `<tr><td colspan="6" class="form-error">${err.message}</td></tr>`;
  }
}

async function loadAdminUsers() {
  const body = $("#admin-users-body");
  try {
    ADMIN_USERS = await api("/api/admin/users");
    body.innerHTML = ADMIN_USERS.map(
      (u) => `
      <tr>
        <td>${u.username}</td>
        <td>${u.display_name}</td>
        <td>${u.team || "—"}</td>
        <td>${u.is_admin ? '<span class="tag-active">yes</span>' : '<span class="tag-inactive">no</span>'}</td>
        <td>${
          u.username === ME.username
            ? ""
            : `<button class="row-action-btn" data-toggle-admin="${u.id}">${u.is_admin ? "Revoke admin" : "Make admin"}</button>`
        }</td>
      </tr>`
    ).join("");
    $$("[data-toggle-admin]").forEach((btn) => {
      btn.addEventListener("click", () => onToggleAdmin(Number(btn.dataset.toggleAdmin)));
    });
  } catch (err) {
    body.innerHTML = `<tr><td colspan="5" class="form-error">${err.message}</td></tr>`;
  }
}

async function onToggleAdmin(userId) {
  try {
    await api(`/api/admin/users/${userId}/toggle-admin`, { method: "POST" });
    await loadAdminUsers();
  } catch (err) {
    alert(err.message);
  }
}

function openChallengeForm(c) {
  EDITING_CHALLENGE_ID = c ? c.id : null;
  $("#challenge-form-title").textContent = c ? "Edit challenge" : "New challenge";
  $("#cf-id").value = c ? c.id : "";
  $("#cf-title").value = c ? c.title : "";
  $("#cf-category").value = c ? c.category : "";
  $("#cf-type").value = c ? c.type : "standard";
  $("#cf-preset").value = "custom";
  $("#cf-difficulty").value = c ? (c.difficulty || "medium") : "easy";
  $("#cf-points").value = c ? c.points : 100;
  $("#cf-description").value = c ? c.description : "";
  $("#cf-rules").value = c && c.rules ? c.rules : "";
  $("#cf-hint").value = c && c.hint ? c.hint : "";
  $("#cf-terminal-fs").value = c && c.terminal_fs ? c.terminal_fs : "";
  $("#cf-terminal-fs-wrap").classList.toggle("hidden", (c ? c.type : "standard") !== "terminal");
  $("#cf-web-wrap").classList.toggle("hidden", (c ? c.type : "standard") !== "web");
  $("#cf-ai-wrap").classList.toggle("hidden", (c ? c.type : "standard") !== "ai");
  $("#cf-quiz-wrap").classList.toggle("hidden", (c ? c.type : "standard") !== "quiz");
  let webConfig = {};
  try { webConfig = c && c.web_config ? JSON.parse(c.web_config) : {}; } catch { webConfig = {}; }
  $("#cf-web-behavior").value = webConfig.behavior || "hidden_path";
  $("#cf-web-title").value = webConfig.title || "Internal site";
  $("#cf-web-path").value = webConfig.secret_path || "/admin";
  $("#cf-web-term").value = webConfig.search_term || "flag";
  $("#cf-web-landing").value = webConfig.landing_text || "Welcome to the internal site.";
  $("#cf-web-success").value = webConfig.success_text || "You found the hidden response.";
  let aiConfig = {};
  try { aiConfig = c && c.ai_config ? JSON.parse(c.ai_config) : {}; } catch { aiConfig = {}; }
  $("#cf-ai-difficulty").value = aiConfig.difficulty || "medium";
  $("#cf-ai-persona").value = aiConfig.persona || "A cautious support engineer";
  $("#cf-ai-marker").value = aiConfig.success_marker || "ACCESS_GRANTED";
  $("#cf-ai-temperature").value = aiConfig.temperature ?? 0.7;
  $("#cf-ai-scenario").value = aiConfig.scenario || "You know one piece of sensitive evidence and must decide whether the requester is authorized.";
  $("#cf-ai-speak").checked = aiConfig.speak !== false;
  $("#cf-ai-voice-style").value = aiConfig.voice_style || "neutral";
  $("#cf-ai-voice-lang").value = aiConfig.voice_language || "en-US";
  $("#cf-ai-voice-pitch").value = aiConfig.voice_pitch || 1;
  $("#cf-ai-voice-rate").value = aiConfig.voice_rate || 1;
  let quizConfig = {};
  try { quizConfig = c && c.quiz_config ? JSON.parse(c.quiz_config) : {}; } catch { quizConfig = {}; }
  $("#cf-quiz-question").value = quizConfig.question || "";
  const quizOptions = quizConfig.options || [];
  [0, 1, 2, 3].forEach((i) => { $(`#cf-quiz-opt-${i}`).value = quizOptions[i] || ""; });
  $("#cf-quiz-correct").value = quizConfig.correct_index ?? 0;
  $("#cf-flag").value = "";
  $("#cf-flag").placeholder = c ? "leave blank to keep existing flag" : "flag{...}";
  $("#cf-active").checked = c ? c.is_active : true;
  $("#cf-delete").classList.toggle("hidden", !c);
  $("#challenge-form-result").textContent = "";
  $("#challenge-form-result").className = "form-result";
  $("#modal-challenge-form").classList.remove("hidden");
}

const CHALLENGE_PRESETS = {
  web: {
    category: "web", type: "web", difficulty: "easy", points: 100,
    title: "Web Footprint", description: "Inspect a web application and identify the exposed clue that leads to the flag.",
    rules: "Use only the provided application. Do not attack the host system or other services.",
    hint: "Inspect the page source, response headers, and paths linked from the application.",
    web: true,
  },
  database: {
    category: "database", type: "standard", difficulty: "hard", points: 300,
    title: "Query Under Pressure", description: "Investigate an unsafe database-backed endpoint and recover the secret record.",
    rules: "Stay within the supplied endpoint and keep requests focused on the challenge data.",
    hint: "Look for places where user input is joined directly into a query.",
  },
  terminal: {
    category: "terminal", type: "terminal", difficulty: "medium", points: 200,
    title: "The Forgotten Shell", description: "Explore a restricted virtual machine with safe read-only commands and find the hidden flag.",
    rules: "Only use the commands available in the challenge terminal. The filesystem is an isolated simulation.",
    hint: "Start with pwd and ls, then inspect unfamiliar directories and files.",
  },
  quiz: {
    category: "quiz", type: "quiz", difficulty: "easy", points: 100,
    title: "Quick Knowledge Check", description: "Answer the question correctly to reveal the flag.",
    rules: "",
    hint: "",
    quiz: true,
  },
};

function applyChallengePreset(name) {
  const preset = CHALLENGE_PRESETS[name];
  if (!preset) return;
  $("#cf-title").value = preset.title;
  $("#cf-category").value = preset.category;
  $("#cf-type").value = preset.type;
  $("#cf-difficulty").value = preset.difficulty;
  $("#cf-points").value = preset.points;
  $("#cf-description").value = preset.description;
  $("#cf-rules").value = preset.rules;
  $("#cf-hint").value = preset.hint;
  $("#cf-terminal-fs-wrap").classList.toggle("hidden", preset.type !== "terminal");
  if (preset.type === "terminal") {
    $("#cf-terminal-fs").value = JSON.stringify({ home: { player: { "readme.txt": "Find the next clue.", ".flag.txt": "flag{replace_me}" } } }, null, 2);
  }
  $("#cf-web-wrap").classList.toggle("hidden", preset.type !== "web");
  $("#cf-ai-wrap").classList.toggle("hidden", preset.type !== "ai");
  $("#cf-quiz-wrap").classList.toggle("hidden", preset.type !== "quiz");
  if (preset.web) {
    $("#cf-web-behavior").value = "xss";
    $("#cf-web-title").value = "Internal site";
    $("#cf-web-path").value = "/admin";
    $("#cf-web-landing").value = "Welcome to the internal site. Can you find the restricted area?";
    $("#cf-web-success").value = "Access granted. The response contains the evidence you need.";
  }
  if (preset.quiz) {
    $("#cf-quiz-question").value = "Which port does HTTPS use by default?";
    $("#cf-quiz-opt-0").value = "21";
    $("#cf-quiz-opt-1").value = "80";
    $("#cf-quiz-opt-2").value = "443";
    $("#cf-quiz-opt-3").value = "3306";
    $("#cf-quiz-correct").value = "2";
  }
}

function updatePointsForDifficulty() {
  const values = { easy: 100, medium: 200, hard: 300, expert: 400 };
  $("#cf-points").value = values[$("#cf-difficulty").value] || 100;
}

async function onSaveChallenge(e) {
  e.preventDefault();
  const result = $("#challenge-form-result");

  const payload = {
    title: $("#cf-title").value,
    category: $("#cf-category").value,
    type: $("#cf-type").value,
    points: Number($("#cf-points").value),
    difficulty: $("#cf-difficulty").value,
    description: $("#cf-description").value,
    rules: $("#cf-rules").value,
    hint: $("#cf-hint").value,
    is_active: $("#cf-active").checked,
  };
  if ($("#cf-type").value === "terminal") {
    payload.terminal_fs = $("#cf-terminal-fs").value;
  }
  const flag = $("#cf-flag").value.trim();
  if ($("#cf-type").value === "web") {
    // The flag revealed on success is always the challenge's own "Flag"
    // field, so the admin only has to type it once. When editing without
    // changing the flag, keep whatever secret the challenge already had.
    let existingSecret = "";
    if (EDITING_CHALLENGE_ID) {
      const existing = ADMIN_CHALLENGES.find((x) => x.id === EDITING_CHALLENGE_ID);
      try { existingSecret = existing && existing.web_config ? (JSON.parse(existing.web_config).secret || "") : ""; } catch { existingSecret = ""; }
    }
    payload.web_config = JSON.stringify({
      behavior: $("#cf-web-behavior").value,
      title: $("#cf-web-title").value,
      secret_path: $("#cf-web-path").value,
      search_term: $("#cf-web-term").value,
      landing_text: $("#cf-web-landing").value,
      success_text: $("#cf-web-success").value,
      secret: flag || existingSecret,
    });
  }
  if ($("#cf-type").value === "ai") {
    payload.ai_config = JSON.stringify({
      difficulty: $("#cf-ai-difficulty").value,
      persona: $("#cf-ai-persona").value,
      success_marker: $("#cf-ai-marker").value,
      temperature: Number($("#cf-ai-temperature").value),
      scenario: $("#cf-ai-scenario").value,
      speak: $("#cf-ai-speak").checked,
      voice_style: $("#cf-ai-voice-style").value,
      voice_language: $("#cf-ai-voice-lang").value,
      voice_pitch: Number($("#cf-ai-voice-pitch").value),
      voice_rate: Number($("#cf-ai-voice-rate").value),
    });
  }
  if ($("#cf-type").value === "quiz") {
    const options = [0, 1, 2, 3]
      .map((i) => $(`#cf-quiz-opt-${i}`).value.trim())
      .filter((value) => value.length > 0);
    payload.quiz_config = JSON.stringify({
      question: $("#cf-quiz-question").value.trim(),
      options,
      correct_index: Number($("#cf-quiz-correct").value),
    });
  }
  if (flag) payload.flag = flag;

  try {
    if (EDITING_CHALLENGE_ID) {
      await api(`/api/admin/challenges/${EDITING_CHALLENGE_ID}`, {
        method: "PUT",
        body: JSON.stringify(payload),
      });
    } else {
      if (!flag) throw new Error("flag is required for a new challenge");
      await api("/api/admin/challenges", {
        method: "POST",
        body: JSON.stringify(payload),
      });
    }
    result.textContent = "Saved.";
    result.className = "form-result ok";
    await loadAdminChallenges();
    await loadAdminStats();
    setTimeout(() => $("#modal-challenge-form").classList.add("hidden"), 400);
  } catch (err) {
    result.textContent = err.message;
    result.className = "form-result err";
  }
}

async function onDeleteChallenge() {
  if (!EDITING_CHALLENGE_ID) return;
  if (!confirm("Delete this challenge? This also removes its submission history.")) return;
  try {
    await api(`/api/admin/challenges/${EDITING_CHALLENGE_ID}`, { method: "DELETE" });
    $("#modal-challenge-form").classList.add("hidden");
    await loadAdminChallenges();
    await loadAdminStats();
  } catch (err) {
    alert(err.message);
  }
}

init();
