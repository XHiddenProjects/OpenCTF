// sound-effects addon
//
// Plays a short synthesized beep via the Web Audio API on a correct flag
// submission, and a lower tone on a wrong one. No audio files to ship -
// just an oscillator. Volume is configurable from the gear button (see
// config.js) - on/off is the addon's own enable toggle in the admin list,
// not a duplicate setting in here: once this script isn't loaded (the
// addon's disabled), there's nothing for it to control.
(function () {
  const FALLBACK = { volume: 0.2 };
  let CONFIG = { ...FALLBACK };
  let audioCtx = null;

  async function loadConfig() {
    try {
      CONFIG = { ...FALLBACK, ...(await window.OpenCTF.getAddonConfig("sound-effects")) };
    } catch {
      CONFIG = { ...FALLBACK };
    }
  }

  function ctx() {
    if (!audioCtx) {
      const AudioContext = window.AudioContext || window.webkitAudioContext;
      if (!AudioContext) return null;
      audioCtx = new AudioContext();
    }
    return audioCtx;
  }

  function beep(freq, durationMs) {
    const c = ctx();
    if (!c) return;
    const volume = Math.max(0, Math.min(1, Number(CONFIG.volume) ?? FALLBACK.volume));
    if (volume === 0) return;
    const osc = c.createOscillator();
    const gain = c.createGain();
    osc.type = "sine";
    osc.frequency.value = freq;
    gain.gain.value = volume;
    gain.gain.exponentialRampToValueAtTime(0.001, c.currentTime + durationMs / 1000);
    osc.connect(gain).connect(c.destination);
    osc.start();
    osc.stop(c.currentTime + durationMs / 1000);
  }

  window.OpenCTF.on("ready", loadConfig);
  window.OpenCTF.on("challenge:solved", () => beep(880, 250));
  window.OpenCTF.on("challenge:wrong", () => beep(180, 200));
  window.OpenCTF.on("addon:config_changed", ({ id, config }) => {
    if (id === "sound-effects") CONFIG = { ...FALLBACK, ...config };
  });
})();
