// confetti-solve addon
//
// Fires a short canvas confetti burst on "challenge:solved". No external
// assets - just <canvas> + requestAnimationFrame. Particle count and
// colors are configurable from the gear button (see config.js).
(function () {
  const FALLBACK = { particle_count: 120, colors: "#e8a33d,#4fae7a,#b98af5,#5fb4e8" };
  let CONFIG = { ...FALLBACK };

  async function loadConfig() {
    try {
      CONFIG = { ...FALLBACK, ...(await window.OpenCTF.getAddonConfig("confetti-solve")) };
    } catch {
      CONFIG = { ...FALLBACK };
    }
  }

  function colorList() {
    const list = (CONFIG.colors || FALLBACK.colors)
      .split(",")
      .map((c) => c.trim())
      .filter(Boolean);
    return list.length ? list : FALLBACK.colors.split(",");
  }

  function burst() {
    const count = Math.max(1, Math.min(500, Number(CONFIG.particle_count) || FALLBACK.particle_count));
    const colors = colorList();

    const canvas = document.createElement("canvas");
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
    canvas.style.cssText = "position:fixed;inset:0;z-index:9998;pointer-events:none;";
    document.body.appendChild(canvas);
    const ctx = canvas.getContext("2d");

    const particles = Array.from({ length: count }, () => ({
      x: Math.random() * canvas.width,
      y: -20 - Math.random() * canvas.height * 0.3,
      vx: (Math.random() - 0.5) * 4,
      vy: 2 + Math.random() * 4,
      size: 4 + Math.random() * 5,
      color: colors[Math.floor(Math.random() * colors.length)],
      rotation: Math.random() * Math.PI * 2,
      spin: (Math.random() - 0.5) * 0.3,
    }));

    const start = performance.now();
    function frame(now) {
      const elapsed = now - start;
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      particles.forEach((p) => {
        p.x += p.vx;
        p.y += p.vy;
        p.vy += 0.03;
        p.rotation += p.spin;
        ctx.save();
        ctx.translate(p.x, p.y);
        ctx.rotate(p.rotation);
        ctx.fillStyle = p.color;
        ctx.fillRect(-p.size / 2, -p.size / 2, p.size, p.size * 0.6);
        ctx.restore();
      });
      if (elapsed < 2600) {
        requestAnimationFrame(frame);
      } else {
        canvas.remove();
      }
    }
    requestAnimationFrame(frame);
  }

  window.OpenCTF.on("ready", loadConfig);
  window.OpenCTF.on("challenge:solved", burst);
  window.OpenCTF.on("addon:config_changed", ({ id, config }) => {
    if (id === "confetti-solve") CONFIG = { ...FALLBACK, ...config };
  });
})();
