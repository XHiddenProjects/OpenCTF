(function () {
  const t = window.OpenCTF.t;
  const SCRIPT_URL = document.currentScript ? document.currentScript.src : "";
  const ADDON_BASE_URL = SCRIPT_URL.replace(/\/addon\.js(\?.*)?$/, "");

  function injectStylesheet() {
    if (document.getElementById("traces-addon-styles") || !ADDON_BASE_URL) return;
    const link = document.createElement("link");
    link.id = "traces-addon-styles";
    link.rel = "stylesheet";
    link.href = `${ADDON_BASE_URL}/style.css`;
    document.head.appendChild(link);
  }

  function escapeHtml(value) {
    return String(value ?? "").replace(/[&<>"']/g, (character) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    })[character]);
  }

  function sortChallenges(challenges) {
    return challenges.slice().sort((left, right) =>
      String(left.category || "").localeCompare(String(right.category || ""))
      || Number(left.points || 0) - Number(right.points || 0)
      || String(left.title || "").localeCompare(String(right.title || ""))
      || Number(left.id) - Number(right.id)
    );
  }

  function groupChallenges(challenges) {
    return challenges.reduce((groups, challenge) => {
      const category = String(challenge.category || "Uncategorized").trim() || "Uncategorized";
      if (!groups.has(category)) groups.set(category, []);
      groups.get(category).push(challenge);
      return groups;
    }, new Map());
  }

  window.OpenCTF.registerView({
    id: "traces",
    label: "Traces",
    location: "admin",
    target: "admin",
    render(container) {
      injectStylesheet();
      container.innerHTML = `
        <section class="traces-panel">
          <header class="traces-header">
            <div>
              <h2>Challenge access</h2>
              <p>Choose which challenges players can access. Changes apply immediately.</p>
            </div>
            <button type="button" class="traces-action traces-refresh" data-traces-refresh title="Refresh challenge status" aria-label="Refresh challenge status">&#8635;</button>
          </header>
          <div class="traces-toolbar">
            <p class="traces-summary" data-traces-summary></p>
            <button type="button" class="traces-action traces-lock-all" data-traces-lock>Lock all</button>
          </div>
          <p class="form-result" data-traces-status role="status" aria-live="polite"></p>
          <div class="traces-categories" data-traces-list></div>
        </section>
      `;

      const lockButton = container.querySelector("[data-traces-lock]");
      const refreshButton = container.querySelector("[data-traces-refresh]");
      const status = container.querySelector("[data-traces-status]");
      const summary = container.querySelector("[data-traces-summary]");
      const list = container.querySelector("[data-traces-list]");

      async function fetchChallenges() {
        return sortChallenges(await window.OpenCTF.api("/api/admin/challenges"));
      }

      function showChallenges(challenges) {
        const activeCount = challenges.filter((challenge) => challenge.is_active).length;
        summary.textContent = `${activeCount} of ${challenges.length} unlocked`;
        const unlockAll = challenges.length > 0 && activeCount === 0;
        lockButton.textContent = unlockAll ? "Unlock all" : "Lock all";
        lockButton.dataset.action = unlockAll ? "unlock" : "lock";
        lockButton.setAttribute("aria-label", unlockAll ? "Unlock all challenges" : "Lock all challenges");
        const groups = groupChallenges(challenges);
        list.innerHTML = [...groups.entries()].map(([category, items]) => {
          const categoryActive = items.filter((challenge) => challenge.is_active).length;
          return `
            <section class="traces-category">
              <header class="traces-category-header">
                <h3>${escapeHtml(category)}</h3>
                <span>${categoryActive} / ${items.length} unlocked</span>
              </header>
              <ul class="traces-challenge-list">
                ${items.map((challenge) => `
                  <li class="traces-challenge ${challenge.is_active ? "is-unlocked" : "is-locked"}">
                    <div class="traces-challenge-info">
                      <span class="traces-challenge-title">${escapeHtml(challenge.title)}</span>
                      <span class="traces-challenge-points">${Number(challenge.points) || 0} points</span>
                    </div>
                    <span class="traces-state">${challenge.is_active ? "Unlocked" : "Locked"}</span>
                    <button type="button" class="traces-toggle ${challenge.is_active ? "is-lock" : "is-unlock"}"
                      data-traces-toggle="${Number(challenge.id)}" aria-pressed="${Boolean(challenge.is_active)}"
                      aria-label="${challenge.is_active ? "Lock" : "Unlock"} ${escapeHtml(challenge.title)}">
                      ${challenge.is_active ? "Lock" : "Unlock"}
                    </button>
                  </li>`).join("")}
              </ul>
            </section>`;
        }).join("");
      }

      function setBusy(busy) {
        lockButton.disabled = busy;
        refreshButton.disabled = busy;
        list.querySelectorAll("button").forEach((button) => { button.disabled = busy; });
      }

      async function refresh() {
        setBusy(true);
        status.textContent = t("common.loading", "Loading challenges...");
        status.className = "form-result";
        try {
          showChallenges(await fetchChallenges());
        } catch (error) {
          status.textContent = error.message;
          status.className = "form-result err";
        } finally {
          setBusy(false);
        }
      }

      lockButton.addEventListener("click", async () => {
        const shouldUnlock = lockButton.dataset.action === "unlock";
        const action = shouldUnlock ? "Unlock" : "Lock";
        const impact = shouldUnlock
          ? "Players will be able to see every challenge."
          : "Players will no longer see any challenges until you unlock them.";
        if (!window.confirm(`${action} every challenge? ${impact}`)) return;
        setBusy(true);
        status.textContent = `${action}ing challenges...`;
        status.className = "form-result";
        try {
          const challenges = await fetchChallenges();
          for (const challenge of challenges) {
            if (Boolean(challenge.is_active) !== shouldUnlock) {
              await window.OpenCTF.api(`/api/admin/challenges/${challenge.id}`, {
                method: "PUT",
                body: JSON.stringify({ is_active: shouldUnlock }),
              });
            }
          }
          showChallenges(await fetchChallenges());
          status.textContent = shouldUnlock ? "All challenges unlocked." : "All challenges locked.";
          status.className = "form-result ok";
        } catch (error) {
          status.textContent = `Could not ${shouldUnlock ? "unlock" : "lock"} all challenges: ${error.message}`;
          status.className = "form-result err";
        } finally {
          setBusy(false);
        }
      });

      list.addEventListener("click", async (event) => {
        const button = event.target.closest("[data-traces-toggle]");
        if (!button || !list.contains(button)) return;
        const challengeId = Number(button.dataset.tracesToggle);
        const shouldUnlock = button.getAttribute("aria-pressed") !== "true";
        setBusy(true);
        status.textContent = `${shouldUnlock ? "Unlocking" : "Locking"} challenge...`;
        status.className = "form-result";
        try {
          await window.OpenCTF.api(`/api/admin/challenges/${challengeId}`, {
            method: "PUT",
            body: JSON.stringify({ is_active: shouldUnlock }),
          });
          showChallenges(await fetchChallenges());
          status.textContent = `Challenge ${shouldUnlock ? "unlocked" : "locked"}.`;
          status.className = "form-result ok";
        } catch (error) {
          status.textContent = `Could not update challenge: ${error.message}`;
          status.className = "form-result err";
        } finally {
          setBusy(false);
        }
      });

      refreshButton.addEventListener("click", refresh);
      refresh();
    },
  });
})();