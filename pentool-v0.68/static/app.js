/* ============================================================
   Pentool WebUI — app.js
   Polling : logs, status/stages, confirmations
   ============================================================ */

(function () {
  "use strict";

  /* ── Utilitaires ─────────────────────────────────────────── */
  const $ = id => document.getElementById(id);
  const RUN_DATA = $("runData");
  const RUN_ID   = RUN_DATA ? RUN_DATA.dataset.runId : null;

  /* ── Dashboard : liste des runs ───────────────────────────── */
  function initDashboard() {
    const tbody = $("runsBody");
    if (!tbody) return;

    async function refreshRuns() {
      try {
        const r = await fetch("/api/runs");
        if (!r.ok) return;
        const d = await r.json();
        // /api/runs retourne un tableau directement (pas {runs:[...]})
        const runs = Array.isArray(d) ? d : (d.runs || []);
        if (!runs.length) {
          tbody.innerHTML = '<tr><td colspan="5" class="muted">Aucun scan.</td></tr>';
          return;
        }
        tbody.innerHTML = runs.map(run => {
          const dur = fmtDuration(run.duration);
          const badge = `<span class="badge ${run.status}">${run.status}</span>`;
          return `<tr>
            <td><a href="/runs/${run.run_id}">${run.run_id.slice(0,8)}</a></td>
            <td>${run.target || "—"}</td>
            <td>${badge}</td>
            <td>${dur}</td>
            <td><a class="btn small" href="/runs/${run.run_id}">Logs</a></td>
          </tr>`;
        }).join("");
      } catch (e) { /* silencieux */ }
    }

    refreshRuns();
    setInterval(refreshRuns, 4000);
  }

  /* ── Page run : logs ──────────────────────────────────────── */
  function initRunLogs() {
    const logEl   = $("log");
    const pauseEl = $("pause");
    const followEl= $("follow");
    if (!logEl || !RUN_ID) return;

    let lastLen = 0;

    async function refreshLog() {
      if (pauseEl && pauseEl.checked) return;
      try {
        const r = await fetch(`/api/log/${RUN_ID}`);
        if (!r.ok) { logEl.textContent = `Erreur ${r.status} — logs indisponibles.`; return; }
        const d = await r.json();
        const text = d.tail || d.log || "";
        if (text.length !== lastLen) {
          lastLen = text.length;
          logEl.textContent = text;
          if (followEl && followEl.checked) {
            logEl.scrollTop = logEl.scrollHeight;
          }
        }
      } catch (e) { /* silencieux */ }
    }

    refreshLog();
    setInterval(refreshLog, 2000);
  }

  /* ── Formatage durée ─────────────────────────────────────── */
  function fmtDuration(sec) {
    if (sec == null || isNaN(sec)) return "—";
    const s = Math.round(sec);
    if (s < 60)  return `${s}s`;
    const m = Math.floor(s / 60);
    const r = s % 60;
    if (m < 60)  return `${m}m ${r.toString().padStart(2,"0")}s`;
    const h = Math.floor(m / 60);
    return `${h}h ${(m % 60).toString().padStart(2,"0")}m`;
  }

  /* ── Page run : statut + étapes ──────────────────────────── */
  /* artifact key → stage element ID */
  const STAGE_MAP = {
    ports_done:         "st_ports",
    enum_done:          "st_enum",
    searchsploit_done:  "st_searchsploit",
    vuln_done:          "st_vuln",
    nuclei_done:        "st_nuclei",
    enum4linux_done:    "st_enum4linux",
    web_done:           "st_web",
    ftp_done:           "st_ftp",
    ssh_done:           "st_ssh",
    exploit_done:       "st_exploit",
    postexploit_done:   "st_postexploit",
    robots_done:        "st_robots",
    js_done:            "st_js",
    git_done:           "st_git",
    archives_done:      "st_archives",
    gpg_done:           "st_gpg",
    wpscan_recon_done:  "st_wpscan",
    wordpress_done:     "st_wordpress",
    wp_exploit_done:    "st_wpexploit",
    report_md:          "st_report",
  };

  /* _current_stage.txt value → stage element ID */
  const RUNNING_MAP = {
    nmap_ports:      "st_ports",
    nmap_enum:       "st_enum",
    nmap_vuln:       "st_vuln",
    searchsploit:    "st_searchsploit",
    nuclei:          "st_nuclei",
    enum4linux:      "st_enum4linux",
    web_enum:        "st_web",
    ftp:             "st_ftp",
    ssh_enum:        "st_ssh",
    exploit:         "st_exploit",
    postexploit:     "st_postexploit",
    robots:          "st_robots",
    js_scrape:       "st_js",
    git_check:       "st_git",
    archives:        "st_archives",
    gpg:             "st_gpg",
    wpscan_recon:    "st_wpscan",
    wordpress_brute: "st_wordpress",
    wp_exploit:      "st_wpexploit",
    report:          "st_report",
  };

  /* All known stage IDs */
  const ALL_STAGE_IDS = new Set(Object.values(STAGE_MAP));

  function initRunStatus() {
    const badge  = $("statusBadge");
    const durEl  = $("duration");
    if (!badge || !RUN_ID) return;

    let startedAt = null;
    let isRunning = false;
    let enabledApplied = false;  // on applique le filtre une seule fois

    setInterval(() => {
      if (durEl && isRunning && startedAt) {
        const elapsed = (Date.now() / 1000) - startedAt;
        durEl.textContent = fmtDuration(elapsed);
      }
    }, 1000);

    async function refreshStatus() {
      try {
        const r = await fetch(`/api/status/${RUN_ID}`);
        if (!r.ok) return;
        const d = await r.json();

        /* badge statut */
        badge.textContent = d.status || "?";
        badge.className   = `badge ${d.status || ""}`;

        /* durée */
        isRunning = (d.status === "running");
        if (d.started) startedAt = d.started;
        if (!isRunning && durEl && d.duration != null) {
          durEl.textContent = fmtDuration(d.duration);
        }

        /* ── Filtrer les badges : ne montrer que les stages activés ─── */
        const enabled = d.enabled_stages || [];
        if (enabled.length && !enabledApplied) {
          enabledApplied = true;
          for (const stageId of ALL_STAGE_IDS) {
            const el = $(stageId);
            if (el) el.classList.toggle("hidden", !enabled.includes(stageId));
          }
        }

        /* ── Couleur des badges ───────────────────────────────────────
           vert  = done (artifact présent)
           jaune = running (stage courant, pas encore done)
           blanc = enabled mais pas encore lancé               */
        const art = d.artifacts || {};
        const runningId = RUNNING_MAP[d.current_stage] || null;

        for (const [key, stageId] of Object.entries(STAGE_MAP)) {
          const el = $(stageId);
          if (!el || el.classList.contains("hidden")) continue;
          const isDone    = !!art[key];
          const isRunNow  = (stageId === runningId);   // running prime sur done
          el.classList.toggle("running", isRunNow);
          el.classList.toggle("done",    isDone && !isRunNow);
        }

        /* boutons téléchargement */
        if (art.report_md || art.report_json) {
          ["dlView","dlHtml","dlMd","dlJson"].forEach(id => {
            const el = $(id);
            if (el) {
              el.classList.remove("disabled");
              el.removeAttribute("aria-disabled");
              el.style.pointerEvents = "";
            }
          });
        }
      } catch (e) { /* silencieux */ }
    }

    refreshStatus();
    setInterval(refreshStatus, 1000);
  }

  /* ── Page run : confirmations exploitation ────────────────── */
  function initConfirmPolling() {
    if (!RUN_ID) return;

    /* Créer la modale si elle n'existe pas encore */
    if (!$("confirmModal")) {
      document.body.insertAdjacentHTML("beforeend", `
        <div id="confirmModal" style="
          display:none; position:fixed; inset:0; z-index:9999;
          background:rgba(0,0,0,.75); align-items:center; justify-content:center;">
          <div style="
            background:#1a1a2e; border:2px solid #ef4444; border-radius:12px;
            padding:2rem; max-width:520px; width:90%; color:#f1f5f9; font-family:inherit;">
            <div style="font-size:2rem; text-align:center; margin-bottom:.5rem;">⚠️</div>
            <h2 id="confirmTitle" style="margin:0 0 .75rem; color:#ef4444; text-align:center; font-size:1.2rem;"></h2>
            <p  id="confirmDesc"  style="margin:0 0 1.25rem; font-size:.9rem; line-height:1.5; color:#cbd5e1;"></p>
            <div style="display:flex; gap:.75rem; justify-content:center;">
              <button id="confirmDeny"  class="btn danger" style="min-width:120px;">✗ Refuser</button>
              <button id="confirmAllow" class="btn primary" style="min-width:120px; background:#16a34a; border-color:#16a34a;">✓ Autoriser</button>
            </div>
          </div>
        </div>
      `);

      $("confirmDeny") .addEventListener("click", () => respondConfirm(false));
      $("confirmAllow").addEventListener("click", () => respondConfirm(true));
    }

    let pendingActionId = null;
    const respondedIds = new Set(); // filet de sécurité côté JS

    async function respondConfirm(confirmed) {
      if (!pendingActionId) return;
      const actionId = pendingActionId;
      pendingActionId = null;
      respondedIds.add(actionId);
      $("confirmModal").style.display = "none";
      try {
        await fetch(`/api/confirm/${RUN_ID}/${actionId}`, {
          method: "POST",
          headers: { "Content-Type": "application/json", "X-CSRFToken": getCsrf() },
          body: JSON.stringify({ confirmed }),
        });
      } catch (e) { console.error("confirm error", e); }
    }

    async function pollConfirm() {
      try {
        const r = await fetch(`/api/confirm/${RUN_ID}`);
        if (!r.ok) return;
        const d = await r.json();
        const pending = (d.pending || []).filter(p => !respondedIds.has(p.action_id));
        if (pending.length && !pendingActionId) {
          const item = pending[0];
          pendingActionId = item.action_id;
          $("confirmTitle").textContent = item.title   || "Action requise";
          $("confirmDesc") .textContent = item.message || item.description || "";
          $("confirmModal").style.display = "flex";
        } else if (!pending.length && pendingActionId) {
          pendingActionId = null;
          $("confirmModal").style.display = "none";
        }
      } catch (e) { /* silencieux */ }
    }

    setInterval(pollConfirm, 2000);
    pollConfirm();
  }

  /* ── CSRF token (meta tag injecté par Jinja2) ─────────────── */
  function getCsrf() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.content : "";
  }

  /* ── Bouton Stop ──────────────────────────────────────────── */
  function initStopBtn() {
    const btn = $("stopBtn");
    if (!btn || !RUN_ID) return;
    btn.addEventListener("click", async () => {
      if (!confirm("Arrêter ce scan ?")) return;
      await fetch(`/api/stop/${RUN_ID}`, {
        method: "POST",
        headers: { "X-CSRFToken": getCsrf() },
      });
    });
  }

  /* ── Bouton Delete ────────────────────────────────────────── */
  function initDeleteBtn() {
    const btn  = $("deleteBtn");
    const modal= $("deleteModal");
    if (!btn) return;

    btn.addEventListener("click", () => {
      if (!modal) {
        execDelete();
      } else {
        $("modalMessage").textContent = `Supprimer le run ${RUN_ID} et tous ses fichiers ?`;
        modal.style.display = "flex";
      }
    });

    const confirmBtn = $("modalConfirm");
    const cancelBtn  = $("modalCancel");
    if (confirmBtn) confirmBtn.addEventListener("click", () => { modal.style.display = "none"; execDelete(); });
    if (cancelBtn)  cancelBtn.addEventListener("click",  () => { modal.style.display = "none"; });

    async function execDelete() {
      await fetch(`/api/run/${RUN_ID}`, {
        method: "DELETE",
        headers: { "X-CSRFToken": getCsrf() },
      });
      window.location.href = "/";
    }
  }

  /* ── Copier la commande ───────────────────────────────────── */
  function initCopyCmd() {
    const btn = $("copyCmd");
    const txt = $("cmdText");
    if (!btn || !txt) return;
    btn.addEventListener("click", () => {
      navigator.clipboard.writeText(txt.textContent).then(() => {
        btn.textContent = "✓ Copié";
        setTimeout(() => btn.textContent = "Copier", 2000);
      });
    });
  }

  /* ── Init ─────────────────────────────────────────────────── */
  document.addEventListener("DOMContentLoaded", () => {
    initDashboard();
    initRunLogs();
    initRunStatus();
    initConfirmPolling();
    initStopBtn();
    initDeleteBtn();
    initCopyCmd();
  });

})();
