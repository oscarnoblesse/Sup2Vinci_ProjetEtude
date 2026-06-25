"""
Pentool WebUI — Flask backend (hardened)

Sécurisation appliquée :
  1. CSRF token sur POST /run           (OWASP A01:2021 — Broken Access Control)
  2. Security headers (CSP, nosniff…)    (OWASP A05:2021 — Security Misconfiguration)
  3. Validation renforcée target          (CWE-20 — Improper Input Validation)
  4. Secret key + session sécurisée       (OWASP A07:2021 — Auth Failures)
  5. Persistance runs en JSON             (Résilience MVP)
"""

from __future__ import annotations

from flask import (
    Flask, render_template, request, redirect, url_for,
    jsonify, send_file, abort, session,
)
import json
import os
import re
import secrets
import signal
import subprocess
import threading
import time
import uuid
from pathlib import Path
from typing import Dict, Any, Optional

# ────────────────────────── Paths ──────────────────────────

BASE_DIR = Path(__file__).resolve().parent
PROJ_DIR = BASE_DIR.parent

# ⚠ Pointe vers le script actuel (v0.063), pas l'ancienne v0.61
PENTOOL_PATH = Path(
    os.environ.get("PENTOOL_PATH", str(PROJ_DIR / "pentool-v0.068.py"))
).resolve()

WORKSPACE = Path(
    os.environ.get("PENTOOL_WORKSPACE", str(PROJ_DIR / "runs"))
).resolve()

HOST = os.environ.get("PENTOOL_WEB_HOST", "127.0.0.1")
PORT = int(os.environ.get("PENTOOL_WEB_PORT", "5000"))

# ────────────────────────── Flask app ──────────────────────────

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(PROJ_DIR / "static"),
)

# ── [4] Secret key aléatoire + session sécurisée ──
# Génère un secret unique à chaque démarrage du serveur.
# En production on le lirait depuis un fichier ou une variable d'env,
# mais pour un outil local de pentest c'est suffisant.
app.secret_key = os.environ.get(
    "PENTOOL_SECRET_KEY", secrets.token_hex(32)
)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,      # JS ne peut pas lire le cookie
    SESSION_COOKIE_SAMESITE="Strict",  # bloque les requêtes cross-site
    SESSION_COOKIE_SECURE=False,       # False car HTTP local (pas HTTPS)
)


# ────────────────────────── [2] Security Headers ──────────────────────────
@app.after_request
def set_security_headers(response):
    """
    Headers de durcissement appliqués à TOUTES les réponses.
    Justification OWASP A05:2021 — Security Misconfiguration.
    """
    # Empêche le navigateur de deviner le Content-Type (MIME sniffing)
    response.headers["X-Content-Type-Options"] = "nosniff"

    # Bloque l'embarquement dans une iframe (anti-clickjacking)
    response.headers["X-Frame-Options"] = "DENY"

    # CSP restrictive : scripts/styles uniquement depuis notre origine
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "frame-ancestors 'none'; "
        "form-action 'self'"
    )

    # Désactive le cache sur les pages dynamiques (évite la fuite de données)
    if "text/html" in response.content_type:
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
        response.headers["Pragma"] = "no-cache"

    # Header legacy XSS protection (utile sur vieux navigateurs)
    response.headers["X-XSS-Protection"] = "1; mode=block"

    # Referrer : n'envoie rien vers l'extérieur
    response.headers["Referrer-Policy"] = "no-referrer"

    return response


# ────────────────────────── [1] CSRF helpers ──────────────────────────
def generate_csrf_token() -> str:
    """
    Génère un token CSRF unique par session.
    Le token est stocké dans la session Flask (cookie signé côté serveur).
    """
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]


def validate_csrf_token() -> bool:
    """
    Vérifie que le token soumis dans le formulaire correspond
    à celui stocké en session. Protège contre CSRF (CWE-352).
    """
    token_form = request.form.get("csrf_token", "")
    token_session = session.get("_csrf_token", "")
    if not token_form or not token_session:
        return False
    return secrets.compare_digest(token_form, token_session)


# Rendre le token accessible dans tous les templates Jinja2
app.jinja_env.globals["csrf_token"] = generate_csrf_token


# ────────────────────────── [3] Target validation ──────────────────────────

# Regex de base : alphanum, dots, colons (IPv6), tirets, underscores
TARGET_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,253}$")

# Patterns interdits — localhost bloqué complètement (pas de flag override)
BLOCKED_TARGETS = {
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "::1",
    "::0",
    "0:0:0:0:0:0:0:1",
    "0:0:0:0:0:0:0:0",
}

# Préfixes de réseaux locaux à bloquer (SSRF prevention)
BLOCKED_PREFIXES = (
    "127.",       # Loopback IPv4
    "0.",         # Default route
    "169.254.",   # Link-local
)


def _safe_target(t: str) -> Optional[str]:
    """
    Valide et nettoie la cible.
    Bloque localhost et IPs dangereuses (CWE-918 — SSRF).
    """
    t = (t or "").strip().lower()
    if not t:
        return None
    if not TARGET_RE.match(t):
        return None

    # Blocage localhost et réseaux dangereux
    if t in BLOCKED_TARGETS:
        return None
    for prefix in BLOCKED_PREFIXES:
        if t.startswith(prefix):
            return None

    return t


# ────────────────────────── [5] Persistance JSON ──────────────────────────

RUNS: Dict[str, Dict[str, Any]] = {}
RUNS_FILE: Optional[Path] = None  # Initialisé au démarrage


def _init_persistence():
    """
    Charge les runs précédents depuis le fichier JSON (s'il existe).
    Appelé une seule fois au démarrage.
    """
    global RUNS_FILE
    RUNS_FILE = WORKSPACE / "_webui" / "runs_state.json"
    RUNS_FILE.parent.mkdir(parents=True, exist_ok=True)

    if RUNS_FILE.exists():
        try:
            data = json.loads(RUNS_FILE.read_text(encoding="utf-8"))
            for run_id, meta in data.items():
                # Les runs "running" au moment du crash sont maintenant "stopped"
                if meta.get("status") in ("running", "queued"):
                    meta["status"] = "stopped"
                    if meta.get("ended") is None:
                        meta["ended"] = meta.get("started")
                RUNS[run_id] = meta
            print(f"[+] Persistance: {len(RUNS)} run(s) rechargé(s) depuis {RUNS_FILE}")
        except Exception as ex:
            print(f"[!] Persistance: erreur lecture {RUNS_FILE}: {ex}")


def _save_runs():
    """
    Sauvegarde l'état courant des runs dans un fichier JSON.
    Appelé à chaque changement d'état (création, stop, fin).
    Thread-safe grâce au GIL Python pour les opérations atomiques.
    """
    if RUNS_FILE is None:
        return
    try:
        RUNS_FILE.write_text(
            json.dumps(RUNS, indent=2, default=str),
            encoding="utf-8",
        )
    except Exception as ex:
        print(f"[!] Persistance: erreur écriture: {ex}")


# ────────────────────────── Helpers ──────────────────────────

def _now() -> float:
    return time.time()


def tail_lines(path: Path, n: int = 300) -> str:
    if not path.exists():
        return ""
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        return "\n".join(lines[-n:])
    except Exception as ex:
        return f"[tail error] {ex}"


def _run_dir(target: str, run_id: str) -> Path:
    return (WORKSPACE / target / run_id).resolve()


def _webui_log(run_id: str) -> Path:
    return (WORKSPACE / "_webui" / run_id / "stdout.log").resolve()


def _artifact_flags(run_dir: Path) -> Dict[str, Any]:
    """Vérifie l'existence des artefacts produits par pentool."""
    logs = run_dir / "logs"
    if not logs.exists():
        return {
            "ports_done": False, "enum_done": False,
            "searchsploit_done": False, "vuln_done": False,
            "nuclei_done": False, "enum4linux_done": False,
            "web_done": False, "report_md": False, "report_json": False,
            "report_html": False,
        }
    return {
        "ports_done": (logs / "nmap_ports_cmd.txt").exists() or (logs / "nmap_ports.nmap").exists(),
        "enum_done": (logs / "nmap_enum_cmd.txt").exists() or (logs / "nmap_enum.nmap").exists(),
        "searchsploit_done": (logs / "searchsploit_cmd.txt").exists() or (logs / "searchsploit_nmap.txt").exists(),
        "vuln_done": (logs / "nmap_vuln_cmd.txt").exists() or (logs / "nmap_vuln.nmap").exists(),
        "nuclei_done": any(logs.glob("nuclei_*")),
        "enum4linux_done": (logs / "enum4linux_cmd.txt").exists() or (logs / "enum4linux_ng.json").exists() or any(logs.glob("enum4linux_*")),
        "web_done": any(logs.glob("whatweb_*.txt")) or any(logs.glob("nikto_*.txt")) or any(logs.glob("gobuster_*.txt")) or any(logs.glob("ffuf_*.txt")),
        # Phases exploit / post-exploit
        "ftp_done": (logs / "exploit_ftp_anon.txt").exists() or (logs / "ftp_to_do.txt").exists(),
        "ssh_done": (logs / "exploit_ssh_userenum.txt").exists() or (logs / "ssh_test_users.txt").exists(),
        "exploit_done": (logs / "exploit_initial_access.txt").exists() or any(logs.glob("exploit_smb*.txt")),
        "postexploit_done": (logs / "post_exploit").exists() and any((logs / "post_exploit").glob("*.txt")),
        # Découverte avancée v0.68
        "robots_done":   (logs / "robots_recon.txt").exists(),
        "js_done":       (logs / "js_scraper.txt").exists(),
        "git_done":      (logs / "git_exposure.txt").exists(),
        "archives_done": (logs / "archive_analysis.txt").exists() or any(logs.glob("ffuf_downloads/*.zip")),
        "gpg_done":      (logs / "gpg_decrypt.txt").exists(),
        "wpscan_recon_done": (logs / "wpscan_recon.txt").exists(),
        "wordpress_done": (logs / "wordpress_bruteforce.txt").exists(),
        "wp_exploit_done": (logs / "wp_theme_inject.txt").exists(),
        # Rapport — vert dès que report.md OU report.json existent (report.html est généré à la volée)
        "report_md": (run_dir / "report.md").exists(),
        "report_json": (run_dir / "report.json").exists(),
        "report_html": (run_dir / "report.html").exists(),
        "report_done": (run_dir / "report.md").exists() or (run_dir / "report.json").exists(),
    }


def _terminate_pid(pid: int, pgid: int = None) -> bool:
    """
    Best-effort terminate.
    Tue le process group entier (SIGTERM puis SIGKILL) pour arrêter
    tous les enfants (nmap, nuclei, gobuster, etc.) et pas juste pentool.
    """
    # Tenter de tuer le group d'abord (tous les enfants)
    if pgid:
        try:
            os.killpg(pgid, signal.SIGTERM)
        except Exception:
            pass

    # Aussi tuer le PID directement (au cas où le group a échoué)
    try:
        os.kill(pid, signal.SIGTERM)
    except Exception:
        if not pgid:
            return False

    # Attendre un peu que tout s'arrête
    deadline = _now() + 2.0
    while _now() < deadline:
        try:
            os.kill(pid, 0)  # Tester si le process principal vit encore
            time.sleep(0.1)
        except Exception:
            return True  # Process mort, OK

    # Forcer avec SIGKILL
    if pgid:
        try:
            os.killpg(pgid, signal.SIGKILL)
        except Exception:
            pass
    try:
        os.kill(pid, signal.SIGKILL)
    except Exception:
        pass
    return True


# ────────────────────────── Worker ──────────────────────────

def _worker(run_id: str, cmd: list[str], log_path: Path):
    r = RUNS.get(run_id)
    if not r:
        return

    r["status"] = "running"
    r["started"] = _now()
    r["ended"] = None
    r["rc"] = None
    _save_runs()

    log_path.parent.mkdir(parents=True, exist_ok=True)

    # Fix logs : forcer Python unbuffered pour que stdout arrive en temps réel
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"

    with log_path.open("w", encoding="utf-8", errors="replace") as f:
        f.write(f"$ {' '.join(cmd)}\n")
        f.write(f"# started: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.flush()
        try:
            # Fix stop : créer un process group pour pouvoir tuer tous les enfants
            # Fix prompts : stdin=/dev/null empêche tout prompt interactif de bloquer
            p = subprocess.Popen(
                cmd,
                stdout=f,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,  # Aucun prompt interactif possible
                text=True,
                env=env,
                preexec_fn=os.setsid,  # Nouveau process group
            )
            r["pid"] = p.pid
            r["pgid"] = os.getpgid(p.pid)  # Stocker le group ID
            _save_runs()
            rc = p.wait()
            r["rc"] = rc
            r["status"] = "done" if rc == 0 else "failed"
        except Exception as ex:
            f.write(f"\n[!] ERROR: {ex}\n")
            r["rc"] = 1
            r["status"] = "failed"
        finally:
            r["ended"] = _now()
            _save_runs()


# ────────────────────────── Routes ──────────────────────────

@app.get("/")
def index():
    return render_template("index.html")


@app.get("/reports")
def reports():
    return render_template("reports.html")


@app.post("/run")
def run():
    # ── [1] Vérification CSRF ──
    if not validate_csrf_token():
        return abort(403, "Token CSRF invalide — requête rejetée.")

    # ── [3] Validation renforcée de la cible ──
    raw_target = request.form.get("target", "")
    target = _safe_target(raw_target)
    if not target:
        blocked = raw_target.strip().lower() in BLOCKED_TARGETS or any(
            raw_target.strip().lower().startswith(p) for p in BLOCKED_PREFIXES
        )
        if blocked:
            return abort(
                400,
                "Cible bloquée : localhost et réseaux locaux sont interdits. "
                "Utilisez uniquement des cibles lab autorisées (HTB, THM, etc.)."
            )
        return abort(400, "Target invalide (A-Z a-z 0-9 _ . : - | max 253 car.)")

    if not request.form.get("authorized"):
        return abort(400, "Autorisation requise")

    run_id = uuid.uuid4().hex[:10]
    WORKSPACE.mkdir(parents=True, exist_ok=True)

    log_path = _webui_log(run_id)
    run_dir = _run_dir(target, run_id)

    cmd = [
        "python3",
        str(PENTOOL_PATH),
        target,
        "--ui", "cli",        # Force CLI mode (pas de prompt "web ou cli?")
        "--authorized",
        "--workspace", str(WORKSPACE),
        "--run-id", run_id,
    ]

    # Options de base
    if request.form.get("pn"):
        cmd.append("--pn")
    if request.form.get("staged"):
        cmd.append("--staged")

    scan_mode = (request.form.get("scan_mode") or "pentest").strip()
    if scan_mode in ("quick", "pentest", "full"):
        cmd += ["--scan-mode", scan_mode]

    preset = (request.form.get("preset") or "pro-fast").strip()
    if preset in ("pro-fast", "custom"):
        cmd += ["--preset", preset]

    # Toggles
    if request.form.get("no_web"):
        cmd.append("--no-web")
    if request.form.get("no_vuln"):
        cmd.append("--no-vuln")
    if request.form.get("vuln_nse"):
        cmd.append("--vuln-nse")
    if request.form.get("searchsploit"):
        cmd.append("--searchsploit")

    # Nouveaux outils v0.63
    if request.form.get("nuclei"):
        cmd.append("--nuclei")
    if request.form.get("enum4linux"):
        cmd.append("--enum4linux")
    if request.form.get("ffuf"):
        cmd.append("--ffuf")
    if request.form.get("no_nikto"):
        cmd.append("--no-nikto")
    if request.form.get("web_early"):
        cmd.append("--web-early")
    if request.form.get("no_web_early"):
        cmd.append("--no-web-early")
    if request.form.get("web_crawl"):
        cmd.append("--web-crawl")
    if request.form.get("sqlmap"):
        cmd.append("--sqlmap")
    if request.form.get("xss"):
        cmd.append("--xss")
    def add_int(flag: str, key: str):
        v = (request.form.get(key) or "").strip()
        if v.isdigit():
            cmd.extend([flag, v])

    add_int("--max-web-urls", "max_web_urls")
    add_int("--max-gobuster", "max_gobuster")
    add_int("--gobuster-threads", "gobuster_threads")

    if request.form.get("verbose"):
        cmd.append("--verbose")

    # ── Initial Access / Post-exploitation (v0.67) ──
    lhost = (request.form.get("lhost") or "").strip()
    lport = (request.form.get("lport") or "4444").strip()
    if lhost and re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", lhost):
        cmd += ["--lhost", lhost]
    if lport.isdigit():
        cmd += ["--lport", lport]

    # ── Exploitation (v0.66) ──
    # pentest et full activent --exploit automatiquement (géré dans parse_args)
    # La checkbox "exploit" dans le formulaire sert uniquement pour le mode quick
    # ── Découverte avancée v0.68 ──
    if not request.form.get("robots"):
        cmd.append("--no-robots")
    if not request.form.get("js_scrape"):
        cmd.append("--no-js-scrape")
    if not request.form.get("git_check"):
        cmd.append("--no-git-check")
    if request.form.get("archive_crack"):
        cmd.append("--archive-crack")
    if request.form.get("wp_brute"):
        cmd.append("--wp-brute")
    if request.form.get("wp_aggressive"):
        cmd.append("--wp-aggressive")
    if request.form.get("wp_exploit"):
        cmd.append("--wp-exploit")

    if request.form.get("exploit_brute"):
        cmd.append("--exploit-brute")
    userlist = (request.form.get("userlist") or "").strip()
    passlist = (request.form.get("passlist") or "").strip()
    if userlist:
        cmd += ["--userlist", userlist]
    if passlist:
        cmd += ["--passlist", passlist]

    # ── Credential hints (v0.69) ──
    hint_username = (request.form.get("hint_username") or "").strip()
    hint_password = (request.form.get("hint_password") or "").strip()
    if hint_username:
        cmd += ["--username", hint_username]
    if hint_password:
        cmd += ["--password", hint_password]

    RUNS[run_id] = {
        "run_id": run_id,
        "target": target,
        "status": "queued",
        "started": _now(),
        "ended": None,
        "rc": None,
        "pid": None,
        "log": str(log_path),
        "cmd": " ".join(cmd),
        "run_dir": str(run_dir),
    }
    _save_runs()

    threading.Thread(target=_worker, args=(run_id, cmd, log_path), daemon=True).start()
    return redirect(url_for("run_view", run_id=run_id))


@app.get("/runs/<run_id>")
def run_view(run_id: str):
    r = RUNS.get(run_id)
    if not r:
        return abort(404)
    return render_template("run.html", run_id=run_id, run=r)


# ────────────────────────── API ──────────────────────────

@app.get("/api/runs")
def api_runs():
    items = sorted(RUNS.values(), key=lambda x: x.get("started") or 0, reverse=True)
    now = _now()
    out = []
    for r in items:
        started = r.get("started")
        ended = r.get("ended")
        duration = (ended - started) if (started and ended) else ((now - started) if started else None)
        run_dir = Path(r.get("run_dir", ""))
        out.append({
            "run_id": r.get("run_id"),
            "target": r.get("target"),
            "status": r.get("status"),
            "rc": r.get("rc"),
            "pid": r.get("pid"),
            "started": started,
            "ended": ended,
            "duration": duration,
            "run_dir": str(run_dir),
            "cmd": r.get("cmd"),
            "artifacts": _artifact_flags(run_dir),
        })
    return jsonify(out)


@app.get("/api/status/<run_id>")
def api_status(run_id: str):
    r = RUNS.get(run_id)
    if not r:
        return abort(404)

    now = _now()
    started = r.get("started")
    ended = r.get("ended")
    duration = (ended - started) if (started and ended) else ((now - started) if started else None)

    run_dir = Path(r.get("run_dir", ""))
    logs_dir = run_dir / "logs"

    # Stage courant (badge jaune) — écrit par pentool dans _current_stage.txt
    current_stage = ""
    try:
        cs_file = logs_dir / "_current_stage.txt"
        if cs_file.exists():
            current_stage = cs_file.read_text(encoding="utf-8").strip()
    except Exception:
        pass

    # Stages activés pour ce run — écrit par pentool dans _config.json
    enabled_stages: list = []
    try:
        cfg_file = logs_dir / "_config.json"
        if cfg_file.exists():
            enabled_stages = json.loads(cfg_file.read_text(encoding="utf-8")).get("enabled_stages", [])
    except Exception:
        pass

    return jsonify({
        "run_id": run_id,
        "target": r.get("target"),
        "status": r.get("status"),
        "rc": r.get("rc"),
        "pid": r.get("pid"),
        "cmd": r.get("cmd"),
        "started": started,
        "ended": ended,
        "duration": duration,
        "run_dir": str(run_dir),
        "artifacts": _artifact_flags(run_dir),
        "current_stage": current_stage,
        "enabled_stages": enabled_stages,
    })


@app.get("/api/log/<run_id>")
def api_log(run_id: str):
    r = RUNS.get(run_id)
    if not r:
        return abort(404)

    parts = []

    # 1. Stdout du pentool (log principal capturé par le worker)
    webui_log = Path(r.get("log", ""))
    if webui_log.exists():
        parts.append(tail_lines(webui_log, n=200))

    # 2. Logs de commandes + résultats dans run_dir/logs/
    run_dir = Path(r.get("run_dir", ""))
    logs_dir = run_dir / "logs"
    if logs_dir.exists():

        # ── 2a. Fichiers *_cmd.txt (sortie brute de chaque outil) ──
        cmd_files = sorted(logs_dir.glob("*_cmd.txt"), key=lambda f: f.stat().st_mtime)
        # Fichiers résultats non-cmd (whatweb, nikto, ffuf log, exploit)
        extra_files = sorted(
            [f for f in logs_dir.glob("exploit_*.txt") if not f.name.endswith("_cmd.txt")],
            key=lambda f: f.stat().st_mtime,
        )
        for cf in list(cmd_files) + extra_files:
            try:
                content = cf.read_text(encoding="utf-8", errors="replace").strip()
                if not content:
                    continue
                header = f"\n{'='*60}\n[{cf.name}]\n{'='*60}\n"

                # ── Nuclei : filtre le bruit (templates, HTML, progress) ──
                if cf.name == "nuclei_cmd.txt":
                    kept = []
                    for line in content.splitlines():
                        clean = line.strip()
                        # Garde : commande lancée, résumé final, findings réels, erreurs importantes
                        if clean.startswith("$") or clean.startswith("# "):
                            kept.append(line)
                        elif "Scan completed" in clean or "matches found" in clean:
                            kept.append(line)
                        elif clean.startswith("[WRN]") and "runtime error" not in clean.lower():
                            kept.append(line)
                        # Ligne de finding nuclei : commence par [template-id] ou contient une sévérité
                        elif re.search(r'^\[.+\]\s+\[.+\]\s+\[', clean):
                            kept.append(line)
                        # Skip tout le reste ([INF], HTML, progress, ASCII art)
                    if not kept:
                        kept = ["(aucun finding — voir section NUCLEI ci-dessous)"]
                    parts.append(header + "\n".join(kept))
                    continue

                lines = content.splitlines()
                parts.append(header + "\n".join(lines[-80:]))
            except Exception:
                pass

        # ── 2b. FFUF — répertoires trouvés (CSV) ──
        ffuf_hits = []
        for csv_file in sorted(logs_dir.glob("ffuf_*.csv"), key=lambda f: f.stat().st_mtime):
            try:
                lines_csv = csv_file.read_text(encoding="utf-8", errors="replace").splitlines()
                for line in lines_csv[1:]:   # skip header
                    line = line.strip()
                    if not line:
                        continue
                    cols = line.split(",")
                    if len(cols) >= 5:
                        fuzz, url, redirect, _, status = cols[0], cols[1], cols[2], cols[3], cols[4]
                        dest = redirect if redirect else url
                        ffuf_hits.append(f"  [{status}] /{fuzz}  →  {dest}")
            except Exception:
                pass
        if ffuf_hits:
            parts.append(
                f"\n{'='*60}\n[FFUF — RÉPERTOIRES TROUVÉS ({len(ffuf_hits)} résultat(s))]\n{'='*60}\n"
                + "\n".join(ffuf_hits)
            )

        # ── 2c. WhatWeb — fingerprint ──
        for ww in sorted(logs_dir.glob("whatweb_*.txt"), key=lambda f: f.stat().st_mtime):
            try:
                content = ww.read_text(encoding="utf-8", errors="replace").strip()
                if content:
                    # Extrait les lignes utiles (pas les lignes de commande)
                    useful = [l for l in content.splitlines()
                              if l.strip() and not l.startswith("$") and not l.startswith("#")]
                    if useful:
                        parts.append(
                            f"\n{'='*60}\n[WHATWEB — {ww.stem}]\n{'='*60}\n"
                            + "\n".join(useful[:30])
                        )
            except Exception:
                pass

        # ── 2d. Nuclei — findings ──
        nuclei_jsonl = logs_dir / "nuclei_results.jsonl"
        nuclei_txt   = logs_dir / "nuclei_results.txt"
        nuclei_hits  = []
        if nuclei_jsonl.exists():
            try:
                import json as _json
                for line in nuclei_jsonl.read_text(encoding="utf-8", errors="replace").splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        j = _json.loads(line)
                        sev  = (j.get("info", {}).get("severity") or "?").upper()
                        name = j.get("info", {}).get("name") or j.get("template-id", "?")
                        tid  = j.get("template-id", "")
                        url  = j.get("matched-at") or j.get("host") or ""
                        # Extrait uniquement les résultats utiles (pas le corps HTTP)
                        extracted = j.get("extracted-results", [])
                        extra = f"  ({', '.join(str(x) for x in extracted[:3])})" if extracted else ""
                        nuclei_hits.append(f"  [{sev}] {name} [{tid}]  →  {url}{extra}")
                    except Exception:
                        pass
            except Exception:
                pass
        elif nuclei_txt.exists():
            try:
                lines_n = [l for l in nuclei_txt.read_text(encoding="utf-8", errors="replace").splitlines() if l.strip()]
                nuclei_hits = [f"  {l}" for l in lines_n[:50]]
            except Exception:
                pass
        if nuclei_hits:
            parts.append(
                f"\n{'='*60}\n[NUCLEI — FINDINGS ({len(nuclei_hits)})]\n{'='*60}\n"
                + "\n".join(nuclei_hits)
            )
        elif nuclei_jsonl.exists() or nuclei_txt.exists():
            parts.append(f"\n{'='*60}\n[NUCLEI — 0 finding]\n{'='*60}")

        # ── 2e. robots.txt / sitemap ──
        robots_f = logs_dir / "robots_recon.txt"
        if robots_f.exists():
            try:
                content = robots_f.read_text(encoding="utf-8", errors="replace").strip()
                if content:
                    parts.append(f"\n{'='*60}\n[ROBOTS.TXT / SITEMAP]\n{'='*60}\n" + content[:2000])
            except Exception:
                pass

        # ── 2f. JS scraper ──
        js_f = logs_dir / "js_scraper.txt"
        if js_f.exists():
            try:
                content = js_f.read_text(encoding="utf-8", errors="replace").strip()
                if content:
                    parts.append(f"\n{'='*60}\n[JS SCRAPER — SECRETS & ENDPOINTS]\n{'='*60}\n" + content[:3000])
            except Exception:
                pass

        # ── 2g. .git exposure ──
        git_f = logs_dir / "git_exposure.txt"
        if git_f.exists():
            try:
                content = git_f.read_text(encoding="utf-8", errors="replace").strip()
                if content:
                    parts.append(f"\n{'='*60}\n[.GIT EXPOSURE]\n{'='*60}\n" + content[:2000])
            except Exception:
                pass

        # ── 2h. Archive analysis ──
        arc_f = logs_dir / "archive_analysis.txt"
        if arc_f.exists():
            try:
                content = arc_f.read_text(encoding="utf-8", errors="replace").strip()
                if content:
                    parts.append(f"\n{'='*60}\n[ARCHIVE ANALYSIS]\n{'='*60}\n" + content[:2000])
            except Exception:
                pass

        # ── 2i. GPG decrypt ──
        gpg_f = logs_dir / "gpg_decrypt.txt"
        if gpg_f.exists():
            try:
                content = gpg_f.read_text(encoding="utf-8", errors="replace").strip()
                if content:
                    parts.append(f"\n{'='*60}\n[GPG DECRYPT — CREDENTIALS]\n{'='*60}\n" + content[:3000])
            except Exception:
                pass

        # ── 2i. SQLmap — résultats ──
        sqlmap_dir = logs_dir / "sqlmap"
        if sqlmap_dir.exists():
            sq_parts = []
            for sf in sorted(sqlmap_dir.glob("*.txt"), key=lambda f: f.stat().st_mtime):
                try:
                    content = sf.read_text(encoding="utf-8", errors="replace").strip()
                    # Extrait uniquement les lignes importantes
                    hits = [l for l in content.splitlines()
                            if any(k in l for k in ["injectable", "Parameter", "Type:", "Title:", "Payload:", "[+]", "[!]"])]
                    if hits:
                        sq_parts.append(f"--- {sf.name} ---\n" + "\n".join(hits[:20]))
                    else:
                        sq_parts.append(f"--- {sf.name} --- (aucune injection détectée)")
                except Exception:
                    pass
            if sq_parts:
                parts.append(
                    f"\n{'='*60}\n[SQLMAP — RÉSULTATS]\n{'='*60}\n"
                    + "\n\n".join(sq_parts)
                )

        # ── 2j. WPScan recon ──
        import re as _re
        _ansi_re = _re.compile(r'\x1b\[[0-9;]*[mK]')

        wpscan_f = logs_dir / "wpscan_recon.txt"
        if wpscan_f.exists():
            try:
                raw = wpscan_f.read_text(encoding="utf-8", errors="replace")
                content = _ansi_re.sub("", raw).strip()
                if content:
                    # Garder les 150 dernières lignes (version, thèmes, plugins, CVEs)
                    tail = "\n".join(content.splitlines()[-150:])
                    parts.append(f"\n{'='*60}\n[WPSCAN — RECON]\n{'='*60}\n" + tail)
            except Exception:
                pass

        # ── 2k. WordPress brute force ──
        wpbrute_f = logs_dir / "wordpress_bruteforce.txt"
        if wpbrute_f.exists():
            try:
                raw = wpbrute_f.read_text(encoding="utf-8", errors="replace")
                content = _ansi_re.sub("", raw).strip()
                if content:
                    lines_bf = content.splitlines()
                    # Lignes clés générées par le pentool (pas le bruit wpscan brut)
                    key_bf = [l for l in lines_bf if any(k in l for k in
                        ["[Wordlist", "[Users", "[USERNAME]", "[CRED]",
                         "CREDENTIAL", "Password found", "Username found",
                         "Valid Combinations Found", "Credentials Found"])]
                    # Résumé : lignes clés + 10 dernières lignes de contexte
                    tail_bf = lines_bf[-10:]
                    section = ""
                    if key_bf:
                        section += "\n".join(key_bf) + "\n"
                    section += "\n[...]\n" + "\n".join(tail_bf)
                    parts.append(f"\n{'='*60}\n[WORDPRESS BRUTE FORCE]\n{'='*60}\n" + section)
            except Exception:
                pass

        # ── 2k-bis. WordPress Theme Inject (post-exploitation WP) ──
        wp_inject_f = logs_dir / "wp_theme_inject.txt"
        if wp_inject_f.exists():
            try:
                content = wp_inject_f.read_text(encoding="utf-8", errors="replace").strip()
                if content:
                    parts.append(
                        f"\n{'='*60}\n[WP THEME INJECT — POST-EXPLOITATION]\n{'='*60}\n"
                        + content[:3000]
                    )
            except Exception:
                pass

        # ── 2l. Post-exploit individuels ──
        postexploit_dir = logs_dir / "post_exploit"
        if postexploit_dir.exists():
            pe_files = sorted(postexploit_dir.glob("*.txt"), key=lambda f: f.stat().st_mtime)
            pe_parts = []
            for pf in pe_files:
                try:
                    content = pf.read_text(encoding="utf-8", errors="replace").strip()
                    if content:
                        pe_parts.append(f"--- {pf.stem} ---\n{content[:500]}")
                except Exception:
                    pass
            if pe_parts:
                parts.append(f"\n{'='*60}\n[POST-EXPLOITATION]\n{'='*60}\n" + "\n\n".join(pe_parts))

    combined = "\n".join(parts) if parts else "(en attente de logs...)"
    # Limiter la taille totale renvoyée
    lines = combined.splitlines()
    if len(lines) > 2000:
        lines = lines[-2000:]
    return jsonify({"tail": "\n".join(lines)})


@app.post("/api/stop/<run_id>")
def api_stop(run_id: str):
    r = RUNS.get(run_id)
    if not r:
        return abort(404)

    if r.get("status") not in ("queued", "running"):
        return jsonify({"ok": False, "message": "not running"}), 400

    pid = r.get("pid")
    if not pid:
        return jsonify({"ok": False, "message": "no pid"}), 400

    okk = _terminate_pid(int(pid), pgid=r.get("pgid"))
    if okk:
        r["status"] = "stopped"
        r["ended"] = _now()
        _save_runs()
        return jsonify({"ok": True})
    return jsonify({"ok": False}), 500


@app.delete("/api/run/<run_id>")
def api_delete_run(run_id: str):
    """
    Supprime un run : dossier disque + entrée dans RUNS.
    Refuse si le scan est encore en cours.
    """
    import shutil
    r = RUNS.get(run_id)
    if not r:
        return abort(404)
    if r.get("status") in ("running", "queued"):
        return jsonify({"ok": False, "message": "Scan en cours — arrêtez-le d'abord"}), 400

    # Suppression du dossier run
    run_dir = Path(r.get("run_dir", ""))
    if run_dir.exists() and str(run_dir).startswith(str(WORKSPACE)):
        try:
            shutil.rmtree(run_dir)
        except Exception as e:
            return jsonify({"ok": False, "message": str(e)}), 500

    # Suppression du log webui
    log_path = Path(r.get("log", ""))
    if log_path.exists():
        try:
            log_path.unlink()
            # Nettoie le dossier parent si vide
            if log_path.parent.exists() and not any(log_path.parent.iterdir()):
                log_path.parent.rmdir()
        except Exception:
            pass

    del RUNS[run_id]
    _save_runs()
    return jsonify({"ok": True})


@app.get("/download/<run_id>/<path:filename>")
def download(run_id: str, filename: str):
    r = RUNS.get(run_id)
    if not r:
        return abort(404)

    # Sécurité : empêche le path traversal (CWE-22)
    fpath = (Path(r["run_dir"]) / filename).resolve()
    run_dir_resolved = Path(r["run_dir"]).resolve()
    if not str(fpath).startswith(str(run_dir_resolved)):
        return abort(403, "Accès interdit (path traversal détecté)")

    if not fpath.exists():
        return abort(404)
    # Les fichiers HTML s'affichent directement dans le navigateur (pas de forcer-téléchargement)
    inline = fpath.suffix.lower() in (".html", ".htm")
    return send_file(str(fpath), as_attachment=not inline)


@app.get("/view/<run_id>/report")
def view_report(run_id: str):
    """
    Sert report.html s'il existe (généré par reporting.py),
    sinon génère un rapport HTML depuis report.json + fichiers de logs.
    """
    import html as _html
    import re as _re

    r = RUNS.get(run_id)
    if not r:
        return abort(404)

    run_dir_resolved = Path(r["run_dir"]).resolve()

    # ── Servir report.html s'il existe déjà (reporting.py l'a généré) ──────
    html_file = run_dir_resolved / "report.html"
    if html_file.exists():
        return send_file(str(html_file), mimetype="text/html")

    # ── Fallback : génération dynamique depuis report.json ──────────────────
    rj_path = run_dir_resolved / "report.json"
    if not rj_path.exists():
        return abort(404, "Aucun rapport disponible — relancez le scan jusqu'à la fin.")

    try:
        rj = json.loads(rj_path.read_text(encoding="utf-8", errors="replace"))
    except Exception as e:
        return abort(500, f"report.json invalide : {e}")

    meta     = rj.get("meta", {})
    cfg      = rj.get("config", {})
    summary  = rj.get("summary", {})
    findings = rj.get("findings", [])
    services = rj.get("services", [])
    timings  = rj.get("timings", {})
    web_logs = rj.get("web_logs", {})
    target   = rj.get("target", r.get("target", "?"))
    ansi_re  = _re.compile(r'\x1b\[[0-9;]*[mK]')

    def esc(s): return _html.escape(str(s) if s is not None else "")
    def read_log(name):
        p = run_dir_resolved / "logs" / name
        if not p.exists(): return ""
        try:
            return ansi_re.sub("", p.read_text(encoding="utf-8", errors="replace")).strip()
        except Exception: return ""
    def sev_badge(sev):
        colors = {"critical":"#ef4444","high":"#f97316","medium":"#eab308",
                  "low":"#3b82f6","info":"#6b7280"}
        c = colors.get(str(sev).lower(), "#6b7280")
        return f'<span class="badge" style="background:{c}">{esc(sev).upper()}</span>'
    def fmt_dur(sec):
        if sec is None: return "—"
        sec = int(sec)
        if sec < 60: return f"{sec}s"
        m, s = divmod(sec, 60)
        if m < 60: return f"{m}m {s:02d}s"
        h, m = divmod(m, 60)
        return f"{h}h {m:02d}m"

    # ── Sections HTML ────────────────────────────────────────────────────────
    S = []   # sections HTML accumulées

    # ─── HEADER ───────────────────────────────────────────────────────────
    got_root  = summary.get("got_root", False)
    got_shell = summary.get("shell_obtained", False)
    shell_user = esc(summary.get("shell_user", "N/A"))
    privesc   = esc(summary.get("privesc_method") or "—")
    nb_services = summary.get("nb_services", len(services))
    nb_findings = summary.get("nb_findings", len(findings))
    nb_crit   = summary.get("nb_critical_high", 0)
    duration  = fmt_dur(timings.get("total"))
    scan_date = esc(meta.get("date", "—"))
    scan_mode = esc(cfg.get("scan_mode", "—"))
    version   = esc(meta.get("version", "0.68"))

    is_partial   = bool(timings.get("interrupted"))
    status_color = "#ef4444" if got_root else ("#f97316" if got_shell else ("#6b7280" if is_partial else "#3b82f6"))
    status_label = "🔴 COMPROMIS (root)" if got_root else ("🟠 SHELL OBTENU" if got_shell else ("⚠️ SCAN INTERROMPU — rapport partiel" if is_partial else "🔵 RECON ONLY"))

    S.append(f"""
<header class="report-header">
  <div class="header-brand">
    <div class="logo-pt">PT</div>
    <div>
      <div class="report-title">Rapport de Test d'Intrusion</div>
      <div class="report-sub">pentool v{version} · {scan_date}</div>
    </div>
  </div>
  <div class="header-status" style="border-color:{status_color};color:{status_color}">{status_label}</div>
</header>

<div class="meta-grid">
  <div class="meta-card"><div class="mc-label">Cible</div><div class="mc-val target-val">{esc(target)}</div></div>
  <div class="meta-card"><div class="mc-label">Run ID</div><div class="mc-val mono">{esc(run_id)}</div></div>
  <div class="meta-card"><div class="mc-label">Mode</div><div class="mc-val">{scan_mode}</div></div>
  <div class="meta-card"><div class="mc-label">Durée</div><div class="mc-val">{duration}</div></div>
  <div class="meta-card"><div class="mc-label">Services</div><div class="mc-val big">{nb_services}</div></div>
  <div class="meta-card"><div class="mc-label">Findings</div><div class="mc-val big">{nb_findings}</div></div>
  <div class="meta-card"><div class="mc-label">Critical/High</div><div class="mc-val big {'red' if nb_crit else ''}">{nb_crit}</div></div>
  <div class="meta-card"><div class="mc-label">Shell</div><div class="mc-val">{'✅ ' + shell_user if got_shell else '❌ Non'}</div></div>
</div>""")

    # ─── 1. SERVICES / PORTS ──────────────────────────────────────────────
    nmap_ports = read_log("nmap_ports.nmap") or read_log("nmap_ports_cmd.txt")
    # Extraire les lignes de ports du nmap output
    port_lines = [l for l in nmap_ports.splitlines()
                  if _re.match(r'^\d+/tcp', l) or _re.match(r'^\d+/udp', l)]

    S.append('<section class="card"><h2>🔌 Services &amp; Ports Découverts</h2>')
    if port_lines:
        S.append('<table><thead><tr><th>Port</th><th>État</th><th>Service</th><th>Version / Info</th></tr></thead><tbody>')
        for pl in port_lines:
            parts_p = pl.split(None, 3)
            port_s = esc(parts_p[0]) if len(parts_p) > 0 else "?"
            state  = esc(parts_p[1]) if len(parts_p) > 1 else "?"
            svc    = esc(parts_p[2]) if len(parts_p) > 2 else "?"
            info   = esc(parts_p[3]) if len(parts_p) > 3 else ""
            S.append(f'<tr><td class="mono port">{port_s}</td><td>{state}</td><td>{svc}</td><td class="mono small">{info}</td></tr>')
        S.append('</tbody></table>')
    elif services:
        S.append('<table><thead><tr><th>Port</th><th>Proto</th><th>Service</th><th>Produit</th><th>Version</th></tr></thead><tbody>')
        for sv in services:
            S.append(f'<tr><td class="mono port">{esc(sv.get("port","?"))}</td>'
                     f'<td>{esc(sv.get("proto","tcp"))}</td>'
                     f'<td>{esc(sv.get("name",""))}</td>'
                     f'<td>{esc(sv.get("product",""))}</td>'
                     f'<td class="mono small">{esc(sv.get("version",""))}</td></tr>')
        S.append('</tbody></table>')
    else:
        S.append('<p class="muted">Aucun port ouvert détecté.</p>')
    S.append('</section>')

    # ─── 2. VULNÉRABILITÉS / FINDINGS ─────────────────────────────────────
    S.append('<section class="card"><h2>🔍 Vulnérabilités &amp; Findings</h2>')
    crit_high = [f for f in findings if f.get("severity") in ("critical","high")]
    med_low   = [f for f in findings if f.get("severity") in ("medium","low")]
    info_f    = [f for f in findings if f.get("severity") == "info"]

    def render_findings(lst):
        html_f = []
        for f in lst:
            title = esc(f.get("title",""))
            src   = esc(f.get("source",""))
            desc  = esc(f.get("description",""))
            cvss  = f.get("cvss")
            cvss_span = (f'  <span class="cvss">CVSS {esc(cvss)}</span>' if cvss else "")
            html_f.append(f'<div class="finding">'
                          f'{sev_badge(f.get("severity","info"))} '
                          f'<strong>{title}</strong>'
                          f'{(" — " + desc) if desc else ""}'
                          f'{cvss_span}'
                          f'<span class="src">[{src}]</span>'
                          f'</div>')
        return "\n".join(html_f)

    if crit_high:
        S.append('<h3 style="color:#ef4444">⚠ Critical / High</h3>')
        S.append(render_findings(crit_high))
    if med_low:
        S.append('<h3 style="color:#eab308">⚡ Medium / Low</h3>')
        S.append(render_findings(med_low))
    if info_f:
        S.append('<details><summary class="details-sum">ℹ Info ({} entrées)</summary>'.format(len(info_f)))
        S.append(render_findings(info_f))
        S.append('</details>')
    if not findings:
        S.append('<p class="muted">Aucun finding enregistré.</p>')
    S.append('</section>')

    # ─── 3. ÉNUMÉRATION WEB ───────────────────────────────────────────────
    whatweb_log = read_log("whatweb_cmd.txt") or ""
    ffuf_hits = []
    logs_dir = run_dir_resolved / "logs"
    if logs_dir.exists():
        for csv_f in sorted(logs_dir.glob("ffuf_*.csv")):
            try:
                for line in csv_f.read_text(encoding="utf-8", errors="replace").splitlines()[1:]:
                    parts_c = line.strip().split(",")
                    if len(parts_c) >= 4:
                        url, status, size, words = parts_c[0], parts_c[1], parts_c[2], parts_c[3]
                        if status not in ("404","") and url:
                            ffuf_hits.append((esc(url), esc(status), esc(size)))
            except Exception:
                pass

    js_log    = read_log("js_scraper.txt")
    robots_log = read_log("robots_recon.txt")
    git_log   = read_log("git_exposure.txt")

    has_web = whatweb_log or ffuf_hits or js_log or robots_log or git_log
    if has_web:
        S.append('<section class="card"><h2>🌐 Énumération Web</h2>')

        if whatweb_log:
            # Extraire les lignes utiles (pas le bruit)
            ww_lines = [l for l in whatweb_log.splitlines()
                        if l.strip() and not l.startswith("$") and not l.startswith("#")][:20]
            if ww_lines:
                S.append('<h3>WhatWeb</h3><pre class="logblock">' + esc("\n".join(ww_lines)) + '</pre>')

        if ffuf_hits:
            S.append(f'<h3>Répertoires trouvés — ffuf ({len(ffuf_hits)} hits)</h3>')
            S.append('<table><thead><tr><th>URL</th><th>Status</th><th>Taille</th></tr></thead><tbody>')
            for url, st, sz in ffuf_hits[:100]:
                S.append(f'<tr><td class="mono small">{url}</td><td>{st}</td><td>{sz}</td></tr>')
            S.append('</tbody></table>')

        if robots_log:
            lines_r = [l for l in robots_log.splitlines() if l.strip() and not l.startswith("#")][:30]
            if lines_r:
                S.append('<h3>robots.txt / sitemap</h3><pre class="logblock">' + esc("\n".join(lines_r)) + '</pre>')

        if js_log:
            # Extraire secrets / endpoints JS
            js_interesting = [l for l in js_log.splitlines()
                              if any(k in l.lower() for k in ["key","token","secret","api","password","endpoint","url","http"])][:30]
            if js_interesting:
                S.append('<h3>JS Scraper — secrets &amp; endpoints</h3>')
                S.append('<pre class="logblock">' + esc("\n".join(js_interesting)) + '</pre>')

        if git_log:
            S.append('<h3 style="color:#ef4444">🗂 Exposition .git détectée</h3>')
            S.append('<pre class="logblock">' + esc(git_log[:2000]) + '</pre>')

        S.append('</section>')

    # ─── 4. WORDPRESS ─────────────────────────────────────────────────────
    wp_recon  = read_log("wpscan_recon.txt")
    wp_brute  = read_log("wordpress_bruteforce.txt")

    if wp_recon or wp_brute:
        S.append('<section class="card"><h2>🔑 WordPress</h2>')

        if wp_recon:
            # Extraire version WP
            ver_m = _re.search(r'WordPress version ([0-9.]+)', wp_recon)
            wp_ver = ver_m.group(1) if ver_m else None
            # Extraire plugins/thèmes vulnérables
            vuln_plugins = _re.findall(r'\[!\]\s+(.+?(?:CVE|vulnerability|vuln).+)', wp_recon, _re.I)
            # Extraire users
            users_m = _re.findall(r'Login:\s*([^\s,\|]+)', wp_recon, _re.I)

            if wp_ver:
                S.append(f'<p>Version WordPress : <strong class="mono">{esc(wp_ver)}</strong></p>')
            if users_m:
                S.append('<p>Utilisateurs énumérés : ' +
                         " ".join(f'<code>{esc(u)}</code>' for u in set(users_m)) + '</p>')
            if vuln_plugins:
                S.append('<h3 style="color:#f97316">Plugins / thèmes vulnérables</h3><ul>')
                for vp in vuln_plugins[:10]:
                    S.append(f'<li class="vuln-item">{esc(vp)}</li>')
                S.append('</ul>')

        if wp_brute:
            # Extraire les credentials
            creds_found = _re.findall(r'\[CRED\]\s*(\S+:\S+)', wp_brute)
            users_found = _re.findall(r'\[USERNAME\]\s*(\S+)', wp_brute)
            if creds_found:
                S.append('<div class="cred-box"><h3>🔑 Credentials trouvés</h3><ul>')
                for c in creds_found:
                    S.append(f'<li><code class="cred">{esc(c)}</code></li>')
                S.append('</ul></div>')
            elif users_found:
                S.append('<p>Utilisateurs : ' +
                         " ".join(f'<code>{esc(u)}</code>' for u in users_found) + '</p>')
                S.append('<p class="muted">Aucun credential trouvé par brute force.</p>')

        S.append('</section>')

    # ─── 5. EXPLOITATION & INITIAL ACCESS ─────────────────────────────────
    exploit_files = []
    if logs_dir.exists():
        exploit_files = sorted(logs_dir.glob("exploit_*.txt"), key=lambda f: f.stat().st_mtime)

    if exploit_files:
        S.append('<section class="card"><h2>⚡ Exploitation &amp; Initial Access</h2>')
        for ef in exploit_files:
            try:
                content_e = ansi_re.sub("",
                    ef.read_text(encoding="utf-8", errors="replace")).strip()
                if not content_e: continue
                # Résumé : last 20 lignes ou lignes contenant des mots-clés importants
                key_e = [l for l in content_e.splitlines()
                         if any(k in l.lower() for k in
                            ["success","found","login","credential","shell","access",
                             "upload","write","exploit","ftp","smb","ssh","error",
                             "fail","denied","connect","anonymous"])][:20]
                display_e = "\n".join(key_e) if key_e else "\n".join(content_e.splitlines()[-15:])
                lbl = ef.stem.replace("exploit_","").replace("_"," ").title()
                S.append(f'<details><summary class="details-sum">📁 {esc(lbl)}</summary>')
                S.append(f'<pre class="logblock">{esc(display_e)}</pre>')
                S.append('</details>')
            except Exception:
                pass
        S.append('</section>')

    # ─── 6. POST-EXPLOITATION ─────────────────────────────────────────────
    pe_dir = logs_dir / "post_exploit" if logs_dir.exists() else None
    pe_files = sorted(pe_dir.glob("*.txt"), key=lambda f: f.stat().st_mtime) if (pe_dir and pe_dir.exists()) else []

    if pe_files or got_shell:
        S.append('<section class="card"><h2>💻 Post-Exploitation</h2>')

        shell_info = {
            "whoami": summary.get("shell_user", "?"),
            "privesc_method": summary.get("privesc_method"),
            "privesc_id": summary.get("privesc_id"),
        }

        if shell_info["whoami"] and shell_info["whoami"] != "N/A":
            S.append(f'<p>Utilisateur initial : <code>{esc(shell_info["whoami"])}</code></p>')
        if shell_info["privesc_method"]:
            S.append(f'<div class="cred-box"><strong>🔑 Élévation de privilèges</strong> : '
                     f'{esc(shell_info["privesc_method"])} '
                     f'{"(<code>" + esc(shell_info["privesc_id"]) + "</code>)" if shell_info["privesc_id"] else ""}</div>')

        for pf in pe_files:
            try:
                content_p = ansi_re.sub("",
                    pf.read_text(encoding="utf-8", errors="replace")).strip()
                if not content_p: continue
                lbl_p = pf.stem.replace("_"," ").title()
                S.append(f'<details><summary class="details-sum">🔎 {esc(lbl_p)}</summary>')
                S.append(f'<pre class="logblock">{esc(content_p[:3000])}</pre>')
                S.append('</details>')
            except Exception:
                pass

        if not pe_files and not got_shell:
            S.append('<p class="muted">Shell non obtenu — aucune donnée post-exploitation.</p>')
        S.append('</section>')

    # ─── 7. SMB / ENUM4LINUX ──────────────────────────────────────────────
    e4l_log = read_log("enum4linux_ng.txt") or read_log("enum4linux_cmd.txt")
    if e4l_log:
        # Extraire shares, users, groups
        shares  = _re.findall(r'(?:Share|Sharename)[\s:]+(\S+)', e4l_log, _re.I)
        smb_users = _re.findall(r'(?:user|username)[\s:]+(\S+)', e4l_log, _re.I)[:10]
        S.append('<section class="card"><h2>📁 SMB / Enum4linux</h2>')
        if shares:
            S.append('<h3>Partages SMB</h3><ul>')
            for sh in set(shares):
                S.append(f'<li><code>{esc(sh)}</code></li>')
            S.append('</ul>')
        if smb_users:
            S.append('<h3>Utilisateurs SMB</h3><ul>')
            for u in set(smb_users):
                S.append(f'<li><code>{esc(u)}</code></li>')
            S.append('</ul>')
        if not shares and not smb_users:
            S.append('<pre class="logblock">' + esc(e4l_log[:1500]) + '</pre>')
        S.append('</section>')

    # ─── 8. TIMELINE / TIMINGS ────────────────────────────────────────────
    if timings:
        S.append('<section class="card"><h2>⏱ Timeline d\'Exécution</h2>')
        S.append('<table><thead><tr><th>Phase</th><th>Durée</th><th></th></tr></thead><tbody>')
        total_secs = timings.get("total", 0) or 1
        for k, v in timings.items():
            if k == "total": continue
            label_k = k.replace("_"," ").title()
            pct = min(int(v / total_secs * 100), 100)
            S.append(f'<tr><td>{esc(label_k)}</td><td class="mono">{fmt_dur(v)}</td>'
                     f'<td><div class="progress-bar"><div style="width:{pct}%"></div></div></td></tr>')
        S.append(f'<tr class="total-row"><td><strong>Total</strong></td>'
                 f'<td class="mono"><strong>{fmt_dur(timings.get("total"))}</strong></td><td></td></tr>')
        S.append('</tbody></table>')
        S.append('</section>')

    # ─── 9. ANNEXES ───────────────────────────────────────────────────────
    annexe_files = []
    if logs_dir.exists():
        annexe_files = sorted([f for f in logs_dir.glob("*.txt") if f.stat().st_size > 0],
                              key=lambda f: f.stat().st_mtime)

    if annexe_files:
        S.append('<section class="card"><h2>📎 Annexes — Logs Bruts</h2>')
        S.append('<p class="muted small">Cliquez sur un fichier pour déplier son contenu.</p>')
        for af in annexe_files:
            try:
                content_a = ansi_re.sub("",
                    af.read_text(encoding="utf-8", errors="replace")).strip()
                if not content_a: continue
                size_kb = af.stat().st_size // 1024
                S.append(f'<details><summary class="details-sum annex-sum">'
                         f'📄 {esc(af.name)} <span class="muted small">({size_kb} ko)</span>'
                         f'</summary>')
                S.append(f'<pre class="logblock annex">{esc(content_a[:5000])}'
                         f'{"..." if len(content_a) > 5000 else ""}</pre>')
                S.append('</details>')
            except Exception:
                pass
        S.append('</section>')

    # ─── ASSEMBLAGE FINAL ─────────────────────────────────────────────────
    body = "\n".join(S)
    lhost = esc(cfg.get("lhost") or "—")
    preset = esc(cfg.get("preset") or "—")

    html_page = f"""<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Rapport — {esc(target)} ({esc(run_id)})</title>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    :root {{
      --bg: #0d1117; --bg2: #161b22; --bg3: #1c2128;
      --border: #30363d; --text: #e6edf3; --muted: #8b949e;
      --green: #3fb950; --green2: #238636;
      --blue: #58a6ff; --orange: #f0883e; --red: #f85149;
    }}
    body {{ font-family: -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
            background:var(--bg); color:var(--text);
            max-width:1100px; margin:0 auto; padding:24px 16px;
            font-size:14px; line-height:1.6; }}
    /* Header */
    .report-header {{ display:flex; align-items:center; justify-content:space-between;
                      background:var(--bg2); border:1px solid var(--border);
                      border-radius:12px; padding:20px 24px; margin-bottom:20px; }}
    .header-brand {{ display:flex; align-items:center; gap:14px; }}
    .logo-pt {{ background:var(--green2); color:#fff; font-weight:800;
                width:42px; height:42px; border-radius:8px;
                display:flex; align-items:center; justify-content:center;
                font-size:1.1rem; letter-spacing:-1px; flex-shrink:0; }}
    .report-title {{ font-size:1.2rem; font-weight:700; }}
    .report-sub {{ color:var(--muted); font-size:.82rem; }}
    .header-status {{ border:2px solid; border-radius:8px;
                      padding:8px 16px; font-weight:700; font-size:.9rem; }}
    /* Meta grid */
    .meta-grid {{ display:grid; grid-template-columns:repeat(auto-fill,minmax(130px,1fr));
                  gap:10px; margin-bottom:20px; }}
    .meta-card {{ background:var(--bg2); border:1px solid var(--border);
                  border-radius:8px; padding:12px 14px; }}
    .mc-label {{ color:var(--muted); font-size:.75rem; text-transform:uppercase;
                 letter-spacing:.05em; margin-bottom:4px; }}
    .mc-val {{ font-size:1rem; font-weight:600; word-break:break-all; }}
    .mc-val.big {{ font-size:1.5rem; }}
    .mc-val.red {{ color:var(--red); }}
    .mc-val.target-val {{ color:var(--blue); font-family:monospace; }}
    /* Cards */
    .card {{ background:var(--bg2); border:1px solid var(--border);
             border-radius:10px; padding:20px 24px; margin-bottom:16px; }}
    h2 {{ font-size:1.05rem; font-weight:700; margin-bottom:14px;
          padding-bottom:8px; border-bottom:1px solid var(--border); }}
    h3 {{ font-size:.9rem; font-weight:600; margin:12px 0 8px; color:var(--green); }}
    /* Tables */
    table {{ width:100%; border-collapse:collapse; font-size:.83rem; margin-bottom:8px; }}
    thead tr {{ background:var(--bg3); }}
    th, td {{ text-align:left; padding:7px 10px; border-bottom:1px solid var(--border); }}
    th {{ color:var(--muted); font-weight:600; font-size:.75rem; text-transform:uppercase; }}
    tr:hover {{ background:rgba(255,255,255,.03); }}
    .total-row td {{ border-top:2px solid var(--border); padding-top:10px; }}
    /* Badges */
    .badge {{ display:inline-block; padding:2px 7px; border-radius:4px;
              font-size:.72rem; font-weight:700; color:#fff;
              text-transform:uppercase; letter-spacing:.04em; margin-right:4px; }}
    /* Findings */
    .finding {{ padding:8px 12px; margin:4px 0; border-radius:6px;
                background:var(--bg3); border-left:3px solid var(--border);
                font-size:.84rem; }}
    .src {{ color:var(--muted); font-size:.75rem; margin-left:8px; }}
    .cvss {{ background:#374151; color:#d1d5db; padding:1px 6px;
             border-radius:4px; font-size:.72rem; margin-left:6px; }}
    /* Creds */
    .cred-box {{ background:#1a0a0a; border:1px solid var(--red);
                 border-radius:8px; padding:12px 16px; margin:10px 0; }}
    .cred {{ color:#f87171; font-family:monospace; font-size:1rem; font-weight:700; }}
    /* Log blocks */
    .logblock {{ background:var(--bg3); border:1px solid var(--border);
                 border-radius:6px; padding:12px; font-family:monospace;
                 font-size:.78rem; white-space:pre-wrap; word-break:break-all;
                 max-height:400px; overflow-y:auto; margin:8px 0; }}
    .logblock.annex {{ max-height:300px; font-size:.72rem; }}
    /* Details */
    details {{ margin:4px 0; }}
    .details-sum {{ cursor:pointer; padding:8px 12px; background:var(--bg3);
                    border:1px solid var(--border); border-radius:6px;
                    font-size:.84rem; font-weight:600; user-select:none; }}
    .details-sum:hover {{ background:#21262d; }}
    details[open] .details-sum {{ border-radius:6px 6px 0 0; border-bottom:none; }}
    details[open] > *:not(summary) {{ border:1px solid var(--border);
      border-top:none; border-radius:0 0 6px 6px; }}
    .annex-sum {{ font-family:monospace; font-size:.78rem; font-weight:400; }}
    /* Progress */
    .progress-bar {{ background:var(--bg3); border-radius:4px; height:8px;
                     width:200px; overflow:hidden; }}
    .progress-bar div {{ background:var(--green); height:100%; border-radius:4px;
                         transition:width .3s; }}
    /* Misc */
    .mono {{ font-family:monospace; }}
    .port {{ color:var(--blue); font-weight:700; }}
    .muted {{ color:var(--muted); }}
    .small {{ font-size:.78rem; }}
    code {{ background:var(--bg3); padding:1px 5px; border-radius:3px;
            font-family:monospace; font-size:.88em; color:var(--blue); }}
    .vuln-item {{ color:var(--orange); margin:3px 0; }}
    p {{ margin:6px 0; }}
    ul {{ padding-left:18px; }}
    li {{ margin:3px 0; }}
    /* Print */
    @media print {{
      body {{ background:#fff; color:#000; }}
      .card {{ border:1px solid #ccc; page-break-inside:avoid; }}
      .logblock {{ max-height:none; }}
    }}
    /* Print button */
    .print-bar {{ display:flex; gap:10px; margin-bottom:16px; }}
    .btn-action {{ background:var(--bg2); border:1px solid var(--border);
                   color:var(--text); padding:8px 14px; border-radius:6px;
                   cursor:pointer; font-size:.83rem; text-decoration:none;
                   display:inline-block; }}
    .btn-action:hover {{ background:var(--bg3); }}
    .btn-action.primary {{ background:var(--green2); border-color:var(--green2);
                           color:#fff; }}
  </style>
</head>
<body>

<div class="print-bar">
  <button class="btn-action primary" onclick="window.print()">🖨 Imprimer / Exporter PDF</button>
  <a class="btn-action" href="/download/{esc(run_id)}/report.json">⬇ report.json</a>
  <a class="btn-action" href="/download/{esc(run_id)}/report.md">⬇ report.md</a>
  <a class="btn-action" href="/runs/{esc(run_id)}">← Retour logs</a>
</div>

{body}

<footer style="text-align:center;color:var(--muted);font-size:.75rem;padding:24px 0;margin-top:24px;border-top:1px solid var(--border)">
  Rapport généré par pentool v{version} · {scan_date} · Cible : {esc(target)} ({esc(run_id)}) ·
  LHOST : {lhost} · Preset : {preset}
</footer>

</body>
</html>"""

    return html_page, 200, {"Content-Type": "text/html; charset=utf-8"}


@app.get("/api/confirm/<run_id>")
def api_confirm_pending(run_id: str):
    """
    Retourne la liste des confirmations en attente pour un run donné.
    Le script pentool écrit un fichier confirm_<action_id>.json quand il a
    besoin d'une validation utilisateur avant une action d'exploitation.
    """
    r = RUNS.get(run_id)
    if not r:
        return abort(404)

    confirm_dir = WORKSPACE / "_webui" / run_id
    pending = []

    if confirm_dir.exists():
        for f in confirm_dir.glob("confirm_*.json"):
            # Exclure les fichiers de réponse (_response.json)
            if f.name.endswith("_response.json"):
                continue
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                if data.get("status") == "pending":
                    pending.append(data)
            except Exception:
                pass

    return jsonify({"pending": pending})


@app.post("/api/confirm/<run_id>/<action_id>")
def api_confirm_respond(run_id: str, action_id: str):
    """
    Enregistre la réponse de l'utilisateur (oui/non) pour une confirmation.
    Le script pentool lit ce fichier de réponse et reprend son exécution.
    Body JSON attendu : {"confirmed": true} ou {"confirmed": false}
    """
    if not validate_csrf_token():
        # Pour les requêtes AJAX, accepter aussi un header X-CSRFToken
        token_header = request.headers.get("X-CSRFToken", "")
        token_session = session.get("_csrf_token", "")
        if not token_header or not token_session:
            return abort(403, "Token CSRF invalide")
        if not secrets.compare_digest(token_header, token_session):
            return abort(403, "Token CSRF invalide")

    r = RUNS.get(run_id)
    if not r:
        return abort(404)

    data = request.get_json(silent=True) or {}
    confirmed = bool(data.get("confirmed", False))

    confirm_dir = WORKSPACE / "_webui" / run_id
    confirm_dir.mkdir(parents=True, exist_ok=True)

    response_file = confirm_dir / f"confirm_{action_id}_response.json"
    try:
        response_file.write_text(
            json.dumps({"confirmed": confirmed, "timestamp": time.time()}, indent=2),
            encoding="utf-8",
        )
        # Marquer le fichier pending comme traité pour que le poll ne le remonte plus
        original_file = confirm_dir / f"confirm_{action_id}.json"
        if original_file.exists():
            try:
                orig = json.loads(original_file.read_text(encoding="utf-8"))
                orig["status"] = "responded"
                original_file.write_text(json.dumps(orig, indent=2), encoding="utf-8")
            except Exception:
                pass
    except Exception as e:
        return jsonify({"ok": False, "message": str(e)}), 500

    return jsonify({"ok": True, "confirmed": confirmed})


@app.get("/api/lhost")
def api_lhost():
    """
    Détecte automatiquement le LHOST (IP VPN) depuis le host macOS ou Linux.
    Lit /proc/net/fib_trie (Linux) ou parse ifconfig (macOS via fichier partagé).
    Priorité : tun* / utun* (VPN) > eth* > fallback.
    """
    import subprocess as _sp
    import re as _re

    # ── Préférence réseau VPN : plages TryHackMe/HTB connues ──────────────
    # TryHackMe OpenVPN: 10.x.x.x ou 192.168.x.x point-to-point
    # HTB OpenVPN: 10.10.x.x
    # On exclut: 127.x, 172.17-172.20 (Docker/hotspot), 192.168.137.x ok car THM
    def _is_vpn_ip(ip: str) -> bool:
        """Retourne True si l'IP ressemble à une IP VPN pentest (pas hotspot/Docker)."""
        if ip.startswith("127."):
            return False
        if ip.startswith("172.17.") or ip.startswith("172.18.") or ip.startswith("172.19."):
            return False  # Docker bridge
        if ip.startswith("172.20.") or ip.startswith("172.16."):
            return False  # iPhone hotspot / link-local
        return True

    # ── Méthode 1 : ip addr (Linux/Docker) ────────────────────────────────
    try:
        all_ifaces = _sp.check_output(["ip", "addr"], stderr=_sp.DEVNULL, text=True)
        # Extraire couples (iface, ip)
        current_iface = ""
        iface_ips = []
        for line in all_ifaces.splitlines():
            m_iface = _re.match(r'^\d+:\s+(\S+):', line)
            if m_iface:
                current_iface = m_iface.group(1).rstrip(":")
            m_ip = _re.match(r'\s+inet (\d+\.\d+\.\d+\.\d+)', line)
            if m_ip:
                iface_ips.append((current_iface, m_ip.group(1)))

        # Priorité 1 : tun* (OpenVPN Linux)
        for iface, ip in iface_ips:
            if iface.startswith("tun") and _is_vpn_ip(ip):
                return jsonify({"lhost": ip, "iface": iface})
        # Priorité 2 : eth* / ens* (câblé Linux)
        for iface, ip in iface_ips:
            if (iface.startswith("eth") or iface.startswith("ens") or iface.startswith("enp")) \
                    and _is_vpn_ip(ip):
                return jsonify({"lhost": ip, "iface": iface})
    except Exception:
        pass

    # ── Méthode 2 : lire /host_ifconfig.txt si le host l'a écrit (macOS) ──
    # Le container peut lire un fichier partagé depuis le host via le volume /runs
    host_ifc = Path(os.environ.get("PENTOOL_WORKSPACE", "/runs")) / "_host_ifconfig.txt"
    if host_ifc.exists():
        try:
            ifc_text = host_ifc.read_text(encoding="utf-8", errors="replace")
            current_iface = ""
            candidates = []  # (priorité, iface, ip)
            for line in ifc_text.splitlines():
                m_iface = _re.match(r'^(\S+):', line)
                if m_iface:
                    current_iface = m_iface.group(1)
                m_inet = _re.search(r'inet (\d+\.\d+\.\d+\.\d+)', line)
                if m_inet and current_iface:
                    ip = m_inet.group(1)
                    if not _is_vpn_ip(ip):
                        continue
                    # utun* = VPN macOS (OpenVPN via utun, WireGuard)
                    if current_iface.startswith("utun"):
                        candidates.append((0, current_iface, ip))
                    elif current_iface.startswith("tun"):
                        candidates.append((1, current_iface, ip))
                    else:
                        candidates.append((9, current_iface, ip))
            if candidates:
                candidates.sort()
                _, iface, ip = candidates[0]
                return jsonify({"lhost": ip, "iface": iface + " (host)"})
        except Exception:
            pass

    # ── Fallback : première IP non-loopback/hotspot dans le container ─────
    ips = _get_all_ips()
    vpn_ips = [ip for ip in ips if _is_vpn_ip(ip)]
    if vpn_ips:
        return jsonify({"lhost": vpn_ips[0], "iface": "auto"})
    if ips:
        return jsonify({"lhost": ips[0], "iface": "auto (non-filtré)"})

    return jsonify({"lhost": None})


# ────────────────────────── Main ──────────────────────────

def _get_all_ips() -> list:
    """Retourne toutes les IPs non-loopback de la machine."""
    import socket as _s
    ips = []
    try:
        hostname = _s.gethostname()
        infos = _s.getaddrinfo(hostname, None)
        for info in infos:
            ip = info[4][0]
            if not ip.startswith("127.") and ":" not in ip:
                if ip not in ips:
                    ips.append(ip)
    except Exception:
        pass
    return ips


if __name__ == "__main__":
    _init_persistence()
    print(f"[+] Pentool WebUI démarré sur le port {PORT}")
    print(f"[+] Pentool script: {PENTOOL_PATH}")
    print(f"[+] Workspace: {WORKSPACE}")
    print(f"[+] Security: CSRF=on | Headers=on | Localhost=blocked | Persistence=on")
    print()
    print(f"[+] URLs d'accès :")
    print(f"    http://127.0.0.1:{PORT}  (si accès local direct)")
    for ip in _get_all_ips():
        print(f"    http://{ip}:{PORT}  ← utilise cette URL depuis ton navigateur")
    print()
    app.run(host=HOST, port=PORT, threaded=True)
