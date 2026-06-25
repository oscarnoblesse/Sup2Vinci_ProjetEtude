"""
reporting.py — Module de reporting Pentool v0.64

Génère 3 formats de rapport :
  - report.md   : Markdown structuré enrichi
  - report.json : JSON machine-readable (CVSS + Kill Chain)
  - report.html : Rapport HTML professionnel AUTO-CONTENU

Nouveautés v0.64 :
  - Contenu des scans EMBEDÉ directement dans le rapport HTML
    (plus de liens vers des fichiers locaux inaccessibles)
  - Parsing intelligent de chaque format de sortie :
      * Nmap .nmap  → extraction CVE, VULNERABLE, bannières
      * Nuclei JSONL → tableau de findings avec sévérité
      * Searchsploit → tableau d'exploits Exploit-DB
      * WhatWeb     → technologies détectées
      * Gobuster / ffuf → répertoires trouvés
      * Nikto        → checks de sécurité web
      * enum4linux-ng → shares, utilisateurs, sessions null
  - Sections <details>/<summary> collapsibles par outil
  - Rapport 100 % auto-contenu et imprimable (sans accès machine)

Usage :
  from reporting import generate_reports
  report_paths = generate_reports(run_dir, app_name, version,
                                  cfg_dict, services, findings,
                                  urls, web_logs, timings)
"""

from __future__ import annotations

import html
import json
import re
import datetime as dt
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple

# ────────────────────────── KILL CHAIN ──────────────────────────

KILL_CHAIN_PHASES = [
    {
        "id": "recon",
        "phase": "1 — Reconnaissance",
        "description": "Identification de la cible, découverte des ports ouverts et des points d'entrée réseau.",
        "tools": ["Nmap (ports discovery)", "DNS resolution"],
        "mitre": "TA0043 — Reconnaissance",
    },
    {
        "id": "enum",
        "phase": "2 — Scanning & Enumeration",
        "description": "Détection des services, versions logicielles et configurations exposées sur chaque port ouvert.",
        "tools": ["Nmap (-sV -sC)", "Banner grabbing"],
        "mitre": "TA0007 — Discovery",
    },
    {
        "id": "vuln",
        "phase": "3 — Vulnerability Analysis",
        "description": "Identification des vulnérabilités connues (CVE) et des exploits publics associés aux services détectés.",
        "tools": ["Nmap NSE vuln scripts", "Searchsploit (Exploit-DB)", "Nuclei (templates communautaires)"],
        "mitre": "TA0001 — Initial Access (préparation)",
    },
    {
        "id": "web",
        "phase": "4a — Web Application Analysis",
        "description": "Fingerprinting des technologies web, recherche de misconfigurations, découverte de répertoires cachés, robots.txt, JS secrets, .git exposure.",
        "tools": ["WhatWeb", "Nikto", "Gobuster / ffuf", "JS Scraper", "git_exposure_check"],
        "mitre": "TA0007 — Discovery (Web)",
    },
    {
        "id": "smb",
        "phase": "4b — SMB/NetBIOS Enumeration",
        "description": "Extraction des shares, utilisateurs, policies de mot de passe et sessions null via SMB.",
        "tools": ["enum4linux-ng"],
        "mitre": "TA0007 — Discovery (Network)",
    },
    {
        "id": "wordpress",
        "phase": "4c — WordPress Recon & Exploitation",
        "description": "Détection WordPress, scan de vulnérabilités de plugins/thèmes, brute force des comptes, injection de payload PHP via l'éditeur de thème.",
        "tools": ["WPScan", "WP Brute Force (XML-RPC)", "WP Theme Injection"],
        "mitre": "TA0001 — Initial Access (Web App)",
    },
    {
        "id": "exploit",
        "phase": "5 — Exploitation",
        "description": "Exploitation contrôlée des vulnérabilités identifiées (FTP anon, SMB anon, SSH, Hydra brute) pour prouver l'impact.",
        "tools": ["FTP anon access", "SMB anon access", "Hydra brute force", "SSH exploit"],
        "mitre": "TA0002 — Execution",
    },
    {
        "id": "postexploit",
        "phase": "6 — Post-Exploitation",
        "description": "Énumération interne après accès initial : sudo, SUID, crontab, réseau interne, fichiers sensibles.",
        "tools": ["Shell recon (sudo/SUID/crontab/network/secrets)"],
        "mitre": "TA0004 — Privilege Escalation / TA0009 — Collection",
    },
    {
        "id": "report",
        "phase": "7 — Reporting",
        "description": "Consolidation des résultats, scoring des risques, recommandations de remédiation.",
        "tools": ["Pentool reporting engine"],
        "mitre": "—",
    },
]


def _kill_chain_status(timings: Dict[str, float], cfg_dict: dict) -> List[dict]:
    phases = []
    for kc in KILL_CHAIN_PHASES:
        status = "skipped"
        duration = None

        if kc["id"] == "recon":
            if "nmap_ports" in timings or "nmap_single" in timings:
                status = "done"
                duration = timings.get("nmap_ports") or timings.get("nmap_single")

        elif kc["id"] == "enum":
            if "nmap_enum" in timings or "nmap_single" in timings:
                status = "done"
                duration = timings.get("nmap_enum") or timings.get("nmap_single")

        elif kc["id"] == "vuln":
            if cfg_dict.get("no_vuln") and not cfg_dict.get("run_searchsploit") and not cfg_dict.get("run_nuclei"):
                status = "skipped"
            else:
                if "nmap_vuln" in timings or "searchsploit" in timings or "nuclei" in timings:
                    status = "done"
                    duration = (timings.get("nmap_vuln", 0) + timings.get("searchsploit", 0) + timings.get("nuclei", 0)) or None

        elif kc["id"] == "web":
            if cfg_dict.get("no_web"):
                status = "skipped"
            elif any(k in timings for k in ("web_enum", "robots", "js_scraper", "git_check", "archives")):
                status = "done"
                duration = (timings.get("web_enum", 0) + timings.get("robots", 0)
                            + timings.get("js_scraper", 0) + timings.get("git_check", 0)) or None

        elif kc["id"] == "smb":
            if not cfg_dict.get("run_enum4linux"):
                status = "skipped"
            elif "enum4linux" in timings:
                status = "done"
                duration = timings.get("enum4linux")

        elif kc["id"] == "wordpress":
            if "wp_recon" in timings or "wp_brute" in timings or "wp_theme_inject" in timings:
                status = "done"
                duration = (timings.get("wp_recon", 0) + timings.get("wp_brute", 0)
                            + timings.get("wp_theme_inject", 0)) or None
            elif not cfg_dict.get("run_wp_brute") and not cfg_dict.get("run_wp_exploit"):
                status = "skipped"

        elif kc["id"] == "exploit":
            if "exploitation" in timings:
                status = "done"
                duration = timings.get("exploitation")
            elif cfg_dict.get("run_exploit") is False:
                status = "skipped"
            else:
                status = "not_implemented"

        elif kc["id"] == "postexploit":
            if "post_exploitation" in timings:
                status = "done"
                duration = timings.get("post_exploitation")
            elif cfg_dict.get("run_postexploit") is False:
                status = "skipped"
            else:
                status = "not_implemented"

        elif kc["id"] == "report":
            status = "done"

        phases.append({**kc, "status": status, "duration": duration})
    return phases


# ────────────────────────── CVSS SCORING ──────────────────────────

HIGH_RISK_SERVICES = {
    "ftp": 6.5, "telnet": 8.0, "ssh": 5.3, "smtp": 5.8,
    "http": 5.0, "https": 4.5, "smb": 7.5, "microsoft-ds": 7.5,
    "netbios-ssn": 6.0, "mysql": 6.5, "postgresql": 6.5,
    "ms-sql-s": 7.0, "oracle": 7.0, "vnc": 7.5, "rdp": 7.0,
    "ms-wbt-server": 7.0, "rpcbind": 5.0, "nfs": 6.0,
    "ldap": 6.5, "snmp": 6.0, "redis": 7.5, "mongodb": 7.5,
    "memcached": 7.0, "elasticsearch": 7.0,
}

CRITICAL_VERSION_KEYWORDS = [
    "eol", "end of life", "outdated", "vulnerable",
    "2.2.", "2.4.1", "1.0.",
    "5.5.", "5.6.",
    "7.2", "7.3",
]


def _score_service(svc: dict) -> dict:
    name = (svc.get("name") or "").lower()
    product = (svc.get("product") or "").lower()
    version = (svc.get("version") or "").lower()

    base_score = 3.0
    for svc_name, score in HIGH_RISK_SERVICES.items():
        if svc_name in name or svc_name in product:
            base_score = max(base_score, score)
            break

    version_bump = 0.0
    for kw in CRITICAL_VERSION_KEYWORDS:
        if kw in version or kw in product:
            version_bump = 1.5
            break

    if name in ("telnet", "ftp") and "ssl" not in name:
        base_score = max(base_score, 8.0)

    final_score = min(10.0, base_score + version_bump)

    if final_score >= 9.0:
        severity = "Critical"
    elif final_score >= 7.0:
        severity = "High"
    elif final_score >= 4.0:
        severity = "Medium"
    elif final_score > 0:
        severity = "Low"
    else:
        severity = "Info"

    parts = []
    if final_score >= 7.0:
        parts.append("Surface d'attaque élevée")
    if name in ("telnet", "ftp") and "ssl" not in name:
        parts.append("Protocole en clair (pas de chiffrement)")
    if any(kw in version or kw in product for kw in CRITICAL_VERSION_KEYWORDS):
        parts.append("Version potentiellement obsolète")
    if not parts:
        parts.append("Port ouvert exposé")

    return {
        **svc,
        "cvss_score": round(final_score, 1),
        "cvss_severity": severity,
        "cvss_rationale": " ; ".join(parts) + ".",
    }


# ────────────────────────── PARSERS DE LOGS ──────────────────────────

def _read_file(path: Any) -> str:
    """Lit un fichier texte de manière sécurisée. Retourne '' si absent."""
    try:
        p = Path(str(path))
        if p.exists() and p.is_file():
            return p.read_text(encoding="utf-8", errors="replace")
    except Exception:
        pass
    return ""


def _find_log(logs_dir: Path, *patterns: str) -> Optional[Path]:
    """Trouve le premier fichier existant parmi les patterns."""
    for pat in patterns:
        p = logs_dir / pat
        if p.exists():
            return p
        # Glob si le pattern contient *
        if "*" in pat:
            matches = sorted(logs_dir.glob(pat))
            if matches:
                return matches[0]
    return None


def _find_logs_glob(logs_dir: Path, pattern: str) -> List[Path]:
    """Retourne tous les fichiers correspondant au glob."""
    try:
        return sorted(logs_dir.glob(pattern))
    except Exception:
        return []


# ── Parser Nmap .nmap (texte) ──

def _parse_nmap_text(text: str) -> dict:
    """
    Extrait de la sortie Nmap :
    - CVE mentionnées
    - Lignes VULNERABLE
    - Bannières de services
    - Lignes d'intérêt général
    """
    if not text:
        return {"cves": [], "vulnerable_lines": [], "banners": [], "raw_lines": 0}

    lines = text.splitlines()
    cves = sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", text)))
    vulnerable_lines = [l.strip() for l in lines if "VULNERABLE" in l.upper()]
    banners = []
    for l in lines:
        ls = l.strip()
        if ls.startswith("|") and any(kw in ls.lower() for kw in ["server:", "x-powered", "banner:", "product:", "version:"]):
            banners.append(ls)

    return {
        "cves": cves,
        "vulnerable_lines": vulnerable_lines[:50],
        "banners": banners[:30],
        "raw_lines": len(lines),
    }


def _parse_nmap_enum_text(text: str) -> List[str]:
    """Extrait les lignes importantes du scan d'énumération Nmap."""
    if not text:
        return []
    keep = []
    for line in text.splitlines():
        ls = line.strip()
        if not ls or ls.startswith("#"):
            continue
        if any(ls.startswith(p) for p in ["PORT", "ORT", "Nmap scan", "Host is", "Service", "MAC"]):
            keep.append(ls)
        elif "/tcp" in ls or "/udp" in ls:
            keep.append(ls)
        elif ls.startswith("|") and len(ls) < 200:
            keep.append(ls)
    return keep[:120]


# ── Parser Nuclei JSONL ──

def _parse_nuclei_jsonl(text: str) -> List[dict]:
    """Parse le fichier JSONL de Nuclei en liste de findings structurés."""
    findings = []
    if not text:
        return findings
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            j = json.loads(line)
            info = j.get("info", {})
            findings.append({
                "template_id": j.get("template-id", ""),
                "name": info.get("name", j.get("template-id", "?")),
                "severity": (info.get("severity") or "info").lower(),
                "description": info.get("description", ""),
                "matched_at": j.get("matched-at", ""),
                "host": j.get("host", ""),
                "tags": ", ".join(info.get("tags", [])),
                "reference": ", ".join(info.get("reference", []) or []),
            })
        except Exception:
            pass
    # Tri par sévérité
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
    findings.sort(key=lambda x: sev_order.get(x["severity"], 5))
    return findings


# ── Parser Searchsploit ──

def _parse_searchsploit(text: str) -> List[dict]:
    """
    Parse la sortie texte de searchsploit --nmap.
    Extrait les lignes contenant | (tableau d'exploits).
    """
    results = []
    if not text:
        return results
    for line in text.splitlines():
        line = line.strip()
        if "|" not in line:
            continue
        if "Exploit Title" in line or "---" in line or not line:
            continue
        parts = line.split("|")
        if len(parts) >= 2:
            title = parts[0].strip()
            path = parts[-1].strip() if len(parts) >= 2 else ""
            if title:
                results.append({"title": title, "path": path})
    return results[:100]


# ── Parser WhatWeb ──

def _parse_whatweb(text: str) -> List[str]:
    """Extrait les lignes de fingerprinting WhatWeb pertinentes."""
    if not text:
        return []
    lines = []
    for line in text.splitlines():
        ls = line.strip()
        if not ls or ls.startswith("#") or ls.startswith("$"):
            continue
        if "http" in ls.lower() or "[" in ls:
            lines.append(ls[:300])
    return lines[:50]


# ── CSV split helper (module-level) ──

def _csv_split(line: str) -> List[str]:
    """Split CSV simple gérant les champs entre guillemets doubles."""
    fields: List[str] = []
    current: List[str] = []
    in_quotes = False
    for ch in line:
        if ch == '"':
            in_quotes = not in_quotes
        elif ch == "," and not in_quotes:
            fields.append("".join(current).strip())
            current = []
        else:
            current.append(ch)
    fields.append("".join(current).strip())
    return fields


# Colonnes connues dans la sortie CSV de ffuf
# (varie selon la version mais ces champs sont toujours présents)
_FFUF_CSV_HEADER_FIELDS = {"url", "status_code", "content_length", "redirectlocation", "position"}


def _is_ffuf_csv_header(line: str) -> bool:
    """Détecte si une ligne est l'en-tête CSV de ffuf."""
    parts = {p.strip().lower() for p in line.split(",")}
    # Au moins 3 champs connus → c'est bien un header ffuf
    return len(parts & _FFUF_CSV_HEADER_FIELDS) >= 3


# ── Parser Gobuster / ffuf ──

def _parse_gobuster(text: str) -> List[str]:
    """Extrait les répertoires/fichiers trouvés par gobuster.

    run_cmd préfixe le fichier avec :
      $ gobuster dir ...
      # started: ...
    Ces lignes sont ignorées via les gardes $ et #.
    """
    if not text:
        return []
    results = []
    for line in text.splitlines():
        ls = line.strip()
        if not ls or ls.startswith("#") or ls.startswith("$") or ls.startswith("="):
            continue
        if ls.startswith("/") or "(Status:" in ls:
            results.append(ls[:200])
    return results[:100]


def _parse_ffuf_csv(text: str) -> List[dict]:
    """
    Parse la sortie CSV de ffuf capturée par run_cmd.

    run_cmd préfixe le fichier capturé avec :
      $ ffuf -u http://... -of csv
      # started: 2026-03-16 12:00:00
      <ligne vide>
      url,redirectlocation,position,status_code,content_length,...  ← vraie ligne header
      http://target/admin,,1,301,312,...

    On ignore tout jusqu'à trouver la vraie ligne d'en-tête CSV
    (détectée par présence d'au moins 3 champs connus de ffuf).
    """
    results = []
    if not text:
        return results

    lines = text.splitlines()
    header: List[str] = []
    data_lines: List[str] = []
    in_data = False

    for line in lines:
        stripped = line.strip()
        if not in_data:
            # Ignore les lignes run_cmd ($, #) et les lignes vides
            if not stripped or stripped.startswith("$") or stripped.startswith("#"):
                continue
            # Cherche le vrai header CSV ffuf
            if _is_ffuf_csv_header(stripped):
                header = [h.strip().lower() for h in stripped.split(",")]
                in_data = True
        else:
            # Fin du bloc données : lignes run_cmd de fin de fichier
            if stripped.startswith("#") or stripped.startswith("$"):
                break
            if stripped:
                data_lines.append(stripped)

    if not header or not data_lines:
        return results

    for line in data_lines:
        parts = _csv_split(line)
        if len(parts) >= len(header):
            row = {header[i]: parts[i] for i in range(len(header))}
            results.append(row)

    return results[:200]


def _parse_ffuf_raw(text: str) -> List[str]:
    """
    Fallback si ffuf est lancé sans -of csv (sortie terminale).
    Format typique :
      phpMyAdmin   [Status: 301, Size: 323, Words: 20, Lines: 10, Duration: 12ms]
    """
    results = []
    if not text:
        return results
    for line in text.splitlines():
        ls = line.strip()
        if not ls or ls.startswith("$") or ls.startswith("#"):
            continue
        if "[Status:" in ls:
            results.append(ls[:300])
        elif ls.startswith("/") and "Status:" in ls:
            results.append(ls[:300])
    return results[:200]


# ── Parser Nikto ──

def _parse_nikto(text: str) -> List[str]:
    """Extrait les findings Nikto."""
    if not text:
        return []
    results = []
    for line in text.splitlines():
        ls = line.strip()
        if not ls or ls.startswith("#") or ls.startswith("$"):
            continue
        if ls.startswith("+") or ls.startswith("-"):
            results.append(ls[:300])
    return results[:80]


# ── Parser enum4linux-ng ──

def _parse_enum4linux(text: str, json_path: Optional[Path] = None) -> dict:
    """Parse la sortie enum4linux-ng."""
    result = {"shares": [], "users": [], "null_session": False, "os_info": "", "raw_lines": []}

    # Essai JSON d'abord
    if json_path:
        json_text = _read_file(json_path)
        if json_text:
            try:
                data = json.loads(json_text)
                shares = data.get("shares") or {}
                result["shares"] = list(shares.keys()) if isinstance(shares, dict) else []
                users = data.get("users") or {}
                result["users"] = list(users.keys()) if isinstance(users, dict) else []
                result["null_session"] = bool(data.get("null_session_possible"))
                os_info = data.get("os_info") or {}
                if os_info:
                    result["os_info"] = str(os_info.get("os", "") or os_info.get("domain", ""))
                return result
            except Exception:
                pass

    # Fallback texte
    if not text:
        return result
    for line in text.splitlines():
        ls = line.strip()
        result["raw_lines"].append(ls)
        if "null session" in ls.lower():
            result["null_session"] = True
        if "share" in ls.lower() and "|" in ls:
            parts = ls.split("|")
            if parts:
                result["shares"].append(parts[0].strip())
        if "username:" in ls.lower():
            m = re.search(r"username:\s*(\S+)", ls, re.I)
            if m:
                result["users"].append(m.group(1))
    result["raw_lines"] = result["raw_lines"][:80]
    return result


# ── Flags CTF ──

# Patterns de flags CTF courants
_FLAG_PATTERNS = [
    r'HTB\{[^}\n]{1,200}\}',
    r'THM\{[^}\n]{1,200}\}',
    r'picoCTF\{[^}\n]{1,200}\}',
    r'flag\{[^}\n]{1,200}\}',
    r'FLAG\{[^}\n]{1,200}\}',
    r'DUCTF\{[^}\n]{1,200}\}',
    r'ctf\{[^}\n]{1,200}\}',
    r'CTF\{[^}\n]{1,200}\}',
    r'root\{[^}\n]{1,200}\}',
    r'user\{[^}\n]{1,200}\}',
    r'[A-Z]{2,10}\{[a-zA-Z0-9_\-\.=+/]{8,120}\}',  # format générique CTF
    r'(?<![a-f0-9])[a-f0-9]{32}(?![a-f0-9])',       # MD5 hex brut (TryHackMe style)
]

def _find_flags(logs_dir: Path) -> List[dict]:
    """Cherche des flags CTF dans tous les fichiers de logs (récursif)."""
    found: List[dict] = []
    seen: set = set()
    if not logs_dir.exists():
        return found

    # ── 1. Lecture directe des fichiers flag_*.txt écrits par le pentool ──────
    # Ces fichiers contiennent la valeur brute du flag (ex. hash MD5 TryHackMe)
    post_exploit_dir = logs_dir / "post_exploit"
    if post_exploit_dir.exists():
        for fpath in sorted(post_exploit_dir.glob("flag_*.txt")):
            try:
                value = fpath.read_text(encoding="utf-8", errors="replace").strip()
                if not value or value in seen:
                    continue
                seen.add(value)
                # Déduire le chemin original depuis le nom de fichier
                # flag_root_root.txt → /root/root.txt
                # flag_home_namelessone_user.txt → /home/namelessone/user.txt
                origin = fpath.stem[5:].replace("_", "/")  # enlève "flag_" et remplace _ par /
                found.append({
                    "flag": value,
                    "file": fpath.name,
                    "context": f"[{origin}] {value}",
                })
            except Exception:
                pass

    # ── 2. Scan regex dans tous les logs ──────────────────────────────────────
    for fpath in sorted(logs_dir.rglob("*.txt")):
        try:
            text = fpath.read_text(encoding="utf-8", errors="replace")
            for pat in _FLAG_PATTERNS:
                for m in re.finditer(pat, text, re.IGNORECASE):
                    flag = m.group(0)
                    if flag in seen:
                        continue
                    seen.add(flag)
                    # Ligne de contexte
                    ls = text.rfind('\n', 0, m.start()) + 1
                    le = text.find('\n', m.end())
                    ctx = text[ls: len(text) if le == -1 else le].strip()[:300]
                    found.append({
                        "flag": flag,
                        "file": fpath.name,
                        "context": ctx,
                    })
        except Exception:
            pass
    return found


# ── Parser robots.txt / sitemap ──

def _parse_robots(text: str) -> dict:
    """Extrait les entrées Disallow/Allow/Sitemap du fichier robots.txt."""
    disallow, allow, sitemaps = [], [], []
    for line in text.splitlines():
        ls = line.strip()
        if ls.lower().startswith("disallow:"):
            v = ls[9:].strip()
            if v:
                disallow.append(v)
        elif ls.lower().startswith("allow:"):
            v = ls[6:].strip()
            if v:
                allow.append(v)
        elif ls.lower().startswith("sitemap:"):
            v = ls[8:].strip()
            if v:
                sitemaps.append(v)
    return {"disallow": disallow[:60], "allow": allow[:60], "sitemaps": sitemaps[:20]}


# ── Parser WPScan ──

def _parse_wpscan(text: str) -> dict:
    """Extrait les infos importantes d'une sortie WPScan."""
    result = {"version": "", "plugins": [], "themes": [], "users": [], "vulns": [], "raw": ""}
    if not text:
        return result
    result["raw"] = text
    for line in text.splitlines():
        ls = line.strip()
        if "WordPress version" in ls:
            m = re.search(r"WordPress version\s+([\d.]+)", ls, re.I)
            if m:
                result["version"] = m.group(1)
        elif "[+] " in ls and "plugin" in ls.lower():
            result["plugins"].append(ls[:200])
        elif "[+] " in ls and "theme" in ls.lower():
            result["themes"].append(ls[:200])
        elif "[+] " in ls and ("user" in ls.lower() or "username" in ls.lower()):
            result["users"].append(ls[:200])
        elif "[!]" in ls or "VULNERABILITY" in ls.upper() or "CVE-" in ls:
            result["vulns"].append(ls[:200])
    result["plugins"] = result["plugins"][:20]
    result["themes"]  = result["themes"][:10]
    result["users"]   = result["users"][:20]
    result["vulns"]   = result["vulns"][:30]
    return result


# ── Parser WP Brute Force ──

def _parse_wp_brute(text: str) -> List[dict]:
    """Extrait les credentials trouvés dans la sortie brute force WP."""
    creds: List[dict] = []
    if not text:
        return creds
    for line in text.splitlines():
        ls = line.strip()
        # Format: [SUCCESS] user:pass ou user:pass FOUND
        m = re.search(r'\[.*?SUCCESS.*?\]\s*(\S+):(\S+)', ls, re.I)
        if not m:
            m = re.search(r'(?:found|valid)\s+.*?(\w+):(\S+)', ls, re.I)
        if not m:
            # wpscan format: [+] Valid Combinations Found: user / pass
            m2 = re.search(r'\|\s*Login:\s*(\S+)\s*\|\s*Password:\s*(\S+)', ls, re.I)
            if m2:
                creds.append({"user": m2.group(1), "password": m2.group(2)})
                continue
        if m:
            creds.append({"user": m.group(1), "password": m.group(2)})
    return creds[:20]


# ────────────────────────── HELPERS HTML ──────────────────────────

def _h(x: Any) -> str:
    return html.escape(str(x or ""))


def _now_iso() -> str:
    return dt.datetime.now().isoformat(timespec="seconds")


def _fmt_duration(secs: Optional[float]) -> str:
    if secs is None:
        return "—"
    secs = max(0, secs)
    if secs >= 3600:
        return f"{secs/3600:.1f}h"
    if secs >= 60:
        return f"{secs/60:.1f}min"
    return f"{secs:.1f}s"


def _severity_color(sev: str) -> str:
    s = sev.lower()
    if s == "critical": return "#9b1d20"
    if s == "high":     return "#d63031"
    if s == "medium":   return "#e67e22"
    if s == "low":      return "#27ae60"
    return "#636e72"


def _severity_bg(sev: str) -> str:
    s = sev.lower()
    if s == "critical": return "#fde8e8"
    if s == "high":     return "#fdeaea"
    if s == "medium":   return "#fef3e2"
    if s == "low":      return "#e8f8f0"
    return "#f0f0f0"


def _severity_badge(sev: str) -> str:
    col = _severity_color(sev)
    bg  = _severity_bg(sev)
    return (
        f'<span style="padding:2px 9px;border-radius:10px;font-size:12px;'
        f'font-weight:700;background:{bg};color:{col}">{_h(sev.upper())}</span>'
    )


def _details_block(summary: str, content: str, open_: bool = False) -> str:
    """Génère un bloc <details> collapsible."""
    op = " open" if open_ else ""
    return (
        f'<details{op} style="margin:8px 0;border:1px solid #e8ecf1;'
        f'border-radius:8px;overflow:hidden">'
        f'<summary style="padding:10px 16px;background:#f4f6f9;cursor:pointer;'
        f'font-weight:600;font-size:14px;user-select:none">{summary}</summary>'
        f'<div style="padding:14px 16px">{content}</div>'
        f'</details>'
    )


def _code_block(text: str, max_lines: int = 200) -> str:
    """Affiche du texte brut dans un bloc code scrollable."""
    lines = (text or "").splitlines()
    if len(lines) > max_lines:
        shown = lines[:max_lines]
        truncated = f"\n… [{len(lines) - max_lines} lignes supplémentaires tronquées] …"
    else:
        shown = lines
        truncated = ""
    content = _h("\n".join(shown)) + _h(truncated)
    return (
        f'<pre style="background:#1e1e1e;color:#d4d4d4;padding:14px;'
        f'border-radius:6px;font-size:12px;overflow-x:auto;white-space:pre;'
        f'max-height:500px;overflow-y:auto;line-height:1.5">{content}</pre>'
    )


def _highlight_cves(text: str) -> str:
    """Met en évidence les CVE dans un texte HTML-escaped."""
    return re.sub(
        r"(CVE-\d{4}-\d{4,7})",
        r'<mark style="background:#fde8e8;color:#9b1d20;padding:1px 4px;border-radius:3px;font-weight:700">\1</mark>',
        _h(text),
    )


def _highlight_vulnerable(text: str) -> str:
    """Met en évidence VULNERABLE et CVE dans du texte HTML-escaped."""
    result = _h(text)
    result = re.sub(
        r"(CVE-\d{4}-\d{4,7})",
        r'<mark style="background:#fde8e8;color:#9b1d20;padding:1px 4px;border-radius:3px;font-weight:700">\1</mark>',
        result,
    )
    result = re.sub(
        r"\b(VULNERABLE|EXPLOITABLE)\b",
        r'<mark style="background:#fde8e8;color:#9b1d20;font-weight:900">\1</mark>',
        result,
    )
    return result


# ────────────────────────── SECTION BUILDERS ──────────────────────────

def _build_nmap_section(logs_dir: Path) -> str:
    """Construit la section complète des résultats Nmap."""
    html_parts = []

    # ── Nmap enum (services) ──
    enum_file = _find_log(logs_dir, "nmap_enum.nmap", "nmap.nmap")
    enum_text = _read_file(enum_file)
    if enum_text:
        important_lines = _parse_nmap_enum_text(enum_text)
        if important_lines:
            content = _code_block("\n".join(important_lines))
        else:
            content = _code_block(enum_text, max_lines=100)
        html_parts.append(_details_block(
            "🔍 Nmap — Énumération des services (ports ouverts)",
            content,
            open_=True,
        ))

    # ── Nmap vuln ──
    vuln_file = _find_log(logs_dir, "nmap_vuln.nmap")
    vuln_text = _read_file(vuln_file)
    if vuln_text:
        parsed = _parse_nmap_text(vuln_text)
        inner = ""

        # CVE trouvées
        if parsed["cves"]:
            cve_badges = " ".join(
                f'<code style="background:#fde8e8;color:#9b1d20;padding:3px 8px;'
                f'border-radius:6px;font-weight:700;font-size:13px">{_h(c)}</code>'
                for c in parsed["cves"]
            )
            inner += f'<div style="margin-bottom:12px"><strong>CVE détectées ({len(parsed["cves"])}) :</strong><br><div style="margin-top:6px;display:flex;flex-wrap:wrap;gap:6px">{cve_badges}</div></div>'

        # Lignes VULNERABLE
        if parsed["vulnerable_lines"]:
            vlines = "\n".join(parsed["vulnerable_lines"])
            inner += f'<div style="margin-bottom:12px"><strong>Mentions VULNERABLE :</strong>'
            inner += f'<pre style="background:#fff8f8;border-left:4px solid #d63031;padding:10px 14px;margin-top:6px;font-size:12px;border-radius:0 6px 6px 0;white-space:pre-wrap">{_highlight_vulnerable(vlines)}</pre></div>'

        # Sortie brute complète
        inner += _details_block(
            f"Sortie brute nmap --script vuln ({parsed['raw_lines']} lignes)",
            _code_block(vuln_text),
        )

        if not inner:
            inner = '<p style="color:#636e72;font-style:italic">Scan NSE vuln exécuté mais aucune vulnérabilité détectée (résultats à valider manuellement).</p>'

        html_parts.append(_details_block(
            f"⚠️ Nmap NSE vuln — {len(parsed['cves'])} CVE | {len(parsed['vulnerable_lines'])} mention(s) VULNERABLE",
            inner,
            open_=bool(parsed["cves"] or parsed["vulnerable_lines"]),
        ))
    else:
        html_parts.append('<p style="color:#636e72;font-style:italic;font-size:13px">Nmap NSE vuln : non exécuté (désactivé ou aucun résultat).</p>')

    return "\n".join(html_parts)


def _build_searchsploit_section(logs_dir: Path, findings: List[dict]) -> str:
    """Construit la section Searchsploit avec les exploits Exploit-DB."""
    ss_file = _find_log(logs_dir, "searchsploit_nmap.txt", "searchsploit_cmd.txt")
    ss_text = _read_file(ss_file)

    # Cherche aussi le finding dans la liste
    ss_finding = next((f for f in findings if f.get("source") == "searchsploit"), None)

    exploits = _parse_searchsploit(ss_text)

    inner = ""
    if ss_finding:
        inner += f'<p style="margin-bottom:10px;font-size:14px"><strong>Résumé :</strong> {_h(ss_finding.get("title", ""))}</p>'

    if exploits:
        rows = "".join(
            f'<tr><td style="font-size:13px">{_h(e["title"])}</td>'
            f'<td style="font-family:monospace;font-size:12px;color:#636e72">{_h(e["path"])}</td></tr>'
            for e in exploits
        )
        inner += (
            f'<p style="margin-bottom:8px;font-size:13px;color:#636e72">'
            f'{len(exploits)} exploit(s) référencé(s) dans Exploit-DB — à valider selon les versions exactes.</p>'
            f'<table style="width:100%;border-collapse:collapse;font-size:13px">'
            f'<thead><tr><th style="background:#1a252f;color:#fff;padding:8px 10px;text-align:left">Titre de l\'exploit</th>'
            f'<th style="background:#1a252f;color:#fff;padding:8px 10px;text-align:left">Chemin Exploit-DB</th></tr></thead>'
            f'<tbody>{rows}</tbody></table>'
        )
    elif ss_text:
        inner += _code_block(ss_text, max_lines=80)
    else:
        return '<p style="color:#636e72;font-style:italic;font-size:13px">Searchsploit : non exécuté ou aucun résultat.</p>'

    count_label = f"{len(exploits)} exploit(s)" if exploits else "résultats"
    return _details_block(
        f"💥 Searchsploit — Références Exploit-DB ({count_label})",
        inner,
        open_=len(exploits) > 0,
    )


def _build_nuclei_section(logs_dir: Path, findings: List[dict]) -> str:
    """Construit la section Nuclei avec les findings parsés."""
    jsonl_file = _find_log(logs_dir, "nuclei_results.jsonl")
    txt_file   = _find_log(logs_dir, "nuclei_results.txt")
    jsonl_text = _read_file(jsonl_file)
    txt_text   = _read_file(txt_file)

    nuclei_finding = next((f for f in findings if f.get("source") == "nuclei"), None)

    nuclei_findings = _parse_nuclei_jsonl(jsonl_text)

    if not nuclei_findings and not txt_text and not nuclei_finding:
        return '<p style="color:#636e72;font-style:italic;font-size:13px">Nuclei : non exécuté ou aucun résultat.</p>'

    inner = ""

    if nuclei_finding:
        sev_data = nuclei_finding.get("severities", {})
        badges = " ".join(
            f'{_severity_badge(k)} <span style="font-weight:700">{v}</span>'
            for k, v in sev_data.items()
        )
        inner += f'<p style="margin-bottom:12px">{badges if badges else _h(nuclei_finding.get("title",""))}</p>'

    if nuclei_findings:
        rows = ""
        for f in nuclei_findings:
            sev = f["severity"]
            rows += (
                f'<tr style="border-bottom:1px solid #e8ecf1">'
                f'<td style="padding:8px 10px">{_severity_badge(sev)}</td>'
                f'<td style="padding:8px 10px;font-weight:600;font-size:13px">{_h(f["name"])}</td>'
                f'<td style="padding:8px 10px;font-family:monospace;font-size:12px;word-break:break-all">{_h(f["matched_at"] or f["host"])}</td>'
                f'<td style="padding:8px 10px;font-size:12px;color:#636e72">{_h(f["tags"])}</td>'
                f'<td style="padding:8px 10px;font-size:12px;color:#636e72">{_h(f["description"][:120])}</td>'
                f'</tr>'
            )
        inner += (
            f'<table style="width:100%;border-collapse:collapse;font-size:13px">'
            f'<thead><tr>'
            f'<th style="background:#1a252f;color:#fff;padding:8px 10px">Sévérité</th>'
            f'<th style="background:#1a252f;color:#fff;padding:8px 10px">Finding</th>'
            f'<th style="background:#1a252f;color:#fff;padding:8px 10px">Cible</th>'
            f'<th style="background:#1a252f;color:#fff;padding:8px 10px">Tags</th>'
            f'<th style="background:#1a252f;color:#fff;padding:8px 10px">Description</th>'
            f'</tr></thead><tbody>{rows}</tbody></table>'
        )
    elif txt_text:
        inner += _code_block(txt_text, max_lines=60)

    sev_label = f"{len(nuclei_findings)} finding(s)" if nuclei_findings else "résultats"
    has_critical = any(f["severity"] in ("critical", "high") for f in nuclei_findings)

    return _details_block(
        f"🎯 Nuclei — Scan de vulnérabilités ({sev_label})",
        inner,
        open_=has_critical or bool(nuclei_findings),
    )


def _build_web_section(logs_dir: Path, web_logs: Dict[str, List[str]]) -> str:
    """Construit la section des résultats web (WhatWeb, Gobuster, ffuf, Nikto)."""
    parts = []

    # ── WhatWeb ──
    whatweb_files = _find_logs_glob(logs_dir, "whatweb_*.txt")
    if whatweb_files:
        ww_inner = ""
        for wf in whatweb_files:
            text = _read_file(wf)
            lines = _parse_whatweb(text)
            if lines:
                url_name = wf.stem.replace("whatweb_", "").replace("_", "://", 1).replace("_", "/", 1)
                content = _code_block("\n".join(lines))
                ww_inner += _details_block(f"→ {wf.name}", content)
        if ww_inner:
            parts.append(_details_block(
                f"🌐 WhatWeb — Fingerprinting ({len(whatweb_files)} URL(s))",
                ww_inner,
                open_=True,
            ))

    # ── Gobuster / ffuf ──
    gobuster_files = _find_logs_glob(logs_dir, "gobuster_*.txt")
    ffuf_files     = _find_logs_glob(logs_dir, "ffuf_*.txt")

    if gobuster_files or ffuf_files:
        fuzz_inner = ""
        total_found = 0

        # Gobuster
        for ff in gobuster_files:
            text = _read_file(ff)
            lines = _parse_gobuster(text)
            if lines:
                total_found += len(lines)
                fuzz_inner += _details_block(
                    f"→ {ff.name} ({len(lines)} entrée(s))",
                    _code_block("\n".join(lines)),
                )

        # ffuf — essai CSV d'abord, fallback texte brut
        for ff in ffuf_files:
            text = _read_file(ff)
            if not text:
                continue

            rows_data = _parse_ffuf_csv(text)

            if rows_data:
                # Rendu CSV en tableau HTML
                total_found += len(rows_data)
                header_keys = list(rows_data[0].keys())
                th = "".join(
                    f'<th style="background:#1a252f;color:#fff;padding:6px 10px">{_h(k)}</th>'
                    for k in header_keys
                )
                trs = ""
                for row in rows_data:
                    status = row.get("status_code", row.get("status", ""))
                    color = (
                        "#27ae60" if status == "200"
                        else "#e67e22" if status in ("301", "302", "307")
                        else "#636e72"
                    )
                    trs += "<tr>" + "".join(
                        f'<td style="padding:6px 10px;font-size:12px;font-family:monospace;'
                        f'color:{color if k in ("status_code","status") else "inherit"}">'
                        f'{_h(v)}</td>'
                        for k, v in row.items()
                    ) + "</tr>"
                table = (
                    f'<table style="width:100%;border-collapse:collapse;font-size:12px">'
                    f'<thead><tr>{th}</tr></thead>'
                    f'<tbody>{trs}</tbody></table>'
                )
                fuzz_inner += _details_block(
                    f"→ {ff.name} — ffuf CSV ({len(rows_data)} entrée(s))",
                    table,
                )
            else:
                # Fallback : cherche des lignes utiles dans la sortie brute
                # ffuf en mode terminal peut afficher les résultats ligne par ligne
                useful = _parse_ffuf_raw(text)
                if useful:
                    total_found += len(useful)
                    fuzz_inner += _details_block(
                        f"→ {ff.name} — ffuf ({len(useful)} résultat(s))",
                        _code_block("\n".join(useful)),
                    )
                elif text.strip():
                    # Affiche quand même la sortie brute complète
                    fuzz_inner += _details_block(
                        f"→ {ff.name} — ffuf (sortie brute)",
                        _code_block(text, max_lines=100),
                    )

        if fuzz_inner:
            label_parts = []
            if gobuster_files:
                label_parts.append("Gobuster")
            if ffuf_files:
                label_parts.append("ffuf")
            fuzz_label = " / ".join(label_parts)
            parts.append(_details_block(
                f"📂 {fuzz_label} — Découverte de répertoires ({total_found} résultat(s))",
                fuzz_inner,
                open_=total_found > 0,
            ))

    # ── Nikto ──
    nikto_files = _find_logs_glob(logs_dir, "nikto_*.txt")
    if nikto_files:
        nikto_inner = ""
        total_findings = 0
        for nf in nikto_files:
            text = _read_file(nf)
            lines = _parse_nikto(text)
            if lines:
                total_findings += len(lines)
                nikto_inner += _details_block(f"→ {nf.name}", _code_block("\n".join(lines)))
        if nikto_inner:
            parts.append(_details_block(
                f"🔎 Nikto — Checks de sécurité web ({total_findings} finding(s))",
                nikto_inner,
                open_=total_findings > 3,
            ))

    return "\n".join(parts) if parts else '<p style="color:#636e72;font-style:italic;font-size:13px">Aucune énumération web exécutée.</p>'


def _build_smb_section(logs_dir: Path, findings: List[dict]) -> str:
    """Construit la section enum4linux-ng."""
    txt_file  = _find_log(logs_dir, "enum4linux_ng.txt", "enum4linux_cmd.txt")
    json_file = _find_log(logs_dir, "enum4linux_ng.json", "enum4linux_ng.json.json")
    txt_text  = _read_file(txt_file)

    smb_finding = next((f for f in findings if f.get("source") == "enum4linux-ng"), None)

    if not txt_text and not smb_finding:
        return '<p style="color:#636e72;font-style:italic;font-size:13px">enum4linux-ng : non exécuté (pas de service SMB détecté ou outil absent).</p>'

    parsed = _parse_enum4linux(txt_text, json_file)
    inner = ""

    # Alerte null session
    if parsed.get("null_session"):
        inner += (
            '<div style="padding:12px 16px;background:#fde8e8;border-left:4px solid #d63031;'
            'border-radius:0 8px 8px 0;margin-bottom:12px;font-weight:700;color:#9b1d20">'
            '🚨 NULL SESSION POSSIBLE — Accès anonyme SMB confirmé (vecteur critique d\'énumération)</div>'
        )

    # Shares
    if parsed.get("shares"):
        shares_list = "".join(f'<li style="font-family:monospace;font-size:13px">{_h(s)}</li>' for s in parsed["shares"])
        inner += f'<div style="margin-bottom:10px"><strong>Shares SMB détectés :</strong><ul style="margin:6px 0 0 20px">{shares_list}</ul></div>'

    # Utilisateurs
    if parsed.get("users"):
        users_list = " ".join(
            f'<code style="background:#f0f3f8;padding:2px 8px;border-radius:4px;font-size:13px">{_h(u)}</code>'
            for u in parsed["users"][:30]
        )
        inner += f'<div style="margin-bottom:10px"><strong>Utilisateurs détectés :</strong><div style="margin-top:6px;display:flex;flex-wrap:wrap;gap:4px">{users_list}</div></div>'

    # Sortie brute
    if txt_text:
        inner += _details_block("Sortie brute enum4linux-ng", _code_block(txt_text, max_lines=150))

    label = smb_finding.get("title", "résultats") if smb_finding else "résultats"
    is_critical = parsed.get("null_session", False)
    return _details_block(
        f"🪟 enum4linux-ng — SMB/NetBIOS ({label})",
        inner,
        open_=is_critical or bool(parsed.get("shares") or parsed.get("users")),
    )


def _build_flags_section(logs_dir: Path, findings: List[dict]) -> str:
    """Section flags CTF : cherche flag{...} / HTB{...} / THM{...} dans tous les logs."""
    flags = _find_flags(logs_dir)
    # Cherche aussi dans les findings
    for f in findings:
        for key in ("flag", "flags", "content"):
            val = f.get(key, "")
            if val and re.search(r'[A-Z]{2,10}\{', str(val), re.I):
                flags.append({"flag": str(val)[:200], "file": f.get("source", "finding"), "context": f.get("title", "")})

    if not flags:
        return '<p style="color:#636e72;font-style:italic;font-size:13px">Aucun flag CTF détecté automatiquement dans les logs.</p>'

    rows = ""
    for item in flags:
        flag_html = f'<code style="background:#1e1e1e;color:#4ec9b0;padding:6px 14px;border-radius:6px;font-size:14px;font-weight:700;letter-spacing:0.5px;display:inline-block;margin:2px 0">{_h(item["flag"])}</code>'
        rows += (
            f'<tr style="border-bottom:1px solid #e8ecf1">'
            f'<td style="padding:10px 14px">{flag_html}</td>'
            f'<td style="padding:10px 14px;font-size:12px;font-family:monospace;color:#636e72">{_h(item["file"])}</td>'
            f'<td style="padding:10px 14px;font-size:12px;color:#2d3436">{_h(item["context"][:120])}</td>'
            f'</tr>'
        )

    table = (
        f'<div style="padding:10px 0 6px;font-size:13px;color:#636e72">{len(flags)} flag(s) trouvé(s) dans les logs — à inclure dans le rapport final.</div>'
        f'<table style="width:100%;border-collapse:collapse">'
        f'<thead><tr>'
        f'<th style="background:#1a252f;color:#fff;padding:9px 14px">Flag</th>'
        f'<th style="background:#1a252f;color:#fff;padding:9px 14px">Fichier source</th>'
        f'<th style="background:#1a252f;color:#fff;padding:9px 14px">Contexte</th>'
        f'</tr></thead><tbody>{rows}</tbody></table>'
    )
    return _details_block(f"🚩 Flags CTF trouvés ({len(flags)})", table, open_=True)


def _build_recon_advanced_section(logs_dir: Path, findings: List[dict]) -> str:
    """Section découverte avancée : robots.txt, JS scraper, .git, archives, GPG."""
    parts = []

    # ── robots.txt / sitemap ──
    robots_file = _find_log(logs_dir, "robots_recon.txt")
    robots_text = _read_file(robots_file)
    if robots_text:
        parsed = _parse_robots(robots_text)
        inner = ""
        if parsed["disallow"]:
            items = "".join(
                f'<li style="font-family:monospace;font-size:13px;padding:2px 0">{_h(p)}</li>'
                for p in parsed["disallow"]
            )
            inner += f'<div style="margin-bottom:10px"><strong>Disallow ({len(parsed["disallow"])}) :</strong><ul style="margin:6px 0 0 20px">{items}</ul></div>'
        if parsed["sitemaps"]:
            items = "".join(
                f'<li><a href="{_h(s)}" style="font-size:13px">{_h(s)}</a></li>'
                for s in parsed["sitemaps"]
            )
            inner += f'<div style="margin-bottom:10px"><strong>Sitemaps :</strong><ul style="margin:6px 0 0 20px">{items}</ul></div>'
        if parsed["allow"]:
            items = "".join(f'<li style="font-family:monospace;font-size:13px">{_h(p)}</li>' for p in parsed["allow"])
            inner += f'<div style="margin-bottom:10px"><strong>Allow :</strong><ul style="margin:6px 0 0 20px">{items}</ul></div>'
        inner += _details_block("Sortie brute robots_recon", _code_block(robots_text, 80))
        n_dis = len(parsed["disallow"])
        parts.append(_details_block(
            f"🤖 Robots.txt / Sitemap — {n_dis} Disallow, {len(parsed['sitemaps'])} Sitemap(s)",
            inner, open_=n_dis > 0,
        ))

    # ── JS Scraper ──
    js_file = _find_log(logs_dir, "js_scraper.txt")
    js_text = _read_file(js_file)
    js_finding = next((f for f in findings if f.get("source") == "js_scraper"), None)
    if js_text or js_finding:
        inner = ""
        # Secrets dans le texte brut
        secret_lines = [l.strip() for l in (js_text or "").splitlines()
                        if any(kw in l.lower() for kw in ["secret", "api_key", "apikey", "token", "password", "pass", "key=", "auth"])]
        if secret_lines:
            inner += (
                '<div style="padding:10px 14px;background:#fde8e8;border-left:4px solid #d63031;border-radius:0 8px 8px 0;margin-bottom:12px">'
                f'<strong style="color:#9b1d20">⚠️ {len(secret_lines)} ligne(s) potentiellement sensibles :</strong><br>'
                + "<br>".join(f'<code style="font-size:12px">{_h(l[:200])}</code>' for l in secret_lines[:20])
                + '</div>'
            )
        if js_finding:
            inner += f'<p style="margin-bottom:8px;font-size:14px"><strong>{_h(js_finding.get("title", ""))}</strong></p>'
        if js_text:
            inner += _details_block("Sortie brute JS scraper", _code_block(js_text, 120))
        parts.append(_details_block(
            f"📜 JS Scraper — Secrets & Endpoints{' ⚠️' if secret_lines else ''}",
            inner, open_=bool(secret_lines or js_finding),
        ))

    # ── .git exposure ──
    git_file = _find_log(logs_dir, "git_exposure.txt")
    git_text = _read_file(git_file)
    git_finding = next((f for f in findings if f.get("source") == "git_exposure"), None)
    if git_text or git_finding:
        inner = ""
        exposed = any(kw in (git_text or "").lower() for kw in ["exposed", "found", "200", "accessible"])
        if exposed or git_finding:
            inner += (
                '<div style="padding:10px 14px;background:#fde8e8;border-left:4px solid #d63031;'
                'border-radius:0 8px 8px 0;margin-bottom:12px;font-weight:700;color:#9b1d20">'
                '🚨 Dépôt .git potentiellement exposé — extraction du code source possible</div>'
            )
        if git_finding:
            inner += f'<p style="margin-bottom:8px">{_h(git_finding.get("title",""))}</p>'
        if git_text:
            inner += _details_block("Sortie brute git_exposure_check", _code_block(git_text, 80))
        parts.append(_details_block(
            "🔑 .git Exposure" + (" 🚨 EXPOSÉ" if exposed or git_finding else ""),
            inner, open_=bool(exposed or git_finding),
        ))

    # ── Archives ──
    arc_file = _find_log(logs_dir, "archive_analysis.txt")
    arc_text = _read_file(arc_file)
    arc_finding = next((f for f in findings if f.get("source") == "archive_analysis"), None)
    if arc_text or arc_finding:
        inner = ""
        if arc_finding:
            inner += f'<p style="margin-bottom:8px">{_h(arc_finding.get("title", ""))}</p>'
            if arc_finding.get("interesting_files"):
                items = "".join(
                    f'<li style="font-family:monospace;font-size:13px">{_h(f)}</li>'
                    for f in arc_finding["interesting_files"][:30]
                )
                inner += f'<strong>Fichiers intéressants :</strong><ul style="margin:6px 0 0 20px">{items}</ul>'
        if arc_text:
            inner += _details_block("Sortie brute archive_analysis", _code_block(arc_text, 100))
        parts.append(_details_block(
            f"📦 Archive Analysis{' — ' + arc_finding['title'] if arc_finding else ''}",
            inner, open_=bool(arc_finding),
        ))

    # ── GPG ──
    gpg_file = _find_log(logs_dir, "gpg_decrypt.txt")
    gpg_text = _read_file(gpg_file)
    gpg_finding = next((f for f in findings if f.get("source") == "gpg_decrypt"), None)
    if gpg_text or gpg_finding:
        inner = ""
        if gpg_finding:
            inner += f'<p style="margin-bottom:8px">{_h(gpg_finding.get("title",""))}</p>'
            creds = gpg_finding.get("creds", [])
            if creds:
                items = "".join(
                    f'<li style="font-family:monospace;font-size:13px">{_h(str(c))}</li>'
                    for c in creds[:20]
                )
                inner += f'<div style="padding:10px 14px;background:#fde8e8;border-left:4px solid #d63031;border-radius:0 8px 8px 0;margin-bottom:10px"><strong style="color:#9b1d20">Credentials extraits :</strong><ul style="margin:6px 0 0 20px">{items}</ul></div>'
        if gpg_text:
            inner += _details_block("Sortie brute GPG", _code_block(gpg_text, 80))
        parts.append(_details_block(
            "🔐 GPG Decrypt" + (" — Credentials trouvés !" if gpg_finding and gpg_finding.get("creds") else ""),
            inner, open_=bool(gpg_finding and gpg_finding.get("creds")),
        ))

    if not parts:
        return '<p style="color:#636e72;font-style:italic;font-size:13px">Aucun module de découverte avancée exécuté ou résultats vides.</p>'
    return "\n".join(parts)


def _build_wordpress_section(logs_dir: Path, findings: List[dict]) -> str:
    """Section WordPress : WPScan recon + brute force + theme injection."""
    parts = []

    # ── WPScan Recon ──
    wp_recon_file = _find_log(logs_dir, "wpscan_recon.txt")
    wp_recon_text = _read_file(wp_recon_file)
    wp_recon_finding = next((f for f in findings if f.get("source") == "wpscan_recon"), None)

    if wp_recon_text or wp_recon_finding:
        parsed = _parse_wpscan(wp_recon_text or "")
        inner = ""
        if parsed["version"]:
            inner += f'<p style="margin-bottom:8px"><strong>Version WordPress :</strong> <code>{_h(parsed["version"])}</code></p>'
        if parsed["vulns"]:
            items = "".join(
                f'<div style="padding:6px 10px;background:#fde8e8;border-left:3px solid #d63031;margin:4px 0;font-size:12px">{_highlight_cves(v)}</div>'
                for v in parsed["vulns"]
            )
            inner += f'<div style="margin-bottom:10px"><strong style="color:#d63031">⚠️ Vulnérabilités WPScan ({len(parsed["vulns"])}) :</strong><div style="margin-top:6px">{items}</div></div>'
        if parsed["users"]:
            items = "".join(f'<code style="margin:2px;display:inline-block">{_h(u)}</code>' for u in parsed["users"])
            inner += f'<p style="margin-bottom:8px"><strong>Utilisateurs détectés :</strong> {items}</p>'
        if parsed["plugins"]:
            items = "".join(f'<li style="font-size:13px">{_h(p)}</li>' for p in parsed["plugins"])
            inner += f'<details style="margin:8px 0"><summary style="cursor:pointer;font-weight:600">Plugins ({len(parsed["plugins"])})</summary><ul style="margin:6px 0 0 20px">{items}</ul></details>'
        if wp_recon_text:
            inner += _details_block("Sortie brute WPScan", _code_block(wp_recon_text, 150))
        has_vulns = bool(parsed["vulns"])
        parts.append(_details_block(
            f"🔍 WPScan Recon — WordPress{' v' + parsed['version'] if parsed['version'] else ''}{' ⚠️ Vulnérabilités' if has_vulns else ''}",
            inner, open_=has_vulns or bool(parsed["users"]),
        ))

    # ── WP Brute Force ──
    wpbf_file = _find_log(logs_dir, "wordpress_bruteforce.txt")
    wpbf_text = _read_file(wpbf_file)
    wpbf_finding = next((f for f in findings if f.get("source") == "wordpress_bruteforce"), None)

    if wpbf_text or wpbf_finding:
        creds = _parse_wp_brute(wpbf_text or "")
        # Aussi dans le finding
        if wpbf_finding and wpbf_finding.get("creds"):
            for c in wpbf_finding["creds"]:
                if c not in creds:
                    creds.append(c)
        inner = ""
        if creds:
            rows = "".join(
                f'<tr>'
                f'<td style="padding:8px 12px;font-family:monospace;font-weight:700;color:#27ae60">{_h(c.get("user",""))}</td>'
                f'<td style="padding:8px 12px;font-family:monospace;color:#e67e22">{_h(c.get("password",""))}</td>'
                f'</tr>'
                for c in creds
            )
            inner += (
                '<div style="padding:10px 14px;background:#e8f8f0;border-left:4px solid #27ae60;'
                'border-radius:0 8px 8px 0;margin-bottom:12px;font-weight:700;color:#1a5c3a">'
                f'✅ {len(creds)} credential(s) WordPress trouvé(s) !</div>'
                f'<table style="width:100%;border-collapse:collapse;margin-bottom:12px">'
                f'<thead><tr><th style="background:#1a252f;color:#fff;padding:8px 12px">Utilisateur</th>'
                f'<th style="background:#1a252f;color:#fff;padding:8px 12px">Mot de passe</th></tr></thead>'
                f'<tbody>{rows}</tbody></table>'
            )
        if wpbf_text:
            inner += _details_block("Sortie brute WP bruteforce", _code_block(wpbf_text, 100))
        parts.append(_details_block(
            f"🔓 WP Brute Force — {len(creds)} credential(s) trouvé(s)" if creds else "🔓 WP Brute Force",
            inner, open_=bool(creds),
        ))

    # ── WP Theme Injection (exploit) ──
    wpex_file = _find_log(logs_dir, "wp_theme_inject.txt")
    wpex_text = _read_file(wpex_file)
    wpex_finding = next((f for f in findings if f.get("source") == "wp_theme_inject"), None)

    if wpex_text or wpex_finding:
        inner = ""
        success = any(kw in (wpex_text or "").lower() for kw in ["shell", "payload injecté", "reverse", "success", "✓"])
        if success or wpex_finding:
            inner += (
                '<div style="padding:10px 14px;background:#fde8e8;border-left:4px solid #d63031;'
                'border-radius:0 8px 8px 0;margin-bottom:12px;font-weight:700;color:#9b1d20">'
                '💀 EXPLOITATION RÉUSSIE — Payload PHP injecté dans le thème WordPress</div>'
            )
        if wpex_finding:
            inner += f'<p style="margin-bottom:8px">{_h(wpex_finding.get("title",""))}</p>'
        if wpex_text:
            inner += _details_block("Log complet — WP Theme Injection", _code_block(wpex_text, 150), open_=True)
        parts.append(_details_block(
            "💀 WordPress Theme Injection — Reverse Shell" + (" ✅ RÉUSSI" if success or wpex_finding else ""),
            inner, open_=bool(success or wpex_finding),
        ))

    if not parts:
        return '<p style="color:#636e72;font-style:italic;font-size:13px">Aucun service WordPress détecté ou modules WP non exécutés.</p>'
    return "\n".join(parts)


def _build_exploitation_section(logs_dir: Path, findings: List[dict]) -> str:
    """Section exploitation : FTP anon, SMB anon, SSH, Hydra, initial access."""
    parts = []

    # ── FTP anon ──
    ftp_file = _find_log(logs_dir, "exploit_ftp_anon.txt", "ftp_to_do.txt")
    ftp_text = _read_file(ftp_file)
    ftp_finding = next((f for f in findings if f.get("source") in ("exploit_ftp", "ftp_anon")), None)
    if ftp_text or ftp_finding:
        inner = ""
        ftp_anon = any(kw in (ftp_text or "").lower() for kw in ["anonymous", "login successful", "230", "ftp_anon"])
        if ftp_anon or ftp_finding:
            inner += (
                '<div style="padding:10px 14px;background:#fde8e8;border-left:4px solid #d63031;'
                'border-radius:0 8px 8px 0;margin-bottom:10px;font-weight:700;color:#9b1d20">'
                '🚨 Accès FTP anonyme confirmé — liste de fichiers possible</div>'
            )
        if ftp_finding:
            inner += f'<p style="margin-bottom:8px">{_h(ftp_finding.get("title",""))}</p>'
            if ftp_finding.get("writable_dirs"):
                dirs = "".join(f'<li style="font-family:monospace;font-size:13px">{_h(d)}</li>' for d in ftp_finding["writable_dirs"])
                inner += f'<strong>Répertoires accessibles :</strong><ul style="margin:6px 0 6px 20px">{dirs}</ul>'
        if ftp_text:
            inner += _details_block("Sortie FTP", _code_block(ftp_text, 100))
        parts.append(_details_block(
            "📁 FTP" + (" — Accès anonyme 🚨" if ftp_anon or ftp_finding else ""),
            inner, open_=bool(ftp_anon or ftp_finding),
        ))

    # ── SMB anon ──
    smb_ex_files = _find_logs_glob(logs_dir, "exploit_smb*.txt")
    smb_ex_finding = next((f for f in findings if f.get("source") in ("exploit_smb", "smb_anon")), None)
    if smb_ex_files or smb_ex_finding:
        inner = ""
        if smb_ex_finding:
            inner += f'<p style="margin-bottom:8px">{_h(smb_ex_finding.get("title",""))}</p>'
        for sf in smb_ex_files:
            inner += _details_block(f"→ {sf.name}", _code_block(_read_file(sf), 80))
        parts.append(_details_block("🪟 SMB Exploitation", inner, open_=bool(smb_ex_finding)))

    # ── SSH ──
    ssh_files = _find_logs_glob(logs_dir, "exploit_ssh*.txt") + _find_logs_glob(logs_dir, "ssh_*.txt")
    ssh_finding = next((f for f in findings if f.get("source") in ("exploit_ssh", "ssh_vuln", "ssh_enum")), None)
    if ssh_files or ssh_finding:
        inner = ""
        if ssh_finding:
            inner += f'<p style="margin-bottom:8px">{_h(ssh_finding.get("title",""))}</p>'
        for sf in ssh_files[:5]:
            inner += _details_block(f"→ {sf.name}", _code_block(_read_file(sf), 60))
        parts.append(_details_block("🔒 SSH", inner, open_=bool(ssh_finding)))

    # ── Hydra ──
    hydra_files = _find_logs_glob(logs_dir, "hydra_*.txt")
    if hydra_files:
        inner = ""
        found_creds = []
        for hf in hydra_files:
            text = _read_file(hf)
            for line in text.splitlines():
                if "[" in line and "]" in line and ("login:" in line.lower() or "password:" in line.lower()):
                    found_creds.append(line.strip()[:200])
            inner += _details_block(f"→ {hf.name}", _code_block(text, 60))
        if found_creds:
            cred_html = "".join(f'<div style="font-family:monospace;font-size:13px;color:#27ae60;padding:3px 0">{_h(c)}</div>' for c in found_creds)
            inner = f'<div style="padding:10px 14px;background:#e8f8f0;border-left:4px solid #27ae60;border-radius:0 8px 8px 0;margin-bottom:10px">{cred_html}</div>' + inner
        parts.append(_details_block(
            f"⚡ Hydra — Brute Force{' ✅ ' + str(len(found_creds)) + ' credential(s)' if found_creds else ''}",
            inner, open_=bool(found_creds),
        ))

    # ── Initial Access ──
    ia_file = _find_log(logs_dir, "exploit_initial_access.txt")
    ia_text = _read_file(ia_file)
    ia_finding = next((f for f in findings if f.get("source") in ("initial_access", "exploit_initial")), None)
    if ia_text or ia_finding:
        inner = ""
        if ia_finding:
            inner += f'<p style="margin-bottom:8px">{_h(ia_finding.get("title",""))}</p>'
        if ia_text:
            inner += _details_block("Log initial access", _code_block(ia_text, 100), open_=True)
        parts.append(_details_block("🎯 Initial Access", inner, open_=True))

    if not parts:
        return '<p style="color:#636e72;font-style:italic;font-size:13px">Aucune phase d\'exploitation exécutée ou résultats vides.</p>'
    return "\n".join(parts)


def _build_postexploit_section(logs_dir: Path, findings: List[dict]) -> str:
    """Section post-exploitation : shell recon (sudo, crontab, SUID, réseau, secrets)."""
    pe_dir = logs_dir / "post_exploit"
    pe_files = sorted(pe_dir.glob("*.txt")) if pe_dir.exists() else []
    pe_findings = [f for f in findings if f.get("source") in ("postexploit", "post_exploit", "shell_recon")]

    if not pe_files and not pe_findings:
        return '<p style="color:#636e72;font-style:italic;font-size:13px">Phase post-exploitation non exécutée ou aucun résultat.</p>'

    parts = []

    # Findings post-exploit
    if pe_findings:
        for f in pe_findings:
            sev = f.get("severity", "info")
            col = _severity_color(sev)
            bg  = _severity_bg(sev)
            parts.append(
                f'<div style="padding:10px 14px;margin:6px 0;border-left:4px solid {col};background:{bg};border-radius:0 8px 8px 0">'
                f'<strong style="color:{col}">[{_h(sev.upper())}]</strong> {_h(f.get("title",""))}'
                f'<br><span style="font-size:12px;color:#636e72">{_h(f.get("details","")[:300])}</span>'
                f'</div>'
            )

    # Fichiers de recon post-exploit
    LABELS = {
        "sudo.txt":     "🔑 sudo -l (élévation de privilèges)",
        "crontab.txt":  "⏰ Crontabs (tâches planifiées)",
        "suid.txt":     "🚀 Binaires SUID (potential priv-esc)",
        "network.txt":  "🌐 Réseau interne (interfaces, routes, ARP)",
        "secrets.txt":  "🔐 Secrets (fichiers sensibles, historique)",
        "system.txt":   "💻 Info système (uname, env, users)",
        "processes.txt":"📋 Processus actifs",
    }
    for fpath in pe_files:
        label = LABELS.get(fpath.name, f"→ {fpath.name}")
        text = _read_file(fpath)
        if not text.strip():
            continue
        # Détection éléments critiques
        crit = any(kw in text.lower() for kw in ["(all)", "nopasswd", "suid", "secret", "password", "id_rsa", "credentials"])
        open_ = crit
        content = text
        # Highlight lignes importantes
        if fpath.name in ("sudo.txt", "suid.txt"):
            lines = text.splitlines()
            highlighted = []
            for line in lines:
                ls = line.strip()
                if any(kw in ls.lower() for kw in ["(all)", "nopasswd", "/usr/bin", "/bin/"]):
                    highlighted.append(f'<span style="background:#fde8e8;color:#d63031;font-weight:700">{_h(ls)}</span>')
                else:
                    highlighted.append(_h(ls))
            content_html = (
                f'<pre style="background:#1e1e1e;color:#d4d4d4;padding:14px;border-radius:6px;'
                f'font-size:12px;overflow:auto;max-height:400px;line-height:1.5">'
                + "<br>".join(highlighted) + "</pre>"
            )
            parts.append(_details_block(label + (" ⚠️" if crit else ""), content_html, open_=open_))
        else:
            parts.append(_details_block(label, _code_block(content, 100), open_=open_))

    return _details_block(
        f"🔓 Post-Exploitation — {len(pe_files)} fichier(s) de recon",
        "\n".join(parts),
        open_=bool(pe_findings),
    )


# ────────────────────────── MARKDOWN REPORT ──────────────────────────

def _generate_md(
    run_dir: Path, app_name: str, version: str, cfg_dict: dict,
    services_scored: List[dict], findings: List[dict], urls: List[str],
    web_logs: Dict[str, List[str]], timings: Dict[str, float],
    kill_chain: List[dict],
) -> str:
    md = []
    target = cfg_dict.get("target", "?")

    md.append(f"# Rapport {app_name} v{version} — {target}\n\n")
    md.append(f"- Date: {_now_iso()}\n")
    md.append(f"- Run ID: `{cfg_dict.get('run_id', '')}`\n")
    md.append(f"- Preset: `{cfg_dict.get('preset', '')}` | Scan mode: `{cfg_dict.get('scan_mode', '')}` | Staged: `{cfg_dict.get('staged_nmap', '')}`\n\n")

    md.append("## Cyber Kill Chain — Couverture\n\n")
    md.append("| Phase | Statut | Durée | Outils | MITRE ATT&CK |\n|---|:---:|---:|---|---|\n")
    for kc in kill_chain:
        icon = {"done": "✅", "skipped": "⏭️", "not_implemented": "🔒"}.get(kc["status"], "—")
        dur  = _fmt_duration(kc.get("duration"))
        tools = ", ".join(kc["tools"])
        md.append(f"| {kc['phase']} | {icon} | {dur} | {tools} | {kc['mitre']} |\n")
    md.append("\n")

    md.append("## Timings\n\n")
    for k, v in timings.items():
        md.append(f"- {k}: **{v:.1f}s**\n")
    md.append("\n")

    md.append("## Résumé\n\n")
    md.append(f"- Ports/services ouverts: **{len(services_scored)}**\n")
    md.append(f"- URLs web détectées: **{len(urls)}**\n")
    md.append(f"- Findings (à valider): **{len(findings)}**\n\n")

    md.append("## Services détectés (scoring CVSS)\n\n")
    md.append("| Port | Proto | Service | Produit | Version | CVSS | Sévérité |\n|---:|:---:|---|---|---|---:|:---:|\n")
    for s in services_scored:
        md.append(
            f"| {s['port']} | {s['proto']} | {s['name']} | {s['product']} | {s['version']} "
            f"| {s['cvss_score']} | {s['cvss_severity']} |\n"
        )
    md.append("\n")

    if urls:
        md.append("## URLs détectées\n\n")
        md.append("\n".join(f"- {u}" for u in urls) + "\n\n")

    md.append("## Findings (à valider)\n\n")
    if findings:
        for f in findings:
            md.append(f"- **[{f.get('severity','info')}] {f.get('title','')}** — {f.get('source','')} (`{f.get('evidence_file','')}`)\n")
    else:
        md.append("- Aucun finding automatique\n")
    md.append("\n")

    md.append("## Recommandations\n\n")
    md.append("1. Valider manuellement chaque finding avant de le qualifier de vulnérabilité exploitable.\n")
    md.append("2. Corréler les résultats searchsploit avec les versions exactes des services.\n")
    md.append("3. Prioriser la remédiation selon le score CVSS et l'exposition réseau.\n")
    md.append("4. Documenter les faux positifs pour améliorer les prochains audits.\n")
    md.append("5. Re-scanner après remédiation pour confirmer la correction effective.\n")

    return "".join(md)


# ────────────────────────── HTML REPORT ──────────────────────────

def _generate_html(
    run_dir: Path, app_name: str, version: str, cfg_dict: dict,
    services_scored: List[dict], findings: List[dict], urls: List[str],
    web_logs: Dict[str, List[str]], timings: Dict[str, float],
    kill_chain: List[dict],
) -> str:
    target     = _h(cfg_dict.get("target", "?"))
    date       = _now_iso()
    run_id     = _h(cfg_dict.get("run_id", ""))
    preset     = _h(cfg_dict.get("preset", ""))
    scan_mode  = _h(cfg_dict.get("scan_mode", ""))
    total_time = _fmt_duration(timings.get("total"))

    n_svc      = len(services_scored)
    n_urls     = len(urls)
    n_findings = len(findings)
    max_cvss   = max((s["cvss_score"] for s in services_scored), default=0.0)
    max_sev    = "critical" if max_cvss >= 9 else "high" if max_cvss >= 7 else "medium" if max_cvss >= 4 else "low"

    # Cherche le logs_dir
    logs_dir = run_dir / "logs"

    # ── Flags CTF ──
    flags_found = _find_flags(logs_dir)
    n_flags = len(flags_found)
    flags_kpi_color = "#27ae60" if n_flags > 0 else "#636e72"

    # ── Kill Chain table ──
    kc_rows = ""
    for kc in kill_chain:
        icon, bg, col = {
            "done":            ("✅", "#e8f8f0", "#27ae60"),
            "skipped":         ("⏭️", "#f0f0f0", "#636e72"),
            "not_implemented": ("🔒", "#fef3e2", "#e67e22"),
        }.get(kc["status"], ("—", "#f0f0f0", "#636e72"))
        dur   = _fmt_duration(kc.get("duration"))
        tools = _h(", ".join(kc["tools"]))
        kc_rows += (
            f'<tr>'
            f'<td style="font-weight:700">{_h(kc["phase"])}</td>'
            f'<td style="text-align:center;background:{bg};color:{col};font-weight:700">{icon}</td>'
            f'<td style="text-align:right;font-family:monospace">{dur}</td>'
            f'<td style="font-size:13px">{tools}</td>'
            f'<td style="font-size:12px;color:#636e72">{_h(kc["mitre"])}</td>'
            f'<td style="font-size:12px;color:#636e72">{_h(kc["description"])}</td>'
            f'</tr>'
        )

    # ── Services table ──
    svc_rows = ""
    for s in services_scored:
        sev = s["cvss_severity"]
        sc  = s["cvss_score"]
        svc_rows += (
            f'<tr>'
            f'<td style="font-weight:700;font-family:monospace">{s["port"]}</td>'
            f'<td>{_h(s["proto"])}</td>'
            f'<td style="font-weight:600">{_h(s["name"])}</td>'
            f'<td>{_h(s["product"])}</td>'
            f'<td style="font-family:monospace">{_h(s["version"])}</td>'
            f'<td style="font-weight:700;text-align:center;color:{_severity_color(sev)}">{sc}</td>'
            f'<td>{_severity_badge(sev)}</td>'
            f'<td style="font-size:12px;color:#636e72">{_h(s.get("cvss_rationale",""))}</td>'
            f'</tr>'
        )

    # ── Findings section ──
    findings_html = ""
    if findings:
        for f in findings:
            sev = f.get("severity", "info")
            col = _severity_color(sev)
            bg  = _severity_bg(sev)
            findings_html += (
                f'<div style="padding:12px 16px;margin:8px 0;border-left:4px solid {col};'
                f'background:{bg};border-radius:0 8px 8px 0">'
                f'<strong style="color:{col}">[{_h(sev.upper())}]</strong> '
                f'{_h(f.get("title",""))}'
                f'<br><span style="font-size:12px;color:#636e72">Source: {_h(f.get("source",""))}</span>'
                f'</div>'
            )
    else:
        findings_html = '<p style="color:#636e72;font-style:italic">Aucun finding automatique. Valider manuellement.</p>'

    # ── URLs section ──
    urls_html = ""
    if urls:
        urls_html = '<div style="display:flex;flex-wrap:wrap;gap:8px;margin:10px 0">'
        for u in urls:
            urls_html += f'<code style="padding:5px 12px;background:#f0f3f8;border-radius:8px;font-size:13px">{_h(u)}</code>'
        urls_html += '</div>'
    else:
        urls_html = '<p style="color:#636e72;font-style:italic">Aucun service HTTP/HTTPS détecté.</p>'

    # ── Timings bars ──
    timings_html = ""
    for k, v in timings.items():
        pct = min(100, (v / max(timings.get("total", 1), 0.1)) * 100)
        timings_html += (
            f'<div style="margin:6px 0">'
            f'<div style="display:flex;justify-content:space-between;font-size:13px;margin-bottom:3px">'
            f'<span style="font-weight:600">{_h(k)}</span>'
            f'<span style="font-family:monospace">{v:.1f}s</span>'
            f'</div>'
            f'<div style="height:8px;background:#e8ecf1;border-radius:4px;overflow:hidden">'
            f'<div style="height:100%;width:{pct:.0f}%;background:#2e75b6;border-radius:4px"></div>'
            f'</div></div>'
        )

    # ── Sections de résultats (v0.65) ──
    flags_section        = _build_flags_section(logs_dir, findings)
    nmap_section         = _build_nmap_section(logs_dir)
    searchsploit_section = _build_searchsploit_section(logs_dir, findings)
    nuclei_section       = _build_nuclei_section(logs_dir, findings)
    web_section          = _build_web_section(logs_dir, web_logs)
    smb_section          = _build_smb_section(logs_dir, findings)
    recon_adv_section    = _build_recon_advanced_section(logs_dir, findings)
    wordpress_section    = _build_wordpress_section(logs_dir, findings)
    exploitation_section = _build_exploitation_section(logs_dir, findings)
    postexploit_section  = _build_postexploit_section(logs_dir, findings)

    # Sévérité header color
    header_accent = _severity_color(max_sev)

    return f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Rapport Pentool v{_h(version)} — {target}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0 }}
  body {{
    font-family: -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
    background: #f4f6f9; color: #2d3436; line-height: 1.6;
    font-size: 15px;
  }}
  .page {{
    max-width: 1200px; margin: 0 auto; padding: 30px 40px;
    background: #fff; min-height: 100vh;
  }}
  h1 {{ font-size: 26px; color: #1a252f; margin-bottom: 4px }}
  h2 {{
    font-size: 19px; color: #2e75b6; margin: 34px 0 14px;
    padding-bottom: 8px; border-bottom: 2px solid #e8ecf1;
  }}
  h3 {{ font-size: 15px; color: #1a252f; margin: 18px 0 8px }}
  table {{
    width: 100%; border-collapse: collapse; font-size: 13px; margin: 10px 0;
  }}
  th {{
    background: #1a252f; color: #fff; padding: 9px 12px;
    text-align: left; font-weight: 700; font-size: 12px;
  }}
  td {{ padding: 8px 12px; border-bottom: 1px solid #e8ecf1; vertical-align: top; }}
  tr:hover td {{ background: #f8f9fb }}
  .meta-grid {{
    display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 12px; margin: 18px 0;
  }}
  .meta-card {{
    padding: 14px 18px; border-radius: 12px; background: #f0f3f8;
    text-align: center; border-top: 3px solid transparent;
  }}
  .meta-card .val {{
    font-size: 30px; font-weight: 900; color: #1a252f; display: block;
  }}
  .meta-card .lbl {{
    font-size: 12px; color: #636e72; margin-top: 3px;
  }}
  details summary {{ list-style: none; }}
  details summary::-webkit-details-marker {{ display: none; }}
  code {{
    background: #f0f3f8; padding: 2px 6px; border-radius: 4px; font-size: 12px;
  }}
  .disclaimer {{
    margin: 28px 0 8px; padding: 14px 18px; background: #fff3e0;
    border-left: 4px solid #e67e22; border-radius: 0 8px 8px 0;
    font-size: 13px; color: #5a3e1b;
  }}
  .footer {{
    margin-top: 36px; padding-top: 14px; border-top: 2px solid #e8ecf1;
    font-size: 11px; color: #b2bec3; text-align: center;
  }}
  @media print {{
    body {{ background: #fff }}
    .page {{ padding: 16px; }}
    table {{ font-size: 10px }}
    details {{ display: block !important }}
    details summary {{ display: none }}
    pre {{ max-height: none !important; white-space: pre-wrap !important; }}
  }}
</style>
</head>
<body>
<div class="page">

  <!-- ══════ HEADER ══════ -->
  <div style="display:flex;align-items:center;gap:16px;margin-bottom:18px;padding-bottom:18px;border-bottom:3px solid {header_accent}">
    <div style="width:50px;height:50px;border-radius:12px;background:{header_accent};display:flex;align-items:center;justify-content:center;color:#fff;font-weight:900;font-size:19px;flex-shrink:0">PT</div>
    <div>
      <h1>Rapport d'audit — {target}</h1>
      <div style="font-size:13px;color:#636e72">{_h(app_name)} v{_h(version)} &nbsp;|&nbsp; {date} &nbsp;|&nbsp; Run <code>{run_id}</code> &nbsp;|&nbsp; Preset: <code>{preset}</code> &nbsp;|&nbsp; Mode: <code>{scan_mode}</code></div>
    </div>
  </div>

  <!-- ══════ KPIs ══════ -->
  <div class="meta-grid">
    <div class="meta-card" style="border-top-color:#2e75b6">
      <span class="val">{n_svc}</span>
      <span class="lbl">Services détectés</span>
    </div>
    <div class="meta-card" style="border-top-color:#2e75b6">
      <span class="val">{n_urls}</span>
      <span class="lbl">URLs web</span>
    </div>
    <div class="meta-card" style="border-top-color:#e67e22">
      <span class="val">{n_findings}</span>
      <span class="lbl">Findings</span>
    </div>
    <div class="meta-card" style="border-top-color:{_severity_color(max_sev)}">
      <span class="val" style="color:{_severity_color(max_sev)}">{max_cvss}</span>
      <span class="lbl">CVSS max</span>
    </div>
    <div class="meta-card" style="border-top-color:{flags_kpi_color}">
      <span class="val" style="color:{flags_kpi_color}">{n_flags}</span>
      <span class="lbl">🚩 Flags CTF</span>
    </div>
    <div class="meta-card" style="border-top-color:#27ae60">
      <span class="val">{total_time}</span>
      <span class="lbl">Durée totale</span>
    </div>
  </div>

  <!-- ══════ KILL CHAIN ══════ -->
  <h2>Cyber Kill Chain — Couverture de l'audit</h2>
  <p style="font-size:13px;color:#636e72;margin-bottom:10px">
    Mapping sur le modèle Lockheed Martin Cyber Kill Chain avec correspondance MITRE ATT&CK.
  </p>
  <table>
    <thead>
      <tr>
        <th>Phase</th><th style="text-align:center">Statut</th>
        <th style="text-align:right">Durée</th><th>Outils</th>
        <th>MITRE</th><th>Description</th>
      </tr>
    </thead>
    <tbody>{kc_rows}</tbody>
  </table>

  <!-- ══════ TIMINGS ══════ -->
  <h2>Performance — Timings</h2>
  <div style="max-width:580px">{timings_html}</div>

  <!-- ══════ SERVICES ══════ -->
  <h2>Services détectés — Scoring CVSS v3.1</h2>
  <p style="font-size:13px;color:#636e72;margin-bottom:10px">
    Score CVSS simplifié basé sur le type de service, le protocole et la version. À valider manuellement.
  </p>
  <table>
    <thead>
      <tr>
        <th>Port</th><th>Proto</th><th>Service</th><th>Produit</th>
        <th>Version</th><th style="text-align:center">CVSS</th>
        <th>Sévérité</th><th>Justification</th>
      </tr>
    </thead>
    <tbody>{svc_rows}</tbody>
  </table>

  <!-- ══════ URLS ══════ -->
  <h2>URLs web détectées</h2>
  {urls_html}

  <!-- ══════ FINDINGS ══════ -->
  <h2>Findings automatiques (à valider manuellement)</h2>
  {findings_html}

  <!-- ══════ FLAGS CTF ══════ -->
  <h2>🚩 Flags CTF</h2>
  {flags_section}

  <!-- ══════ RÉSULTATS DES SCANS (v0.65) ══════ -->
  <h2>Résultats détaillés des scans</h2>
  <p style="font-size:13px;color:#636e72;margin-bottom:14px">
    Contenu intégral des sorties de chaque outil — cliquer sur un titre pour déplier.
    Le rapport est auto-contenu : aucun accès à la machine nécessaire.
  </p>

  <h3>📡 Nmap</h3>
  {nmap_section}

  <h3 style="margin-top:20px">💥 Exploit-DB / Searchsploit</h3>
  {searchsploit_section}

  <h3 style="margin-top:20px">🎯 Nuclei</h3>
  {nuclei_section}

  <h3 style="margin-top:20px">🌐 Énumération web</h3>
  {web_section}

  <h3 style="margin-top:20px">🪟 SMB / NetBIOS</h3>
  {smb_section}

  <h3 style="margin-top:20px">🔎 Découverte avancée (Robots · JS · Git · Archives · GPG)</h3>
  {recon_adv_section}

  <h3 style="margin-top:20px">🌐 WordPress</h3>
  {wordpress_section}

  <h3 style="margin-top:20px">💀 Exploitation</h3>
  {exploitation_section}

  <h3 style="margin-top:20px">🔓 Post-Exploitation</h3>
  {postexploit_section}

  <!-- ══════ RECOMMANDATIONS ══════ -->
  <h2>Recommandations</h2>
  <div style="font-size:14px;line-height:1.8">
    <p style="margin:6px 0"><strong>1.</strong> Valider manuellement chaque finding avant de le qualifier de vulnérabilité exploitable.</p>
    <p style="margin:6px 0"><strong>2.</strong> Corréler les exploits Searchsploit avec les versions exactes des services pour éliminer les faux positifs.</p>
    <p style="margin:6px 0"><strong>3.</strong> Prioriser la remédiation selon le score CVSS (Critical → High → Medium) et l'exposition réseau.</p>
    <p style="margin:6px 0"><strong>4.</strong> Pour les services Telnet/FTP en clair : migrer vers SSH/SFTP (désactivation immédiate recommandée).</p>
    <p style="margin:6px 0"><strong>5.</strong> Si null session SMB confirmée : restreindre les accès anonymes et appliquer les GPO de sécurité SMB.</p>
    <p style="margin:6px 0"><strong>6.</strong> Re-scanner après remédiation pour confirmer la correction effective.</p>
    <p style="margin:6px 0"><strong>7.</strong> Documenter les faux positifs identifiés pour améliorer la précision des prochains audits.</p>
  </div>

  <!-- ══════ DISCLAIMER ══════ -->
  <div class="disclaimer">
    <strong>Avertissement légal :</strong> Ce rapport est généré automatiquement par {_h(app_name)} v{_h(version)}.
    Les scores CVSS sont des estimations — ils ne remplacent pas une analyse manuelle approfondie.
    Les findings doivent être validés individuellement avant toute action de remédiation.
    Cet audit a été réalisé dans un cadre légal autorisé (lab / plateforme CTF).
    <strong>Aucune exploitation réelle n'a été effectuée.</strong>
  </div>

  <div class="footer">
    {_h(app_name)} v{_h(version)} — Rapport généré le {date} — 
    Classification : usage interne / lab uniquement — 
    Conforme cadre pédagogique SUP DE VINCI Mastère Cybersécurité 2025
  </div>

</div>
</body>
</html>"""


# ────────────────────────── PUBLIC API ──────────────────────────

def generate_reports(
    run_dir: Path,
    app_name: str,
    version: str,
    cfg_dict: dict,
    services: List[dict],
    findings: List[dict],
    urls: List[str],
    web_logs: Dict[str, List[str]],
    timings: Dict[str, float],
) -> Dict[str, Path]:
    """
    Point d'entrée principal du module reporting v0.64.
    Génère MD + JSON + HTML et retourne leurs chemins.
    """
    services_scored = [_score_service(s) for s in services]
    kill_chain      = _kill_chain_status(timings, cfg_dict)

    # ── Markdown ──
    md_content = _generate_md(
        run_dir, app_name, version, cfg_dict,
        services_scored, findings, urls, web_logs, timings, kill_chain,
    )
    report_md = run_dir / "report.md"
    report_md.write_text(md_content, encoding="utf-8", errors="replace")

    # ── JSON ──
    report_json = run_dir / "report.json"
    report_json.write_text(
        json.dumps({
            "meta": {
                "app": app_name, "version": version,
                "date": _now_iso(), "run_dir": str(run_dir),
                "run_id": cfg_dict.get("run_id", ""),
            },
            "config": cfg_dict,
            "target": cfg_dict.get("target", ""),
            "kill_chain": kill_chain,
            "services": services_scored,
            "urls": urls,
            "findings": findings,
            "web_logs": web_logs,
            "timings": timings,
        }, indent=2, default=str),
        encoding="utf-8", errors="replace",
    )

    # ── HTML ──
    html_content = _generate_html(
        run_dir, app_name, version, cfg_dict,
        services_scored, findings, urls, web_logs, timings, kill_chain,
    )
    report_html = run_dir / "report.html"
    report_html.write_text(html_content, encoding="utf-8", errors="replace")

    return {"md": report_md, "json": report_json, "html": report_html}
