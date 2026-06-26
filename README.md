# Pentool v0.68

Toolbox pentest automatisée — SUP DE VINCI 2026 — Projet M1 Cybersécurité

Couvre le cycle complet : **Recon → Énumération → Analyse vulnérabilités → Exploitation → Reporting**.

---

## 🚀 Lancement — 3 méthodes

### Méthode 1 : `start.sh` (recommandée)

Le script gère tout automatiquement : vérifie Docker, build l'image si absente, lance l'application.

```bash
# WebUI (interface graphique) → http://localhost:5001
./start.sh

# CLI — wizard interactif (demande la cible au démarrage)
./start.sh --cli

# CLI — scan direct sans wizard
./start.sh --cli 10.10.10.1 --authorized --scan-mode pentest --pn --staged

# Forcer le rebuild de l'image (après modification du code)
./start.sh --build

# Arrêter les conteneurs
./start.sh --stop

# Voir les logs WebUI en direct
./start.sh --logs
```

> **Prérequis** : Docker Desktop installé (le script tente de le démarrer automatiquement si ce n'est pas le cas).

---

### Méthode 2 : Docker manuel

```bash
# Build
docker compose build

# WebUI → http://localhost:5001
docker compose up -d webui

# CLI — wizard interactif
docker run --rm -it \
  --cap-add NET_RAW --cap-add NET_ADMIN \
  --network host \
  -v $(pwd)/runs:/runs \
  -e PYTHONUNBUFFERED=1 \
  -e TERM=xterm-256color \
  pentool:0.68 \
  python3 pentool-v0.068.py

# CLI — scan direct
docker run --rm -it \
  --cap-add NET_RAW --cap-add NET_ADMIN \
  --network host \
  -v $(pwd)/runs:/runs \
  -e PYTHONUNBUFFERED=1 \
  -e TERM=xterm-256color \
  pentool:0.68 \
  python3 pentool-v0.068.py 10.10.10.1 --authorized --scan-mode pentest --pn --staged

# Arrêter
docker compose down
```

Les résultats sont sauvegardés dans `./runs/` sur ta machine.

### VPN — TryHackMe / HackTheBox

Les trois méthodes utilisent `--network host` par défaut, ce qui permet d'accéder aux cibles VPN depuis l'hôte. Si ce n'est pas le cas, vérifie que `network_mode: "host"` est actif dans `docker-compose.yml`.

---

### Méthode 3 : Local (sans Docker, Kali / Debian)

```bash
# Outils système
sudo apt install -y nmap ffuf gobuster whatweb nikto smbclient smbmap \
                    hydra exploitdb enum4linux-ng nuclei sqlmap wpscan \
                    nfs-common rpcbind python2

# Wordlists (recommandé)
sudo apt install -y seclists

# Dépendances Python
pip3 install flask requests paramiko rich --break-system-packages

# WebUI
python3 pentool-v0.068.py --ui web

# CLI — wizard interactif
python3 pentool-v0.068.py

# CLI — scan direct
python3 pentool-v0.068.py 10.10.10.1 --authorized --scan-mode pentest --pn --staged
```

> ⚠️ Sans Docker, les outils doivent être installés manuellement. Docker est recommandé pour un environnement clé-en-main.

---

## Modes de scan

| Mode | Ports scannés | Exploitation | Durée |
|------|:---:|:---:|:---:|
| `quick` | top 1000 | ❌ (opt-in `--exploit`) | ~1 min |
| `pentest` | top 1000 | ✅ automatique | ~2 min |
| `full` | 65 535 | ✅ automatique | 10+ min |

```bash
--scan-mode quick    # Recon uniquement
--scan-mode pentest  # Recommandé CTF — quick + exploitation
--scan-mode full     # Scan complet + exploitation
```

---

## Kill Chain couverte

| Phase | Outils | Statut |
|---|---|:---:|
| 1 — Reconnaissance | Nmap ports discovery (staged) | ✅ |
| 2 — Scanning & Enum | Nmap -sV -sC, enum4linux-ng | ✅ |
| 3 — Analyse vulnérabilités | NSE vuln, Searchsploit, Nuclei | ✅ |
| 4 — Web Analysis | WhatWeb, ffuf/Gobuster, Nikto | ✅ |
| 5 — Exploitation FTP | FTP anonyme → listing + download + write test | ✅ |
| 5 — Exploitation SMB | smbclient + smbmap → shares + permissions | ✅ |
| 5 — Exploitation SSH | Détection CVE-2018-15473 (OpenSSH < 7.7) | ✅ |
| 5 — Brute Force | Hydra FTP/SSH (opt-in `--exploit-brute`) | ✅ |
| 6 — Reporting | HTML/MD/JSON auto-contenu | ✅ |

---

## Structure

```
pentool-v0.68/
├── pentool-v0.068.py     # Script principal (CLI + WebUI + Exploitation)
├── start.sh              # Script de démarrage tout-en-un
├── Dockerfile            # Image Docker (Kali Rolling)
├── docker-compose.yml    # Compose : webui + cli
├── .dockerignore
├── webui/
│   ├── app.py            # Flask backend (CSRF, CSP, validation)
│   └── templates/        # Jinja2 templates
├── static/               # CSS + JS WebUI
└── runs/                 # Résultats des scans (gitignore recommandé)
```

---

## Options exploitation

```bash
--exploit              # Active la phase exploitation (pour scan-mode quick)
--no-exploit           # Désactive même si pentest/full
--exploit-brute        # Brute force Hydra (opt-in, lent)
--userlist <path>      # Wordlist usernames pour Hydra
--passlist <path>      # Wordlist passwords pour Hydra
```

---

## Cadre légal

Outil pédagogique — usage **exclusivement** sur des cibles pour lesquelles tu as une autorisation explicite :
TryHackMe · Hack The Box · Root-Me · Labs autorisés.

Le flag `--authorized` est requis pour tout lancement.

