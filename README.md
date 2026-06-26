# Pentool v0.68

Toolbox pentest automatisée  SUP DE VINCI 2026  Projet M1 Cybersécurité

Couvre le cycle complet : **Recon > Énumération > Analyse vulnérabilités > Exploitation > Reporting**.


## Installation locale (script python)

```bash
# Permission d'exécution
chmod +x pentool-v0.068.py

# Lancement
sudo ./pentool-v0.068.py
sudo ./pentool-v0.068.py --ui web          # Interface Web
sudo ./pentool-v0.068.p <IP_cible> --authorized --scan-mode pentest # Preset pentest
```

---
## Démarrage rapide — start.sh (recommandé)
Le script gère tout automatiquement : vérifie Docker, l'installe si absent, build l'image si nécessaire, puis lance l'application.
```bash
bash./start.sh                  # WebUI → http://localhost:5001
./start.sh --cli            # CLI wizard interactif
./start.sh --build          # Force le rebuild de l'image
./start.sh --stop           # Arrête les conteneurs
./start.sh --logs           # Logs WebUI en direct
```
Prérequis : Docker Desktop. Si absent, start.sh propose de l'installer automatiquement (macOS/Linux).

## 🐳 Démarrage rapide — Docker

Docker embarque tous les outils (nmap, ffuf, smbclient, hydra, nuclei, exploitdb, python2…) sans rien installer sur ta machine.

### Build

```bash
docker build -t pentool:0.66 .
```

### WebUI (interface graphique)

```bash
docker compose up webui
# → http://localhost:5000
```

Les résultats sont sauvegardés dans `./runs/` sur ta machine.

### CLI — scan direct

```bash
# Mode pentest (quick + exploitation auto)
docker compose run --rm cli 10.10.10.1 --authorized --scan-mode pentest --pn --staged

# Mode quick (recon seul)
docker compose run --rm cli 10.10.10.1 --authorized --scan-mode quick --pn --staged

# Mode full (65535 ports + exploitation)
docker compose run --rm cli 10.10.10.1 --authorized --scan-mode full --pn --staged
```

### VPN — TryHackMe / HackTheBox

Si ta cible est accessible via VPN sur l'hôte, décommente `network_mode: "host"` dans `docker-compose.yml` :

```yaml
# docker-compose.yml → service webui ou cli
network_mode: "host"
# (supprimer les "ports:" si network_mode: host)
```

Ou directement :

```bash
docker run --rm -it \
  --cap-add NET_RAW --cap-add NET_ADMIN \
  --network host \
  -v $(pwd)/runs:/runs \
  pentool:0.66 \
  python3 pentool-v0.065.py 10.10.10.1 --authorized --scan-mode pentest --pn --staged
```
## Options exploitation

```bash
--exploit              # Active la phase exploitation (pour scan-mode quick)
--no-exploit           # Désactive même si pentest/full
--exploit-brute        # Brute force Hydra (opt-in, lent)
--userlist <path>      # Wordlist usernames pour Hydra
--passlist <path>      # Wordlist passwords pour Hydra

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

## Cadre légal

Outil pédagogique — usage **exclusivement** sur des cibles pour lesquelles tu as une autorisation explicite :
TryHackMe · Hack The Box · Root-Me · Labs autorisés.

---
