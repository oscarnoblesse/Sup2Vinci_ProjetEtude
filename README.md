# Pentool v0.68

**Toolbox de pentest automatisée**
**SUP DE VINCI — M1 Cybersécurité (Projet 2026)**

Couvre le cycle complet :

**Reconnaissance → Énumération → Analyse de vulnérabilités → Exploitation → Reporting**

---

# Installation locale (Python)

```bash
# Donner les permissions
chmod +x pentool-v0.068.py

# Lancement
sudo ./pentool-v0.068.py

# Interface Web
sudo ./pentool-v0.068.py --ui web

# Scan pentest
sudo ./pentool-v0.068.py <IP_cible> --authorized --scan-mode pentest
```

---

# Options d'exploitation

```bash
--exploit              # Active l'exploitation (mode quick)
--no-exploit           # Désactive l'exploitation
--exploit-brute        # Hydra (opt-in)
--userlist <path>      # Wordlist utilisateurs
--passlist <path>      # Wordlist mots de passe
```

---

# Modes de scan

| Mode      |   Ports  |      Exploitation      |  Durée  |
| --------- | :------: | :--------------------: | :-----: |
| `quick`   | Top 1000 | ❌ (option `--exploit`) |  ~1 min |
| `pentest` | Top 1000 |      ✅ Automatique     |  ~2 min |
| `full`    |  65 535  |      ✅ Automatique     | 10+ min |

```bash
--scan-mode quick
--scan-mode pentest
--scan-mode full
```

---

# Démarrage rapide (Docker) — start.sh (recommandé)

Le script gère automatiquement :

* Vérification de Docker
* Installation de Docker si nécessaire
* Build de l'image
* Lancement de l'application

```bash
./start.sh
```

Interface Web :

```
http://localhost:5001
```

Autres options :

```bash
./start.sh --cli
./start.sh --build
./start.sh --stop
./start.sh --logs
```

Prérequis :

* Docker Desktop (Windows/macOS)
* Docker Engine (Linux)

---

# 🐳 Docker

Docker embarque tous les outils :

* Nmap
* ffuf
* smbclient
* Hydra
* Nuclei
* Searchsploit
* Python 2
* Python 3

## Build

```bash
docker build -t pentool:0.68 .
```

## Interface Web

```bash
docker compose up webui
```

Puis ouvrir :

```
http://localhost:5000
```

Les résultats sont sauvegardés dans :

```
runs/
```

---

## CLI

### Pentest

```bash
docker compose run --rm cli 10.10.10.1 --authorized --scan-mode pentest --pn --staged
```

### Quick

```bash
docker compose run --rm cli 10.10.10.1 --authorized --scan-mode quick --pn --staged
```

### Full

```bash
docker compose run --rm cli 10.10.10.1 --authorized --scan-mode full --pn --staged
```

---

# VPN (Hack The Box / TryHackMe)

Décommenter dans `docker-compose.yml` :

```yaml
network_mode: "host"
```

Supprimer ensuite :

```yaml
ports:
```

Ou lancer directement :

```bash
docker run --rm -it \
  --cap-add NET_RAW \
  --cap-add NET_ADMIN \
  --network host \
  -v $(pwd)/runs:/runs \
  pentool:0.68 \
  python3 pentool-v0.068.py 10.10.10.1 \
  --authorized \
  --scan-mode pentest \
  --pn \
  --staged
```

---

# Kill Chain couverte

| Phase                      | Fonction                               | Statut |
| -------------------------- | -------------------------------------- | :----: |
| Reconnaissance             | Nmap (Discovery)                       |    ✅   |
| Énumération                | Nmap `-sV -sC`, enum4linux-ng          |    ✅   |
| Analyse des vulnérabilités | NSE, Searchsploit, Nuclei              |    ✅   |
| Analyse Web                | WhatWeb, ffuf, Gobuster, Nikto         |    ✅   |
| Exploitation FTP           | Anonymous Login, Download, Upload Test |    ✅   |
| Exploitation SMB           | smbclient, smbmap                      |    ✅   |
| Exploitation SSH           | Détection CVE-2018-15473               |    ✅   |
| Brute Force                | Hydra (optionnel)                      |    ✅   |
| Reporting                  | HTML / Markdown / JSON                 |    ✅   |

---

# Structure du projet

```text
pentool-v0.68/
├── pentool-v0.068.py
├── Dockerfile
├── docker-compose.yml
├── .dockerignore
├── webui/
│   ├── app.py
│   └── templates/
├── static/
└── runs/
```

---

# Cadre légal

 Outil pédagogique.

À utiliser **uniquement** sur des systèmes pour lesquels tu disposes d'une autorisation explicite.

Exemples :

* TryHackMe
* Hack The Box
* Root-Me
* Laboratoires personnels
* Environnements autorisés
