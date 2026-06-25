# Pentool — Historique des fonctionnalités

> Projet de fin de Master en Cybersécurité — SUP DE VINCI 2025  
> Toolbox d'automatisation pentest avec génération de rapport HTML/MD/JSON

---

## Base initiale — v0.60 (fondations)

Point de départ du projet : script CLI de reconnaissance automatisée (detection-only, pas d'exploitation).

- **Mode CLI interactif** : wizard de démarrage (cible, mode scan, confirmation légale `--authorized`)
- **Mode WebUI Flask** : interface graphique locale sur `http://localhost:5000`
- **Scan Nmap** : découverte de ports + énumération services (`-sV -sC`)
- **WhatWeb** : fingerprinting des technologies web (CMS, serveur, langage)
- **Nikto** : audit web legacy (misconfigs, headers, fichiers sensibles)
- **Gobuster** : bruteforce de répertoires et fichiers
- **Searchsploit** : mapping automatique Exploit-DB depuis les services détectés par Nmap
- **Nuclei** : scanner de vulnérabilités par templates (CVE, expositions, misconfigs)
- **enum4linux-ng** : énumération SMB/NetBIOS (partages, utilisateurs, policies de mots de passe)
- **Rapport MD + JSON** : génération automatique en fin de scan

---

## v0.62 — Preset "pro-fast" & Web enum progressive

- **Preset `pro-fast`** : profil de performance qui désactive les outils lents et active Searchsploit par défaut
- **Web enum "early"** : démarrage progressif de l'énumération web en parallèle du scan Nmap (dès la détection d'un port ouvert), avec garde-fous sur la concurrence (max URLs simultanées, max Gobuster, threads réduits)
- **FFUF** : fuzzing web avancé (répertoires + vhosts) en remplacement/complément de Gobuster

---

## v0.64 — Reporting embarqué (HTML inline)

- **Rapport HTML auto-contenu** : les résultats de tous les scans (Nmap, Nuclei, Searchsploit, enum4linux…) sont intégrés directement dans le fichier HTML — plus besoin de fichiers externes
- Export triple **MD + JSON + HTML** en fin de chaque run, stocké sous `runs/<ip>/<run_id>/`
- **`reporting.py`** : module externe dédié, séparé du moteur de scan

---

## v0.64.1 — Portabilité & résultats reproductibles

- **Environnement d'exécution figé** pour toutes les commandes : locale `C.UTF-8`, couleurs désactivées (`TERM=dumb`, `NO_COLOR`), `PYTHONIOENCODING=utf-8` → même résultat peu importe la locale système (fr/de/en)
- **Nettoyage ANSI** systématique (`strip_ansi`) avant tout parsing regex
- **Searchsploit** : comptage fiable des hits (exclut les bordures et titres de tableau ASCII)
- **Nmap vuln** : ne compte que les vulnérabilités CONFIRMÉES (exclut "NOT VULNERABLE" / "LIKELY VULNERABLE")
- **enum4linux-ng** : détection de session nulle robuste (JSON multi-clés + repli texte, quel que soit la version de l'outil)
- **Sonde HTTP/HTTPS** : timeout relevé 1.2 s → 4.0 s, configurable via `--probe-timeout` (cibles VPN distantes)
- **`parse_nmap_xml`** : champs `None`-safe, ports invalides ignorés proprement

---

## v0.65 — Stabilité, performance & UX

- **Preset `pro-fast` vraiment rapide** : tune désormais les paramètres coûteux (wordlist courte `common.txt`, Nuclei sévérité `high,critical` uniquement, ffuf `-t 20`, timeouts adaptés) — l'utilisateur garde le dernier mot via flags explicites
- **Nettoyage des sous-processus** : chaque outil tourne dans sa propre session de processus (`start_new_session=True`) ; gestionnaire `Ctrl-C / SIGTERM / fin` tue tout le groupe → plus d'orphelins `ffuf / nmap / nuclei`
- **Kill groupe au timeout** : le groupe de processus entier est tué (pas seulement le parent)
- **Affichage Rich corrigé** : les labels `[nmap ports]` ne sont plus interprétés comme balises de markup par Rich
- **Feedback anti-silence** : message "toujours en cours (Xs)" toutes les 30 s pour les outils web longs lancés en thread (ffuf, nikto…)
- **Résumé de config** : affiche la sévérité Nuclei et les threads ffuf choisis au démarrage

---

## v0.66 — Phase Exploitation automatique

- **FTP anonyme** : listing récursif, téléchargement de fichiers intéressants, test d'écriture dans les répertoires
- **SMB anonyme** : énumération des partages + permissions via `smbclient` + `smbmap`
- **SSH CVE-2018-15473** : détection de la vulnérabilité d'énumération d'utilisateurs (OpenSSH < 7.7) via timing-based check
- **Hydra brute force** : attaque par dictionnaire FTP/SSH (opt-in : `--exploit-brute` + `--userlist` / `--passlist`)
- **Nouveaux flags** : `--exploit`, `--no-exploit`, `--exploit-brute`, `--userlist`, `--passlist`
- La phase exploitation ne se déclenche que si `--exploit` + `--authorized` sont fournis, et seulement si le recon le justifie

---

## v0.67 — Initial Access & Post-Exploitation

- **Initial Access via FTP** : génère un payload bash reverse shell, l'uploade dans un répertoire FTP writable détecté en phase recon, ouvre un listener Python natif, attend la connexion (90 s)
- **Post-exploitation automatique** après obtention du shell :
  - Collecte système : `id`, `whoami`, `hostname`, `uname -a`
  - Lecture `/etc/passwd` et `/etc/shadow`
  - Recherche des binaires SUID avec matching GTFOBins intégré (dictionnaire local)
  - Audit `sudo -l` (entrées sans mot de passe)
  - Post-exploit via **SSH + paramiko** si identifiants découverts par Hydra
  - Privesc avancée : exploitation SUID/sudo via GTFOBins, lecture fichiers sensibles
- **GTFOBins** : dictionnaire local des binaires exploitables (bash, python3, find, vim, awk, curl…)
- **Nouveaux flags** : `--lhost`, `--lport`, `--no-postexploit`

---

## v0.68 — Découverte avancée & Pipeline WordPress

### Découverte avancée

- **`robots.txt` + `sitemap.xml`** : parsing automatique, extraction et injection des URLs cachées dans le pipeline de scan web
- **Scraper JS** : analyse des fichiers JavaScript (clés API exposées, endpoints internes, secrets hardcodés)
- **Détection `.git` exposé** : vérifie si le dépôt Git est accessible publiquement (`.git/HEAD`, `.git/config`)
- **Analyse d'archives** : extraction + recherche de credentials dans les archives récupérées (zip, tar.gz…) ; crack de protection avec `zip2john` + `john` (opt-in `--archive-crack`)
- **Déchiffrement GPG** : tentative de déchiffrement des fichiers `.gpg` trouvés lors du recon
- **Nouveaux flags** : `--no-robots`, `--no-js-scrape`, `--no-git-check`, `--archive-crack`

### Pipeline WordPress (4 étapes en cascade)

- **Étape 1 — Scan recon (auto)** : WPScan recon passif — version WP, utilisateurs énumérés, plugins et thèmes installés, Searchsploit sur les CVE détectés (lancé automatiquement si WordPress détecté)
- **Étape 2 — Brute force** (opt-in `--wp-brute`) : attaque par dictionnaire sur les comptes WP découverts à l'étape 1 via WPScan + wordlist auto
- **Étape 3 — Scan agressif** (opt-in `--wp-aggressive`) : WPScan mode agressif — détection exhaustive de tous les plugins et thèmes installés, y compris les versions vulnérables (lent)
- **Étape 4 — Theme Injection** (opt-in `--wp-exploit`) : post-exploitation — injection d'un reverse shell PHP dans le thème actif via `wp-admin` (nécessite credentials obtenus à l'étape 2 + `--lhost`)
- **Cascade** : l'étape 2 déverrouille les étapes 3 et 4 (impossibles sans brute force réussi)

### Améliorations WebUI (interface Flask)

- **Dashboard réorganisé** : sections regroupées par dépendance technologique (réseau, web, WordPress, brute force & cracking, post-exploitation)
- **Pipeline WP visuel** : 4 blocs cliquables (toute la surface, pas seulement la checkbox) avec cascade visuelle (étapes 3 et 4 grisées jusqu'à activation de l'étape 2)
- **Brute force & cracking** déplacés hors de la section LHOST (Hydra/archives ne nécessitent pas d'IP attaquant)
- **Hydra simplifié** : une seule checkbox au lieu d'une section imbriquée confuse
- **Suppression du bouton auto-détect LHOST** (non fonctionnel)
- **Suppression de la section web auth** (fonctionnalité non utilisée — retirée du template et de `app.py`)
- **Correction CSP** : ajout de `'unsafe-inline'` dans `script-src` pour débloquer le JavaScript inline (inline `<script>` et handlers `onclick` bloqués silencieusement par la directive précédente)

---

## Fonctionnalités web avancées (intégrées progressivement)

- **Web crawl** (`--web-crawl`) : crawl récursif des pages, extraction de liens, formulaires et paramètres GET/POST
- **Scan XSS** (`--xss`) : injection de payloads XSS sur tous les formulaires et paramètres découverts par le crawl
- **SQLmap** (`--sqlmap`) : injection SQL automatique sur les URLs et formulaires découverts
- **FFUF vhosts** : discovery de sous-domaines/vhosts par fuzzing du header `Host`

---

## Infrastructure & déploiement

- **Dockerfile** (Kali Rolling) : image tout-en-un avec nmap, ffuf, gobuster, whatweb, nikto, smbclient, hydra, exploitdb, nuclei, python3
- **Docker Compose** : deux services — `webui` (Flask sur `:5000`) et `cli` (scan direct)
- **3 modes de scan** :
  - `quick` — top 1 000 ports, recon seul (~1 min)
  - `pentest` — top 1 000 ports + exploitation automatique (~2 min)
  - `full` — 65 535 ports + exploitation (~10 min+)
- **VPN support** : `network_mode: host` pour TryHackMe / HackTheBox

---

## Kill chain couverte

| Phase | Outils / Modules | Statut |
|---|---|:---:|
| 1 — Reconnaissance | Nmap ports discovery (staged), WhatWeb | ✅ |
| 2 — Scanning & Enum | Nmap `-sV -sC`, enum4linux-ng, ffuf/Gobuster | ✅ |
| 3 — Analyse vulnérabilités | NSE vuln, Searchsploit, Nuclei | ✅ |
| 4 — Web Analysis | Nikto, crawl, XSS, SQLmap, JS scrape, robots, .git | ✅ |
| 4b — WordPress | WPScan recon → brute → agressif → theme inject | ✅ |
| 5 — Exploitation | FTP anon, SMB anon, SSH CVE-2018-15473, Hydra | ✅ |
| 5b — Initial Access | Reverse shell FTP + listener Python natif | ✅ |
| 6 — Post-Exploitation | SUID/sudo/GTFOBins, passwd/shadow, SSH paramiko | ✅ |
| 7 — Reporting | HTML inline / MD / JSON auto-générés | ✅ |
