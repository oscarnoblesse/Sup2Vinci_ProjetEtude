# ─────────────────────────────────────────────
#  Pentool v0.68 — Image Docker
#  Base : Kali Linux Rolling (tous les outils
#  pentest disponibles via apt)
# ─────────────────────────────────────────────
FROM kalilinux/kali-rolling

LABEL version="0.68"
LABEL description="Pentool v0.68 - Toolbox de pentest automatisée (Recon + Exploitation + Reporting) - SUP DE VINCI 2026 - Projet M1 Cybersécurité"

# Évite les prompts interactifs pendant apt
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PENTOOL_WORKSPACE=/runs

# ── 1. Outils système + pentest ──────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Runtime Python
    python3 python3-pip python3-flask \
    # Python 2 (scripts ExploitDB legacy — ex: 45939.py SSH user enum)
    python2 \
    # Scanning réseau
    nmap \
    # Web fuzzing
    ffuf gobuster \
    # Wordlists (SecLists complet + dirb fallback)
    seclists dirb \
    # Fingerprinting web
    whatweb nikto \
    # SMB enumeration & access
    smbclient smbmap \
    # Brute force
    hydra \
    # SMB avancé
    enum4linux-ng \
    # Exploit references
    exploitdb \
    # Vuln scanner moderne
    nuclei \
    # Injection SQL automatique
    sqlmap \
    # WordPress scanner
    wpscan \
    # NFS enumeration (showmount, rpcinfo)
    nfs-common rpcbind \
    # Utils
    curl wget git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ── 2. Mise à jour des templates Nuclei ──────
RUN nuclei -update-templates -silent || true

# ── 3. Dépendances Python supplémentaires ────
RUN pip3 install --break-system-packages \
    flask \
    requests \
    paramiko

# ── 4. Application ───────────────────────────
WORKDIR /pentool
COPY . .

# ── 5. Répertoire de sortie (à monter en volume)
RUN mkdir -p /runs

# ── 6. Port WebUI ────────────────────────────
EXPOSE 5000

# ── Commande par défaut : WebUI ──────────────
# Override pour CLI :
#   docker run --rm -it --cap-add NET_RAW --cap-add NET_ADMIN \
#     pentool python3 pentool-v0.068.py 10.10.10.1 --authorized --scan-mode pentest
CMD ["python3", "pentool-v0.068.py", "--ui", "web", \
     "--web-host", "0.0.0.0", \
     "--workspace", "/runs"]
