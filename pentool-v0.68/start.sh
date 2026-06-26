#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
#  Pentool v0.68 — Script de démarrage
#  Usage :
#    ./start.sh          → build si nécessaire + lance WebUI
#    ./start.sh --build  → force le rebuild de l'image
#    ./start.sh --stop   → arrête les conteneurs
#    ./start.sh --logs   → affiche les logs en direct
#    ./start.sh --cli <target> [args]  → lance un scan CLI direct
# ─────────────────────────────────────────────────────────────

set -euo pipefail

# ── Couleurs ────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

PENTOOL_VERSION="0.68"
IMAGE_NAME="pentool:${PENTOOL_VERSION}"
WEBUI_URL="http://localhost:5001"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Banner ───────────────────────────────────────────────────
banner() {
  echo -e "${CYAN}"
  echo "  ██████╗ ███████╗███╗   ██╗████████╗ ██████╗  ██████╗ ██╗     "
  echo "  ██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██╔═══██╗██╔═══██╗██║     "
  echo "  ██████╔╝█████╗  ██╔██╗ ██║   ██║   ██║   ██║██║   ██║██║     "
  echo "  ██╔═══╝ ██╔══╝  ██║╚██╗██║   ██║   ██║   ██║██║   ██║██║     "
  echo "  ██║     ███████╗██║ ╚████║   ██║   ╚██████╔╝╚██████╔╝███████╗"
  echo "  ╚═╝     ╚══════╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝"
  echo -e "${NC}"
  echo -e "  ${BOLD}Pentool v${PENTOOL_VERSION}${NC} - Toolbox de pentest automatisée (Recon + Exploitation + Reporting)"
  echo -e "  SUP DE VINCI 2026 - Projet M1 Cybersécurité"
  echo ""
}

# ── Helpers ──────────────────────────────────────────────────
ok()   { echo -e "  ${GREEN}[✓]${NC} $*"; }
info() { echo -e "  ${CYAN}[i]${NC} $*"; }
warn() { echo -e "  ${YELLOW}[!]${NC} $*"; }
err()  { echo -e "  ${RED}[✗]${NC} $*"; }
die()  { err "$*"; exit 1; }
sep()  { echo -e "  ${CYAN}────────────────────────────────────────${NC}"; }

# Installe Docker automatiquement selon l'OS
propose_docker_install() {
  err "Docker n'est pas installé sur cette machine."
  echo ""
  echo -e "  Docker est nécessaire pour lancer Pentool."
  echo -e "  ${BOLD}Voulez-vous l'installer automatiquement maintenant ?${NC}"
  echo ""
  printf "  [o/N] → "
  read -r REPLY </dev/tty
  echo ""

  if [[ ! "$REPLY" =~ ^[oOyY]$ ]]; then
    info "Installation annulée."
    info "Installe Docker manuellement : https://www.docker.com/products/docker-desktop"
    exit 1
  fi

  OS="$(uname -s)"
  ARCH="$(uname -m)"

  case "$OS" in

    Darwin)
      # ── macOS ──────────────────────────────────────────────
      if command -v brew &>/dev/null; then
        info "Homebrew détecté → installation via brew..."
        brew install --cask docker
        ok "Docker Desktop installé."
        info "Ouverture de Docker Desktop..."
        open -a Docker 2>/dev/null || true

      else
        # Pas de brew → téléchargement du .dmg officiel
        info "Homebrew absent → téléchargement du .dmg Docker Desktop..."
        if [[ "$ARCH" == "arm64" ]]; then
          DMG_URL="https://desktop.docker.com/mac/main/arm64/Docker.dmg"
        else
          DMG_URL="https://desktop.docker.com/mac/main/amd64/Docker.dmg"
        fi
        DMG_PATH="/tmp/Docker.dmg"
        info "Téléchargement depuis $DMG_URL (peut prendre quelques minutes)..."
        curl -L --progress-bar "$DMG_URL" -o "$DMG_PATH" || die "Échec du téléchargement."
        info "Montage du .dmg..."
        hdiutil attach "$DMG_PATH" -quiet
        info "Copie de Docker.app dans /Applications..."
        cp -R /Volumes/Docker/Docker.app /Applications/ || die "Impossible de copier Docker.app."
        hdiutil detach /Volumes/Docker -quiet 2>/dev/null || true
        rm -f "$DMG_PATH"
        ok "Docker Desktop installé dans /Applications."
        info "Ouverture de Docker Desktop..."
        open -a Docker 2>/dev/null || true
      fi
      ;;

    Linux)
      # ── Linux ───────────────────────────────────────────────
      if ! command -v curl &>/dev/null; then
        die "curl est requis pour télécharger Docker. Lance : sudo apt install curl"
      fi
      info "Installation via le script officiel Docker (get.docker.com)..."
      curl -fsSL https://get.docker.com | sudo sh || die "Échec de l'installation Docker."
      ok "Docker Engine installé."

      # Ajoute l'utilisateur au groupe docker (évite sudo à chaque commande)
      if id -nG "$USER" | grep -qw docker; then
        ok "Utilisateur $USER déjà dans le groupe docker."
      else
        info "Ajout de $USER au groupe docker..."
        sudo usermod -aG docker "$USER"
        warn "Groupe docker appliqué — il faudra te reconnecter (ou lancer : newgrp docker) pour l'effet immédiat."
      fi

      # Démarrage du service
      info "Démarrage du service Docker..."
      if command -v systemctl &>/dev/null; then
        sudo systemctl enable docker --now || die "Impossible de démarrer Docker."
      else
        sudo service docker start || die "Impossible de démarrer Docker."
      fi
      ok "Docker Engine démarré."
      ;;

    MINGW*|MSYS*|CYGWIN*)
      # ── Windows (Git Bash / MSYS2 / Cygwin) ────────────────
      echo ""
      err "Windows détecté — installation automatique non supportée."
      echo ""
      echo -e "  Installe ${BOLD}Docker Desktop pour Windows${NC} manuellement :"
      echo -e "  ${CYAN}https://www.docker.com/products/docker-desktop${NC}"
      echo ""
      echo -e "  Une fois installé, démarre Docker Desktop puis relance : ${YELLOW}./start.sh${NC}"
      echo ""
      exit 1
      ;;

    *)
      die "OS non supporté : $OS. Installe Docker manuellement : https://docs.docker.com/get-docker/"
      ;;
  esac

  echo ""
  # Attend que Docker soit prêt avant de continuer
  info "En attente que Docker soit prêt"
  TRIES=0
  until docker info &>/dev/null 2>&1; do
    sleep 2
    TRIES=$((TRIES + 1))
    printf "."
    if [[ $TRIES -ge 30 ]]; then
      echo ""
      warn "Docker installé mais pas encore démarré."
      info "Lance Docker Desktop manuellement puis relance : ${YELLOW}./start.sh${NC}"
      exit 1
    fi
  done
  echo ""
  ok "Docker est prêt — poursuite du lancement..."
  echo ""
}

# ── Commandes rapides ────────────────────────────────────────
if [[ "${1:-}" == "--stop" ]]; then
  banner
  info "Arrêt des conteneurs Pentool..."
  cd "$SCRIPT_DIR"
  docker compose down
  ok "Conteneurs arrêtés."
  exit 0
fi

if [[ "${1:-}" == "--logs" ]]; then
  cd "$SCRIPT_DIR"
  exec docker compose logs -f webui
fi

if [[ "${1:-}" == "--cli" ]]; then
  shift
  banner
  cd "$SCRIPT_DIR"
  mkdir -p "$SCRIPT_DIR/runs"

  # ── 1. Vérification Docker installé ───────────────────────
  sep
  info "Vérification de Docker..."
  if ! command -v docker &>/dev/null; then
    propose_docker_install
  fi
  ok "Docker trouvé : $(docker --version)"

  # ── 2. Démarrage du daemon Docker si nécessaire ───────────
  if ! docker info &>/dev/null 2>&1; then
    warn "Le daemon Docker n'est pas démarré. Tentative de démarrage..."

    OS="$(uname -s)"
    case "$OS" in
      Darwin)
        info "macOS détecté → ouverture de Docker Desktop..."
        open -a Docker 2>/dev/null || die "Impossible d'ouvrir Docker Desktop. Lance-le manuellement."
        ;;
      Linux)
        info "Linux détecté → démarrage du service Docker..."
        if command -v systemctl &>/dev/null; then
          sudo systemctl start docker || die "Impossible de démarrer Docker. Lance : sudo systemctl start docker"
        else
          sudo service docker start || die "Impossible de démarrer Docker. Lance : sudo service docker start"
        fi
        ;;
      *)
        die "OS non supporté : $OS"
        ;;
    esac

    info "En attente du démarrage de Docker"
    TRIES=0
    until docker info &>/dev/null 2>&1; do
      sleep 2
      TRIES=$((TRIES + 1))
      printf "."
      [[ $TRIES -ge 30 ]] && echo "" && die "Docker n'a pas démarré après 60 secondes. Vérifie Docker Desktop."
    done
    echo ""
    ok "Docker est prêt."
  else
    ok "Docker daemon actif."
  fi

  # ── 3. Vérification / build de l'image ────────────────────
  sep
  if ! docker image inspect "$IMAGE_NAME" &>/dev/null 2>&1; then
    info "Image $IMAGE_NAME absente → build en cours..."
    info "Première installation : le build peut prendre 5-10 minutes (téléchargement Kali + outils pentest)."
    echo ""
    docker compose build
    ok "Image ${IMAGE_NAME} construite."
  else
    ok "Image ${IMAGE_NAME} déjà présente."
  fi
  sep

  # Le code est embarqué dans l'image (COPY . . dans le Dockerfile).
  # On monte uniquement ./runs pour récupérer les résultats sur l'hôte.
  # → Pas de conflit de filesystem macOS/Docker sur les imports Python.
  # Si tu modifies le code : ./start.sh --build pour rebuilder l'image.
  #
  # Sans arg  → wizard interactif (demande la cible)
  # Avec args → scan direct : ./start.sh --cli 10.10.10.1 --authorized ...
  if [[ $# -eq 0 ]]; then
    LAUNCH_CMD="python3 pentool-v0.068.py"
  else
    LAUNCH_CMD="python3 pentool-v0.068.py $*"
  fi

  # Boucle : après chaque scan le wizard se relance automatiquement.
  # Ctrl-C pendant le scan arrête l'outil en cours puis revient au menu.
  # Ctrl-C sur le menu (ou deux fois rapidement) quitte le conteneur.
  LOOP_CMD="trap 'echo \"\"; echo \"[pentool] Bye!\"; exit 0' INT; while true; do $LAUNCH_CMD || true; echo ''; echo '[pentool] Scan terminé — relance dans 1s (Ctrl-C sur ce message pour quitter)'; sleep 3; done"

  # Transmet la taille et le type du terminal hôte au conteneur
  # pour que Rich/curses ait le même rendu qu'en local.
  _COLS=$(tput cols 2>/dev/null || echo 120)
  _LINES=$(tput lines 2>/dev/null || echo 40)
  _TERM="${TERM:-xterm-256color}"

  # Détecte le color system : truecolor si COLORTERM le dit, sinon 256
  if [[ "${COLORTERM:-}" == "truecolor" || "${COLORTERM:-}" == "24bit" ]]; then
    _PENTOOL_COLOR="truecolor"
  else
    _PENTOOL_COLOR="256"
  fi

  exec docker run --rm -it \
    --cap-add NET_RAW \
    --cap-add NET_ADMIN \
    --network host \
    -v "$SCRIPT_DIR/runs":/runs \
    -w /pentool \
    -e PYTHONUNBUFFERED=1 \
    -e PENTOOL_WORKSPACE=/runs \
    -e TERM="$_TERM" \
    -e COLORTERM="${COLORTERM:-}" \
    -e COLUMNS="$_COLS" \
    -e LINES="$_LINES" \
    -e _PENTOOL_COLOR="$_PENTOOL_COLOR" \
    --entrypoint bash \
    "$IMAGE_NAME" \
    -i -c "$LOOP_CMD"
fi

# ── Mode principal : WebUI ────────────────────────────────────
banner
FORCE_BUILD=false
[[ "${1:-}" == "--build" ]] && FORCE_BUILD=true

# ── 1. Vérification Docker installé ─────────────────────────
sep
info "Vérification de Docker..."
if ! command -v docker &>/dev/null; then
  propose_docker_install
fi
ok "Docker trouvé : $(docker --version)"

# ── 2. Démarrage du daemon Docker si nécessaire ──────────────
if ! docker info &>/dev/null 2>&1; then
  warn "Le daemon Docker n'est pas démarré. Tentative de démarrage..."

  OS="$(uname -s)"
  case "$OS" in
    Darwin)
      info "macOS détecté → ouverture de Docker Desktop..."
      open -a Docker 2>/dev/null || die "Impossible d'ouvrir Docker Desktop. Lance-le manuellement."
      ;;
    Linux)
      info "Linux détecté → démarrage du service Docker..."
      if command -v systemctl &>/dev/null; then
        sudo systemctl start docker || die "Impossible de démarrer Docker. Lance : sudo systemctl start docker"
      else
        sudo service docker start || die "Impossible de démarrer Docker. Lance : sudo service docker start"
      fi
      ;;
    *)
      die "OS non supporté : $OS"
      ;;
  esac

  # Attente que Docker soit prêt (max 60s)
  info "En attente du démarrage de Docker"
  TRIES=0
  until docker info &>/dev/null 2>&1; do
    sleep 2
    TRIES=$((TRIES + 1))
    printf "."
    [[ $TRIES -ge 30 ]] && echo "" && die "Docker n'a pas démarré après 60 secondes. Vérifie Docker Desktop."
  done
  echo ""
  ok "Docker est prêt."
else
  ok "Docker daemon actif."
fi

# ── 3. Build de l'image si absente ou --build forcé ─────────
sep
if $FORCE_BUILD; then
  info "Rebuild forcé de l'image ${IMAGE_NAME}..."
  cd "$SCRIPT_DIR"
  docker compose build --no-cache
  ok "Image ${IMAGE_NAME} reconstruite."
elif ! docker image inspect "$IMAGE_NAME" &>/dev/null 2>&1; then
  info "Image ${IMAGE_NAME} absente → build en cours..."
  info "Première installation : le build peut prendre 5-10 minutes (téléchargement Kali + outils pentest)."
  echo ""
  cd "$SCRIPT_DIR"
  docker compose build
  ok "Image ${IMAGE_NAME} construite."
else
  ok "Image ${IMAGE_NAME} déjà présente (utilise --build pour forcer le rebuild)."
fi

# ── 4. Arrêt du conteneur existant si nécessaire ─────────────
sep
if docker ps -a --format '{{.Names}}' | grep -q "^pentool_webui$"; then
  RUNNING=$(docker ps --format '{{.Names}}' | grep "^pentool_webui$" || true)
  if [[ -n "$RUNNING" ]]; then
    info "Conteneur pentool_webui déjà en cours → redémarrage..."
    cd "$SCRIPT_DIR"
    docker compose restart webui
  else
    info "Conteneur pentool_webui arrêté → démarrage..."
    cd "$SCRIPT_DIR"
    docker compose start webui
  fi
else
  info "Démarrage du conteneur WebUI..."
  cd "$SCRIPT_DIR"
  docker compose up -d webui
fi

# ── 5. Attente que le WebUI soit accessible ──────────────────
info "En attente du démarrage du WebUI"
TRIES=0
until curl -sf "${WEBUI_URL}" -o /dev/null 2>/dev/null; do
  sleep 1
  TRIES=$((TRIES + 1))
  printf "."
  [[ $TRIES -ge 30 ]] && echo "" && warn "WebUI long à démarrer. Vérifie les logs : ./start.sh --logs" && break
done
echo ""
ok "WebUI disponible."

# ── 6. Ouverture du navigateur ───────────────────────────────
sep
OS="$(uname -s)"
case "$OS" in
  Darwin) open "${WEBUI_URL}" 2>/dev/null || true ;;
  Linux)
    if command -v xdg-open &>/dev/null; then
      xdg-open "${WEBUI_URL}" 2>/dev/null || true
    elif command -v firefox &>/dev/null; then
      firefox "${WEBUI_URL}" &>/dev/null &
    fi
    ;;
esac

# ── 7. Récapitulatif ─────────────────────────────────────────
sep
echo ""
echo -e "  ${BOLD}${GREEN}✓ Pentool v${PENTOOL_VERSION} est lancé !${NC}"
echo ""
echo -e "  ${BOLD}WebUI${NC}          → ${CYAN}${WEBUI_URL}${NC}"
echo -e "  ${BOLD}Logs live${NC}      → ${YELLOW}./start.sh --logs${NC}"
echo -e "  ${BOLD}Arrêter${NC}        → ${YELLOW}./start.sh --stop${NC}"
echo -e "  ${BOLD}Rebuild image${NC}  → ${YELLOW}./start.sh --build${NC}"
echo -e "  ${BOLD}Scan CLI${NC}       → ${YELLOW}./start.sh --cli <target_ip> --authorized --scan-mode pentest${NC}"
echo ""
sep
