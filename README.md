# Python Killchain Toolkit

A modular, containerized penetration testing toolkit inspired by Metasploit.

## Features
- **Cross-Platform**: Runs on Windows, macOS, and Linux via Docker.
- **Modular**: Easy to add new exploits/modules.
- **Console Interface**: User-friendly command-line interface.

## Prerequisites
- [Docker](https://www.docker.com/) installed and running.

## Installation & Setup

1. **Clone the repository** (if you haven't already):
   ```bash
   git clone <repository-url>
   cd Sup2Vinci_ProjetEtude
   ```

2. **Build the container**:
   ```bash
   docker-compose build
   ```

3. **Run the toolkit**:
   ```bash
   docker-compose up -d
   docker-compose exec toolkit python src/main.py
   ```
   Or for an interactive shell inside the container:
   ```bash
   docker-compose exec toolkit /bin/bash
   ```

## Development
- The source code in `src/` is mounted to `/app/src` in the container.
- Changes to files in `src/` are reflected immediately (unless they require a restart of the python process or new dependencies).
