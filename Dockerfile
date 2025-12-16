FROM python:3.11-slim

# Prevent Python from writing pyc files and buffering stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    net-tools \
    iputils-ping \
    nmap \
    gobuster \
    wget \
    sqlmap \
    && rm -rf /var/lib/apt/lists/*

# Install ExploitDB (SearchSploit)
RUN git clone https://github.com/offensive-security/exploitdb.git /opt/exploitdb \
    && ln -s /opt/exploitdb/searchsploit /usr/local/bin/searchsploit \
    && cp -n /opt/exploitdb/.searchsploit_rc ~/ 2>/dev/null || true


# Setup Wordlists
COPY wordlists/ /usr/share/wordlists/


# Set working directory
WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code (this is also mounted via docker-compose for dev)
COPY src ./src

# Default command
CMD ["python", "src/main.py"]
