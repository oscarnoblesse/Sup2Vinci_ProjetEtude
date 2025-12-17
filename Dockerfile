FROM python:3.11-slim

# Prevent Python from writing pyc files and buffering stdout/stderr
# Prevent Python from writing pyc files and buffering stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV TERM=xterm-256color

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
    hydra \
    ruby \
    ruby-dev \
    build-essential \
    libcurl4-openssl-dev \
    openssh-client \
    libreadline-dev \
    && rm -rf /var/lib/apt/lists/*

# Configure SSH to accept legacy algorithms (for Hydra/Paramiko against old targets)
RUN mkdir -p /root/.ssh && \
    echo "Host *\n\tHostKeyAlgorithms +ssh-rsa,ssh-dss\n\tPubkeyAcceptedKeyTypes +ssh-rsa,ssh-dss" > /root/.ssh/config && \
    chmod 600 /root/.ssh/config && \
    echo "    HostKeyAlgorithms +ssh-rsa,ssh-dss" >> /etc/ssh/ssh_config && \
    echo "    PubkeyAcceptedKeyTypes +ssh-rsa,ssh-dss" >> /etc/ssh/ssh_config

# Install WPScan
RUN gem install wpscan && wpscan --update


# Install Nikto (from Git)
RUN git clone https://github.com/sullo/nikto.git /opt/nikto \
    && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto


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
