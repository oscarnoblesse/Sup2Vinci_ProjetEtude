import subprocess
import shlex
import os
import re
from rich.panel import Panel
from src.core.module import BaseModule, console

import paramiko
import time
import shutil
import socket
import requests
from urllib.parse import urlparse
from rich.prompt import Prompt

class Module(BaseModule):
    def __init__(self):
        super().__init__()
        self.name = "Automated Reconnaissance & Audit"
        self.description = "Automates Nmap, Nikto, and Gobuster for a comprehensive target audit."
        self.author = ["Antigravity"]
        
        self.register_option("TARGET", "", True, "Target IP or URL (e.g. 192.168.1.1 or http://example.com)")
        self.register_option("REVIEW", "yes", False, "Pause for review between steps? (yes/no)")

    def run(self):
        if not self.validate_options():
            return

        raw_target = self.options['TARGET']['value']
        review = self.options['REVIEW']['value'].lower() == 'yes'
        
        # Step 0: Validation & Resolution
        console.print(Panel(f"Starting Auto Audit on {raw_target}", style="bold blue"))
        
        target_ip, target_domain = self.validate_and_resolve(raw_target)
        if not target_ip:
            console.print("[red]Could not resolve target. Exiting.[/red]")
            return
            
        console.print(f"[bold green][+] Target Resolved: {target_ip} ({target_domain if target_domain else 'No Domain'})[/bold green]")

        # --- Report Sections ---
        summary_section = []
        vuln_section = []
        auth_section = []
        recon_section = []
        raw_output_section = []
        
        summary_section.append(f"# Audit Report for {raw_target} ({target_ip})")
        summary_section.append(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        summary_section.append("-" * 40)

        # Step 1: Nmap Fast Scan
        console.print("\n[bold yellow][*] Step 1: Fast Nmap Scan (Discovery)[/bold yellow]")
        nmap_cmd = f"nmap -F {target_ip}"
        nmap_output, _ = self.run_command(nmap_cmd)
        
        raw_output_section.append("\n## [Raw] Nmap Fast Scan\n")
        raw_output_section.append(nmap_output)

        open_ports = self.extract_open_ports(nmap_output)
        port_msg = f"Found {len(open_ports)} open ports: {', '.join(open_ports)}"
        console.print(f"[green][+] {port_msg}[/green]")
        summary_section.append(f"\n## Network Summary\n- **Open Ports**: {', '.join(open_ports) if open_ports else 'None'}")
        
        if review: Prompt.ask("\nPress Enter to proceed to Web Enumeration...")

        # Step 2: Web Enumeration (Gobuster + Nikto)
        web_ports = [p for p in open_ports if p in ['80', '443', '8080', '8000', '8443']]
        
        if web_ports:
            console.print(f"\n[bold yellow][*] Step 2: Web Enumeration (Ports: {', '.join(web_ports)})[/bold yellow]")
            
            # Decide URL base (http vs https - heuristic)
            protocol = "https" if '443' in web_ports else "http"
            base_host = target_domain if target_domain else target_ip
            url = f"{protocol}://{base_host}"
            
            console.print(f"  -> Target URL: {url}")
            recon_section.append(f"\n## Web Reconnaissance ({url})\n")
            
            # 2a. Gobuster
            console.print("\n[cyan]--- Gobuster Directory Scan ---[/cyan]")
            wordlist = "/usr/share/wordlists/common.txt"
            if not os.path.exists(wordlist):
                 console.print(f"[red]Wordlist {wordlist} not found. Skipping Gobuster.[/red]")
            else:
                 gobuster_cmd = f"gobuster dir -u {url} -w {wordlist} -t 20 --no-error"
                 go_out, _ = self.run_command(gobuster_cmd)
                 raw_output_section.append(f"\n## [Raw] Gobuster\n{go_out}\n")
                 
                 # Extract interesting findings for Recon section
                 hits = [line for line in go_out.splitlines() if "Status: 200" in line or "Status: 301" in line]
                 if hits:
                     recon_section.append("### Interesting Directories:")
                     for h in hits: recon_section.append(f"- {h.strip()}")

            # 2b. CMS Scan (WPScan vs Nikto)
            console.print("\n[cyan]--- CMS/Web Server Scan ---[/cyan]")
            
            is_wp = self.detect_wordpress(url)
            if is_wp:
                console.print("[bold green][!] WordPress detected! Switching to WPScan.[/bold green]")
                summary_section.append("- **CMS Detected**: WordPress")
                wpscan_out = self.run_wpscan(url)
                raw_output_section.append(f"\n## [Raw] WPScan\n{wpscan_out}\n")
                
                # Basic wp parse
                if "[!]" in wpscan_out:
                    vuln_section.append("\n### WPScan Potential Issues")
                    for line in wpscan_out.splitlines():
                        if "[!]" in line: vuln_section.append(f"- {line.strip()}")
            else:
                console.print("[blue]Not WordPress. Running Nikto...[/blue]")
                
                import shutil
                if shutil.which("nikto") is None:
                    msg = "Nikto not found. Rebuild docker."
                    console.print(f"[red]{msg}[/red]")
                else:
                    nikto_cmd = f"nikto -h {url} -Tuning 123b -maxtime 10m"
                    nikto_out, _ = self.run_command(nikto_cmd)
                    raw_output_section.append(f"\n## [Raw] Nikto\n{nikto_out}\n")
                    
                    # Add Nikto findings to vuln section if critical
                    if "+ " in nikto_out:
                         recon_section.append("\n### Nikto Highlights:")
                         for line in nikto_out.splitlines():
                             if "+ " in line and ("OSVDB" in line or "Citrix" in line or "Vulnerable" in line):
                                 recon_section.append(f"- {line.strip()}")

        else:
            console.print("\n[bold yellow][*] Step 2: No web ports found. Skipping Web Enum.[/bold yellow]")

        if review: Prompt.ask("\nPress Enter to proceed to Vulnerability Scan...")

        # Step 3: Nmap Vulnerability Scan
        vuln_findings = []
        if open_ports:
            console.print("\n[bold yellow][*] Step 3: Vulnerability Scanning (Nmap NSE)[/bold yellow]")
            ports_str = ",".join(open_ports)
            
            # Use --script vuln -sV for service versions and vulns
            vuln_cmd = f"nmap -p {ports_str} --script vuln -sV {target_ip}"
            vuln_output, _ = self.run_command(vuln_cmd)
            
            raw_output_section.append("\n## [Raw] Nmap Vulnerability Scan\n")
            # Collapsible Block for Scan
            raw_output_section.append(f"<details>\n<summary>Click to view full Nmap Output</summary>\n\n```\n{vuln_output}\n```\n</details>\n")
            
            # Parse vulnerabilities
            vuln_findings = self.parse_nmap_vulns(vuln_output)
            
            # Step 4: SSH Audit (If SSH is open)
            if '22' in open_ports:
                console.print("\n[bold yellow][*] Step 4: SSH Audit & Exploitation[/bold yellow]")
                ssh_report = self.ssh_workflow(target_ip)
                if ssh_report:
                    auth_section.append("\n## SSH Audit & Compromise Attempt\n")
                    auth_section.append(ssh_report)
                    
                    # Capture credentials if successful
                    if "Credentials Valid!" in ssh_report or "HYDRA SUCCESS" in ssh_report:
                         summary_section.append("- **[CRITICAL] SSH ACCESS CONFIRMED**")
        else:
             console.print("\n[bold yellow][*] Step 3: No open ports. Skipping Vuln Scan.[/bold yellow]")

        # Step 5: Vulnerability Summary processing
        if vuln_findings:
            console.print("\n[bold red][!] ACTIONABLE VULNERABILITIES FOUND:[/bold red]")
            vuln_section.insert(0, "\n## [CRITICAL] CONFIRMED VULNERABILITIES")
            
            for vuln in vuln_findings:
                summary = f"[*] {vuln['id']} - {vuln['name']}"
                console.print(f"[red]{summary}[/red]")
                
                details = f"### {vuln['name']} ({vuln['id']})\n- **Info**: {vuln['info']}\n"
                vuln_section.append(details)
                
                # Add short summary to Executive Summary
                summary_section.append(f"- **[VULN]** {vuln['name']} ({vuln['id']})")
        else:
            console.print("\n[green][*] No obvious vulnerabilities detected by NSE scripts.[/green]")
            vuln_section.append("\n## Vulnerabilities\n- No Critical CVEs detected by Nmap NSE (Standard Scripts).")

        # Step 6: Generating Report
        console.print("\n[bold yellow][*] Step 6: Generating Report[/bold yellow]")
        
        final_report_content = []
        final_report_content.extend(summary_section)
        final_report_content.append("\n" + "="*40 + "\n")
        final_report_content.extend(vuln_section)
        final_report_content.append("\n" + "="*40 + "\n")
        final_report_content.extend(auth_section)
        final_report_content.append("\n" + "="*40 + "\n")
        final_report_content.extend(recon_section)
        final_report_content.append("\n" + "="*40 + "\n")
        final_report_content.extend(raw_output_section)
        
        report_file = f"audit_report_{target_ip.replace('.', '_')}.md"
        
        # Organize reports in a dedicated folder
        reports_dir = os.path.join("/app", "reports")
        if not os.path.exists(reports_dir):
            os.makedirs(reports_dir, exist_ok=True)
            # Try to fix dir permissions too
            try: os.chmod(reports_dir, 0o777)
            except: pass
            
        output_path = os.path.join(reports_dir, report_file)
        
        try:
            with open(output_path, "w") as f:
                f.write("\n".join(final_report_content))
            
            # CRITICAL: Fix permissions so Linux host user can read/write/delete (rw-rw-rw-)
            try:
                os.chmod(output_path, 0o666)
            except Exception as ex:
                console.print(f"[yellow]Warning: Could not set file permissions: {ex}[/yellow]")

            console.print(f"[bold green][+] Report saved to: reports/{report_file}[/bold green]")
            console.print(f"[dim](Accessible on your host machine in the 'reports' folder)[/dim]")
        except Exception as e:
            console.print(f"[red]Failed to save report: {e}[/red]")

        console.print(Panel("Audit Complete! check report for details.", style="bold green"))

    def validate_and_resolve(self, target):
        """
        Validates validation and resolves URL to IP.
        Returns (ip, domain_name_or_None)
        """
        # Check if it looks like a URL
        if target.startswith("http://") or target.startswith("https://"):
            try:
                parsed = urlparse(target)
                domain = parsed.netloc
                # Remove port if present for DNS resolution
                if ":" in domain:
                    domain = domain.split(":")[0]
                
                try:
                    ip = socket.gethostbyname(domain)
                    return ip, domain
                except socket.gaierror:
                    console.print(f"[red]Error: Could not resolve hostname {domain}[/red]")
                    return None, None
            except Exception as e:
                console.print(f"[red]Error parsing URL: {e}[/red]")
                return None, None
        
        # Assume it's an IP or Hostname
        try:
            # removing protocol if user lazily forgot http but typed www.
             if "://" not in target:
                 # Check if it's a valid IP
                 try:
                     socket.inet_aton(target)
                     return target, None # It's an IP
                 except socket.error:
                     # Treat as hostname
                     try:
                         ip = socket.gethostbyname(target)
                         return ip, target
                     except socket.gaierror:
                         console.print(f"[red]Error: Could not resolve {target}[/red]")
                         return None, None
        except Exception as e:
            console.print(f"[red]Error validating target: {e}[/red]")
            return None, None

    def ssh_workflow(self, target_ip):
        """Interactive SSH Audit Logic"""
        console.print(Panel(f"SSH detected on {target_ip}. Starting credential check...", style="blue"))
        
        # 0. Check SSH Version for CVE-2018-15473
        ssh_banner = self.grab_ssh_banner(target_ip)
        console.print(f"[*] SSH Banner: {ssh_banner}")
        
        user = ""
        password = ""
        
        # Heuristic version check
        is_vulnerable = False
        if "OpenSSH" in ssh_banner:
            try:
                # Example: SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.10
                ver_str = ssh_banner.split("OpenSSH_")[1].split(" ")[0].split("p")[0]
                version = float(ver_str)
                if version < 7.7:
                    is_vulnerable = True
                    console.print(f"[bold red][!] Target runs OpenSSH {version} (< 7.7) -> Potentially Vulnerable to User Enum (CVE-2018-15473)[/bold red]")
            except:
                pass

        user = Prompt.ask("Do you have a username? (Leave empty if no)", default="")
        
        # 1. User Enum Trigger
        if not user and is_vulnerable:
             if Prompt.ask("No username provided. Run CVE-2018-15473 User Enumeration?", choices=["y", "n"], default="y") == "y":
                 from src.modules.tools.reconnaissance.ssh_user_enum import SSHUserEnumCVE
                 wordlist = "/usr/share/wordlists/common.txt" # or ask user
                 
                 enum_tool = SSHUserEnumCVE(target_ip)
                 found_users = enum_tool.run(wordlist)
                 
                 if found_users:
                     console.print(f"[green]Users identified: {', '.join(found_users)}[/green]")
                     if len(found_users) == 1:
                         user = found_users[0]
                         console.print(f"[*] Using discovered user: {user}")
                     else:
                         # Let user pick or attack all
                         choice = Prompt.ask(f"Found {len(found_users)} users. Enter specific user to attack or leave empty to Attack ALL via Hydra:", default="")
                         if choice:
                             user = choice
                         else:
                             # We will pass the list file to hydra later? 
                             # Simpler: Just pick the first one or ask to create a userlist?
                             # Let's save them to a temp file for Hydra
                             with open("/tmp/valid_users.txt", "w") as f:
                                 f.write("\n".join(found_users))
                             console.print("[*] Users saved for Hydra attack.")
                             # Logic adjustment: run_hydra needs to handle a list if valid_users.txt exists and user is empty?
                             # For now, let's stick to simple flow.
                             user = "" # logic continues

        password = Prompt.ask("Do you have a password? (Leave empty if no)", default="", password=True)
        
        # Scenario 1: User + Password -> Try Login
        if user and password:
            console.print(f"[*] Trying credentials: {user}:{password}")
            success, client = self.try_ssh_login(target_ip, user, password)
            if success:
                # Keep session open for audit
                console.print("[bold green][!] Credentials Valid! Starting Internal Audit...[/bold green]")
                return self.perform_internal_audit(client, user, password)
            else:
                console.print("[red]Login failed.[/red]")
        
        # Scenario 2, 3, 4: Brute Force Options
        if Prompt.ask("Do you want to run a Brute Force attack?", choices=["y", "n"], default="n") == "y":
            
            wordlist = "/usr/share/wordlists/common.txt"
            if not os.path.exists(wordlist):
                console.print(f"[red]Wordlist {wordlist} not found.[/red]")
                return "Brute force skipped (No wordlist)."

            console.print("[yellow][*] Starting Hydra...[/yellow]")
            
            # Construct Hydra Command logic
            if user:
                console.print(f"[*] Brute forcing PASSWORD for user '{user}'...")
                return self.run_hydra(target_ip, user=user, pass_list=wordlist)
            
            elif password:
                console.print(f"[*] Brute forcing USERNAME for password '{password}'...")
                return self.run_hydra(target_ip, password=password, user_list=wordlist)
            
            else:
                # Check if we have our enumerated list
                if os.path.exists("/tmp/valid_users.txt"):
                     console.print("[*] using Enumerated Users List against Common Password List...")
                     return self.run_hydra(target_ip, user_list="/tmp/valid_users.txt", pass_list=wordlist)
                else:
                     console.print("[*] Brute forcing BOTH username and password...")
                     return self.run_hydra(target_ip, user_list=wordlist, pass_list=wordlist)
        else:
            return "User skipped brute force."
            
    def grab_ssh_banner(self, ip, port=22):
        try:
            sock = socket.socket()
            sock.settimeout(2)
            sock.connect((ip, int(port)))
            banner = sock.recv(1024).decode().strip()
            sock.close()
            return banner
        except:
            return "Unknown"

    def try_ssh_login(self, ip, user, password):
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            # Short timeout usually
            client.connect(ip, username=user, password=password, timeout=3)
            # Return True AND the client object (open session)
            console.print(f"[bold green][!] SUCCESS: Login confirmed for {user}![/bold green]")
            return True, client
        except Exception as e:
            return False, None

    def perform_internal_audit(self, client, user, password):
        """
        Executes a suite of commands on the remote host via SSH and generates a Rich Report.
        """
        results = {}
        
        # Command List (User provided + Extras)
        commands = {
            "System Info": "uname -a && uname -r && cat /etc/os-release",
            "Uptime": "uptime",
            "Current User": "whoami && id && groups",
            "Sudo Privileges": f"echo '{password}' | sudo -S -l 2>/dev/null || sudo -l", 
            "Network Config": "ip a && ip r",
            "Listening Ports": "ss -tulnp",
            "ARP Table": "arp -a",
            "Processes (Top 20 MEM)": "ps aux --sort=-%mem | head -n 20",
            # Run from /tmp to avoid "Could not chdir" errors if home is broken
            "SUID Binaries": "cd /tmp && find / -type f -perm -4000 -ls 2>/dev/null", 
            # Check Global Crons + User Crons
            "Crontab & Timers": "ls -la /etc/cron* /var/spool/cron* 2>/dev/null && cat /etc/crontab 2>/dev/null && crontab -l 2>/dev/null",
            # Explicitly check for interpreters. Output format: /usr/bin/python Python 2.7.12
            "Dev Tools & Interpreters": "for p in python python3 perl gcc g++ make nc netcat socat wget curl php ruby; do path=$(command -v $p); [ -n \"$path\" ] && echo \"$path $($p --version 2>&1 | head -n 1)\"; done",
            "Installed Packages": "dpkg -l | head -n 20 || rpm -qa | head -n 20",
            "Passwd File": "cat /etc/passwd | tail -n 10",
            "Sensitive Files (Search)": "grep -Ri 'password' /var/www 2>/dev/null | head -n 10"
        }
        
        console.print("[yellow][*] Execution internal audit commands... Please wait.[/yellow]")
        
        raw_report_blocks = []
        
        for title, cmd in commands.items():
            console.print(f"  -> {title}...")
            try:
                stdin, stdout, stderr = client.exec_command(cmd, timeout=10)
                out = stdout.read().decode('utf-8', errors='replace').strip()
                err = stderr.read().decode('utf-8', errors='replace').strip()
                
                output = out if out else (f"[Error]: {err}" if err else "[Empty]")
                results[title] = output
                
                # Format specific blocks
                icon = "📄"
                if "Sudo" in title: icon = "🔑"
                if "SUID" in title: icon = "⚡"
                if "Ports" in title: icon = "🌐"
                if "Dev" in title: icon = "🛠️"
                
                # Collapsible for long outputs
                if len(output.splitlines()) > 5:
                    block = f"""
### {icon} {title}
<details>
<summary>Click to view content</summary>

```bash
{output}
```
</details>
"""
                else:
                    block = f"""
### {icon} {title}
```bash
{output}
```
"""
                raw_report_blocks.append(block)
                
            except Exception as e:
                results[title] = f"Error executing: {e}"
                raw_report_blocks.append(f"### ❌ {title}\n**Failed**: {e}")

        # Close connection after audit
        client.close()
        
        # SMART ANALYSIS with Color & SearchSploit
        analysis_report = self.analyze_audit_results_colored(results)
        exploit_report = self.check_software_exploits(results)
        
        # Combine
        final_report = "## 🕵️‍♂️ Post-Exploitation & System Audit\n"
        final_report += f"> **Credentials Used**: `{user}` : `{password}`\n\n"
        final_report += analysis_report
        final_report += exploit_report
        final_report += "\n" + "="*40 + "\n### 📂 Detailed System Enumeration\n"
        final_report += "".join(raw_report_blocks)
        
        return final_report
        
    def analyze_audit_results_colored(self, results):
        """Analyzes results and returns a formatted HTML/Markdown string with colors"""
        findings = []
        
        # 1. Check Sudo - The Holy Grail
        sudo_out = results.get("Sudo Privileges", "")
        if "(ALL)" in sudo_out or "NOPASSWD" in sudo_out:
             findings.append("""
> [!CAUTION]
> **CRITICAL: SUDO PRIVILEGES DETECTED!**
> <span style="color:red; font-weight:bold;">User has SUDO rights. Full Root Compromise is likely possible.</span>
""")
        
        # 2. Check SUID (GTFOBins candidates)
        suid_out = results.get("SUID Binaries", "")
        dangerous_suids = ["nmap", "vim", "nano", "find", "bash", "cp", "mv", "awk", "python", "perl", "tar", "zip", "systemctl"]
        hits = []
        for bin_name in dangerous_suids:
            if f"/{bin_name}" in suid_out:
                hits.append(bin_name)
        
        if hits:
             findings.append(f"""
> [!WARNING]
> **Dangerous SUID Binaries Found**
> <span style="color:orange;">Binaries that can be abused for Privilege Escalation:</span> `{", ".join(hits)}`
> Check GTFOBins: https://gtfobins.github.io/
""")

        # 3. Check Secrets
        secrets_www = results.get("Sensitive Files (Search)", "")
        if secrets_www and "password" in secrets_www.lower() and "[Empty]" not in secrets_www:
             findings.append("""
> [!IMPORTANT]
> **Sensitive Data Found**
> <span style="color:blue;">Potential passwords found in /var/www. Check detailed output.</span>
""")

        # 4. Kernel
        uname = results.get("System Info", "")
        if "Linux 2.6" in uname or "Linux 3." in uname:
             findings.append("> [!NOTE]\n> **Old Kernel Detected**: Potential DirtyCOW or similar kernel exploits may apply.")

        if not findings:
            return "\n> [!TIP]\n> Automated checks didn't find obvious privilege escalation vectors. Check the manual enumeration below.\n"
        
        return "\n".join(findings) + "\n"

    def check_software_exploits(self, results):
        """
        Parses detected software and runs local SearchSploit checks.
        """
        findings = []
        
        # 1. Kernel Exploits
        # Try to find a version number in System Info using Regex
        sys_info = results.get("System Info", "")
        # Regex for Kernel: 3.13.0-32-generic etc.
        import re
        kernel_match = re.search(r"(\d+\.\d+\.\d+[-\w]*)", sys_info)
        
        if kernel_match:
             kernel_version = kernel_match.group(1)
             console.print(f"[magenta][debug] Checking Kernel: {kernel_version}[/magenta]")
             findings.append(self.query_searchsploit("Linux Kernel", kernel_version))

        # 2. Interpreter Versions
        dev_out = results.get("Dev Tools & Interpreters", "")
        console.print(f"[magenta][debug] Parsing Dev Tools...[/magenta]")
        
        for line in dev_out.splitlines():
            if "/" in line:
                 try:
                     parts = line.split()
                     path = parts[0]
                     name = os.path.basename(path)
                     
                     # Improved Parsings: Find the first token that looks like a version x.y.z
                     version = ""
                     # specialized regex for version
                     ver_match = re.search(r"(\d+\.\d+(\.\d+)?)", line)
                     if ver_match:
                         # Ensure we don't pick up the process ID or something random, usually strictly after name
                         # Heuristic: skip if match is in the path itself
                         if ver_match.group(1) not in path:
                             version = ver_match.group(1)
                     
                     if version:
                         console.print(f"[magenta][debug] Found {name} -> {version}. Querying SearchSploit...[/magenta]")
                         findings.append(self.query_searchsploit(name, version))
                 except Exception as e:
                     console.print(f"[red][debug] Error parsing line '{line}': {e}[/red]")

        findings = [f for f in findings if f]
        
        if not findings:
            console.print("[magenta][debug] No exploits found or parsed.[/magenta]")
            return ""
            
        return "\n### 💣 Potential Exploits (SearchSploit)\n" + "\n".join(findings)

    def _get_exploit_csv(self):
        """Downloads the ExploitDB CSV index if not present"""
        csv_path = "/tmp/files_exploits.csv"
        url = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
        
        if os.path.exists(csv_path) and os.path.getsize(csv_path) > 0:
            return csv_path
            
        try:
            console.print(f"[cyan][*] Downloading ExploitDB CSV Index...[/cyan]")
            import requests # Lazy import
            r = requests.get(url, timeout=10)
            if r.status_code == 200:
                with open(csv_path, 'wb') as f:
                    f.write(r.content)
                return csv_path
        except Exception as e:
            console.print(f"[red]Failed to download ExploitDB CSV: {e}[/red]")
            return None
            
        return None

    def query_searchsploit(self, name, version):
        """
        Searches exploits in the CSV index (Lightweight method).
        Matches if 'name' AND 'version' appear in the description.
        """
        csv_path = self._get_exploit_csv()
        if not csv_path:
            return ""

        short_ver = ".".join(version.split(".")[:2])
        if not short_ver: short_ver = version
        
        # Search terms
        t_name = name.lower()
        t_ver = short_ver.lower()
        
        matches = []
        try:
            import csv
            with open(csv_path, 'r', encoding='utf-8', errors='ignore') as f:
                reader = csv.reader(f)
                next(reader, None) # Skip header
                
                for row in reader:
                    if len(row) < 3: continue
                    
                    exploit_id = row[0]
                    description = row[2].lower()
                    
                    # Basic matching logic
                    if t_name in description and t_ver in description:
                        # Match!
                        matches.append((exploit_id, row[2])) # Original Clean Desc
                        
            if not matches:
                # Debug info if zero matches found despite version existing
                # console.print(f"[dim]No matches for {t_name} + {t_ver}[/dim]")
                return ""
                
            # Limit to top 5 to avoid spam
            top_matches = matches[:5]
            
            console.print(f"[green]  -> Found {len(matches)} exploits for {name} {version}![/green]")
            
            links = []
            for eid, desc in top_matches:
                links.append(f"- [**{eid}**] [{desc}](https://www.exploit-db.com/exploits/{eid})")
            
            return f"""
#### 🕷️ {name.title()} {version} (Found {len(matches)} Exploits)
<details>
<summary>Click to view Exploit-DB Links</summary>

{chr(10).join(links)}

[View all results on Exploit-DB](https://www.exploit-db.com/search?q={name}+{version})
</details>
"""
        except Exception as e:
            # console.print(f"[red]CSV Search Error: {e}[/red]")
            return ""
        # 4. Kernel
        uname = results.get("System Info", "")
        if "Linux 2.6" in uname or "Linux 3." in uname:
             findings.append("> [!NOTE]\n> **Old Kernel Detected**: Potential DirtyCOW or similar kernel exploits may apply.")

        if not findings:
            return "\n> [!TIP]\n> Automated checks didn't find obvious privilege escalation vectors. Check the manual enumeration below.\n"
        
        return "\n".join(findings) + "\n"

    def run_hydra(self, ip, user=None, password=None, user_list=None, pass_list=None):
        cmd = "hydra"
        
        # Login args
        if user:
            cmd += f" -l {user}"
        elif user_list:
            cmd += f" -L {user_list}"
            
        # Password args
        if password:
            cmd += f" -p {password}"
        elif pass_list:
            cmd += f" -P {pass_list}"
            
        # -t 4: tasks
        # -I: ignore existing restore
        # -V: verbose
        # -e nsr: try "null" password, "same" as user, "reverse" as user
        cmd += f" ssh://{ip} -t 4 -I -V -e nsr"
        
        # Run
        output, _ = self.run_command(cmd)
        
        # Check for specific error about password auth
        if "does not support password authentication" in output:
             console.print("[bold red][!] ERROR: Target server has disabled Password Authentication.[/bold red]")
             console.print("[yellow]    -> Attempts to brute force passwords will fail.[/yellow]")
             console.print("[yellow]    -> The server may require an SSH Key or Keyboard-Interactive auth (which Hydra might not support easily here).[/yellow]")
        
        # Check for success in output (hydra usually prints host: ip login: user password: pass)
        # Regex is safer than simple string check as output format can vary
        if "login:" in output and "password:" in output and "0 valid password found" not in output:
             console.print("[bold green][!] HYDRA SUCCESS![/bold green]")
             return f"Hydra Findings:\n{output}"
        else:
             console.print("[yellow]Hydra finished without obvious success.[/yellow]")
             return f"Hydra Output (No success):\n{output}"



    def detect_wordpress(self, url):
        """Checks if the target is a WordPress site."""
        try:
            # Check for wp-login.php
            r = requests.get(f"{url}/wp-login.php", timeout=5, verify=False)
            if r.status_code == 200 and "wordpress" in r.text.lower():
                return True
                
            # Check homepage for wp-content/
            r2 = requests.get(url, timeout=5, verify=False)
            if "wp-content/" in r2.text:
                return True
                
            return False
        except:
            return False

    def run_wpscan(self, url):
        """Runs WPScan against the target"""
        # --enumerate u: User enumeration
        # --disable-tls-checks: Ignore SSL errors
        # Removing --no-update to ensure DB runs at least once
        cmd = f"wpscan --url {url} --disable-tls-checks --enumerate u"
        
        console.print(f"[blue]Running: {cmd}[/blue]")
        # WPScan writes progress to stderr mostly, finding to stdout
        output, _ = self.run_command(cmd)
        return output

    def run_command(self, command):
        """Helper to run a command and return output + return code"""
        console.print(f"[blue]Running: {command}[/blue]")
        try:
            cmd_parts = shlex.split(command)
            result = subprocess.run(
                cmd_parts, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.STDOUT, 
                text=True
            )
            if result.stdout:
                console.print(result.stdout.strip())
            return result.stdout, result.returncode
        except Exception as e:
            console.print(f"[red]Error executing command: {e}[/red]")
            return str(e), -1

    def extract_open_ports(self, nmap_output):
        """Simple regex to find open ports from nmap output"""
        ports = []
        # Pattern for "80/tcp open http"
        for line in nmap_output.splitlines():
            if "/tcp" in line and " open " in line:
                port = line.split("/")[0].strip()
                ports.append(port)
        return ports

    def parse_nmap_vulns(self, nmap_output):
        """Parses standard Nmap NSE output for vulnerability details"""
        findings = []
        current_vuln = {}
        
        lines = nmap_output.splitlines()
        for idx, line in enumerate(lines):
            line = line.strip()
            
            # Detect script start (approximate) or State: VULNERABLE
            # Example: "|   State: VULNERABLE"
            if "State: VULNERABLE" in line:
                # Look backwards for the script name (usually the line starting with "| " or "|_")
                # and explicitly look for ID/CVE
                
                # Check surrounding lines for context
                # This is a basic parser; nmap XML output would be better but requires xml.etree
                
                # Simple strategy: If line says VULNERABLE, capture the previous lines as name
                # and subsequent lines as details until blank or next script
                
                vuln_name = "Unknown Vulnerability"
                # Try to find name in previous lines (heuristic)
                for i in range(1, 10):
                    prev = lines[idx - i].strip()
                    if prev.startswith("| ") or prev.startswith("|_"):
                        # remove format chars
                        vuln_name = re.sub(r"^\|_?\s*", "", prev).split(":")[0]
                        break
                
                # Try to find IDs in subsequent lines
                vuln_id = "No ID"
                details = ""
                for i in range(1, 20):
                    if idx + i >= len(lines): break
                    next_line = lines[idx + i].strip()
                    details += next_line + " "
                    
                    if "IDs:" in next_line:
                        vuln_id = next_line.split("IDs:")[1].strip()
                
                findings.append({
                    'name': vuln_name,
                    'id': vuln_id,
                    'info': details[:200] + "..." # Truncate detailed info
                })
                
        return findings
