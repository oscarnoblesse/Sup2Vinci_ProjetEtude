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

        report_data = []
        report_data.append(f"Audit Report for {raw_target} ({target_ip})")
        report_data.append("="*40 + "\n")

        # Step 1: Nmap Fast Scan
        console.print("\n[bold yellow][*] Step 1: Fast Nmap Scan (Discovery)[/bold yellow]")
        nmap_cmd = f"nmap -F {target_ip}"
        nmap_output, _ = self.run_command(nmap_cmd)
        
        report_data.append("\n[NMAP FAST SCAN]\n")
        report_data.append(nmap_output)

        open_ports = self.extract_open_ports(nmap_output)
        console.print(f"[green][+] Found {len(open_ports)} open ports: {', '.join(open_ports)}[/green]")
        
        if review: Prompt.ask("\nPress Enter to proceed to Web Enumeration...")

        # Step 2: Web Enumeration (Gobuster + Nikto)
        web_ports = [p for p in open_ports if p in ['80', '443', '8080', '8000', '8443']]
        
        if web_ports:
            console.print(f"\n[bold yellow][*] Step 2: Web Enumeration (Ports: {', '.join(web_ports)})[/bold yellow]")
            
            # Decide URL base (http vs https - heuristic)
            protocol = "https" if '443' in web_ports else "http"
            # Use domain if available for vhosts, otherwise IP
            base_host = target_domain if target_domain else target_ip
            url = f"{protocol}://{base_host}"
            
            console.print(f"  -> Target URL: {url}")
            report_data.append("\n[WEB ENUMERATION]\n")
            
            # 2a. Gobuster
            console.print("\n[cyan]--- Gobuster Directory Scan ---[/cyan]")
            wordlist = "/usr/share/wordlists/common.txt"
            if not os.path.exists(wordlist):
                 console.print(f"[red]Wordlist {wordlist} not found. Skipping Gobuster.[/red]")
            else:
                 gobuster_cmd = f"gobuster dir -u {url} -w {wordlist} -t 20 --no-error"
                 go_out, _ = self.run_command(gobuster_cmd)
                 report_data.append(f"--- Gobuster ---\n{go_out}\n")

            # 2b. CMS Scan (WPScan vs Nikto)
            console.print("\n[cyan]--- CMS/Web Server Scan ---[/cyan]")
            
            is_wp = self.detect_wordpress(url)
            if is_wp:
                console.print("[bold green][!] WordPress detected! Switching to WPScan.[/bold green]")
                wpscan_out = self.run_wpscan(url)
                report_data.append(f"--- WPScan ---\n{wpscan_out}\n")
            else:
                console.print("[blue]Not WordPress. Running Nikto...[/blue]")
                
                import shutil
                if shutil.which("nikto") is None:
                    msg = "[red]Error: 'nikto' binary not found in PATH.[/red]\n[yellow]Please rebuild the Docker image to install it:[/yellow]\n[bold]docker-compose build --no-cache[/bold]"
                    console.print(msg)
                    report_data.append(f"--- Nikto ---\n{msg}\n")
                else:
                    # Speed optimization:
                    # -Tuning 123b: Interesting files, Misconfigs, Info Disclosure, Software ID
                    # -maxtime 600s: Limit scan to 10 minutes max
                    nikto_cmd = f"nikto -h {url} -Tuning 123b -maxtime 10m"
                    nikto_out, _ = self.run_command(nikto_cmd)
                    report_data.append(f"--- Nikto ---\n{nikto_out}\n")

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
            
            report_data.append("\n[VULNERABILITY SCAN]\n")
            report_data.append(vuln_output)
            
            # Parse vulnerabilities
            vuln_findings = self.parse_nmap_vulns(vuln_output)
            
            # Step 4: SSH Audit (If SSH is open)
            if '22' in open_ports:
                console.print("\n[bold yellow][*] Step 4: SSH Audit & Exploitation[/bold yellow]")
                ssh_report = self.ssh_workflow(target_ip)
                if ssh_report:
                    report_data.append("\n[SSH AUDIT]\n")
                    report_data.append(ssh_report)
        else:
             console.print("\n[bold yellow][*] Step 3: No open ports. Skipping Vuln Scan.[/bold yellow]")

        # Step 5: Vulnerability Summary
        if vuln_findings:
            console.print("\n[bold red][!] ACTIONABLE VULNERABILITIES FOUND:[/bold red]")
            report_data.append("\n" + "="*40 + "\n[ACTIONABLE VULNERABILITIES]\n" + "="*40 + "\n")
            
            for vuln in vuln_findings:
                summary = f"[*] {vuln['id']} - {vuln['name']}"
                console.print(f"[red]{summary}[/red]")
                report_data.append(summary)
                if vuln['info']:
                    report_data.append(f"    Info: {vuln['info']}")
        else:
            console.print("\n[green][*] No obvious vulnerabilities detected by NSE scripts.[/green]")
            report_data.append("\n[SUMMARY] No obvious vulnerabilities detected.")

        # Step 6: Report Generation
        console.print("\n[bold yellow][*] Step 6: Generating Report[/bold yellow]")
        report_file = f"audit_report_{target_ip.replace('.', '_')}.txt"
        
        # Ensure we write where we can see it (mounted volume root or reports/ dir)
        # Assuming run from /app/src, let's write to /app (project root)
        output_path = os.path.join("/app", report_file)
        
        try:
            with open(output_path, "w") as f:
                f.write("\n".join(report_data))
            console.print(f"[bold green][+] Report saved to: {output_path}[/bold green]")
        except Exception as e:
            console.print(f"[red]Failed to save report: {e}[/red]")

        console.print(Panel("Audit Complete!", style="bold green"))

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
        
        user = Prompt.ask("Do you have a username? (Leave empty if no)", default="")
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
                # Fall through to brute force request if they want
        
        # Scenario 2, 3, 4: Brute Force Options
        if Prompt.ask("Do you want to run a Brute Force attack?", choices=["y", "n"], default="n") == "y":
            
            wordlist = "/usr/share/wordlists/common.txt"
            if not os.path.exists(wordlist):
                console.print(f"[red]Wordlist {wordlist} not found.[/red]")
                return "Brute force skipped (No wordlist)."

            console.print("[yellow][*] Starting Hydra...[/yellow]")
            
            # Construct Hydra Command logic
            if user:
                # Have user, brute passwords (U + p)
                # hydra -l user -P list ssh://ip
                console.print(f"[*] Brute forcing PASSWORD for user '{user}'...")
                return self.run_hydra(target_ip, user=user, pass_list=wordlist)
            
            elif password:
                # Have pass, brute users (u + P)
                # hydra -L list -p pass ssh://ip
                console.print(f"[*] Brute forcing USERNAME for password '{password}'...")
                return self.run_hydra(target_ip, password=password, user_list=wordlist)
            
            else:
                # Have nothing, brute both (U + P)
                # hydra -L list -P list ssh://ip
                console.print("[*] Brute forcing BOTH username and password...")
                return self.run_hydra(target_ip, user_list=wordlist, pass_list=wordlist)
        else:
            return "User skipped brute force."

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
        Executes a suite of commands on the remote host via SSH.
        Returns a formatted string report.
        """
        results = {}
        
        # Command List (User provided + Extras)
        commands = {
            "System Info": "uname -a && uname -r && cat /etc/os-release",
            "Hostname": "hostname",
            "Uptime": "uptime",
            "Current User": "whoami && id && groups",
            "Sudo Privileges": f"echo '{password}' | sudo -S -l 2>/dev/null || sudo -l", # Try sudo -l with pass if needed
            "Network Config": "ip a && ip r",
            "Listening Ports": "ss -tulnp",
            "ARP Table": "arp -a",
            "Processes (Top 20 MEM)": "ps aux --sort=-%mem | head -n 20",
            "SUID Binaries": "find / -type f -perm -4000 -ls 2>/dev/null",
            "Crontab": "crontab -l",
            "Installed Packages (Debian/RedHat)": "dpkg -l | head -n 20 || rpm -qa | head -n 20",
            "Password Search (Var/WWW)": "grep -Ri 'password' /var/www 2>/dev/null | head -n 20",
            "Password Search (Etc)": "grep -Ri 'password' /etc 2>/dev/null | head -n 20"
        }
        
        console.print("[yellow][*] Execution internal audit commands... Please wait.[/yellow]")
        
        raw_report = []
        
        for title, cmd in commands.items():
            console.print(f"  -> {title}...")
            try:
                stdin, stdout, stderr = client.exec_command(cmd, timeout=10)
                # sudo -S prompt handling is tricky non-interactively, handled by echo pass | sudo -S
                out = stdout.read().decode('utf-8', errors='replace').strip()
                err = stderr.read().decode('utf-8', errors='replace').strip()
                
                output = out if out else (f"[Error/Empty]: {err}" if err else "[Empty]")
                results[title] = output
                
                raw_report.append(f"\n[{title.upper()}]\n{output}\n")
                
            except Exception as e:
                results[title] = f"Error executing: {e}"
                raw_report.append(f"\n[{title.upper()}] - FAILED\n{e}\n")

        # Close connection after audit
        client.close()
        
        # SMART ANALYSIS
        analysis_report = self.analyze_audit_results(results)
        
        # Combine
        final_report = "--- INTERNAL SYSTEM AUDIT ---\n"
        final_report += f"Credentials used: {user}:{password}\n\n"
        final_report += analysis_report
        final_report += "\n" + "="*40 + "\n[RAW COMMAND OUTPUTS]\n" + "="*40 + "\n"
        final_report += "".join(raw_report)
        
        return final_report

    def analyze_audit_results(self, results):
        """Patterns to check for in the results to flag critical issues"""
        findings = []
        
        # 1. Check Sudo
        sudo_out = results.get("Sudo Privileges", "")
        if "(ALL)" in sudo_out or "NOPASSWD" in sudo_out:
             findings.append("[CRITICAL] User has SUDO privileges (ALL or NOPASSWD detected).")
        
        # 2. Check SUID (GTFOBins candidates)
        suid_out = results.get("SUID Binaries", "")
        # Common dangerous SUIDs
        dangerous_suids = ["nmap", "vim", "nano", "find", "bash", "cp", "mv", "awk", "python", "perl", "tar", "zip"]
        for bin_name in dangerous_suids:
            # Check for /bin/name or /usr/bin/name
            if f"/{bin_name}" in suid_out:
                findings.append(f"[HIGH] Dangerous SUID Binary found: {bin_name} (Likely GTFOBins vector)")

        # 3. Check Secrets
        secrets_www = results.get("Password Search (Var/WWW)", "")
        secrets_etc = results.get("Password Search (Etc)", "")
        
        count_secrets = 0
        if secrets_www and "Error" not in secrets_www and "[Empty]" not in secrets_www:
             count_secrets += len(secrets_www.splitlines())
        if secrets_etc and "Error" not in secrets_etc and "[Empty]" not in secrets_etc:
             count_secrets += len(secrets_etc.splitlines())
             
        if count_secrets > 0:
             findings.append(f"[MEDIUM] Potential cleartext passwords found in files ({count_secrets} hits). Check Raw Output.")

        # 4. Kernel (Very basic check for old stuff)
        uname = results.get("System Info", "")
        if "Linux 2.6" in uname or "Linux 3." in uname:
             findings.append("[MEDIUM] Old Kernel version detected (Potential DirtyCOW/etc).")

        # Format Analysis Report
        if not findings:
            return "[+] Smart Analysis: No obvious critical vulnerabilities found in this pass.\n"
        
        report = "[!] SMART ANALYSIS - CRITICAL FINDINGS DETECTED:\n"
        report += "="*50 + "\n"
        for f in findings:
            report += f"  {f}\n"
        report += "="*50 + "\n"
        return report

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
