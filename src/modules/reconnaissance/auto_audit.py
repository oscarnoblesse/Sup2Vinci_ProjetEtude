import subprocess
import shlex
import os
import re
from rich.panel import Panel
from src.core.module import BaseModule, console

class Module(BaseModule):
    def __init__(self):
        super().__init__()
        self.name = "Automated Reconnaissance & Audit"
        self.description = "Automates Nmap scanning, Gobuster enumeration, and Nmap Vuln scanning."
        self.author = ["Antigravity"]
        
        self.register_option("TARGET", None, True, "The target IP address or hostname")
        self.register_option("Review", "no", False, "Wait for user keypress between steps? (yes/no)")

    def run(self):
        if not self.validate_options():
            return

        target = self.options['TARGET']['value']
        pause = self.options['REVIEW']['value'].lower() == 'yes'
        report_data = []

        console.print(Panel(f"Starting Automated Audit against {target}", style="bold blue"))
        report_data.append(f"Automated Audit Report for {target}\n" + "="*40 + "\n")

        # Step 1: Nmap Fast Scan (Discovery)
        console.print("\n[bold yellow][*] Step 1: Port Discovery (Fast Nmap)[/bold yellow]")
        
        nmap_cmd = f"nmap -F {target}" # Fast scan top 100 ports
        output, rc = self.run_command(nmap_cmd)
        
        report_data.append("\n[PORT DISCOVERY]\n")
        report_data.append(output)
        
        if rc != 0:
            console.print("[red]Nmap scan failed. Aborting.[/red]")
            return

        open_ports = self.extract_open_ports(output)
        console.print(f"[green]Open ports found:[/green] {', '.join(open_ports)}")

        if pause: input("\nPress Enter to continue to next step...")

        # Step 2: Web Enumeration (Gobuster)
        web_ports = [p for p in open_ports if p in ['80', '443', '8080', '8000']]
        if web_ports:
            console.print("\n[bold yellow][*] Step 2: Web Directory Enumeration (Gobuster)[/bold yellow]")
            
            for port in web_ports:
                protocol = "https" if port == '443' else "http"
                url = f"{protocol}://{target}:{port}"
                console.print(f"  -> Scanning {url}...")
                
                # Check if wordlist exists, otherwise warn
                wordlist = "/usr/share/wordlists/common.txt"
                if not os.path.exists(wordlist):
                    console.print(f"[red]Wordlist not found at {wordlist}. Skipping Gobuster.[/red]")
                    continue

                gobuster_cmd = f"gobuster dir -u {url} -w {wordlist} -t 50 --no-error -z -q"
                gb_output, _ = self.run_command(gobuster_cmd)
                
                report_data.append(f"\n[GOBUSTER - {url}]\n")
                if gb_output.strip():
                     report_data.append(gb_output)
                else:
                    report_data.append("No directory findings.")

            if pause: input("\nPress Enter to continue to next step...")
        else:
            console.print("\n[bold yellow][*] Step 2: No web ports found. Skipping Gobuster.[/bold yellow]")

        # Step 3: Nmap Vulnerability Scan
        if open_ports:
            console.print("\n[bold yellow][*] Step 3: Vulnerability Scanning (Nmap NSE)[/bold yellow]")
            ports_str = ",".join(open_ports)
            
            # Use --script vuln -sV for service versions and vulns
            vuln_cmd = f"nmap -p {ports_str} --script vuln -sV {target}"
            vuln_output, _ = self.run_command(vuln_cmd)
            
            report_data.append("\n[VULNERABILITY SCAN]\n")
            report_data.append(vuln_output)
        else:
             console.print("\n[bold yellow][*] Step 3: No open ports. Skipping Vuln Scan.[/bold yellow]")

        # Step 4: Report Generation
        console.print("\n[bold yellow][*] Step 4: Generating Report[/bold yellow]")
        report_file = f"audit_report_{target.replace('.', '_')}.txt"
        
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
