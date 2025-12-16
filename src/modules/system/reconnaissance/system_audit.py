import paramiko
import subprocess
import shlex
from rich.panel import Panel
from rich.prompt import Prompt
from src.core.module import BaseModule, console

class Module(BaseModule):
    def __init__(self):
        super().__init__()
        self.name = "System Audit (SSH/IP)"
        self.description = "Audits a system via direct SSH connection or remote Network Scan."
        self.author = ["Antigravity"]
        # Options are handled interactively in run()

    def run(self):
        console.print(Panel("System Audit Mode Selection", style="bold blue"))
        console.print("1. [bold green]SSH Connection[/bold green] (Credentials required)")
        console.print("2. [bold cyan]Remote IP Scan[/bold cyan] (Network finding)")
        
        choice = Prompt.ask("\nSelect Scan Type", choices=["1", "2"], default="2")

        if choice == "1":
            self.run_ssh_audit()
        else:
            self.run_ip_audit()

    def run_ssh_audit(self):
        console.print("\n[bold yellow][*] SSH Audit Mode[/bold yellow]")
        
        target_ip = Prompt.ask("Target IP")
        username = Prompt.ask("Username")
        password = Prompt.ask("Password", password=True)
        
        console.print(f"\n[blue]Connecting to {target_ip} as {username}...[/blue]")
        
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(target_ip, username=username, password=password, timeout=10)
            
            console.print("[green][+] Connection Successful![/green]\n")
            
            self.ssh_exec(client, "Hostname", "hostname")
            self.ssh_exec(client, "OS Info", "cat /etc/os-release | grep PRETTY_NAME")
            self.ssh_exec(client, "Kernel", "uname -a")
            self.ssh_exec(client, "Current User", "id")
            self.ssh_exec(client, "Network Interfaces", "ip addr show")
            
            client.close()
            console.print("\n[bold green]SSH Audit Complete.[/bold green]")
            
        except paramiko.AuthenticationException:
            console.print("[red][!] Authentication Failed.[/red]")
        except paramiko.SSHException as e:
             console.print(f"[red][!] SSH Error: {e}[/red]")
        except Exception as e:
            console.print(f"[red][!] Connection Error: {e}[/red]")

    def ssh_exec(self, client, label, command):
        console.print(f"[cyan]--- {label} ---[/cyan]")
        stdin, stdout, stderr = client.exec_command(command)
        output = stdout.read().decode().strip()
        error = stderr.read().decode().strip()
        
        if output:
            console.print(output)
        if error:
            console.print(f"[red]Error: {error}[/red]")
        print() # Newline

    def run_ip_audit(self):
        console.print("\n[bold yellow][*] Remote IP Audit Mode[/bold yellow]")
        target_ip = Prompt.ask("Target IP")
        
        console.print(f"[blue]Running Nmap aggressive scan on {target_ip}...[/blue]")
        
        # Using -A for OS detection, version detection, script scanning, and traceroute
        command = f"nmap -A {target_ip}"
        
        try:
            cmd_parts = shlex.split(command)
            subprocess.run(
                cmd_parts, 
                stdout=None, # Let it print to terminal directly 
                stderr=None
            )
        except Exception as e:
             console.print(f"[red]Error executing nmap: {e}[/red]")
