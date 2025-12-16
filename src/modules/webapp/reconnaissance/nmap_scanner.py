import subprocess
import shlex
from src.core.module import BaseModule, console

class Module(BaseModule):
    def __init__(self):
        super().__init__()
        self.name = "Nmap Network Scanner"
        self.description = "Performs network reconnaissance using Nmap."
        self.author = ["Antigravity"]
        
        self.register_option("TARGET", None, True, "The target IP address or hostname")
        self.register_option("ARGS", "-sV", False, "Additional Nmap arguments")

    def run(self):
        if not self.validate_options():
            return

        target = self.options['TARGET']['value']
        args = self.options['ARGS']['value']
        
        command_str = f"nmap {args} {target}"
        console.print(f"[bold blue][*] Running: {command_str}[/bold blue]")

        try:
            # Using shlex to split correctly, but be careful with complex args
            cmd = shlex.split(command_str)
            
            # Using Popen to stream output potentially, or just run_command
            process = subprocess.Popen(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                text=True
            )
            
            while True:
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    break
                if output:
                    console.print(output.strip())
            
            rc = process.poll()
            if rc != 0:
                err = process.stderr.read()
                console.print(f"[red]Nmap execution failed:[/red]\n{err}")
            else:
                console.print("[bold green][+] Scan completed successfully.[/bold green]")

        except FileNotFoundError:
             console.print("[bold red]Error:[/bold red] nmap not found. Ensure it is installed in the container.")
        except Exception as e:
            console.print(f"[bold red]Error running nmap:[/bold red] {e}")
