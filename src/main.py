from prompt_toolkit import PromptSession
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.styles import Style
from rich.console import Console
from rich.panel import Panel
import sys
import os
import importlib.util
import sys
import time

# Add the project root (parent of src) to sys.path so 'import src...' works
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt

console = Console()

class KillChainToolkit:
    def __init__(self):
        self.modules_dir = os.path.join(os.path.dirname(__file__), 'modules')

    def print_banner(self):
        banner = """
    __ ___  __    __        __          _        
   / //_(_)/ /   / /  _____/ /_  ____ _(_)___    
  / ,< / // /   / /  / ___/ __ \/ __ `/ / __ \   
 / /| / // /   / /__/ /__/ / / / /_/ / / / / /   
/_/ |/_//_/   /_____/\___/_/ /_/\__,_/_/_/ /_/    
                                                 
        """
        console.clear()
        console.print(Panel(banner, title="Kill Chain Toolkit", subtitle="v2.0.0", style="bold red"))

    def run(self):
        while True:
            self.print_banner()
            domains = self.get_domains()
            
            console.print("[bold underline]Select a Domain:[/bold underline]\n")
            for idx, domain in enumerate(domains, 1):
                clean_name = domain.title()
                console.print(f"  [bold green]{idx}.[/bold green] {clean_name}")
            
            console.print(f"\n  [bold red]0.[/bold red] Exit")
            
            choice = Prompt.ask("\n[bold cyan]Select a domain[/bold cyan]")
            
            if choice == '0':
                sys.exit(0)
            
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(domains):
                    self.show_phase_menu(domains[idx])
                else:
                    console.print("[red]Invalid selection.[/red]")
                    time.sleep(1)
            except ValueError:
                console.print("[red]Please enter a number.[/red]")
                time.sleep(1)

    def get_domains(self):
        if not os.path.exists(self.modules_dir):
            return []
        # List only directories that are not __pycache__
        return [d for d in os.listdir(self.modules_dir) 
                if os.path.isdir(os.path.join(self.modules_dir, d)) and not d.startswith('__')]

    def get_phases(self, domain):
        domain_dir = os.path.join(self.modules_dir, domain)
        if not os.path.exists(domain_dir):
            return []
        
        ordered_phases = [
            "reconnaissance", "weaponization", "delivery", "exploitation", 
            "installation", "command_and_control", "actions_on_objectives"
        ]
        
        available = [d for d in os.listdir(domain_dir) if os.path.isdir(os.path.join(domain_dir, d))]
        
        result = []
        for phase in ordered_phases:
            if phase in available:
                result.append(phase)
        
        for phase in available:
            if phase not in result:
                result.append(phase)
                
        return result

    def show_phase_menu(self, domain):
        while True:
            self.print_banner()
            phases = self.get_phases(domain)
            
            console.print(f"[bold underline]Domain: {domain.title()} -> Select Phase[/bold underline]\n")
            
            if not phases:
                 console.print("[yellow]No phases found in this domain.[/yellow]")
                 Prompt.ask("Press Enter to go back")
                 return

            for idx, phase in enumerate(phases, 1):
                clean_name = phase.replace('_', ' ').title()
                console.print(f"  [bold green]{idx}.[/bold green] {clean_name}")
            
            console.print(f"\n  [bold red]0.[/bold red] Back")
            
            choice = Prompt.ask("\n[bold cyan]Select a phase[/bold cyan]")
            
            if choice == '0':
                return
            
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(phases):
                    self.show_module_menu(domain, phases[idx])
                else:
                    console.print("[red]Invalid selection.[/red]")
                    time.sleep(1)
            except ValueError:
                console.print("[red]Please enter a number.[/red]")
                time.sleep(1)

    def show_module_menu(self, domain, phase_name):
        phase_dir = os.path.join(self.modules_dir, domain, phase_name)
        
        while True:
            self.print_banner()
            console.print(f"[bold underline]{domain.title()} -> {phase_name.replace('_', ' ').title()}[/bold underline]\n")
            
            if not os.path.exists(phase_dir):
                 console.print("[yellow]Directory not found.[/yellow]")
                 Prompt.ask("Press Enter to go back")
                 return

            modules = [f[:-3] for f in os.listdir(phase_dir) if f.endswith('.py') and f != '__init__.py']
            
            if not modules:
                console.print("[yellow]No modules found in this phase.[/yellow]")
                Prompt.ask("Press Enter to go back")
                return

            for idx, mod in enumerate(modules, 1):
                console.print(f"  [bold green]{idx}.[/bold green] {mod}")
            
            console.print(f"\n  [bold red]0.[/bold red] Back")
            
            choice = Prompt.ask("\n[bold cyan]Select a module[/bold cyan]")
            
            if choice == '0':
                return
            
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(modules):
                    self.run_module_wizard(domain, phase_name, modules[idx])
                else:
                    console.print("[red]Invalid selection.[/red]")
                    time.sleep(1)
            except ValueError:
                console.print("[red]Please enter a number.[/red]")
                time.sleep(1)

    def run_module_wizard(self, domain, phase_name, module_name):
        module_path = os.path.join(self.modules_dir, domain, phase_name, module_name + ".py")
        
        # Dynamic import
        spec = importlib.util.spec_from_file_location("module", module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        
        if not hasattr(module, 'Module'):
            console.print("[red]Error: Invalid module file.[/red]")
            return

        instance = module.Module()
        
        self.print_banner()
        console.print(f"[bold underline]Module: {instance.name}[/bold underline]")
        console.print(f"{instance.description}\n")
        
        console.print("[bold yellow]Configuration:[/bold yellow]")
        
        # Simple wizard to set options
        for name, opt in instance.options.items():
            default = opt['value'] if opt['value'] is not None else ""
            required = "[red](Required)[/red]" if opt['required'] else "(Optional)"
            
            user_val = Prompt.ask(f"  {name} {required}", default=str(default))
            
            if user_val:
                instance.set_option(name, user_val)
            elif opt['required'] and not default:
                console.print(f"[red]Error: {name} is required![/red]")
                time.sleep(1)
                return

        console.print("\n[bold green]Launching...[/bold green]\n")
        instance.run()
        
        Prompt.ask("\nPress Enter to continue...")

if __name__ == "__main__":
    app = KillChainToolkit()
    app.run()
