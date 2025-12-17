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
        self.root_dir = os.path.dirname(os.path.abspath(__file__))
        # Base modules dir
        self.modules_base = os.path.join(self.root_dir, 'modules')
        
    def print_banner(self):
        os.system('cls' if os.name == 'nt' else 'clear')
        console.print(Panel.fit(
            "[bold red]PYTHON KILLCHAIN TOOLKIT[/bold red]\n"
            "[bold white]Dockerized Penetration Testing Framework[/bold white]\n"
            "[italic]Author: Antigravity[/italic]",
            subtitle="v1.3 - Automation & Tools",
            style="bold red"
        ))

    def run(self):
        while True:
            self.print_banner()
            console.print("[bold underline]Main Menu:[/bold underline]\n")
            console.print("  [bold green]1.[/bold green] Automation")
            console.print("  [bold green]2.[/bold green] Manual Tools")
            console.print(f"\n  [bold red]0.[/bold red] Exit")
            
            choice = Prompt.ask("\n[bold cyan]Select mode[/bold cyan]")
            
            if choice == '1':
                self.run_automation_menu()
            elif choice == '2':
                self.run_tools_menu()
            elif choice == '0':
                sys.exit(0)
            else:
                console.print("[red]Invalid selection.[/red]")
                time.sleep(1)

    def run_automation_menu(self):
        automation_dir = os.path.join(self.modules_base, 'automation')
        if not os.path.exists(automation_dir):
            console.print("[yellow]Automation directory not found.[/yellow]")
            time.sleep(1)
            return

        while True:
            self.print_banner()
            console.print("[bold underline]Automation Modules:[/bold underline]\n")
            
            modules = [f[:-3] for f in os.listdir(automation_dir) if f.endswith('.py') and f != '__init__.py']
            
            if not modules:
                console.print("[yellow]No automation modules found.[/yellow]")
                Prompt.ask("Press Enter to go back")
                return

            for idx, mod in enumerate(modules, 1):
                console.print(f"  [bold green]{idx}.[/bold green] {mod}")
            
            console.print(f"\n  [bold red]0.[/bold red] Back")
            
            choice = Prompt.ask("\n[bold cyan]Select automation module[/bold cyan]")
            
            if choice == '0':
                return
            
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(modules):
                    # Launch wizard directly for automation module
                    self.run_module_wizard(automation_dir, modules[idx])
                else:
                    console.print("[red]Invalid selection.[/red]")
                    time.sleep(1)
            except ValueError:
                console.print("[red]Please enter a number.[/red]")
                time.sleep(1)

    def run_tools_menu(self):
        tools_dir = os.path.join(self.modules_base, 'tools')
        if not os.path.exists(tools_dir):
             console.print("[yellow]Tools directory not found.[/yellow]")
             time.sleep(1)
             return

        while True:
            self.print_banner()
            console.print("[bold underline]Manual Tools - Select Domain:[/bold underline]\n")
            
            domains = [d for d in os.listdir(tools_dir) 
                      if os.path.isdir(os.path.join(tools_dir, d)) and not d.startswith('__')]
            
            for idx, domain in enumerate(domains, 1):
                clean_name = domain.title()
                console.print(f"  [bold green]{idx}.[/bold green] {clean_name}")
            
            console.print(f"\n  [bold red]0.[/bold red] Back")
            
            choice = Prompt.ask("\n[bold cyan]Select domain[/bold cyan]")
            
            if choice == '0':
                return
            
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(domains):
                    self.run_tools_phase_menu(tools_dir, domains[idx])
                else:
                    console.print("[red]Invalid selection.[/red]")
                    time.sleep(1)
            except ValueError:
                console.print("[red]Please enter a number.[/red]")
                time.sleep(1)

    def run_tools_phase_menu(self, tools_dir, domain):
        domain_dir = os.path.join(tools_dir, domain)
        
        while True:
            self.print_banner()
            console.print(f"[bold underline]Tools: {domain.title()} -> Select Phase[/bold underline]\n")
            
            ordered_phases = [
                "reconnaissance", "weaponization", "delivery", "exploitation", 
                "installation", "command_and_control", "actions_on_objectives"
            ]
            
            available = [d for d in os.listdir(domain_dir) if os.path.isdir(os.path.join(domain_dir, d))]
            
            phases = []
            for phase in ordered_phases:
                if phase in available:
                    phases.append(phase)
            for phase in available:
                if phase not in phases:
                    phases.append(phase)

            if not phases:
                 console.print("[yellow]No phases found in this domain.[/yellow]")
                 Prompt.ask("Press Enter to go back")
                 return

            for idx, phase in enumerate(phases, 1):
                clean_name = phase.replace('_', ' ').title()
                console.print(f"  [bold green]{idx}.[/bold green] {clean_name}")
            
            console.print(f"\n  [bold red]0.[/bold red] Back")
            
            choice = Prompt.ask("\n[bold cyan]Select phase[/bold cyan]")
            
            if choice == '0':
                return
            
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(phases):
                    self.run_tools_module_menu(domain_dir, phases[idx])
                else:
                    console.print("[red]Invalid selection.[/red]")
                    time.sleep(1)
            except ValueError:
                console.print("[red]Please enter a number.[/red]")
                time.sleep(1)

    def run_tools_module_menu(self, domain_dir, phase_name):
        phase_dir = os.path.join(domain_dir, phase_name)
        
        while True:
            self.print_banner()
            console.print(f"[bold underline]Category: {phase_name.replace('_', ' ').title()}[/bold underline]\n")
            
            if not os.path.exists(phase_dir):
                 console.print("[yellow]Directory not found.[/yellow]")
                 Prompt.ask("Press Enter to go back")
                 return

            modules = [f[:-3] for f in os.listdir(phase_dir) if f.endswith('.py') and f != '__init__.py']
            
            if not modules:
                console.print("[yellow]No modules found here.[/yellow]")
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
                    # Launch wizard
                    self.run_module_wizard(phase_dir, modules[idx])
                else:
                    console.print("[red]Invalid selection.[/red]")
                    time.sleep(1)
            except ValueError:
                console.print("[red]Please enter a number.[/red]")
                time.sleep(1)

    def run_module_wizard(self, dir_path, module_name):
        module_path = os.path.join(dir_path, module_name + ".py")
        
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
