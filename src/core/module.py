from abc import ABC, abstractmethod
from rich.console import Console
from rich.table import Table

console = Console()

class BaseModule(ABC):
    def __init__(self):
        self.options = {}  # Dictionary to store options: { 'NAME': {'value': val, 'required': bool, 'desc': str} }
        self.name = "Base Module"
        self.description = "Base Module Description"
        self.author = ["Unknown"]

    def register_option(self, name, value, required=True, description=""):
        self.options[name.upper()] = {
            'value': value,
            'required': required,
            'description': description
        }

    def set_option(self, name, value):
        name = name.upper()
        if name in self.options:
            self.options[name]['value'] = value
            console.print(f"[green]=> {name} set to {value}[/green]")
            return True
        else:
            console.print(f"[red]Error: Option {name} not found.[/red]")
            return False

    def validate_options(self):
        for name, opt in self.options.items():
            if opt['required'] and not opt['value']:
                console.print(f"[red]Error: Required option {name} is not set.[/red]")
                return False
        return True

    def show_options(self):
        table = Table(title=f"Module Options ({self.name})")
        table.add_column("Name", style="cyan", no_wrap=True)
        table.add_column("Current Setting", style="magenta")
        table.add_column("Required", style="green")
        table.add_column("Description", style="white")

        for name, opt in self.options.items():
            table.add_row(
                name,
                str(opt['value']) if opt['value'] is not None else "",
                "yes" if opt['required'] else "no",
                opt['description']
            )

        console.print(table)

    @abstractmethod
    def run(self):
        pass
