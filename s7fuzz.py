#!/usr/bin/env python3
import socket
import random
import time
from enum import Enum
from scapy.all import Raw, TCP
from scapy.contrib.s7comm import S7Header, S7Communication, S7WriteVarParameterReq
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich.layout import Layout

console = Console()

class FuzzType(Enum):
    FUNCTION = "function"
    DATA = "data"
    ALL = "all"

class S7FuzzerCLI:
    def __init__(self):
        self.target = ""
        self.port = 102
        self.fuzz_type = FuzzType.ALL
        self.iterations = 1000
        self.running = False
        self.socket = None
        self.crash_count = 0
        
        self.layout = Layout()
        self.layout.split(
            Layout(name="header", size=3),
            Layout(name="main", ratio=1),
            Layout(name="footer", size=3)
        )
        
    def _show_header(self):
        self.layout["header"].update(
            Panel("S7 Protocol Fuzzer - Industrial Control System Testing Tool", style="bold blue")
        )
        
    def _show_main_menu(self):
        menu = Table.grid(padding=1)
        menu.add_column("Key", style="cyan")
        menu.add_column("Option", style="magenta")
        
        menu.add_row("1", "Set Target")
        menu.add_row("2", "Set Port")
        menu.add_row("3", "Set Fuzz Type")
        menu.add_row("4", "Set Iterations")
        menu.add_row("5", "Start Fuzzing")
        menu.add_row("Q", "Quit")
        
        self.layout["main"].update(
            Panel(menu, title="Main Menu")
        )
        
    def _show_status(self):
        status = Table.grid(padding=1)
        status.add_column("Parameter", style="bold green")
        status.add_column("Value", style="yellow")
        
        status.add_row("Target:", self.target)
        status.add_row("Port:", str(self.port))
        status.add_row("Fuzz Type:", self.fuzz_type.value)
        status.add_row("Iterations:", str(self.iterations))
        status.add_row("Crashes Detected:", str(self.crash_count))
        
        self.layout["footer"].update(
            Panel(status, title="Current Status")
        )
        
    def _clear_screen(self):
        console.clear()
        
    def _get_target(self):
        self.target = Prompt.ask("Enter target IP address", default=self.target)
        
    def _get_port(self):
        self.port = int(Prompt.ask("Enter port number", default=str(self.port)))
        
    def _get_fuzz_type(self):
        choice = Prompt.ask(
            "Select fuzz type",
            choices=["function", "data", "all"],
            default=self.fuzz_type.value
        )
        self.fuzz_type = FuzzType(choice)
        
    def _get_iterations(self):
        self.iterations = int(Prompt.ask(
            "Number of iterations",
            default=str(self.iterations)
        ))
        
    def connect(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(2)
            self.socket.connect((self.target, self.port))
            return True
        except Exception as e:
            console.print(f"[bold red]Connection failed: {e}[/]")
            return False
        
    def fuzz(self):
        if not self.connect():
            return
            
        base_pkt = S7Header()/S7Communication()/S7WriteVarParameterReq(
            Items=[
                {"VariableSpecification": 0x12, "Length": 0x0a00}
            ]
        )
        
        with Progress() as progress:
            task = progress.add_task("[cyan]Fuzzing...", total=self.iterations)
            
            for i in range(self.iterations):
                if not self.running:
                    break
                    
                try:
                    # Fuzzing logic here
                    if self.fuzz_type == FuzzType.FUNCTION:
                        mutated = base_pkt.copy()
                        mutated[S7Header].function = random.randint(0, 255)
                    elif self.fuzz_type == FuzzType.DATA:
                        mutated = base_pkt.copy()
                        mutated[Raw].load = os.urandom(random.randint(1, 128))
                        
                    self.socket.send(bytes(mutated))
                    response = self.socket.recv(1024)
                    
                    if not response:
                        self.crash_count += 1
                        console.print(f"[bold red]Potential crash at iteration {i}![/]")
                        
                except Exception as e:
                    self.crash_count += 1
                    console.print(f"[bold red]Error at iteration {i}: {e}[/]")
                    
                progress.update(task, advance=1)
                
        self.socket.close()
        
    def run(self):
        self.running = True
        with console.screen():
            while self.running:
                self._clear_screen()
                self._show_header()
                self._show_main_menu()
                self._show_status()
                
                choice = Prompt.ask(
                    "Select option",
                    choices=["1", "2", "3", "4", "5", "q"],
                    default="5"
                ).lower()
                
                if choice == "1":
                    self._get_target()
                elif choice == "2":
                    self._get_port()
                elif choice == "3":
                    self._get_fuzz_type()
                elif choice == "4":
                    self._get_iterations()
                elif choice == "5":
                    if Confirm.ask("Start fuzzing?"):
                        self.fuzz()
                elif choice == "q":
                    self.running = False
                    console.print("[bold yellow]Exiting...[/]")
                    break

if __name__ == "__main__":
    try:
        fuzzer = S7FuzzerCLI()
        fuzzer.run()
    except KeyboardInterrupt:
        console.print("[bold red]Operation cancelled by user[/]")