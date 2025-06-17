#!/usr/bin/env python3
import socket
import random
import time
import os
from enum import Enum
from scapy.all import Raw, TPKT, COTP_CR, COTP_DT, S7, S7SetupCommunication, S7Header, S7Parameter, S7WriteVarRequest
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
        self.iterations = 100
        self.running = False
        self.socket = None
        self.crash_count = 0
        
        self.layout = Layout()
        self.layout.split(
            Layout(name="header", size=3),
            Layout(name="main", ratio=1),
            Layout(name="footer", size=5)
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
        
        status.add_row("Target:", self.target or "Not set")
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
        self.target = Prompt.ask("Enter target IP address", default=self.target or "192.168.1.100")
        
    def _get_port(self):
        try:
            self.port = int(Prompt.ask("Enter port number", default=str(self.port)))
        except ValueError:
            console.print("[bold red]Invalid port number, using default (102)[/]")
            self.port = 102
        
    def _get_fuzz_type(self):
        choice = Prompt.ask(
            "Select fuzz type",
            choices=["function", "data", "all"],
            default=self.fuzz_type.value
        )
        self.fuzz_type = FuzzType(choice)
        
    def _get_iterations(self):
        try:
            self.iterations = int(Prompt.ask(
                "Number of iterations",
                default=str(self.iterations)
            ))
        except ValueError:
            console.print("[bold red]Invalid number, using default (100)[/]")
            self.iterations = 100
        
    def connect(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(2)
            self.socket.connect((self.target, self.port))
            
            # Send COTP Connection Request
            cotp_cr = TPKT()/COTP_CR()
            self.socket.send(bytes(cotp_cr))
            response = self.socket.recv(1024)
            if not response:
                console.print("[bold red]COTP connection failed: No response[/]")
                return False
            
            # Send S7 Setup Communication
            s7_setup = TPKT()/COTP_DT()/S7()/S7SetupCommunication()
            self.socket.send(bytes(s7_setup))
            response = self.socket.recv(1024)
            if not response:
                console.print("[bold red]S7 setup failed: No response[/]")
                return False
                
            return True
        except Exception as e:
            console.print(f"[bold red]Connection failed: {e}[/]")
            return False
        
    def fuzz(self):
        if not self.target:
            console.print("[bold red]Target IP address not set![/]")
            return
            
        if not self.connect():
            return
            
        base_pkt = TPKT()/COTP_DT()/S7()/S7Header()/S7WriteVarRequest(
            Items=[
                {"VariableSpecification": 0x12, "Length": 0x04, "SyntaxID": 0x10}
            ]
        )
        
        with Progress() as progress:
            task = progress.add_task("[cyan]Fuzzing...", total=self.iterations)
            
            for i in range(self.iterations):
                if not self.running:
                    break
                    
                try:
                    mutated = base_pkt.copy()
                    
                    if self.fuzz_type in [FuzzType.FUNCTION, FuzzType.ALL]:
                        mutated[S7Header].FunctionCode = random.randint(0, 255)
                    if self.fuzz_type in [FuzzType.DATA, FuzzType.ALL]:
                        mutated[S7WriteVarRequest].Items[0].Length = random.randint(1, 128)
                        mutated[Raw].load = os.urandom(mutated[S7WriteVarRequest].Items[0].Length)
                    
                    self.socket.send(bytes(mutated))
                    response = self.socket.recv(1024)
                    
                    if not response:
                        self.crash_count += 1
                        console.print(f"[bold red]Potential crash at iteration {i}![/]")
                        
                    time.sleep(0.1)  # Small delay to avoid overwhelming target
                    
                except Exception as e:
                    self.crash_count += 1
                    console.print(f"[bold red]Error at iteration {i}: {e}[/]")
                    
                progress.update(task, advance=1)
                
        self.socket.close()
        self.socket = None
        
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