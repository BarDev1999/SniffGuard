# sniffguard/ui.py
from collections import deque
from rich.table import Table
from rich.console import Console

class LiveUI:
    """
    Manages all 'rich' UI elements, including the live table
    and packet history.
    """
    def __init__(self, console: Console, max_rows: int):
        self.console = console
        self.max_rows = max_rows
        self.recent_packets = deque(maxlen=self.max_rows)
        self.last_alert_message = "[green]Status: Monitoring... All clear.[/green]"
        
        # This will be set by the main app after interfaces are discovered
        self.monitored_interfaces_str = "..." 

    def create_table(self) -> Table:
        """
        Build a Rich table populated from recent packet history.
        This is a modified version of the original create_table() function.
        """
        table = Table(title=f"Live Network Traffic Dashboard (Monitoring: {self.monitored_interfaces_str}) 🚦")
        table.add_column("Interface", style="dim blue")
        table.add_column("Source IP", style="cyan")
        table.add_column("Source Port", style="cyan")
        table.add_column("->", style="white", justify="center")
        table.add_column("Destination IP", style="magenta")
        table.add_column("Dest. Port", style="magenta")
        table.add_column("Flags", style="yellow")

        # Add rows from the deque
        for packet_info in self.recent_packets:
            table.add_row(*packet_info)

        table.caption = self.last_alert_message
        return table

    def add_packet_row(self, packet_info: tuple):
        """
        Adds a new packet tuple to the UI's history.
        """
        self.recent_packets.append(packet_info)

    def set_alert_message(self, message: str):
        """
        Updates the table's caption with an alert or status message.
        """
        self.last_alert_message = message
