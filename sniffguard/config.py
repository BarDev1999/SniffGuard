# sniffguard/config.py
import argparse
import logging
from rich.console import Console

class Config:
    """
    Class to parse CLI arguments and hold all runtime settings.
    This replaces all the global state variables.
    """
    def __init__(self):
        self.args = self._parse_args()
        
        # Static settings (things that don't come from CLI)
        self.console = Console()
        self.log_level_map = {
            "debug": logging.DEBUG,
            "info": logging.INFO,
            "warning": logging.WARNING,
            "error": logging.ERROR,
        }

        # Dynamic settings populated from args
        self.preferred_interfaces = self.args.interfaces
        self.port_scan_threshold = self.args.port_scan_threshold
        self.time_window_seconds = self.args.time_window_seconds
        self.bpf_filter = self.args.bpf_filter # עכשיו "tcp"
        self.evidence_dir = self.args.evidence_dir
        self.table_max_rows = self.args.table_max_rows
        self.alert_cooldown_seconds = self.args.alert_cooldown_seconds
        self.ui_update_interval = self.args.ui_update_interval
        self.log_file = self.args.log_file
        self.log_level = self.log_level_map.get(self.args.log_level, logging.INFO)
        self.evidence_buffer_size = self.args.evidence_buffer_size

    def _parse_args(self) -> argparse.Namespace:
        """
        This function is a direct copy of build_arg_parser() 
        from the original sniffer_proj.py with BPF filter change.
        """
        parser = argparse.ArgumentParser(
            description="Simple SYN-based IDS with live Rich UI and PCAP evidence."
        )
        parser.add_argument(
            "--interfaces",
            nargs="+",
            default=["lo", "enp0s8", "enp0s3"],
            help="Interfaces to monitor. If none of these are found, falls back to all available interfaces.",
        )
        parser.add_argument(
            "--port-scan-threshold",
            type=int,
            default=15,
            help="Unique destination ports within the time window required to trigger a port-scan alert.",
        )
        parser.add_argument(
            "--time-window-seconds",
            type=int,
            default=10,
            help="Sliding time window (seconds) for grouping ports into one scan session.",
        )
        parser.add_argument(
            "--bpf-filter",
            default="tcp", # <--- MODIFIED
            help="BPF capture filter. Default captures all TCP packets.",
        )
        parser.add_argument(
            "--evidence-dir",
            default="evidence",
            help="Directory to store PCAP evidence files.",
        )
        parser.add_argument(
            "--table-max-rows",
            type=int,
            default=20,
            help="Max rows displayed in the live table.",
        )
        parser.add_argument(
            "--alert-cooldown-seconds",
            type=int,
            default=60,
            help="Minimum seconds between alerts for the same (src_ip, dst_ip) pair.",
        )
        parser.add_argument(
            "--ui-update-interval",
            type=float,
            default=0.2,
            help="Seconds between Rich UI refreshes.",
        )
        parser.add_argument(
            "--log-file",
            default="logs/ids_alerts.log",
            help="Path to the alerts log file.",
        )
        parser.add_argument(
            "--log-level",
            choices=["debug", "info", "warning", "error"],
            default="info",
            help="Logging verbosity.",
        )
        parser.add_argument(
            "--evidence-buffer-size",
            type=int,
            default=2000,
            help="Ring buffer size for evidence packets stored per scan session.",
        )
        return parser.parse_args()

# Create a single, globally-accessible instance of the settings.
settings = Config()
