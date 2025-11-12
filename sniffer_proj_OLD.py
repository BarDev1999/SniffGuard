# sniffer_project.py
# by bar sberro

import argparse
import time
import os
import re
import sys
import logging
from logging.handlers import RotatingFileHandler
from collections import deque

from scapy.all import sniff, wrpcap, get_if_list, get_if_addr
from scapy.layers.inet import IP, TCP

from rich.console import Console
from rich.live import Live
from rich.table import Table


# =========================
#       CLI ARGPARSE
# =========================
def build_arg_parser() -> argparse.ArgumentParser:
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
        default="tcp and (tcp[tcpflags] & tcp-syn != 0)",
        help="BPF capture filter. Default tracks SYN packets only.",
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
        default="ids_alerts.log",
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
    return parser


# =========================
#     HELPER FUNCTIONS
# =========================
def setup_logger(log_file_name: str) -> logging.Logger:
    """
    Set up a rotating file logger.
    Why:
    - Prevents the log file from growing without bounds.
    - Keeps a few backups for later investigation.
    """
    log_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    handler = RotatingFileHandler(log_file_name, maxBytes=5_000_000, backupCount=3)
    handler.setFormatter(log_formatter)

    logger_obj = logging.getLogger("ids_logger")
    logger_obj.setLevel(logging.getLogger().level)  # inherit root level set by CLI
    # Avoid adding multiple handlers if setup_logger is called more than once
    if not any(isinstance(h, RotatingFileHandler) for h in logger_obj.handlers):
        logger_obj.addHandler(handler)

    return logger_obj


def to_safe_filename(s: str) -> str:
    """
    Sanitize a string for safe use in filenames.
    Example: convert IP or interface names into valid file components.
    """
    return re.sub(r"[^a-zA-Z0-9_.-]", "_", s)[:100]


# =========================
#     GLOBAL STATE
# =========================
console = Console()

# These will be set in __main__ after parsing CLI args
preferred_interfaces = []
port_scan_threshold = 0
time_window_seconds = 0
bpf_filter = ""
evidence_dir = ""
table_max_rows = 0
alert_cooldown_seconds = 0
ui_update_interval = 0.0
log_file_name = ""
evidence_buffer_size = 0

logger = None  # type: ignore

# Scan tracking:
# (src_ip, dst_ip) -> {
#   'timestamp': last update time (monotonic),
#   'ports': set of unique destination ports,
#   'packets': ring buffer of packets for evidence
# }
scan_tracker: dict = {}

# Cooldown to avoid alert spam for same (src, dst)
scan_cooldown_tracker: dict = {}

# UI elements
last_alert_message = "[green]Status: Monitoring... All clear.[/green]"
recent_packets = None  # will be a deque set in __main__

# Timing
monotonic_time = time.monotonic

# Runtime-discovered
monitored_interfaces = []
local_ips = set()


# =========================
#       UI RENDERING
# =========================
def create_table() -> Table:
    """
    Build a Rich table populated from recent packet history.
    This function is UI-only and does not modify detection state.
    """
    table = Table(title=f"Live Network Traffic Dashboard (Monitoring: {', '.join(monitored_interfaces)}) 🚦")
    table.add_column("Interface", style="dim blue")
    table.add_column("Source IP", style="cyan")
    table.add_column("Source Port", style="cyan")
    table.add_column("->", style="white", justify="center")
    table.add_column("Destination IP", style="magenta")
    table.add_column("Dest. Port", style="magenta")
    table.add_column("Flags", style="yellow")

    if recent_packets is not None:
        for packet_info in recent_packets:
            table.add_row(*packet_info)

    table.caption = last_alert_message
    return table


# =========================
#      IDS CORE LOGIC
# =========================
def process_packet(packet) -> None:
    """
    Process a single packet:
    1. Detect SYN-based port scans within a sliding time window.
    2. Save PCAP evidence if the threshold is exceeded.
    3. Update UI packet history for display.
    """
    global last_alert_message

    # Step 1: SYN port scan detection
    if IP in packet and TCP in packet and (packet[TCP].flags & 0x02) and (
        packet[IP].src in local_ips or packet[IP].dst in local_ips
    ):
        key = (packet[IP].src, packet[IP].dst)
        dest_port = packet[TCP].dport
        now = monotonic_time()

        # Start new session or reset if the time window expired
        if key not in scan_tracker:
            scan_tracker[key] = {
                "timestamp": now,
                "ports": {dest_port},
                "packets": deque([packet], maxlen=evidence_buffer_size),
            }
        elif now - scan_tracker[key]["timestamp"] > time_window_seconds:
            scan_tracker[key] = {
                "timestamp": now,
                "ports": {dest_port},
                "packets": deque([packet], maxlen=evidence_buffer_size),
            }
        else:
            scan_tracker[key]["ports"].add(dest_port)
            scan_tracker[key]["timestamp"] = now
            scan_tracker[key]["packets"].append(packet)

        scanned_ports_count = len(scan_tracker[key]["ports"])

        # Threshold exceeded → port scan detected
        if scanned_ports_count > port_scan_threshold:
            on_cooldown = key in scan_cooldown_tracker and (
                now - scan_cooldown_tracker.get(key, 0)
            ) < alert_cooldown_seconds

            if not on_cooldown:
                attacker, victim = key
                timestamp_str = time.strftime("%Y-%m-%d_%H-%M-%S")
                pcap_path = f"{evidence_dir}/scan_{timestamp_str}_from_{to_safe_filename(attacker)}.pcap"

                wrote_pcap = False
                try:
                    packets_to_save = list(scan_tracker[key]["packets"])
                    if packets_to_save:
                        wrpcap(pcap_path, packets_to_save)
                        wrote_pcap = True
                    else:
                        logger.info(f"No evidence packets to write for {attacker}->{victim} (skipping PCAP).")
                except Exception as e:
                    logger.error(f"Failed to save PCAP to {pcap_path}: {e}")

                iface = getattr(packet, "sniffed_on", "unknown")
                evidence_suffix = f"Evidence saved to {pcap_path}" if wrote_pcap else "No evidence file written"

                alert_message = (
                    f"PORT SCAN DETECTED on interface {iface}: {attacker} -> {victim} "
                    f"({scanned_ports_count} unique ports in {time_window_seconds}s; "
                    f"threshold={port_scan_threshold}). {evidence_suffix}"
                )
                display_timestamp = time.strftime("%H:%M:%S")
                last_alert_message = (
                    f"🚨 [bold red]Last Alert ({display_timestamp}): PORT SCAN from {attacker}. "
                    f"{evidence_suffix}[/bold red]"
                )

                logger.warning(alert_message)
                scan_cooldown_tracker[key] = now
                # Clean old session to avoid memory bloat over time
                scan_tracker.pop(key, None)

    # Step 2: Update UI history
    if IP in packet and TCP in packet and recent_packets is not None:
        interface_name = getattr(packet, "sniffed_on", "unknown")
        source_ip = packet[IP].src
        source_port = str(packet[TCP].sport)
        destination_ip = packet[IP].dst
        destination_port = str(packet[TCP].dport)
        tcp_flags = str(packet[TCP].flags)

        packet_info = (interface_name, source_ip, source_port, "->", destination_ip, destination_port, tcp_flags)
        recent_packets.append(packet_info)


# =========================
#         __MAIN__
# =========================
if __name__ == "__main__":
    # Require root privileges on Unix
    is_unix = hasattr(os, "geteuid")
    if is_unix and os.geteuid() != 0:
        print("This script requires root privileges. Please run with sudo.")
        sys.exit(1)

    # Parse CLI args
    arg_parser = build_arg_parser()
    args = arg_parser.parse_args()

    # Map CLI args to module-level settings
    preferred_interfaces = args.interfaces
    port_scan_threshold = args.port_scan_threshold
    time_window_seconds = args.time_window_seconds
    bpf_filter = args.bpf_filter
    evidence_dir = args.evidence_dir
    table_max_rows = args.table_max_rows
    alert_cooldown_seconds = args.alert_cooldown_seconds
    ui_update_interval = args.ui_update_interval
    log_file_name = args.log_file
    evidence_buffer_size = args.evidence_buffer_size

    # Configure root logging level before creating our rotating file logger
    level_map = {
        "debug": logging.DEBUG,
        "info": logging.INFO,
        "warning": logging.WARNING,
        "error": logging.ERROR,
    }
    logging.getLogger().setLevel(level_map[args.log_level])

    # Prepare logger and evidence directory
    logger = setup_logger(log_file_name)
    if not os.path.exists(evidence_dir):
        os.makedirs(evidence_dir)

    # Discover available interfaces
    all_system_interfaces = get_if_list()
    monitored_interfaces = [iface for iface in preferred_interfaces if iface in all_system_interfaces]
    if not monitored_interfaces:
        console.print(
            f"[yellow]Warning:[/yellow] None of the preferred interfaces ({', '.join(preferred_interfaces)}) were found."
        )
        monitored_interfaces = list(all_system_interfaces)
        if not monitored_interfaces:
            console.print("[bold red]Error:[/bold red] No network interfaces found on this system.")
            sys.exit(1)
        console.print(
            f"Falling back to monitoring all available interfaces: [bold cyan]{', '.join(monitored_interfaces)}[/bold cyan]"
        )

    # Collect local IPv4 addresses for the selected interfaces
    local_ips = set()
    for iface in monitored_interfaces:
        try:
            ip = get_if_addr(iface)
            if ip and ip != "0.0.0.0":
                local_ips.add(ip)
        except Exception as e:
            logger.warning(f"Could not get IP for interface {iface}: {e}")

    if not local_ips:
        console.print("[bold red]Error:[/bold red] No valid IPv4 addresses found on the selected interfaces.")
        sys.exit(1)

    # UI packet history deque
    recent_packets = deque(maxlen=table_max_rows)

    # Intro
    console.print("[bold green][*] Starting IDS v2.0 (Self-Healing & Robust)...[/bold green]")
    console.print(f"[*] Monitoring interfaces: [bold cyan]{', '.join(monitored_interfaces)}[/bold cyan]")
    console.print(f"[*] Local IPs: [bold yellow]{local_ips}[/bold yellow]")
    console.print(f"[*] Alerts will be logged to '{log_file_name}'")
    console.print(f"[*] Evidence PCAP files will be saved in '{evidence_dir}/' directory.")
    console.print("[*] Press Ctrl+C to stop.")

    # Developer note:
    # If you run this on a quiet host, you may not see much traffic.
    # Try generating traffic manually or run a light nmap scan from another host.

    # Live UI loop
    with Live(create_table(), refresh_per_second=5) as live:
        last_ui_update = [monotonic_time()]

        def update_live_table(packet):
            process_packet(packet)
            now = monotonic_time()
            if now - last_ui_update[0] >= ui_update_interval:
                live.update(create_table())
                last_ui_update[0] = now

        try:
            sniff(iface=monitored_interfaces, filter=bpf_filter, prn=update_live_table, store=False)
        except KeyboardInterrupt:
            console.print("\n[*] Sniffer stopped by user.")
        except Exception as e:
            console.print(f"[!] Error while sniffing (check permissions/interface/BPF): {e}")
            logger.error(f"Sniff error: {e}")
        finally:
            # Render the final state of the table before exiting
            live.update(create_table())
