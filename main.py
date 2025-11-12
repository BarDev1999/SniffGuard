# main.py
"""
SniffGuard: A lightweight, modular Intrusion Detection System.
This is the main entry point for the application.
"""

import sys
import os
import logging
import time

from scapy.all import sniff, get_if_list, get_if_addr
from rich.live import Live

# ייבוא הרכיבים שבנינו
from sniffguard.config import settings
from sniffguard.utils import setup_logger
from sniffguard.ui import LiveUI
from sniffguard.detector import PortScanDetector
from sniffguard.packet_handler import PacketHandler
from sniffguard.stealth_scan_detector import StealthScanDetector

def main():
    """
    Main application entry point.
    Initializes components, discovers interfaces, and starts the sniffer.
    """
    
    # 1. בדיקת הרשאות (מהקובץ הישן)
    is_unix = hasattr(os, "geteuid")
    if is_unix and os.geteuid() != 0:
        settings.console.print("[bold red]Error:[/bold red] This script requires root privileges. Please run with sudo.")
        sys.exit(1)

    # 2. הגדרת לוגר ותיקיית ראיות
    logging.getLogger().setLevel(settings.log_level)
    logger = setup_logger(settings.log_file)
    
    if not os.path.exists(settings.evidence_dir):
        try:
            os.makedirs(settings.evidence_dir)
        except OSError as e:
            settings.console.print(f"[bold red]Error:[/bold red] Failed to create evidence directory at '{settings.evidence_dir}': {e}")
            sys.exit(1)

    # 3. גילוי ממשקים וכתובות IP
    all_system_interfaces = get_if_list()
    monitored_interfaces = [iface for iface in settings.preferred_interfaces if iface in all_system_interfaces]
    
    if not monitored_interfaces:
        settings.console.print(
            f"[yellow]Warning:[/yellow] None of the preferred interfaces ({', '.join(settings.preferred_interfaces)}) were found."
        )
        monitored_interfaces = list(all_system_interfaces)
        if not monitored_interfaces:
            settings.console.print("[bold red]Error:[/bold red] No network interfaces found on this system.")
            sys.exit(1)
        settings.console.print(
            f"Falling back to monitoring all available interfaces: [bold cyan]{', '.join(monitored_interfaces)}[/bold cyan]"
        )

    # איסוף כתובות IP מקומיות
    local_ips = set()
    for iface in monitored_interfaces:
        try:
            ip = get_if_addr(iface)
            if ip and ip != "0.0.0.0":
                local_ips.add(ip)
        except Exception as e:
            logger.warning(f"Could not get IP for interface {iface}: {e}")

    if not local_ips:
        settings.console.print("[bold red]Error:[/bold red] No valid IPv4 addresses found on the selected interfaces.")
        sys.exit(1)

    # 4. אתחול הרכיבים שלנו
    # שים לב איך אנחנו "מזריקים" את התלויות
    
    ui = LiveUI(
        console=settings.console, 
        max_rows=settings.table_max_rows
    )
    ui.monitored_interfaces_str = ', '.join(monitored_interfaces) # עדכון ה-UI עם הממשקים

    # צור גלאי 1: SYN
    syn_detector = PortScanDetector(
        threshold=settings.port_scan_threshold,
        time_window=settings.time_window_seconds,
        cooldown=settings.alert_cooldown_seconds,
        evidence_dir=settings.evidence_dir,
        buffer_size=settings.evidence_buffer_size,
        local_ips=local_ips
    )

    # צור גלאי 2: STEALTH
    # הוא משתמש באותן הגדרות, אבל אתה יכול לשנות אותן אם תרצה
    stealth_detector = StealthScanDetector(
        threshold=settings.port_scan_threshold,
        time_window=settings.time_window_seconds,
        cooldown=settings.alert_cooldown_seconds,
        evidence_dir=settings.evidence_dir,
        buffer_size=settings.evidence_buffer_size,
        local_ips=local_ips
    )

    # צור רשימה של כל הגלאים הפעילים
    all_detectors = [syn_detector, stealth_detector]

    # העבר את הרשימה ל-Handler
    handler = PacketHandler(
        detectors=all_detectors,
        ui=ui
    )

    # 5. הדפסת הודעת פתיחה
    settings.console.print("[bold green][*] SniffGuard IDS Started (Modular Version)[/bold green]")
    settings.console.print(f"[*] Monitoring interfaces: [bold cyan]{', '.join(monitored_interfaces)}[/bold cyan]")
    settings.console.print(f"[*] Local IPs: [bold yellow]{local_ips}[/bold yellow]")
    settings.console.print(f"[*] Alerts will be logged to '{settings.log_file}'")
    settings.console.print(f"[*] Evidence PCAP files will be saved in '{settings.evidence_dir}/' directory.")
    settings.console.print("[*] Press Ctrl+C to stop.")

    # 6. הפעלת הלולאה הראשית
    monotonic_time = time.monotonic
    with Live(ui.create_table(), refresh_per_second=5, console=settings.console) as live:
        last_ui_update = [monotonic_time()]

        def update_live_table(packet):
            # זו הפונקציה ש-Scapy קוראת לה
            handler.process_packet(packet)
            
            # עדכון ה-UI במרווחים קבועים (כמו בקוד הישן)
            now = monotonic_time()
            if now - last_ui_update[0] >= settings.ui_update_interval:
                live.update(ui.create_table())
                last_ui_update[0] = now

        try:
            sniff(
                iface=monitored_interfaces, 
                filter=settings.bpf_filter, 
                prn=update_live_table, 
                store=False
            )
        except KeyboardInterrupt:
            settings.console.print("\n[*] Sniffer stopped by user.")
        except Exception as e:
            settings.console.print(f"[!] Error while sniffing (check permissions/interface/BPF): {e}")
            logger.error(f"Sniff error: {e}")
        finally:
            # עדכון אחרון לטבלה לפני יציאה
            live.update(ui.create_table())

if __name__ == "__main__":
    main()
