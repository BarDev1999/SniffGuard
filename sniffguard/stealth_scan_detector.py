# sniffguard/stealth_scan_detector.py
import time
import logging
from collections import deque
from scapy.all import wrpcap
from scapy.layers.inet import IP, TCP
from sniffguard.utils import to_safe_filename

# TCP Flags
FIN = 0x01
PSH = 0x08
URG = 0x20

# XMAS = FIN + PSH + URG
XMAS_FLAGS = (FIN | PSH | URG) # 0x29

class StealthScanDetector:
    """
    Manages the state and logic for detecting Stealth Scans
    (FIN, NULL, XMAS).
    """
    def __init__(self, threshold: int, time_window: int, cooldown: int, evidence_dir: str, buffer_size: int, local_ips: set):
        # Settings
        self.port_scan_threshold = threshold
        self.time_window_seconds = time_window
        self.alert_cooldown_seconds = cooldown
        self.evidence_dir = evidence_dir
        self.evidence_buffer_size = buffer_size
        self.local_ips = local_ips
        
        # Internal state
        self.scan_tracker = {}
        self.scan_cooldown_tracker = {}
        
        # Dependencies
        self.logger = logging.getLogger("ids_logger")
        self.monotonic_time = time.monotonic
        
        # מפה שעוזרת לנו לתת שמות להתראות
        self.scan_type_map = {
            FIN: "FIN SCAN",
            0x00: "NULL SCAN",
            XMAS_FLAGS: "XMAS SCAN"
        }

    def get_scan_type(self, flags: int) -> int | None:
        """בדוק אם הפקט מתאים לאחת מסריקות ההתגנבות."""
        if flags == FIN:
            return FIN
        if flags == 0x00:
            return 0x00
        if flags == XMAS_FLAGS:
            return XMAS_FLAGS
        return None

    def detect(self, packet) -> dict | None:
        """
        Processes a packet and checks for stealth scans.
        Returns alert details if triggered, otherwise None.
        """
        
        if not (IP in packet and TCP in packet):
            return None

        try:
            flags = packet[TCP].flags
            
            # בדוק אם זה פקט שאנחנו מחפשים
            scan_type_flag = self.get_scan_type(flags)
            if scan_type_flag is None:
                return None
                
            # בדוק אם זה קשור אלינו
            if not (packet[IP].src in self.local_ips or packet[IP].dst in self.local_ips):
                 return None
                 
            key = (packet[IP].src, packet[IP].dst, scan_type_flag)
            dest_port = packet[TCP].dport
            
        except (AttributeError, IndexError):
            return None
        
        now = self.monotonic_time()

        # התחל סשן חדש או אפס
        if key not in self.scan_tracker or (now - self.scan_tracker[key]["timestamp"] > self.time_window_seconds):
            self.scan_tracker[key] = {
                "timestamp": now,
                "ports": {dest_port},
                "packets": deque([packet], maxlen=self.evidence_buffer_size),
            }
        else:
            # עדכן סשן קיים
            self.scan_tracker[key]["ports"].add(dest_port)
            self.scan_tracker[key]["timestamp"] = now
            self.scan_tracker[key]["packets"].append(packet)

        scanned_ports_count = len(self.scan_tracker[key]["ports"])

        if scanned_ports_count <= self.port_scan_threshold:
            return None

        # --- התראה הופעלה ---
        
        if key in self.scan_cooldown_tracker and \
           (now - self.scan_cooldown_tracker.get(key, 0)) < self.alert_cooldown_seconds:
            return None

        # --- התראה חדשה ---
        
        attacker, victim, scan_type = key
        scan_name = self.scan_type_map.get(scan_type, "STEALTH SCAN")
        
        timestamp_str = time.strftime("%Y-%m-%d_%H-%M-%S")
        pcap_filename = f"{scan_name.split(' ')[0]}_{timestamp_str}_from_{to_safe_filename(attacker)}.pcap"
        pcap_path = f"{self.evidence_dir}/{pcap_filename}"

        # שמור ראיות
        wrote_pcap = False
        try:
            packets_to_save = list(self.scan_tracker[key]["packets"])
            if packets_to_save:
                wrpcap(pcap_path, packets_to_save)
                wrote_pcap = True
        except Exception as e:
            self.logger.error(f"Failed to save PCAP to {pcap_path}: {e}")

        iface = getattr(packet, "sniffed_on", "unknown")
        evidence_suffix = f"Evidence saved to {pcap_path}" if wrote_pcap else "No evidence file written"

        # רשום ללוג
        alert_message = (
            f"{scan_name} DETECTED on {iface}: {attacker} -> {victim} "
            f"({scanned_ports_count} unique ports in {self.time_window_seconds}s). {evidence_suffix}"
        )
        self.logger.warning(alert_message)
        
        self.scan_cooldown_tracker[key] = now
        self.scan_tracker.pop(key, None)

        # החזר פרטים ל-UI
        return {
            "attacker": attacker,
            "victim": victim,
            "scan_name": scan_name,
            "evidence_suffix": evidence_suffix
        }
