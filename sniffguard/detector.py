# sniffguard/detector.py
import time
import logging
from collections import deque

from scapy.all import wrpcap
from scapy.layers.inet import IP, TCP

# אנחנו צריכים את פונקציית העזר שיצרנו
from sniffguard.utils import to_safe_filename

class PortScanDetector:
    """
    Manages the state and logic for detecting SYN-based port scans.
    This class is stateful and tracks scans over time.
    """
    def __init__(self, threshold: int, time_window: int, cooldown: int, evidence_dir: str, buffer_size: int, local_ips: set):
        # Settings
        self.port_scan_threshold = threshold
        self.time_window_seconds = time_window
        self.alert_cooldown_seconds = cooldown
        self.evidence_dir = evidence_dir
        self.evidence_buffer_size = buffer_size
        self.local_ips = local_ips # <-- חשוב! המחלקה יודעת מה ה-IP המקומי

        # Internal state (מה שהיה פעם משתנים גלובליים)
        self.scan_tracker = {}
        self.scan_cooldown_tracker = {}

        # Dependencies
        self.logger = logging.getLogger("ids_logger")
        self.monotonic_time = time.monotonic

    def detect(self, packet) -> dict | None:
        """
        Processes a single packet and checks if it triggers a port scan alert.

        If a scan is detected, it logs the alert, saves the evidence,
        and returns a dictionary with alert details for the UI.

        Returns:
            dict: Alert details if triggered, otherwise None.
        """

        # אנחנו מחפשים רק פקטים של SYN (flags=0x02)
        if not (TCP in packet and (packet[TCP].flags & 0x02)):
            return None

        try:
            # בדיקה אם הפקט הזה קשור לאחד ה-IPs המנוטרים
            if not (packet[IP].src in self.local_ips or packet[IP].dst in self.local_ips):
                 return None

            key = (packet[IP].src, packet[IP].dst)
            dest_port = packet[TCP].dport
        except (AttributeError, IndexError):
            # פקט פגום או לא IP/TCP
            return None

        now = self.monotonic_time()

        # התחל סשן חדש או אפס אם חלון הזמן פג
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

        # בדוק אם עברנו את הסף
        if scanned_ports_count <= self.port_scan_threshold:
            return None

        # --- התראה הופעלה ---

        # בדוק אם הזוג (src, dst) הזה נמצא ב-cooldown
        on_cooldown = key in self.scan_cooldown_tracker and \
                      (now - self.scan_cooldown_tracker.get(key, 0)) < self.alert_cooldown_seconds

        if on_cooldown:
            return None

        # --- התראה חדשה (לא ב-COOLDOWN) ---

        attacker, victim = key
        timestamp_str = time.strftime("%Y-%m-%d_%H-%M-%S")
        pcap_filename = f"scan_{timestamp_str}_from_{to_safe_filename(attacker)}.pcap"
        pcap_path = f"{self.evidence_dir}/{pcap_filename}"

        # שמור ראיות PCAP
        wrote_pcap = False
        try:
            packets_to_save = list(self.scan_tracker[key]["packets"])
            if packets_to_save:
                wrpcap(pcap_path, packets_to_save)
                wrote_pcap = True
            else:
                self.logger.info(f"No evidence packets to write for {attacker}->{victim} (skipping PCAP).")
        except Exception as e:
            self.logger.error(f"Failed to save PCAP to {pcap_path}: {e}")

        iface = getattr(packet, "sniffed_on", "unknown")
        evidence_suffix = f"Evidence saved to {pcap_path}" if wrote_pcap else "No evidence file written"

        # רשום את ההתראה הטכנית לקובץ הלוג
        alert_message = (
            f"PORT SCAN DETECTED on interface {iface}: {attacker} -> {victim} "
            f"({scanned_ports_count} unique ports in {self.time_window_seconds}s; "
            f"threshold={self.port_scan_threshold}). {evidence_suffix}"
        )
        self.logger.warning(alert_message)

        # עדכן cooldown ונקה את הסשן
        self.scan_cooldown_tracker[key] = now
        self.scan_tracker.pop(key, None)

        # החזר פרטים ל-UI
        return {
            "attacker": attacker,
            "victim": victim,
            "interface": iface,
            "port_count": scanned_ports_count,
            "evidence_suffix": evidence_suffix
        }
