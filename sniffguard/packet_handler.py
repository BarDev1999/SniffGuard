# sniffguard/packet_handler.py
import time
from scapy.layers.inet import IP, TCP

from sniffguard.ui import LiveUI

class PacketHandler:
    """
    Acts as the intermediary between Scapy, the UI, and the Detector.
    Its job is to orchestrate the flow of data.
    """
    def __init__(self, detectors: list, ui: LiveUI):
        self.detectors = detectors  # This is now a list
        self.ui = ui

    def process_packet(self, packet):
        """
        This is the main callback function called by Scapy's sniff().
        It performs two tasks:
        1. Update the UI with the packet info.
        2. Pass the packet to ALL detectors for analysis.
        """
        
        # 1. עדכון UI
        try:
            if IP in packet and TCP in packet:
                interface_name = getattr(packet, "sniffed_on", "unknown")
                source_ip = packet[IP].src
                source_port = str(packet[TCP].sport)
                destination_ip = packet[IP].dst
                destination_port = str(packet[TCP].dport)
                tcp_flags = str(packet[TCP].flags)

                packet_info = (interface_name, source_ip, source_port, "->", destination_ip, destination_port, tcp_flags)
                self.ui.add_packet_row(packet_info)
        except (AttributeError, IndexError):
            pass

        # 2. שלח לכל הגלאים
        for detector in self.detectors:
            alert_details = detector.detect(packet)
            
            # 3. אם חזרה התראה, עדכן UI
            if alert_details:
                display_timestamp = time.strftime("%H:%M:%S")
                attacker = alert_details['attacker']
                evidence_suffix = alert_details['evidence_suffix']
                
                # בדוק אם זה SYN scan או סוג אחר (scan_name נוסף ע"י StealthScanDetector)
                scan_name = alert_details.get("scan_name", "PORT SCAN (SYN)") 
                
                alert_msg = (
                    f"🚨 [bold red]Last Alert ({display_timestamp}): {scan_name} from {attacker}. "
                    f"{evidence_suffix}[/bold red]"
                )
                self.ui.set_alert_message(alert_msg)
                
                # מצאנו התראה, אין צורך להמשיך לבדוק בגלאים אחרים
                break
