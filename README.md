# SniffGuard 🛡️
*A lightweight, command-line Intrusion Detection System with a live dashboard & PCAP evidence capture.*

This is a project I built to deepen my understanding of data communications and cybersecurity. It's a lightweight IDS written in Python that monitors live network traffic, detects suspicious SYN-based port scans, logs alerts, and saves raw packet evidence for forensic analysis.

---
## ✨ Key Features
* Modular Architecture:Refactored into dedicated, decoupled classes (`Detector`, `UI`, `Handler`) for clean, scalable development.
* Live Dashboard:Real-time traffic display using the Rich library.
* 🛡️ **Multi-Protocol Scan Detection:** A robust, stateful engine now detects **SYN, FIN, NULL, and XMAS Scans**.
* **PCAP Evidence:** Saves all packets from a detected scan to a `.pcap` file for analysis in tools like Wireshark.
* **Dynamic & Robust:** Automatically detects available interfaces, uses efficient BPF filters, and handles errors gracefully.
* **Professional Logging:** Alerts are saved to a rotating log file to prevent disk space issues.
* **Fully Configurable:** All parameters (interfaces, thresholds, etc.) can be controlled via CLI arguments.
---

### 🖼️ Showcase
Here is a short video demonstrating the project's core functionality:
https://youtu.be/RRBL-ykiJFo
| Normal Monitoring | Alert Triggered |
| :---: | :---: |
| ![Normal Terminal](https://github.com/user-attachments/assets/3b942c29-8003-4ccf-bdca-dc30c8913276) | ![Alert Terminal](https://github.com/user-attachments/assets/7eed5f88-d8f2-49d0-8928-b2b7fe3b773d) |

---

### ✅ Prerequisites
* Python 3.8+
* Root/Administrator privileges to run.
* On Windows, [Npcap](https://npcap.com/) must be installed.

---

## 🚀 Quick Start

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/BarDev1999/SniffGuard.git](https://github.com/BarDev1999/SniffGuard.git)
    cd SniffGuard
    ```

2.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

3.  **Run the IDS:**
    ```bash
    # On Linux/macOS, run the new main entry point
    sudo python3 main.py
    ```

---

## ⚙️ Lab Demo Commands
You can test the IDS safely in your lab environment with these commands. Note that the BPF filter is now set to capture all TCP traffic to enable stealth scan detection.

```bash
# 1. SYN Scan (Standard Nmap Stealth Scan)
sudo nmap -sS -p 1-200 127.0.0.1

# 2. FIN Scan (Nmap Stealth Scan using FIN flag)
sudo nmap -sF -p 1-200 127.0.0.1

# 3. NULL Scan (Nmap Stealth Scan with no flags set)
sudo nmap -sN -p 1-200 127.0.0.1

# 4. XMAS Scan (Nmap Stealth Scan with FIN, PSH, URG flags)
sudo nmap -sX -p 1-200 127.0.0.1
```
---

📜 License
This project is licensed under the MIT License.
