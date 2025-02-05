# Network Packet Sniffer

## 📌 Overview
This **Network Packet Sniffer** captures and analyzes network traffic in real time. It logs packet details, identifies potential threats (such as **SYN scans**), and automatically blacklists suspicious IPs. It also features a **real-time GUI** to display captured traffic.

## 🚀 Features
✔ **Real-time packet sniffing** (TCP, UDP, IP)
✔ **Graphical User Interface (GUI)** to visualize captured packets
✔ **Automatic detection of suspicious activity** (e.g., SYN scans)
✔ **Email alerts** for flagged threats
✔ **IP Blacklisting** – stores flagged IPs in `blacklist_ips.txt`
✔ **Multi-threaded for performance**

## 📦 Installation
### **1️⃣ Install Dependencies**
```bash
pip install scapy tkinter
```

### **2️⃣ Configure Email Alerts**
- Replace `EMAIL_ADDRESS`, `EMAIL_PASSWORD`, and `ALERT_RECIPIENT` in the script.
- If using Gmail, enable **Less Secure Apps** or use an **App Password**.

## 🛠 Usage
### **Run the script (Root/Admin required)**
```bash
sudo python network_packet_sniffer.py
```

### **Provide Input**
1. **Enter your network interface** (e.g., `eth0`, `wlan0`).
2. **Monitor the GUI for live packet activity**.
3. **View alerts in real-time for suspicious packets**.

### **Example Output**
```
Enter network interface (e.g., eth0, wlan0): wlan0
[+] Starting network packet sniffer on interface: wlan0
[+] Packet Captured: 192.168.1.10 -> 192.168.1.1 (TCP)
[!] Possible SYN scan detected from 192.168.1.20
[!] 192.168.1.20 added to blacklist.
[+] Alert email sent successfully!
```

## 📄 Logs & Blacklist
- **Captured packets** are logged in `network_traffic.log`
- **Blacklisted IPs** are stored in `blacklist_ips.txt`

## ⚠️ Disclaimer
This tool is for **educational and security research purposes only**. Unauthorized use on external networks is **illegal**. Ensure you have **explicit permission** before running it.

🔒 **Stay ethical and secure!**

