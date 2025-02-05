from scapy.all import sniff, IP, TCP, UDP
import logging
import smtplib
import threading
import queue
import tkinter as tk
from tkinter import scrolledtext
from email.message import EmailMessage

# Configure logging
LOG_FILE = "network_traffic.log"
BLACKLIST_FILE = "blacklist_ips.txt"
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(message)s')

# Email alert configuration
EMAIL_ADDRESS = "your_email@gmail.com"  # Replace with your email
EMAIL_PASSWORD = "your_password"  # Replace with your email password
ALERT_RECIPIENT = "recipient_email@gmail.com"  # Replace with recipient email

# GUI Application Setup
def update_gui(log_text, message):
    log_text.insert(tk.END, message + "\n")
    log_text.yview(tk.END)

def start_gui(packet_queue):
    root = tk.Tk()
    root.title("Network Packet Sniffer")
    
    log_text = scrolledtext.ScrolledText(root, width=80, height=20)
    log_text.pack()
    
    def process_packets():
        while True:
            if not packet_queue.empty():
                message = packet_queue.get()
                update_gui(log_text, message)
            root.update()
    
    threading.Thread(target=process_packets, daemon=True).start()
    root.mainloop()

def send_email_alert(alert_message):
    """Send an email alert when suspicious activity is detected."""
    try:
        msg = EmailMessage()
        msg.set_content(alert_message)
        msg["Subject"] = "[ALERT] Suspicious Network Activity Detected"
        msg["From"] = EMAIL_ADDRESS
        msg["To"] = ALERT_RECIPIENT
        
        server = smtplib.SMTP_SSL("smtp.gmail.com", 465)
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.send_message(msg)
        server.quit()
        print("[+] Alert email sent successfully!")
    except Exception as e:
        print(f"[-] Failed to send alert email: {e}")

def add_to_blacklist(ip_address):
    """Add suspicious IPs to a blacklist file."""
    with open(BLACKLIST_FILE, "a") as f:
        f.write(ip_address + "\n")
    print(f"[!] {ip_address} added to blacklist.")
    logging.warning(f"Blacklisted IP: {ip_address}")

def packet_handler(packet, packet_queue):
    """Processes captured network packets and logs suspicious activity."""
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "OTHER"
        
        log_message = f"[+] Packet Captured: {src_ip} -> {dst_ip} ({protocol})"
        print(log_message)
        logging.info(log_message)
        packet_queue.put(log_message)
        
        if protocol == "TCP" and packet.haslayer(TCP):
            flags = packet[TCP].flags
            if flags == 2:  # SYN flag (potential scanning activity)
                alert_message = f"[!] Possible SYN scan detected from {src_ip}"
                print(alert_message)
                logging.warning(alert_message)
                send_email_alert(alert_message)
                add_to_blacklist(src_ip)

def filter_packets(packet):
    """Filters packets to capture only suspicious traffic (e.g., SYN scans or specific ports)."""
    if packet.haslayer(TCP):
        flags = packet[TCP].flags
        if flags == 2:  # Capturing only SYN packets (potential port scans)
            return True
    return False

def start_sniffing(interface, packet_queue):
    print(f"[+] Starting network packet sniffer on interface: {interface}")
    sniff(iface=interface, prn=lambda pkt: packet_handler(pkt, packet_queue), store=False, lfilter=filter_packets)

if __name__ == "__main__":
    network_interface = input("Enter network interface (e.g., eth0, wlan0): ")
    packet_queue = queue.Queue()
    
    # Start GUI in a separate thread
    threading.Thread(target=start_gui, args=(packet_queue,), daemon=True).start()
    
    # Start packet sniffing in another thread
    sniffing_thread = threading.Thread(target=start_sniffing, args=(network_interface, packet_queue))
    sniffing_thread.start()
