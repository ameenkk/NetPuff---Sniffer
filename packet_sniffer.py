import tkinter as tk
from tkinter import ttk
from scapy.all import sniff, IP, TCP, UDP
import threading
import openpyxl

# List to hold captured packets
captured_packets = []

# Function to start packet sniffing in a separate thread
def packet_sniffer():
    def packet_callback(packet):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "Other"
            payload = bytes(packet[TCP].payload) if TCP in packet else bytes(packet[UDP].payload) if UDP in packet else None
            payload = payload.decode(errors="ignore") if payload else "No Payload"
            packet_data = {"src_ip": src_ip, "dst_ip": dst_ip, "protocol": protocol, "payload": payload}
            captured_packets.append(packet_data)
            display_packets(captured_packets)  # Update the table when a new packet is captured

    sniff(prn=packet_callback, store=False)

# Function to start sniffing in a separate thread
def start_sniffing():
    threading.Thread(target=packet_sniffer, daemon=True).start()

# Function to stop sniffing and clear the captured data
def stop_sniffing():
    global captured_packets
    captured_packets = []  # Reset captured data
    display_packets(captured_packets)

# Function to download captured data as an Excel file
def download_excel():
    workbook = openpyxl.Workbook()
    sheet = workbook.active
    sheet.title = "Captured Packets"

    # Add headers
    sheet.append(["Source IP", "Destination IP", "Protocol", "Payload"])

    # Add captured packet data
    for packet in captured_packets:
        sheet.append([packet["src_ip"], packet["dst_ip"], packet["protocol"], packet["payload"]])

    file_path = "captured_packets.xlsx"
    workbook.save(file_path)

    # You can add your logic to show a file dialog or notify user about the download here
    print(f"Captured data saved to {file_path}")

# Function to display captured packets in the table
def display_packets(data):
    for row in treeview.get_children():
        treeview.delete(row)  # Clear existing rows

    for packet in data:
        treeview.insert("", "end", values=(packet["src_ip"], packet["dst_ip"], packet["protocol"], packet["payload"]))

# Create the main window
root = tk.Tk()
root.title("Net Puff")  # Title of the window
root.geometry("800x600")

# Create and place the buttons and search bar
start_button = tk.Button(root, text="Start Sniffing", command=start_sniffing)
start_button.pack(pady=10)

stop_button = tk.Button(root, text="Stop Sniffing", command=stop_sniffing)
stop_button.pack(pady=10)

download_button = tk.Button(root, text="Download Excel", command=download_excel)
download_button.pack(pady=10)

search_label = tk.Label(root, text="Search:")
search_label.pack(pady=5)
search_entry = tk.Entry(root)
search_entry.pack(pady=5)

# Create the Treeview to display the packet information
columns = ("Source IP", "Destination IP", "Protocol", "Payload")
treeview = ttk.Treeview(root, columns=columns, show="headings")
treeview.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

# Define headings
for col in columns:
    treeview.heading(col, text=col)

# Start the Tkinter event loop
root.mainloop()
