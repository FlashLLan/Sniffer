import sys
import threading
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP
from scapy.layers.dns import DNS
from scapy.utils import wrpcap, rdpcap
from scapy.packet import Raw
from scapy.sendrecv import sniff
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QPushButton, QVBoxLayout, QWidget,
    QTableWidget, QTableWidgetItem, QFileDialog, QLineEdit, QMessageBox, QHeaderView
)
from PyQt6.QtGui import QColor
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QTextEdit


# global variables
captured_packets = []
sniffing = False

# colors for protocols
protocol_colors = {
    "TCP": QColor(204, 229, 255),  # Light blue
    "UDP": QColor(212, 255, 212),  # Light green
    "ARP": QColor(255, 225, 155),  # Light yellow
    "ICMP": QColor(255, 200, 255),  # Light pink
    "HTTP": QColor(212, 199, 255), # Light purple
    "Other": QColor(255, 190, 190)  # Light red
}

def extract_packet_info(packet):
    src_ip, dst_ip = "N/A", "N/A"
    protocol = "Other"
    info = "N/A"

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
    elif packet.haslayer(ARP):
        src_ip = packet[ARP].psrc
        dst_ip = packet[ARP].pdst
        protocol = "ARP"
        info = "ARP Request" if packet[ARP].op == 1 else "ARP Reply"
        return src_ip, dst_ip, protocol, info

    #protocols
    if packet.haslayer(TCP):
        protocol = "TCP"
    elif packet.haslayer(UDP):
        protocol = "UDP"
    elif packet.haslayer(ICMP):
        protocol = "ICMP"

    # DNS
    if packet.haslayer(DNS):
        dns = packet[DNS]
        try:
            domain = dns.qd.qname.decode() if dns.qd else "<no domain>"
            if dns.qr == 0:
                info = f"DNS Query: {domain}"
            else:
                answers = []
                for i in range(dns.ancount):
                    ans = dns.an[i]
                    if hasattr(ans, 'rdata'):
                        rdata = str(ans.rdata)
                        if rdata.startswith("b'"):
                            rdata = rdata[2:-1]
                        answers.append(rdata)
                info = f"DNS Response: {domain} → {', '.join(answers)}" if answers else f"DNS Response: {domain}"
        except Exception:
            info = "DNS (parse error)"
        return src_ip, dst_ip, protocol, info

    # ICMP
    if packet.haslayer(ICMP):
        icmp = packet[ICMP]
        if icmp.type == 8:
            info = "ICMP Echo Request"
        elif icmp.type == 0:
            info = "ICMP Echo Reply"
        elif icmp.type == 3:
            info = "Destination Unreachable"
        elif icmp.type == 11:
            info = "Time Exceeded"
        else:
            info = f"ICMP Type={icmp.type} Code={icmp.code}"
        return src_ip, dst_ip, protocol, info

    # UDP
    if packet.haslayer(UDP):
        udp = packet[UDP]
        info = f"UDP {udp.sport} → {udp.dport}"
        return src_ip, dst_ip, protocol, info

    # TCP
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        flags = tcp.sprintf("%TCP.flags%")
        if flags == "S":
            info = f"SYN to port {tcp.dport}"
        elif flags == "SA":
            info = f"SYN-ACK from port {tcp.sport}"
        elif flags == "A":
            info = f"ACK Seq={tcp.seq} Ack={tcp.ack}"
        elif flags == "PA":
            info = f"PSH-ACK Seq={tcp.seq} Ack={tcp.ack}"
        elif flags == "FA":
            info = f"FIN-ACK Seq={tcp.seq} Ack={tcp.ack}"
        else:
            info = f"TCP Seq={tcp.seq} Ack={tcp.ack} Flags={flags}"

        # HTTP detection
        if packet.haslayer(Raw):
            try:
                payload = packet[Raw].load.decode(errors="ignore")
                if "HTTP" in payload or payload.startswith(("GET", "POST", "HEAD")):
                    info = f"HTTP: {payload.splitlines()[0]}"
                    protocol = "HTTP"
            except:
                pass

        return src_ip, dst_ip, protocol, info

    # fallback summary
    try:
        info = packet.summary()
    except:
        pass

    return src_ip, dst_ip, protocol, info




# sniffing function
def start_sniffing(filter_str, update_ui):
    global sniffing
    sniffing = True
    try:
        sniff(filter=filter_str, prn=lambda pkt: packet_callback(pkt, update_ui), store=False, stop_filter=lambda x: not sniffing)
    except Exception as e:
        QMessageBox.critical(None, "Filter Error", f"Invalid filter syntax: {e}")


# callback function for captured packets
def packet_callback(packet, update_ui):
    if not sniffing:
        return


    packet_num = len(captured_packets) + 1
    src_ip, dst_ip, protocol, info = extract_packet_info(packet)

    packet_len = len(packet)
    captured_packets.append(packet)
    update_ui(packet_num, src_ip, dst_ip, protocol, packet_len, info, packet)

    packet_len = len(packet)

    if packet.haslayer(DNS):
        if packet[DNS].qr == 0:
            info = f"DNS Query: {packet[DNS].qd.qname.decode()}"

    if packet.haslayer(Raw) and packet.haslayer(TCP):
        payload = packet[Raw].load.decode(errors="ignore")
        if "HTTP" in payload:
            info = f"HTTP: {payload.splitlines()[0]}"

    captured_packets.append(packet)
    update_ui(packet_num, src_ip, dst_ip, protocol, packet_len, info, packet)


# PyQt6 GUI
class PacketSnifferGUI(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Modern Packet Sniffer")
        self.setGeometry(100, 100, 1200, 700)


        layout = QVBoxLayout()

        # filter input
        self.filter_input = QLineEdit(self)
        self.filter_input.setPlaceholderText("Enter filter (e.g., tcp, udp, port 53)")
        self.filter_input.setStyleSheet("background-color: #222; color: white; padding: 5px; border: 1px solid #444; font-size: 14px;")
        layout.addWidget(self.filter_input)


        button_style = """
            QPushButton {
                background-color: #333; 
                color: white; 
                border: 1px solid #555; 
                padding: 10px; 
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #444;
            }
            QPushButton:pressed {
                background-color: #666;
            }
        """

        self.start_button = QPushButton("Start Sniffing", self)
        self.start_button.setStyleSheet(button_style)
        self.start_button.clicked.connect(self.start_sniffing)
        layout.addWidget(self.start_button)

        self.stop_button = QPushButton("Stop Sniffing", self)
        self.stop_button.setStyleSheet(button_style)
        self.stop_button.clicked.connect(self.stop_sniffing)
        layout.addWidget(self.stop_button)

        self.clear_button = QPushButton("Clear Packets", self)
        self.clear_button.setStyleSheet(button_style)
        self.clear_button.clicked.connect(self.clear_packets)
        layout.addWidget(self.clear_button)

        self.save_button = QPushButton("Save to PCAP", self)
        self.save_button.setStyleSheet(button_style)
        self.save_button.clicked.connect(self.save_pcap)
        layout.addWidget(self.save_button)

        self.load_button = QPushButton("Load PCAP", self)
        self.load_button.setStyleSheet(button_style)
        self.load_button.clicked.connect(self.load_pcap)
        layout.addWidget(self.load_button)

        # packet table
        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(6)
        self.packet_table.setHorizontalHeaderLabels(["#", "Source IP", "Destination IP", "Protocol", "Length", "Info"])
        self.packet_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.packet_table.verticalHeader().setVisible(False)
        self.packet_table.setShowGrid(False)
        self.packet_table.setStyleSheet("background-color: #1E1E1E; color: white; font-size: 14px;")
        self.packet_table.horizontalHeader().setStyleSheet(
            "QHeaderView::section {background-color: #444; color: white; font-weight: bold;}")
        self.packet_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.packet_table.setStyleSheet("""
            QTableWidget::item:selected { background-color: #4477AA; color: white; }
        """)
        self.packet_table.cellDoubleClicked.connect(self.show_packet_details)  # for the full packet view
        layout.addWidget(self.packet_table)

        # main container
        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

    def show_packet_details(self, row, col):
        packet = captured_packets[row]

        self.details_window = QWidget()  # store a reference to prevent garbage collection
        self.details_window.setWindowTitle(f"Packet #{row + 1} Details")
        self.details_window.resize(700, 500)

        layout = QVBoxLayout(self.details_window)

        text_box = QTextEdit()
        text_box.setText(packet.show(dump=True))  #packet details
        text_box.setReadOnly(True)

        layout.addWidget(text_box)

        self.details_window.setLayout(layout)
        self.details_window.show()


    def start_sniffing(self):
        global sniffing
        sniffing = True
        filter_str = self.filter_input.text().strip()
        threading.Thread(target=start_sniffing, args=(filter_str, self.update_table), daemon=True).start()

    def stop_sniffing(self):
        global sniffing
        sniffing = False

    def clear_packets(self):
        global captured_packets
        captured_packets = []
        self.packet_table.setRowCount(0)

    # save PCAP
    def save_pcap(self):
        if not captured_packets:
            QMessageBox.warning(self, "No Data", "No packets to save!")
            return
        filename, _ = QFileDialog.getSaveFileName(self, "Save File", "", "PCAP Files (*.pcap)")
        if filename:
            wrpcap(filename, captured_packets)
            QMessageBox.information(self, "Success", f"Packets saved to {filename}")

    # load PCAP
    def load_pcap(self):
        filename, _ = QFileDialog.getOpenFileName(self, "Open File", "", "PCAP Files (*.pcap)")
        if not filename:
            return

        global captured_packets
        captured_packets = rdpcap(filename)
        self.packet_table.setRowCount(0)

        for idx, packet in enumerate(captured_packets, start=1):
            src_ip, dst_ip, protocol, info = extract_packet_info(packet)

            if packet.haslayer(IP):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                protocol = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(
                    UDP) else "ICMP" if packet.haslayer(
                    ICMP) else "Other"
            elif packet.haslayer(ARP):
                src_ip = packet[ARP].psrc
                dst_ip = packet[ARP].pdst
                protocol = "ARP"
                info = "ARP Request" if packet[ARP].op == 1 else "ARP Reply"



            if packet.haslayer(Raw) and packet.haslayer(TCP):
                try:
                    payload = packet[Raw].load.decode(errors="ignore")
                    if "HTTP" in payload:
                        info = f"HTTP: {payload.splitlines()[0]}"
                except:
                    pass

            self.update_table(idx, src_ip, dst_ip, protocol, len(packet), info, packet)

    def update_table(self, packet_num, src_ip, dst_ip, protocol, packet_len, info, packet):
        row_count = self.packet_table.rowCount()
        self.packet_table.insertRow(row_count)

        for col, value in enumerate([str(packet_num), src_ip, dst_ip, protocol, str(packet_len), info]):
            item = QTableWidgetItem(value)
            item.setForeground(QColor(0, 0, 0))
            item.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)

            if protocol in protocol_colors:
                item.setBackground(protocol_colors[protocol])

            self.packet_table.setItem(row_count, col, item)



app = QApplication(sys.argv)
window = PacketSnifferGUI()
window.show()
sys.exit(app.exec())
